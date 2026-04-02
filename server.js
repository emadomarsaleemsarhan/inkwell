const express = require('express');
const path = require('path');
const multer = require('multer');
const mammoth = require('mammoth');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'inkwell-dev-secret-change-in-production';

// ─── Cloudinary Config ────────────────────────────────────────────────────────
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ─── PostgreSQL Pool ──────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// ─── DB Init ──────────────────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email       TEXT UNIQUE NOT NULL,
      username    TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL,
      password    TEXT NOT NULL,
      bio         TEXT DEFAULT '',
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS articles (
      id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      author_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title        TEXT NOT NULL,
      description  TEXT DEFAULT '',
      content      TEXT NOT NULL,
      cover_image  TEXT DEFAULT '',
      tags         TEXT[] DEFAULT '{}',
      status       TEXT DEFAULT 'draft',
      slug         TEXT UNIQUE,
      views        INTEGER DEFAULT 0,
      reading_time INTEGER DEFAULT 1,
      word_count   INTEGER DEFAULT 0,
      language     TEXT DEFAULT 'ar',
      created_at   TIMESTAMPTZ DEFAULT NOW(),
      published_at TIMESTAMPTZ
    );

    CREATE INDEX IF NOT EXISTS idx_articles_author ON articles(author_id);
    CREATE INDEX IF NOT EXISTS idx_articles_status ON articles(status);
    CREATE INDEX IF NOT EXISTS idx_articles_published ON articles(published_at DESC);
  `);
  console.log('✅ Database initialized');
}

// ─── Security Middleware ──────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many requests' } });
const apiLimiter  = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use('/api/auth', authLimiter);
app.use('/api', apiLimiter);

// ─── Multer: docx (memory) ────────────────────────────────────────────────────
const docxUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.originalname.endsWith('.docx')) cb(null, true);
    else cb(new Error('Only .docx files allowed'));
  },
});

// ─── Multer: cover image → Cloudinary ────────────────────────────────────────
const coverStorage = new CloudinaryStorage({
  cloudinary,
  params: { folder: 'inkwell/covers', allowed_formats: ['jpg', 'jpeg', 'png', 'webp'], transformation: [{ width: 1200, height: 630, crop: 'fill', quality: 'auto' }] },
});
const coverUpload = multer({ storage: coverStorage, limits: { fileSize: 5 * 1024 * 1024 } });

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

function optionalAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (token) { try { req.user = jwt.verify(token, JWT_SECRET); } catch {} }
  next();
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function calcReadingTime(text) {
  const words = text.trim().split(/\s+/).length;
  return { words, minutes: Math.max(1, Math.ceil(words / 200)) };
}

function detectLanguage(text) {
  const arabicChars = (text.match(/[\u0600-\u06FF]/g) || []).length;
  return arabicChars > text.length * 0.3 ? 'ar' : 'en';
}

function makeSlug(title) {
  return title.toLowerCase()
    .replace(/[\u0600-\u06FF\s]+/g, m => encodeURIComponent(m).slice(0, 15))
    .replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-').slice(0, 80)
    + '-' + Date.now().toString(36);
}

function sanitizeUsername(u) {
  return u.toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 30);
}

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { email, password, username, displayName } = req.body;
  if (!email || !password || !username || !displayName)
    return res.status(400).json({ error: 'All fields required' });

  const cleanUsername = sanitizeUsername(username);
  if (cleanUsername.length < 3) return res.status(400).json({ error: 'Username too short' });

  try {
    const hashed = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO users (email, username, display_name, password)
       VALUES ($1, $2, $3, $4) RETURNING id, username, display_name, bio`,
      [email.toLowerCase(), cleanUsername, displayName, hashed]
    );
    const user = rows[0];
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, username: user.username, displayName: user.display_name, bio: user.bio } });
  } catch (err) {
    if (err.code === '23505') {
      const field = err.constraint?.includes('email') ? 'Email' : 'Username';
      return res.status(400).json({ error: `${field} already taken` });
    }
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email?.toLowerCase()]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, username: user.username, displayName: user.display_name, bio: user.bio } });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/auth/profile', authMiddleware, async (req, res) => {
  const { displayName, bio } = req.body;
  try {
    await pool.query('UPDATE users SET display_name=$1, bio=$2 WHERE id=$3', [displayName, bio, req.user.id]);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

// ─── ARTICLE ROUTES ───────────────────────────────────────────────────────────
// Parse .docx
app.post('/api/articles/parse', authMiddleware, docxUpload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const result = await mammoth.convertToHtml({ buffer: req.file.buffer }, {
      styleMap: [
        "p[style-name='Heading 1'] => h1:fresh",
        "p[style-name='Heading 2'] => h2:fresh",
        "p[style-name='Heading 3'] => h3:fresh",
      ]
    });
    const html = result.value;
    const plain = html.replace(/<[^>]+>/g, ' ');
    const { words, minutes } = calcReadingTime(plain);
    const language = detectLanguage(plain);
    const imgMatch = html.match(/<img[^>]+src="([^"]+)"/);
    const titleMatch = html.match(/<h1[^>]*>(.*?)<\/h1>/i) || html.match(/<p[^>]*>(.*?)<\/p>/i);
    const suggestedTitle = titleMatch ? titleMatch[1].replace(/<[^>]+>/g, '') : '';
    res.json({ html, words, readingTime: minutes, language, firstImage: imgMatch?.[1] || null, suggestedTitle });
  } catch (err) { res.status(500).json({ error: 'Failed to parse: ' + err.message }); }
});

// Upload cover → Cloudinary
app.post('/api/articles/cover', authMiddleware, coverUpload.single('cover'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ url: req.file.path });
});

// Create article
app.post('/api/articles', authMiddleware, async (req, res) => {
  const { title, description, content, coverImage, tags, status, readingTime, wordCount, language } = req.body;
  if (!title || !content) return res.status(400).json({ error: 'Title and content required' });
  const slug = makeSlug(title);
  try {
    const { rows } = await pool.query(
      `INSERT INTO articles (author_id, title, description, content, cover_image, tags, status, slug, reading_time, word_count, language, published_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [req.user.id, title, description||'', content, coverImage||'', tags||[], status||'draft',
       slug, readingTime||1, wordCount||0, language||'ar',
       status==='published' ? new Date() : null]
    );
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Server error: ' + err.message }); }
});

// Update article
app.put('/api/articles/:id', authMiddleware, async (req, res) => {
  const { title, description, content, coverImage, tags, status } = req.body;
  try {
    const { rows } = await pool.query('SELECT * FROM articles WHERE id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    if (rows[0].author_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    const publishedAt = status === 'published' && rows[0].status !== 'published' ? new Date() : rows[0].published_at;
    await pool.query(
      `UPDATE articles SET title=$1, description=$2, content=$3, cover_image=$4, tags=$5, status=$6, published_at=$7 WHERE id=$8`,
      [title, description, content, coverImage, tags, status, publishedAt, req.params.id]
    );
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

// Delete article
app.delete('/api/articles/:id', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT author_id FROM articles WHERE id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    if (rows[0].author_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    await pool.query('DELETE FROM articles WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

// Home feed
app.get('/api/articles', optionalAuth, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 12;
  const offset = (page - 1) * limit;
  try {
    const { rows: countRows } = await pool.query(`SELECT COUNT(*) FROM articles WHERE status='published'`);
    const total = parseInt(countRows[0].count);
    const { rows } = await pool.query(
      `SELECT a.id, a.title, a.description, a.cover_image, a.tags, a.status,
              a.reading_time, a.word_count, a.language, a.views,
              a.created_at, a.published_at,
              u.username, u.display_name
       FROM articles a JOIN users u ON u.id = a.author_id
       WHERE a.status='published'
       ORDER BY a.published_at DESC
       LIMIT $1 OFFSET $2`,
      [limit, offset]
    );
    const articles = rows.map(r => ({
      id: r.id, title: r.title, description: r.description,
      coverImage: r.cover_image, tags: r.tags, status: r.status,
      readingTime: r.reading_time, wordCount: r.word_count,
      language: r.language, views: r.views,
      createdAt: r.created_at, publishedAt: r.published_at,
      author: { username: r.username, displayName: r.display_name }
    }));
    res.json({ articles, total, page, pages: Math.ceil(total / limit) });
  } catch (err) { res.status(500).json({ error: 'Server error: ' + err.message }); }
});

// Single article
app.get('/api/articles/:id', optionalAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT a.*, u.username, u.display_name, u.bio
       FROM articles a JOIN users u ON u.id = a.author_id
       WHERE a.id=$1`,
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const a = rows[0];
    if (a.status === 'draft' && (!req.user || req.user.id !== a.author_id))
      return res.status(404).json({ error: 'Not found' });
    res.json({
      id: a.id, title: a.title, description: a.description,
      content: a.content, coverImage: a.cover_image, tags: a.tags,
      status: a.status, readingTime: a.reading_time, wordCount: a.word_count,
      language: a.language, views: a.views,
      createdAt: a.created_at, publishedAt: a.published_at,
      author: { username: a.username, displayName: a.display_name, bio: a.bio }
    });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

// Increment views
app.post('/api/articles/:id/view', async (req, res) => {
  try {
    await pool.query('UPDATE articles SET views = views + 1 WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch { res.json({ success: false }); }
});

// ─── USERS ROUTES ─────────────────────────────────────────────────────────────
app.get('/api/users/:username', async (req, res) => {
  try {
    const { rows: users } = await pool.query('SELECT * FROM users WHERE username=$1', [req.params.username]);
    if (!users.length) return res.status(404).json({ error: 'Author not found' });
    const user = users[0];
    const { rows: articles } = await pool.query(
      `SELECT id, title, description, cover_image, tags, reading_time, word_count, language, views, created_at, published_at
       FROM articles WHERE author_id=$1 AND status='published' ORDER BY published_at DESC`,
      [user.id]
    );
    const mapped = articles.map(a => ({
      id: a.id, title: a.title, description: a.description,
      coverImage: a.cover_image, tags: a.tags,
      readingTime: a.reading_time, wordCount: a.word_count,
      language: a.language, views: a.views,
      createdAt: a.created_at, publishedAt: a.published_at,
    }));
    const totalViews = mapped.reduce((s, a) => s + (a.views || 0), 0);
    res.json({
      user: { id: user.id, username: user.username, displayName: user.display_name, bio: user.bio, createdAt: user.created_at },
      articles: mapped, totalArticles: mapped.length, totalViews
    });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

// ─── DASHBOARD ────────────────────────────────────────────────────────────────
app.get('/api/dashboard', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, title, description, cover_image, tags, status, reading_time, word_count, language, views, created_at, published_at
       FROM articles WHERE author_id=$1 ORDER BY created_at DESC`,
      [req.user.id]
    );
    const articles = rows.map(a => ({
      id: a.id, title: a.title, description: a.description,
      coverImage: a.cover_image, tags: a.tags, status: a.status,
      readingTime: a.reading_time, wordCount: a.word_count,
      language: a.language, views: a.views,
      createdAt: a.created_at, publishedAt: a.published_at,
    }));
    const published = articles.filter(a => a.status === 'published');
    const totalViews = published.reduce((s, a) => s + (a.views || 0), 0);
    res.json({
      articles,
      stats: {
        total: articles.length,
        published: published.length,
        drafts: articles.filter(a => a.status === 'draft').length,
        totalViews,
        topArticles: [...published].sort((a, b) => b.views - a.views).slice(0, 5)
      }
    });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

// ─── Static + SPA ────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.get('/{*splat}', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ─── Start ────────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`\n🖋️  Inkwell running on port ${PORT}\n`));
}).catch(err => {
  console.error('❌ DB init failed:', err.message);
  process.exit(1);
});
