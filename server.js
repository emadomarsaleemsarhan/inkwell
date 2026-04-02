const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const mammoth = require('mammoth');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'inkwell-secret-2025';

// Database setup
const adapter = new FileSync(path.join(__dirname, 'db.json'));
const db = low(adapter);
db.defaults({ users: [], articles: [] }).write();

// Multer config for docx uploads
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 20 * 1024 * 1024 }, // 20MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
        file.originalname.endsWith('.docx')) {
      cb(null, true);
    } else {
      cb(new Error('Only .docx files are allowed'));
    }
  }
});

// Cover image upload
const coverStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => cb(null, `cover-${uuidv4()}${path.extname(file.originalname)}`)
});
const coverUpload = multer({ storage: coverStorage, limits: { fileSize: 5 * 1024 * 1024 } });

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// ─── Auth Middleware ────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function optionalAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (token) {
    try { req.user = jwt.verify(token, JWT_SECRET); } catch {}
  }
  next();
}

// ─── Helpers ────────────────────────────────────────────────────────────────
function calcReadingTime(text) {
  const words = text.trim().split(/\s+/).length;
  return { words, minutes: Math.max(1, Math.ceil(words / 200)) };
}

function detectLanguage(text) {
  const arabicChars = (text.match(/[\u0600-\u06FF]/g) || []).length;
  return arabicChars > text.length * 0.3 ? 'ar' : 'en';
}

function sanitizeUsername(username) {
  return username.toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 30);
}

// ─── Auth Routes ─────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { email, password, username, displayName } = req.body;
  if (!email || !password || !username || !displayName)
    return res.status(400).json({ error: 'All fields required' });

  const cleanUsername = sanitizeUsername(username);
  if (cleanUsername.length < 3)
    return res.status(400).json({ error: 'Username must be at least 3 characters' });

  const existingEmail = db.get('users').find({ email }).value();
  if (existingEmail) return res.status(400).json({ error: 'Email already registered' });

  const existingUser = db.get('users').find({ username: cleanUsername }).value();
  if (existingUser) return res.status(400).json({ error: 'Username already taken' });

  const hashed = await bcrypt.hash(password, 10);
  const user = {
    id: uuidv4(), email, username: cleanUsername, displayName,
    password: hashed, bio: '', createdAt: new Date().toISOString()
  };
  db.get('users').push(user).write();

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, username: user.username, displayName: user.displayName, bio: user.bio } });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.get('users').find({ email }).value();
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, username: user.username, displayName: user.displayName, bio: user.bio } });
});

app.put('/api/auth/profile', authMiddleware, (req, res) => {
  const { displayName, bio } = req.body;
  db.get('users').find({ id: req.user.id }).assign({ displayName, bio }).write();
  res.json({ success: true });
});

// ─── Articles Routes ─────────────────────────────────────────────────────────
// Upload and parse .docx
app.post('/api/articles/parse', authMiddleware, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const result = await mammoth.convertToHtml({ buffer: req.file.buffer }, {
      styleMap: [
        "p[style-name='Heading 1'] => h1:fresh",
        "p[style-name='Heading 2'] => h2:fresh",
        "p[style-name='Heading 3'] => h3:fresh",
        "p[style-name='Heading 4'] => h4:fresh",
        "b => strong",
        "i => em",
        "u => u"
      ]
    });

    const html = result.value;
    const plainText = html.replace(/<[^>]+>/g, ' ');
    const { words, minutes } = calcReadingTime(plainText);
    const language = detectLanguage(plainText);

    // Extract first image if any
    const imgMatch = html.match(/<img[^>]+src="([^"]+)"/);
    const firstImage = imgMatch ? imgMatch[1] : null;

    // Suggest title from first h1 or first paragraph
    const titleMatch = html.match(/<h1[^>]*>(.*?)<\/h1>/i) || html.match(/<p[^>]*>(.*?)<\/p>/i);
    const suggestedTitle = titleMatch ? titleMatch[1].replace(/<[^>]+>/g, '') : '';

    res.json({ html, words, readingTime: minutes, language, firstImage, suggestedTitle });
  } catch (err) {
    res.status(500).json({ error: 'Failed to parse document: ' + err.message });
  }
});

// Upload cover image
app.post('/api/articles/cover', authMiddleware, coverUpload.single('cover'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ url: `/uploads/${req.file.filename}` });
});

// Create/publish article
app.post('/api/articles', authMiddleware, (req, res) => {
  const { title, description, content, coverImage, tags, status, readingTime, wordCount, language } = req.body;
  if (!title || !content) return res.status(400).json({ error: 'Title and content required' });

  const slug = title
    .toLowerCase()
    .replace(/[\u0600-\u06FF\s]+/g, (m) => encodeURIComponent(m).slice(0, 20))
    .replace(/[^a-z0-9-]/g, '-')
    .replace(/-+/g, '-')
    .slice(0, 80) + '-' + Date.now().toString(36);

  const article = {
    id: uuidv4(), authorId: req.user.id,
    title, description: description || '', content,
    coverImage: coverImage || '', tags: tags || [],
    status: status || 'published', slug,
    views: 0, readingTime: readingTime || 5,
    wordCount: wordCount || 0,
    language: language || 'ar',
    createdAt: new Date().toISOString(),
    publishedAt: status === 'published' ? new Date().toISOString() : null
  };

  db.get('articles').push(article).write();
  res.json(article);
});

// Update article
app.put('/api/articles/:id', authMiddleware, (req, res) => {
  const article = db.get('articles').find({ id: req.params.id }).value();
  if (!article) return res.status(404).json({ error: 'Not found' });
  if (article.authorId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });

  const { title, description, content, coverImage, tags, status } = req.body;
  const update = { title, description, content, coverImage, tags };
  if (status && status !== article.status) {
    update.status = status;
    if (status === 'published') update.publishedAt = new Date().toISOString();
  }
  db.get('articles').find({ id: req.params.id }).assign(update).write();
  res.json({ success: true });
});

// Delete article
app.delete('/api/articles/:id', authMiddleware, (req, res) => {
  const article = db.get('articles').find({ id: req.params.id }).value();
  if (!article) return res.status(404).json({ error: 'Not found' });
  if (article.authorId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  db.get('articles').remove({ id: req.params.id }).write();
  res.json({ success: true });
});

// Get home feed (published articles)
app.get('/api/articles', optionalAuth, (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 12;
  const tag = req.query.tag;

  let articles = db.get('articles')
    .filter({ status: 'published' })
    .orderBy('publishedAt', 'desc')
    .value();

  if (tag) articles = articles.filter(a => a.tags?.includes(tag));

  const total = articles.length;
  const paginated = articles.slice((page - 1) * limit, page * limit);

  // Enrich with author info
  const enriched = paginated.map(a => {
    const author = db.get('users').find({ id: a.authorId }).value();
    return {
      ...a,
      content: a.content.slice(0, 500), // truncate for listing
      author: author ? { username: author.username, displayName: author.displayName } : null
    };
  });

  res.json({ articles: enriched, total, page, pages: Math.ceil(total / limit) });
});

// Get single article
app.get('/api/articles/:id', optionalAuth, (req, res) => {
  const article = db.get('articles').find({ id: req.params.id }).value();
  if (!article) return res.status(404).json({ error: 'Not found' });

  // Only show drafts to author
  if (article.status === 'draft') {
    if (!req.user || req.user.id !== article.authorId)
      return res.status(404).json({ error: 'Not found' });
  }

  const author = db.get('users').find({ id: article.authorId }).value();
  res.json({
    ...article,
    author: author ? { username: author.username, displayName: author.displayName, bio: author.bio } : null
  });
});

// Increment views
app.post('/api/articles/:id/view', (req, res) => {
  const article = db.get('articles').find({ id: req.params.id }).value();
  if (article) {
    db.get('articles').find({ id: req.params.id }).assign({ views: (article.views || 0) + 1 }).write();
  }
  res.json({ success: true });
});

// ─── Users/Authors Routes ────────────────────────────────────────────────────
app.get('/api/users/:username', (req, res) => {
  const user = db.get('users').find({ username: req.params.username }).value();
  if (!user) return res.status(404).json({ error: 'Author not found' });

  const articles = db.get('articles')
    .filter({ authorId: user.id, status: 'published' })
    .orderBy('publishedAt', 'desc')
    .map(a => ({ ...a, content: a.content.slice(0, 400) }))
    .value();

  res.json({
    user: { id: user.id, username: user.username, displayName: user.displayName, bio: user.bio, createdAt: user.createdAt },
    articles,
    totalArticles: articles.length,
    totalViews: articles.reduce((sum, a) => sum + (a.views || 0), 0)
  });
});

// ─── Dashboard ───────────────────────────────────────────────────────────────
app.get('/api/dashboard', authMiddleware, (req, res) => {
  const articles = db.get('articles')
    .filter({ authorId: req.user.id })
    .orderBy('createdAt', 'desc')
    .value();

  const published = articles.filter(a => a.status === 'published');
  const totalViews = published.reduce((sum, a) => sum + (a.views || 0), 0);
  const topArticles = [...published].sort((a, b) => (b.views || 0) - (a.views || 0)).slice(0, 5);

  res.json({
    articles,
    stats: {
      total: articles.length,
      published: published.length,
      drafts: articles.filter(a => a.status === 'draft').length,
      totalViews,
      topArticles
    }
  });
});

// ─── Serve SPA ────────────────────────────────────────────────────────────────
app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🖋️  Inkwell is running at http://localhost:${PORT}\n`);
});
