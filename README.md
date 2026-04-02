# 🖋️ Inkwell — منصة التدوين

## 🚀 تشغيل محلي

```bash
npm install
npm start
```

## ☁️ النشر على Render

### 1. قاعدة البيانات (PostgreSQL)
- في Render → **New** → **PostgreSQL**
- سمّها `inkwell-db`
- انسخ الـ **Internal Database URL**

### 2. خدمة الصور (Cloudinary)
- سجّل على [cloudinary.com](https://cloudinary.com) (مجاني)
- من Dashboard انسخ: Cloud Name, API Key, API Secret

### 3. Web Service
- في Render → **New** → **Web Service** → اربط بـ GitHub repo
- **Build Command:** `npm install`
- **Start Command:** `node server.js`

### 4. متغيرات البيئة (Environment Variables)
أضف هذه في Render → Environment:

```
DATABASE_URL          = (Internal URL من قاعدة البيانات)
JWT_SECRET            = (نص سري طويل عشوائي)
CLOUDINARY_CLOUD_NAME = (من Cloudinary Dashboard)
CLOUDINARY_API_KEY    = (من Cloudinary Dashboard)
CLOUDINARY_API_SECRET = (من Cloudinary Dashboard)
NODE_ENV              = production
```
