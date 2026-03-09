const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();

app.use(helmet());
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || 'http://localhost:3000', credentials: true }));
app.use(express.json({ limit: '10mb' }));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use(limiter);

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });

const DATA_DIR = path.join(__dirname, 'data');
const ARTICLES_FILE = path.join(DATA_DIR, 'articles.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const ENV_FILE = path.join(__dirname, '.env');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(ARTICLES_FILE)) fs.writeFileSync(ARTICLES_FILE, '[]');

const resetCodes = new Map();

const readArticles = () => {
  try { return JSON.parse(fs.readFileSync(ARTICLES_FILE, 'utf8')); }
  catch (e) { return []; }
};

const writeArticles = (data) => {
  fs.writeFileSync(ARTICLES_FILE, JSON.stringify(data, null, 2));
};

const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token manquant' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token manquant' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Token invalide' });
  }
};

// ✅ Storage multer avec filtre PDF + Word + images
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});

const fileFilter = (req, file, cb) => {
  const allowedMimes = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'text/plain'
  ];
  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Type de fichier non autorisé'), false);
  }
};

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // ✅ 10MB au lieu de 5MB
  fileFilter
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
    if (username !== process.env.ADMIN_USERNAME) return res.status(401).json({ error: 'Identifiants invalides' });
    let valid = false;
    if (process.env.ADMIN_PASSWORD_HASH && process.env.ADMIN_PASSWORD_HASH.length > 10) {
      valid = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
    }
    if (!valid && process.env.ADMIN_PASSWORD && process.env.ADMIN_PASSWORD.length > 0) {
      valid = (password === process.env.ADMIN_PASSWORD);
    }
    if (!valid) return res.status(401).json({ error: 'Identifiants invalides' });
    const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, message: 'Connexion reussie' });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/reset/request', authLimiter, (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email manquant' });
    const adminEmail = process.env.ADMIN_EMAIL || 'rboussougouisidk@groupeisi.com';
    if (email.trim().toLowerCase() !== adminEmail.trim().toLowerCase())
      return res.status(400).json({ error: 'Email non reconnu' });
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + 10 * 60 * 1000;
    resetCodes.set(email.toLowerCase(), { code, expires });
    res.json({ success: true, code, email });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/reset/verify', authLimiter, (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ error: 'Donnees manquantes' });
    const stored = resetCodes.get(email.toLowerCase());
    if (!stored) return res.status(400).json({ error: 'Aucun code demande' });
    if (Date.now() > stored.expires) {
      resetCodes.delete(email.toLowerCase());
      return res.status(400).json({ error: 'Code expire' });
    }
    if (stored.code !== code.trim()) return res.status(400).json({ error: 'Code incorrect' });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/reset/change', authLimiter, async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    if (!email || !code || !newPassword) return res.status(400).json({ error: 'Donnees manquantes' });
    const stored = resetCodes.get(email.toLowerCase());
    if (!stored) return res.status(400).json({ error: 'Session expiree' });
    if (Date.now() > stored.expires) {
      resetCodes.delete(email.toLowerCase());
      return res.status(400).json({ error: 'Code expire' });
    }
    if (stored.code !== code.trim()) return res.status(400).json({ error: 'Code incorrect' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'Mot de passe trop court' });
    const hash = await bcrypt.hash(newPassword, 12);
    let envContent = fs.readFileSync(ENV_FILE, 'utf8');
    if (envContent.includes('ADMIN_PASSWORD_HASH=')) {
      envContent = envContent.replace(/ADMIN_PASSWORD_HASH=[^\n]*/g, 'ADMIN_PASSWORD_HASH=' + hash);
    } else {
      envContent += '\nADMIN_PASSWORD_HASH=' + hash;
    }
    envContent = envContent.replace(/ADMIN_PASSWORD=[^\n]*/g, 'ADMIN_PASSWORD=');
    fs.writeFileSync(ENV_FILE, envContent);
    process.env.ADMIN_PASSWORD_HASH = hash;
    process.env.ADMIN_PASSWORD = '';
    resetCodes.delete(email.toLowerCase());
    res.json({ success: true, message: 'Mot de passe mis a jour' });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur: ' + e.message });
  }
});

app.get('/api/articles', (req, res) => {
  try {
    res.json(readArticles().filter(a => a.publie));
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/articles/all', authenticate, (req, res) => {
  try {
    res.json(readArticles());
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/articles/:id', (req, res) => {
  try {
    const article = readArticles().find(a => a.id === req.params.id);
    if (!article) return res.status(404).json({ error: 'Article non trouve' });
    res.json(article);
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/articles', authenticate, (req, res) => {
  try {
    const articles = readArticles();
    const article = {
      id: Date.now().toString(),
      titre: req.body.titre || 'Sans titre',
      contenu: req.body.contenu || '',
      extrait: req.body.extrait || '',
      categorie: req.body.categorie || 'General',
      image: req.body.image || '',
      fichier: req.body.fichier || null, // ✅ Champ fichier (PDF/Word)
      publie: req.body.publie || false,
      dateCreation: new Date().toISOString(),
      dateModification: new Date().toISOString(),
    };
    articles.unshift(article);
    writeArticles(articles);
    res.status(201).json(article);
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.put('/api/articles/:id', authenticate, (req, res) => {
  try {
    const articles = readArticles();
    const idx = articles.findIndex(a => a.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Article non trouve' });
    articles[idx] = { ...articles[idx], ...req.body, dateModification: new Date().toISOString() };
    writeArticles(articles);
    res.json(articles[idx]);
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.delete('/api/articles/:id', authenticate, (req, res) => {
  try {
    const articles = readArticles();
    // ✅ Supprime aussi le fichier physique si existant
    const article = articles.find(a => a.id === req.params.id);
    if (article) {
      if (article.image) {
        const imagePath = path.join(UPLOADS_DIR, path.basename(article.image));
        if (fs.existsSync(imagePath)) fs.unlinkSync(imagePath);
      }
      if (article.fichier && article.fichier.url) {
        const fichierPath = path.join(UPLOADS_DIR, path.basename(article.fichier.url));
        if (fs.existsSync(fichierPath)) fs.unlinkSync(fichierPath);
      }
    }
    const filtered = articles.filter(a => a.id !== req.params.id);
    if (filtered.length === articles.length) return res.status(404).json({ error: 'Article non trouve' });
    writeArticles(filtered);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ✅ Upload image (couverture article)
app.post('/api/upload', authenticate, upload.single('image'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Pas de fichier' });
    res.json({ url: '/uploads/' + req.file.filename });
  } catch (e) {
    res.status(500).json({ error: 'Erreur upload' });
  }
});

// ✅ Upload fichier joint (PDF, Word, etc.)
app.post('/api/upload/fichier', authenticate, upload.single('fichier'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Pas de fichier' });
    res.json({
      url: '/uploads/' + req.file.filename,
      nom: req.file.originalname,
      mimetype: req.file.mimetype,
      taille: req.file.size
    });
  } catch (e) {
    res.status(500).json({ error: 'Erreur upload: ' + e.message });
  }
});

app.use('/uploads', express.static(UPLOADS_DIR));

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log('Serveur BBRS sur port ' + PORT));