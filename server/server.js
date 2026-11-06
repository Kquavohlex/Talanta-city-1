require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const path = require('path');
const pool = require('./db');

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  throw new Error('Set JWT_SECRET to a random secret of at least 32 characters in Render environment variables.');
}
const app = express();
const PORT = process.env.PORT || 3000;
const COOKIE_NAME = 'talantatix_session';
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '..', 'public')));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: 'draft-7', legacyHeaders: false });
const registerSchema = z.object({
  name: z.string().trim().min(2).max(120),
  phone: z.string().trim().min(7).max(30),
  email: z.string().trim().email().max(255),
  country: z.string().trim().min(2).max(100),
  password: z.string().min(8).max(72),
  confirmPassword: z.string().min(8).max(72)
}).refine(v => v.password === v.confirmPassword, { message: 'Passwords do not match.', path: ['confirmPassword'] });
const loginSchema = z.object({ email: z.string().trim().email().max(255), password: z.string().min(1).max(72) });
function makeToken(user) {
  return jwt.sign({ sub: String(user.id), email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
}
function setSession(res, user) {
  res.cookie(COOKIE_NAME, makeToken(user), { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000, path: '/' });
}
function publicUser(row) { return { id: row.id, name: row.name, phone: row.phone, email: row.email, country: row.country, createdAt: row.created_at }; }

app.get('/api/health', (_req, res) => res.json({ success: true, service: 'TalantaTix API' }));
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ success: false, message: parsed.error.issues[0].message });
  const { name, phone, email, country, password } = parsed.data;
  try {
    const existing = await pool.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1', [email]);
    if (existing.rowCount) return res.status(409).json({ success: false, message: 'An account with this email already exists. Please log in.' });
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      'INSERT INTO users (name, phone, email, country, password_hash) VALUES ($1,$2,LOWER($3),$4,$5) RETURNING id,name,phone,email,country,created_at',
      [name, phone, email, country, passwordHash]
    );
    const user = result.rows[0]; setSession(res, user);
    return res.status(201).json({ success: true, message: 'Account created successfully. Welcome to TalantaTix!', user: publicUser(user) });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ success: false, message: 'Could not create your account. Please try again.' });
  }
});
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ success: false, message: 'Enter a valid email and password.' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1', [parsed.data.email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(parsed.data.password, user.password_hash))) {
      return res.status(401).json({ success: false, message: 'Incorrect email or password.' });
    }
    setSession(res, user);
    return res.json({ success: true, message: 'Login successful. Welcome back!', user: publicUser(user) });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ success: false, message: 'Unable to log in right now. Please try again.' });
  }
});
app.get('/api/auth/me', async (req, res) => {
  try {
    const token = req.cookies[COOKIE_NAME];
    if (!token) return res.status(401).json({ success: false, message: 'Not logged in.' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const result = await pool.query('SELECT id,name,phone,email,country,created_at FROM users WHERE id=$1', [decoded.sub]);
    if (!result.rowCount) return res.status(401).json({ success: false, message: 'Account not found.' });
    return res.json({ success: true, user: publicUser(result.rows[0]) });
  } catch (_error) { return res.status(401).json({ success: false, message: 'Your session has expired. Please log in again.' }); }
});
app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/' });
  res.json({ success: true, message: 'You have been logged out.' });
});
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ success: false, message: 'API endpoint not found.' });
  return res.sendFile(path.join(__dirname, '..', 'public', 'index.html'), next);
});
async function start() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    phone VARCHAR(30) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    country VARCHAR(100) NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query('CREATE INDEX IF NOT EXISTS users_email_lower_idx ON users (LOWER(email))');
  app.listen(PORT, () => console.log(`TalantaTix server listening on port ${PORT}`));
}
start().catch((error) => {
  console.error('Server startup failed:', error.message);
  process.exit(1);
});
