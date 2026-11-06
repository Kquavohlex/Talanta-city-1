require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomUUID } = require('crypto');
const QRCode = require('qrcode');
const { z } = require('zod');
const db = require('./db');
const { authenticate, requireAdmin } = require('./middleware');

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  console.error('Set JWT_SECRET to a random value of at least 32 characters.');
  process.exit(1);
}

const app = express();
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN ? process.env.FRONTEND_ORIGIN.split(',').map(s => s.trim()) : false,
  methods: ['GET','POST','PATCH','DELETE'],
  allowedHeaders: ['Content-Type','Authorization']
}));
app.use(express.json({ limit: '20kb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 250, standardHeaders: 'draft-7', legacyHeaders: false }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, message: { error: 'Too many attempts. Try again later.' } });
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const tokenFor = user => jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '2h' });

app.get('/api/health', (req, res) => res.json({ status: 'ok', service: 'TalantaTix API' }));

const registerSchema = z.object({
  fullName: z.string().trim().min(2).max(120),
  email: z.string().trim().email().max(254),
  phone: z.string().trim().min(7).max(30),
  country: z.string().trim().min(2).max(80),
  age: z.coerce.number().int().min(18).max(120),
  password: z.string().min(8).max(100),
  promoCode: z.string().trim().max(40).optional().or(z.literal(''))
});

app.post('/api/auth/register', authLimiter, asyncRoute(async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Please check your registration details.', details: parsed.error.flatten() });
  const { fullName, email, phone, country, age, password } = parsed.data;
  const passwordHash = await bcrypt.hash(password, 12);
  try {
    const result = await db.query(
      `INSERT INTO users(full_name,email,phone,country,age,password_hash)
       VALUES($1,$2,$3,$4,$5,$6)
       RETURNING id,full_name,email,phone,country,age,role`,
      [fullName, email.toLowerCase(), phone, country, age, passwordHash]
    );
    const user = result.rows[0];
    res.status(201).json({ message: 'Account created.', token: tokenFor(user), user });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'An account with this email already exists.' });
    throw err;
  }
}));

app.post('/api/auth/login', authLimiter, asyncRoute(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
  const result = await db.query('SELECT * FROM users WHERE email=$1', [email]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'Incorrect email or password.' });
  }
  const publicUser = { id: user.id, full_name: user.full_name, email: user.email, role: user.role };
  res.json({ message: 'Login successful.', token: tokenFor(publicUser), user: publicUser });
}));

app.get('/api/auth/me', authenticate, asyncRoute(async (req, res) => {
  const result = await db.query('SELECT id,full_name,email,phone,country,age,role FROM users WHERE id=$1', [req.user.id]);
  if (!result.rowCount) return res.status(404).json({ error: 'Account not found.' });
  res.json({ user: result.rows[0] });
}));

app.get('/api/events', asyncRoute(async (req, res) => {
  const result = await db.query(
    `SELECT e.id,e.title,e.description,e.venue,e.event_date,
      COALESCE(json_agg(json_build_object('id',t.id,'name',t.name,'priceKes',t.price_kes)
      ORDER BY t.price_kes) FILTER (WHERE t.id IS NOT NULL),'[]') AS tickets
     FROM events e LEFT JOIN ticket_types t ON t.event_id=e.id
     WHERE e.active=TRUE GROUP BY e.id ORDER BY e.event_date NULLS LAST`
  );
  res.json({ events: result.rows });
}));

app.post('/api/orders', authenticate, asyncRoute(async (req, res) => {
  const eventId = Number(req.body.eventId);
  const ticketTypeId = Number(req.body.ticketTypeId);
  const quantity = Number(req.body.quantity);
  if (!Number.isInteger(eventId) || !Number.isInteger(ticketTypeId) || !Number.isInteger(quantity) || quantity < 1 || quantity > 10) {
    return res.status(400).json({ error: 'Provide a valid event, ticket type and quantity (1–10).' });
  }
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const ticket = await client.query(
      `SELECT t.*,e.id AS event_id FROM ticket_types t JOIN events e ON e.id=t.event_id
       WHERE t.id=$1 AND e.id=$2 AND e.active=TRUE FOR UPDATE OF t`,
      [ticketTypeId, eventId]
    );
    if (!ticket.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Ticket type not found.' }); }
    const item = ticket.rows[0];
    if (item.quantity_available < quantity) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'Not enough tickets available.' }); }
    const total = item.price_kes * quantity;
    const order = await client.query(
      `INSERT INTO orders(user_id,event_id,ticket_type_id,quantity,unit_price_kes,total_kes)
       VALUES($1,$2,$3,$4,$5,$6) RETURNING id,status,total_kes`,
      [req.user.id, eventId, ticketTypeId, quantity, item.price_kes, total]
    );
    await client.query('UPDATE ticket_types SET quantity_available=quantity_available-$1 WHERE id=$2', [quantity, ticketTypeId]);
    await client.query('COMMIT');
    res.status(201).json({ message: 'Order created. Payment is not yet initiated.', order: order.rows[0], currency: 'KES' });
  } catch (err) { await client.query('ROLLBACK'); throw err; }
  finally { client.release(); }
}));

app.get('/api/orders/mine', authenticate, asyncRoute(async (req, res) => {
  const result = await db.query(
    `SELECT o.id,o.quantity,o.total_kes,o.status,o.created_at,e.title AS event,t.name AS ticket_type
     FROM orders o JOIN events e ON e.id=o.event_id JOIN ticket_types t ON t.id=o.ticket_type_id
     WHERE o.user_id=$1 ORDER BY o.created_at DESC`, [req.user.id]
  );
  res.json({ orders: result.rows });
}));

// Payment adapter intentionally fails closed until the official TinyPesa API contract is supplied.
app.post('/api/payments/tinypesa/initiate', authenticate, asyncRoute(async (req, res) => {
  const orderId = Number(req.body.orderId);
  if (!Number.isInteger(orderId)) return res.status(400).json({ error: 'A valid orderId is required.' });
  const order = await db.query('SELECT id,total_kes,status FROM orders WHERE id=$1 AND user_id=$2', [orderId, req.user.id]);
  if (!order.rowCount) return res.status(404).json({ error: 'Order not found.' });
  if (order.rows[0].status !== 'pending') return res.status(409).json({ error: 'This order is not pending payment.' });
  if (!process.env.TINYPESA_BASE_URL || !process.env.TINYPESA_API_KEY || !process.env.TINYPESA_API_SECRET) {
    return res.status(503).json({ error: 'TinyPesa is not configured. Add credentials and implement the provider request using the official TinyPesa API documentation. No payment has been made.' });
  }
  return res.status(501).json({ error: 'TinyPesa credentials are present, but the exact provider API request and callback verification must be implemented from your official integration documentation. No payment has been made.' });
}));

// Never mark an order paid from a browser request. Payment confirmation must be verified server-to-server.
app.post('/api/payments/tinypesa/callback', async (req, res) => {
  return res.status(501).json({ error: 'Payment callback verification is not configured. Orders remain pending.' });
});

app.get('/api/tickets/:code/qr', authenticate, asyncRoute(async (req, res) => {
  const result = await db.query(
    `SELECT tk.ticket_code,o.user_id,o.status,e.title,t.name AS ticket_type
     FROM tickets tk JOIN orders o ON o.id=tk.order_id
     JOIN events e ON e.id=o.event_id JOIN ticket_types t ON t.id=o.ticket_type_id
     WHERE tk.ticket_code=$1 AND o.user_id=$2`,
    [req.params.code, req.user.id]
  );
  if (!result.rowCount || result.rows[0].status !== 'paid') return res.status(404).json({ error: 'Paid ticket not found.' });
  const qr = await QRCode.toDataURL(JSON.stringify({ ticketCode: result.rows[0].ticket_code }));
  res.json({ ticket: result.rows[0], qrDataUrl: qr });
}));

app.get('/api/admin/dashboard', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  const [users, orders, revenue] = await Promise.all([
    db.query('SELECT COUNT(*)::int AS count FROM users WHERE role=$1', ['customer']),
    db.query('SELECT COUNT(*)::int AS count FROM orders'),
    db.query("SELECT COALESCE(SUM(total_kes),0)::int AS kes FROM orders WHERE status='paid'")
  ]);
  res.json({ customers: users.rows[0].count, orders: orders.rows[0].count, revenueKes: revenue.rows[0].kes });
}));

app.patch('/api/admin/tickets/:id/price', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  const price = Number(req.body.priceKes);
  if (!Number.isInteger(price) || price < 1 || price > 10000000) return res.status(400).json({ error: 'priceKes must be a positive integer.' });
  const result = await db.query('UPDATE ticket_types SET price_kes=$1 WHERE id=$2 RETURNING id,name,price_kes', [price, req.params.id]);
  if (!result.rowCount) return res.status(404).json({ error: 'Ticket type not found.' });
  res.json({ ticketType: result.rows[0] });
}));

app.get('/api/admin/orders', authenticate, requireAdmin, asyncRoute(async (req, res) => {
  const result = await db.query(
    `SELECT o.id,o.total_kes,o.status,o.created_at,u.full_name,u.email,e.title,t.name AS ticket_type
     FROM orders o JOIN users u ON u.id=o.user_id JOIN events e ON e.id=o.event_id
     JOIN ticket_types t ON t.id=o.ticket_type_id ORDER BY o.created_at DESC LIMIT 200`
  );
  res.json({ orders: result.rows });
}));

app.use((req, res) => res.status(404).json({ error: 'API route not found.' }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'An unexpected server error occurred.' });
});

const port = Number(process.env.PORT || 10000);
app.listen(port, () => console.log(`TalantaTix API listening on port ${port}`));
