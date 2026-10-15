import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import SQLiteStoreFactory from 'connect-sqlite3';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import Razorpay from 'razorpay';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === 'production';
const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error('SESSION_SECRET must be at least 32 characters. Set it in .env.');
  process.exit(1);
}
if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD.length < 12) {
  console.error('Set ADMIN_EMAIL and ADMIN_PASSWORD (at least 12 characters) in .env.');
  process.exit(1);
}
if (isProd) app.set('trust proxy', 1);

const db = new Database(path.join(dataDir, 'store.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS products (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 price INTEGER NOT NULL, image TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT 'T-Shirts',
 sizes TEXT NOT NULL DEFAULT '["S","M","L","XL"]', stock INTEGER NOT NULL DEFAULT 0,
 active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders (
 id TEXT PRIMARY KEY, customer_name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT NOT NULL,
 address TEXT NOT NULL, city TEXT NOT NULL, state TEXT NOT NULL, pincode TEXT NOT NULL,
 items_json TEXT NOT NULL, amount INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'payment_pending',
 payment_status TEXT NOT NULL DEFAULT 'pending', razorpay_order_id TEXT, razorpay_payment_id TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS webhook_events (event_id TEXT PRIMARY KEY, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
`);
const adminEmail = process.env.ADMIN_EMAIL.toLowerCase().trim();
const existingAdmin = db.prepare('SELECT id FROM admins WHERE email = ?').get(adminEmail);
if (!existingAdmin) {
  const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
  db.prepare('INSERT INTO admins(email,password_hash) VALUES(?,?)').run(adminEmail, hash);
}
const productCount = db.prepare('SELECT COUNT(*) AS n FROM products').get().n;
if (productCount === 0) {
  const seed = db.prepare('INSERT INTO products(name,description,price,image,category,sizes,stock) VALUES(?,?,?,?,?,?,?)');
  [
    ['Midnight Oversized Tee','Heavyweight everyday streetwear fit.',129900,'https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?auto=format&fit=crop&w=900&q=85','Oversized','["S","M","L","XL","XXL"]',20],
    ['Concrete Graphic Tee','Minimal graphic. Maximum attitude.',99900,'https://images.unsplash.com/photo-1503341504253-dff4815485f1?auto=format&fit=crop&w=900&q=85','Graphic','["S","M","L","XL"]',18],
    ['Essential Cream Tee','A clean staple for your rotation.',119900,'https://images.unsplash.com/photo-1523381210434-271e8be1f52b?auto=format&fit=crop&w=900&q=85','Essentials','["S","M","L","XL","XXL"]',15],
    ['After Hours Tee','Relaxed fit made for late nights.',109900,'https://images.unsplash.com/photo-1576566588028-4147f3842f27?auto=format&fit=crop&w=900&q=85','Graphic','["S","M","L","XL"]',12]
  ].forEach(p => seed.run(...p));
}
// User-provided collection: each item is priced at ₹499 (₹49,900 in paise).
const customProducts = [
  ['Paris Colorblock Tee','Black, grey and white colorblock streetwear T-shirt.',49900,'/products/paris-colorblock.avif','Graphic','["S","M","L","XL","XXL"]',20],
  ['Money Bear Graphic Tee','Black graphic T-shirt with teddy bear artwork.',49900,'/products/money-bear.avif','Graphic','["S","M","L","XL","XXL"]',20],
  ['Batman Black Tee','Black oversized-style graphic T-shirt.',49900,'/products/batman-black.jpg','Graphic','["S","M","L","XL","XXL"]',20],
  ['Green Textured Tee','Green textured everyday T-shirt.',49900,'/products/green-texture.avif','Essentials','["S","M","L","XL","XXL"]',20],
  ['Maroon Leopard Tee','Maroon graphic T-shirt with leopard artwork.',49900,'/products/maroon-leopard.webp','Graphic','["S","M","L","XL","XXL"]',20],
  ['You Can Sleeveless Hoodie','Black sleeveless hoodie with motivational text.',49900,'/products/sleeveless-hoodie.avif','Oversized','["S","M","L","XL","XXL"]',20]
];
const insertCustom = db.prepare('INSERT INTO products(name,description,price,image,category,sizes,stock) SELECT ?,?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM products WHERE name=?)');
for (const p of customProducts) insertCustom.run(...p, p[0]);
const Store = SQLiteStoreFactory(session);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'", 'https://checkout.razorpay.com'],
  styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:', 'https:'],
  connectSrc: ["'self'"], frameSrc: ["https://api.razorpay.com", "https://checkout.razorpay.com"],
  upgradeInsecureRequests: isProd ? [] : null
}}}));
app.use('/api/payments/webhook', express.raw({ type: 'application/json', limit: '1mb' }));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(session({
  store: new Store({ db: 'sessions.sqlite', dir: dataDir, concurrentDB: true }),
  name: 'mob.sid', secret: process.env.SESSION_SECRET,
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, secure: isProd, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false });
const checkoutLimiter = rateLimit({ windowMs: 10 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });
const razorpay = process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET
  ? new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET }) : null;

const productInput = z.object({
  name: z.string().trim().min(2).max(100),
  description: z.string().trim().max(1000).default(''),
  price: z.number().int().min(100).max(10000000),
  image: z.string().trim().max(1000).refine(v => !v || /^https:\/\/\S+$/i.test(v), 'Image must be an HTTPS URL'),
  category: z.string().trim().min(1).max(50),
  sizes: z.array(z.enum(['XS','S','M','L','XL','XXL'])).min(1).max(6),
  stock: z.number().int().min(0).max(100000),
  active: z.boolean().default(true)
});
const customerSchema = z.object({
  name: z.string().trim().min(2).max(100),
  email: z.string().trim().email().max(200),
  phone: z.string().trim().regex(/^[6-9]\d{9}$/,'Enter a valid 10-digit Indian mobile number'),
  address: z.string().trim().min(8).max(300),
  city: z.string().trim().min(2).max(80),
  state: z.string().trim().min(2).max(80),
  pincode: z.string().trim().regex(/^\d{6}$/,'Enter a valid 6-digit PIN code'),
  items: z.array(z.object({ productId: z.number().int().positive(), quantity: z.number().int().min(1).max(10), size: z.enum(['XS','S','M','L','XL','XXL']) })).min(1).max(30)
});
const publicProduct = p => ({ id:p.id, name:p.name, description:p.description, price:p.price, image:p.image, category:p.category, sizes:JSON.parse(p.sizes), stock:p.stock });
function requireAdmin(req,res,next) { if (!req.session.adminId) return res.status(401).json({error:'Please sign in again.'}); next(); }
function safeEqualHex(a,b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
function verifyCheckoutSignature(orderId,paymentId,signature) {
  const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(`${orderId}|${paymentId}`).digest('hex');
  return safeEqualHex(expected, signature);
}
function verifyWebhookSignature(raw,signature) {
  if (!process.env.RAZORPAY_WEBHOOK_SECRET || !Buffer.isBuffer(raw) || typeof signature !== 'string') return false;
  const expected = crypto.createHmac('sha256', process.env.RAZORPAY_WEBHOOK_SECRET).update(raw).digest('hex');
  return safeEqualHex(expected, signature);
}

app.get('/api/config', (req,res) => res.json({ keyId: process.env.RAZORPAY_KEY_ID || '', currency:'INR', onlinePaymentsReady: !!razorpay }));
app.get('/api/products', (req,res) => {
  const products = db.prepare('SELECT * FROM products WHERE active=1 ORDER BY created_at DESC, id DESC').all();
  res.json(products.map(publicProduct));
});
app.get('/api/products/:id', (req,res) => {
  const p = db.prepare('SELECT * FROM products WHERE id=? AND active=1').get(Number(req.params.id));
  if (!p) return res.status(404).json({error:'Product not found'});
  res.json(publicProduct(p));
});
app.post('/api/admin/login', loginLimiter, async (req,res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  const password = String(req.body?.password || '');
  const admin = db.prepare('SELECT * FROM admins WHERE email=?').get(email);
  const ok = admin && await bcrypt.compare(password, admin.password_hash);
  if (!ok) return res.status(401).json({error:'Email or password is incorrect.'});
  req.session.regenerate(err => {
    if (err) return res.status(500).json({error:'Could not start admin session.'});
    req.session.adminId = admin.id;
    req.session.adminEmail = admin.email;
    req.session.save(saveErr => saveErr ? res.status(500).json({error:'Could not save session.'}) : res.json({ok:true,email:admin.email}));
  });
});
app.get('/api/admin/me', (req,res) => req.session.adminId ? res.json({authenticated:true,email:req.session.adminEmail}) : res.status(401).json({authenticated:false}));
app.post('/api/admin/logout', requireAdmin, (req,res) => req.session.destroy(() => { res.clearCookie('mob.sid'); res.json({ok:true}); }));
app.get('/api/admin/products', requireAdmin, (req,res) => res.json(db.prepare('SELECT * FROM products ORDER BY id DESC').all().map(p=>({...publicProduct(p),active:!!p.active}))));
app.post('/api/admin/products', requireAdmin, (req,res) => {
  const parsed = productInput.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({error:parsed.error.issues[0].message});
  const p=parsed.data;
  const info=db.prepare('INSERT INTO products(name,description,price,image,category,sizes,stock,active) VALUES(?,?,?,?,?,?,?,?)')
    .run(p.name,p.description,p.price,p.image,p.category,JSON.stringify(p.sizes),p.stock,p.active?1:0);
  res.status(201).json({id:info.lastInsertRowid});
});
app.put('/api/admin/products/:id', requireAdmin, (req,res) => {
  const parsed=productInput.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({error:parsed.error.issues[0].message});
  const p=parsed.data;
  const info=db.prepare('UPDATE products SET name=?,description=?,price=?,image=?,category=?,sizes=?,stock=?,active=? WHERE id=?')
    .run(p.name,p.description,p.price,p.image,p.category,JSON.stringify(p.sizes),p.stock,p.active?1:0,Number(req.params.id));
  if (!info.changes) return res.status(404).json({error:'Product not found'});
  res.json({ok:true});
});
app.delete('/api/admin/products/:id', requireAdmin, (req,res) => {
  const info=db.prepare('UPDATE products SET active=0 WHERE id=?').run(Number(req.params.id));
  if (!info.changes) return res.status(404).json({error:'Product not found'});
  res.json({ok:true});
});
app.get('/api/admin/orders', requireAdmin, (req,res) => {
  const rows=db.prepare('SELECT * FROM orders ORDER BY created_at DESC LIMIT 500').all();
  res.json(rows.map(o=>({...o,items:JSON.parse(o.items_json)})));
});
app.patch('/api/admin/orders/:id', requireAdmin, (req,res) => {
  const allowed=['confirmed','processing','shipped','delivered','cancelled'];
  if (!allowed.includes(req.body?.status)) return res.status(400).json({error:'Invalid order status.'});
  const order=db.prepare('SELECT * FROM orders WHERE id=?').get(req.params.id);
  if (!order) return res.status(404).json({error:'Order not found'});
  if (req.body.status==='cancelled' && order.payment_status==='paid') return res.status(400).json({error:'Refund the payment through your payment provider before cancelling a paid order.'});
  db.prepare('UPDATE orders SET status=? WHERE id=?').run(req.body.status,req.params.id);
  res.json({ok:true});
});
app.get('/api/orders/lookup/:id', (req,res) => {
  const id=String(req.params.id||'').trim();
  const email=String(req.query.email||'').trim().toLowerCase();
  if (!id || !email) return res.status(400).json({error:'Enter order ID and checkout email.'});
  const o=db.prepare('SELECT id,email,items_json,amount,status,payment_status,created_at FROM orders WHERE id=? AND lower(email)=?').get(id,email);
  if (!o) return res.status(404).json({error:'No order matched those details.'});
  res.json({...o,items:JSON.parse(o.items_json)});
});

app.post('/api/checkout/create-order', checkoutLimiter, async (req,res) => {
  if (!razorpay) return res.status(503).json({error:'Online payments are not configured yet. Add Razorpay test keys to the server .env file.'});
  const parsed=customerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({error:parsed.error.issues[0].message});
  const c=parsed.data;
  try {
    const resolved=[];
    let total=0;
    for (const item of c.items) {
      const p=db.prepare('SELECT * FROM products WHERE id=? AND active=1').get(item.productId);
      if (!p) return res.status(400).json({error:'A selected product is unavailable. Refresh your cart.'});
      if (!JSON.parse(p.sizes).includes(item.size)) return res.status(400).json({error:`Size ${item.size} is unavailable for ${p.name}.`});
      if (p.stock < item.quantity) return res.status(400).json({error:`Only ${p.stock} item(s) left for ${p.name}.`});
      total += p.price*item.quantity;
      resolved.push({productId:p.id,name:p.name,unitPrice:p.price,quantity:item.quantity,size:item.size,image:p.image});
    }
    if (total < 100 || total > 100000000) return res.status(400).json({error:'Order total is outside the allowed range.'});
    const receipt='mob_'+crypto.randomBytes(8).toString('hex');
    const rpOrder=await razorpay.orders.create({amount:total,currency:'INR',receipt,notes:{brand:'My Own Brand'}});
    const id=crypto.randomUUID();
    db.prepare(`INSERT INTO orders(id,customer_name,email,phone,address,city,state,pincode,items_json,amount,status,payment_status,razorpay_order_id)
      VALUES(?,?,?,?,?,?,?,?,?,?, 'payment_pending','pending',?)`)
      .run(id,c.name,c.email.toLowerCase(),c.phone,c.address,c.city,c.state,c.pincode,JSON.stringify(resolved),total,rpOrder.id);
    res.json({orderId:id,razorpayOrderId:rpOrder.id,amount:total,currency:'INR',keyId:process.env.RAZORPAY_KEY_ID,customer:{name:c.name,email:c.email,phone:c.phone}});
  } catch (e) {
    console.error('Checkout create error:',e.message);
    res.status(502).json({error:'Could not start payment. Please try again.'});
  }
});
app.post('/api/checkout/verify', checkoutLimiter, async (req,res) => {
  if (!razorpay) return res.status(503).json({error:'Payments are not configured.'});
  const {orderId,razorpay_order_id,razorpay_payment_id,razorpay_signature}=req.body||{};
  if (![orderId,razorpay_order_id,razorpay_payment_id,razorpay_signature].every(v=>typeof v==='string' && v.length<300)) return res.status(400).json({error:'Invalid payment verification details.'});
  const order=db.prepare('SELECT * FROM orders WHERE id=? AND razorpay_order_id=?').get(orderId,razorpay_order_id);
  if (!order) return res.status(404).json({error:'Order not found.'});
  if (!verifyCheckoutSignature(razorpay_order_id,razorpay_payment_id,razorpay_signature)) return res.status(400).json({error:'Payment signature could not be verified.'});
  try {
    const payment=await razorpay.payments.fetch(razorpay_payment_id);
    if (payment.order_id!==razorpay_order_id || payment.amount!==order.amount || payment.currency!=='INR') return res.status(400).json({error:'Payment details did not match this order.'});
    if (payment.status==='captured') {
      db.prepare("UPDATE orders SET payment_status='paid',status='confirmed',razorpay_payment_id=? WHERE id=?").run(razorpay_payment_id,orderId);
      const items=JSON.parse(order.items_json);
      const decrement=db.transaction(() => {
        for (const item of items) {
          const info=db.prepare('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?').run(item.quantity,item.productId,item.quantity);
          if (!info.changes) throw new Error('Stock changed during checkout. Contact support for order '+orderId);
        }
      });
      try { decrement(); } catch(e) { console.error(e.message); }
      return res.json({ok:true,orderId,paymentStatus:'paid'});
    }
    if (payment.status==='failed') db.prepare("UPDATE orders SET payment_status='failed',status='payment_failed' WHERE id=?").run(orderId);
    return res.status(402).json({error:'Payment is not captured yet. If money was deducted, wait for provider confirmation before retrying.'});
  } catch(e) {
    console.error('Payment verify error:',e.message);
    return res.status(502).json({error:'Could not confirm payment. Your order will update after provider confirmation.'});
  }
});
app.post('/api/payments/webhook', (req,res) => {
  const signature=req.get('x-razorpay-signature');
  if (!verifyWebhookSignature(req.body,signature)) return res.status(400).send('Invalid webhook signature');
  let event;
  try { event=JSON.parse(req.body.toString('utf8')); } catch { return res.status(400).send('Invalid JSON'); }
  const eventId=req.get('x-razorpay-event-id') || crypto.createHash('sha256').update(req.body).digest('hex');
  const insert=db.prepare('INSERT OR IGNORE INTO webhook_events(event_id) VALUES(?)').run(eventId);
  if (!insert.changes) return res.json({ok:true,duplicate:true});
  const payment=event.payload?.payment?.entity;
  if (payment?.order_id) {
    const order=db.prepare('SELECT * FROM orders WHERE razorpay_order_id=?').get(payment.order_id);
    if (order && payment.amount===order.amount && payment.currency==='INR') {
      if (event.event==='payment.captured') {
        db.prepare("UPDATE orders SET payment_status='paid',status=CASE WHEN status='payment_pending' THEN 'confirmed' ELSE status END,razorpay_payment_id=? WHERE id=?")
          .run(payment.id,order.id);
      } else if (event.event==='payment.failed' && order.payment_status!=='paid') {
        db.prepare("UPDATE orders SET payment_status='failed',status='payment_failed',razorpay_payment_id=? WHERE id=?").run(payment.id,order.id);
      }
    }
  }
  res.json({ok:true});
});

app.get('/admin', (req,res) => res.sendFile(path.join(__dirname,'public','admin.html')));
app.get('/checkout', (req,res) => res.sendFile(path.join(__dirname,'public','checkout.html')));
app.get('/track', (req,res) => res.sendFile(path.join(__dirname,'public','track.html')));
app.get('*', (req,res,next) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({error:'API route not found'});
  res.sendFile(path.join(__dirname,'public','index.html'), err => err && next(err));
});
app.use((err,req,res,next) => {
  console.error(err.message);
  res.status(500).json({error:'Something went wrong. Please try again.'});
});
app.listen(PORT, () => console.log(`My Own Brand running at ${process.env.BASE_URL || `http://localhost:${PORT}`}`));
