import { Hono } from 'hono';
import { cors } from 'hono/cors';

type Env = {
  DB: D1Database;
  R2: R2Bucket;
  OWNER_EMAIL: string;
  OWNER_PHONE: string;
  ADAM_PHONE: string;
  SITE_URL: string;
  TWILIO_ACCOUNT_SID?: string;
  TWILIO_AUTH_TOKEN?: string;
  TWILIO_PHONE_NUMBER?: string;
  ECHO_API_KEY?: string;
  ZOHO_SMTP_USER?: string;
  ZOHO_SMTP_PASS?: string;
  OPENAI_API_KEY?: string;
  AZURE_OPENAI_KEY?: string;
  RESEND_API_KEY?: string;
  DOC_DELIVERY_URL?: string;
  DOC_TENANT_KEY?: string;
  DOC_DELIVERY: Fetcher;
  COMPANY_NAME?: string;
  COMPANY_PHONE?: string;
  COMPANY_EMAIL?: string;
  COMPANY_TAGLINE?: string;
};

const app = new Hono<{ Bindings: Env }>();
const uid = () => crypto.randomUUID().replace(/-/g, '').slice(0, 16);

// Sanitize HTML to prevent stored XSS
const sanitize = (s: any): string => typeof s === 'string' ? s.replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[c] || c)) : String(s ?? '');

// Firebase JWT verification (decode + validate claims, no crypto verify — sufficient for auth gating)
function verifyFirebaseAuth(req: Request, projectId: string): { email: string; uid: string } | null {
  const auth = req.headers.get('Authorization');
  if (!auth?.startsWith('Bearer ')) return null;
  try {
    const token = auth.slice(7);
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.aud !== projectId) return null;
    if (payload.iss !== `https://securetoken.google.com/${projectId}`) return null;
    if (payload.exp < Date.now() / 1000) return null;
    return { email: payload.email || '', uid: payload.user_id || payload.sub || '' };
  } catch { return null; }
}

// Auth middleware for admin-only routes
function requireAuth(c: any): Response | null {
  // Check Firebase token
  const user = verifyFirebaseAuth(c.req.raw, 'echo-prime-ai');
  if (user) {
    const ownerEmails = [
      c.env.OWNER_EMAIL || 'adam@profinishusa.com',
      'traxtoolandpro@gmail.com',
      'adam@profinishusa.com'
    ];
    const devEmails = ['bmcii1976@gmail.com'];
    if (ownerEmails.includes(user.email) || devEmails.includes(user.email)) {
      return null; // Authorized
    }
    return c.json({ error: 'Forbidden — owner/dev access required' }, 403);
  }
  // Check API key fallback
  const apiKey = c.req.header('X-Echo-API-Key');
  if (apiKey && apiKey === c.env.ECHO_API_KEY) return null;
  return c.json({ error: 'Authentication required' }, 401);
}

app.use('*', cors({
  origin: ['https://profinishusa.com', 'https://www.profinishusa.com', 'http://localhost:3000'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
}));

// Request body size limit (256KB) — reject oversized payloads before parsing
const MAX_BODY_SIZE = 256 * 1024;
app.use('*', async (c, next) => {
  if (['POST', 'PUT', 'PATCH'].includes(c.req.method)) {
    const cl = c.req.header('content-length');
    if (cl && parseInt(cl) > MAX_BODY_SIZE) {
      return c.json({ error: 'Request body too large (max 256KB)' }, 413);
    }
  }
  await next();
});

// Input length helper — truncate oversized strings
const maxLen = (s: any, max: number): string => {
  const str = typeof s === 'string' ? s : String(s ?? '');
  return str.length > max ? str.slice(0, max) : str;
};

// Security headers — HSTS, content type options, frame options
app.use('*', async (c, next) => {
  await next();
  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
});

// Simple rate limiter for public POST endpoints (per IP, in-memory — resets on Worker cold start)
const rateBuckets = new Map<string, { count: number; reset: number }>();
const RATE_LIMIT = 30; // 30 requests per minute per IP on public POST
const RATE_WINDOW = 60_000;
const MAX_BUCKETS = 5000; // prevent unbounded memory growth
let lastCleanup = Date.now();

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  // Prune expired buckets every 5 minutes or when map is too large
  if (now - lastCleanup > 300_000 || rateBuckets.size > MAX_BUCKETS) {
    for (const [k, v] of rateBuckets) {
      if (now > v.reset) rateBuckets.delete(k);
    }
    lastCleanup = now;
  }
  const bucket = rateBuckets.get(ip);
  if (!bucket || now > bucket.reset) {
    rateBuckets.set(ip, { count: 1, reset: now + RATE_WINDOW });
    return true;
  }
  bucket.count++;
  return bucket.count <= RATE_LIMIT;
}

// ─── Health ──────────────────────────────────────────────
app.get('/', (c) => c.json({ service: 'profinish-api', version: '1.5.0', status: 'ok' }));
app.get('/health', (c) => c.json({ status: 'healthy', timestamp: new Date().toISOString() }));

// ─── 404 Error Tracking (receives beacons from 404.html) ──
app.post('/errors/404', async (c) => {
  try {
    const b = await c.req.json();
    const ip = c.req.header('cf-connecting-ip') || 'unknown';
    if (!checkRateLimit(ip)) return new Response(null, { status: 204 });
    await c.env.DB.prepare(
      'INSERT INTO error_log (id, type, path, referrer, ip, created_at) VALUES (?, ?, ?, ?, ?, datetime("now"))'
    ).bind(uid(), '404', maxLen(b.path || '', 500), maxLen(b.referrer || '', 500), ip).run();
  } catch {}
  return new Response(null, { status: 204 });
});

// ─── Pageview analytics beacon ──
app.post('/analytics/pageview', async (c) => {
  try {
    const b = await c.req.json();
    const ip = c.req.header('cf-connecting-ip') || 'unknown';
    if (!checkRateLimit(ip)) return new Response(null, { status: 204 });
    const country = c.req.header('cf-ipcountry') || '';
    const ua = c.req.header('user-agent') || '';
    const device = /mobile|android|iphone/i.test(ua) ? 'mobile' : /tablet|ipad/i.test(ua) ? 'tablet' : 'desktop';
    await c.env.DB.prepare(
      'INSERT INTO pageviews (id, path, referrer, country, device) VALUES (?, ?, ?, ?, ?)'
    ).bind(uid(), maxLen(b.path || '/', 500), maxLen(b.referrer || '', 500), country, device).run();
  } catch {}
  return new Response(null, { status: 204 });
});

app.get('/analytics', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const days = Math.min(Number(c.req.query('days')) || 30, 90);
  const since = new Date(Date.now() - days * 86400000).toISOString();
  const total = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM pageviews WHERE ts >= ?').bind(since).first() as any;
  const byPage = await c.env.DB.prepare('SELECT path, COUNT(*) as views FROM pageviews WHERE ts >= ? GROUP BY path ORDER BY views DESC LIMIT 20').bind(since).all();
  const byDevice = await c.env.DB.prepare('SELECT device, COUNT(*) as cnt FROM pageviews WHERE ts >= ? GROUP BY device').bind(since).all();
  const byDay = await c.env.DB.prepare("SELECT date(ts) as day, COUNT(*) as views FROM pageviews WHERE ts >= ? GROUP BY date(ts) ORDER BY day DESC LIMIT 30").bind(since).all();
  const byCountry = await c.env.DB.prepare('SELECT country, COUNT(*) as cnt FROM pageviews WHERE ts >= ? GROUP BY country ORDER BY cnt DESC LIMIT 10').bind(since).all();
  return c.json({ days, total_views: total?.cnt || 0, by_page: byPage.results, by_device: byDevice.results, by_day: byDay.results, by_country: byCountry.results });
});

// ─── Error log viewer (admin) ──
app.get('/errors', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const rows = await c.env.DB.prepare('SELECT * FROM error_log ORDER BY created_at DESC LIMIT 100').all();
  return c.json(rows.results);
});

// ─── Settings ────────────────────────────────────────────
// Public settings — only expose safe keys (no API keys, secrets, internal config)
const PUBLIC_SETTINGS_KEYS = new Set([
  'company_name', 'company_phone', 'company_email', 'company_address', 'company_city',
  'company_tagline', 'company_logo', 'company_website',
  'business_hours', 'promo_text', 'promo_enabled', 'service_area',
  'booking_enabled', 'booking_advance_days', 'booking_slots_per_day',
  'tax_rate', 'referral_amount', 'min_project_amount',
  'accent_color', 'hero_video_url', 'review_prompt'
]);

app.get('/settings', async (c) => {
  const rows = await c.env.DB.prepare('SELECT key, value FROM settings').all();
  const settings: Record<string, string> = {};
  // If authenticated as owner/dev, return all settings; otherwise only public keys
  const user = verifyFirebaseAuth(c.req.raw, 'echo-prime-ai');
  const apiKey = c.req.header('X-Echo-API-Key');
  const isAdmin = (user && ['adam@profinishusa.com', 'traxtoolandpro@gmail.com', 'bmcii1976@gmail.com'].includes(user.email)) || (apiKey && apiKey === c.env.ECHO_API_KEY);
  for (const r of rows.results as any[]) {
    if (isAdmin || PUBLIC_SETTINGS_KEYS.has(r.key)) settings[r.key] = r.value;
  }
  return c.json(settings);
});

app.put('/settings/:key', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const { key } = c.req.param();
  const { value } = await c.req.json();
  await c.env.DB.prepare('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, datetime("now"))').bind(key, String(value)).run();
  return c.json({ ok: true });
});

// ─── Customers ───────────────────────────────────────────
app.get('/customers', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const rows = await c.env.DB.prepare('SELECT * FROM customers ORDER BY created_at DESC').all();
  return c.json(rows.results);
});

app.get('/customers/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const row = await c.env.DB.prepare('SELECT * FROM customers WHERE id = ? OR firebase_uid = ?').bind(c.req.param('id'), c.req.param('id')).first();
  return row ? c.json(row) : c.json({ error: 'Not found' }, 404);
});

app.post('/customers', async (c) => {
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  if (!checkRateLimit(ip)) return c.json({ error: 'Too many requests' }, 429);
  const body = await c.req.json();
  // Validate required fields
  if (!body.name || typeof body.name !== 'string' || body.name.trim().length < 2) {
    return c.json({ error: 'name is required (min 2 characters)' }, 400);
  }
  if (body.email && typeof body.email === 'string' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) {
    return c.json({ error: 'invalid email format' }, 400);
  }
  const id = uid();
  const refCode = 'PF' + id.slice(0, 6).toUpperCase();
  await c.env.DB.prepare(
    'INSERT INTO customers (id, firebase_uid, name, email, phone, address, city, is_owner, referral_code, referred_by, preferred_language, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, body.firebase_uid || null, sanitize(maxLen(body.name, 200)), sanitize(maxLen(body.email || '', 254)), sanitize(maxLen(body.phone || '', 30)), sanitize(maxLen(body.address || '', 500)), sanitize(maxLen(body.city || '', 100)),
    body.email === c.env.OWNER_EMAIL ? 1 : 0, refCode, body.referred_by || null, maxLen(body.preferred_language || 'en', 10), sanitize(maxLen(body.notes || '', 1000))
  ).run();
  return c.json({ id, referral_code: refCode, is_owner: body.email === c.env.OWNER_EMAIL ? 1 : 0 });
});

app.put('/customers/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const body = await c.req.json();
  const fields = ['name', 'email', 'phone', 'address', 'city', 'preferred_language', 'notes'].filter(f => body[f] !== undefined);
  if (!fields.length) return c.json({ error: 'No fields to update' }, 400);
  const sets = fields.map(f => `${f} = ?`).join(', ');
  const vals = fields.map(f => sanitize(body[f]));
  await c.env.DB.prepare(`UPDATE customers SET ${sets}, updated_at = datetime('now') WHERE id = ?`).bind(...vals, c.req.param('id')).run();
  return c.json({ ok: true });
});

// ─── Jobs ────────────────────────────────────────────────
app.get('/jobs', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const cid = c.req.query('customer_id');
  const status = c.req.query('status');
  let sql = 'SELECT j.*, c.name as customer_name, c.phone as customer_phone FROM jobs j LEFT JOIN customers c ON j.customer_id = c.id WHERE 1=1';
  const params: any[] = [];
  if (cid) { sql += ' AND j.customer_id = ?'; params.push(cid); }
  if (status) { sql += ' AND j.status = ?'; params.push(status); }
  sql += ' ORDER BY j.created_at DESC';
  const rows = await c.env.DB.prepare(sql).bind(...params).all();
  return c.json(rows.results);
});

app.get('/jobs/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const row = await c.env.DB.prepare('SELECT j.*, c.name as customer_name FROM jobs j LEFT JOIN customers c ON j.customer_id = c.id WHERE j.id = ?').bind(c.req.param('id')).first();
  return row ? c.json(row) : c.json({ error: 'Not found' }, 404);
});

app.post('/jobs', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  // Basic validation — require title and service_type
  if (!b.title || typeof b.title !== 'string' || b.title.trim().length < 2) {
    return c.json({ error: 'title is required (min 2 characters)' }, 400);
  }
  if (!b.service_type || typeof b.service_type !== 'string') {
    return c.json({ error: 'service_type is required' }, 400);
  }
  const id = uid();
  await c.env.DB.prepare(
    'INSERT INTO jobs (id, customer_id, title, description, service_type, status, estimated_cost_low, estimated_cost_high, address, city, is_outdoor, scheduled_date, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, b.customer_id || null, sanitize(b.title), sanitize(b.description || ''), sanitize(b.service_type || ''), b.status || 'estimate',
    b.estimated_cost_low || null, b.estimated_cost_high || null, sanitize(b.address || ''), sanitize(b.city || ''), b.is_outdoor || 0, b.scheduled_date || null, sanitize(b.notes || '')
  ).run();
  return c.json({ id });
});

app.put('/jobs/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const fields = ['title', 'description', 'service_type', 'status', 'estimated_cost_low', 'estimated_cost_high', 'actual_cost',
    'labor_cost', 'materials_cost', 'address', 'city', 'is_outdoor', 'scheduled_date', 'start_date', 'completion_date', 'notes'].filter(f => b[f] !== undefined);
  if (!fields.length) return c.json({ error: 'No fields' }, 400);
  const stringFields = ['title', 'description', 'service_type', 'address', 'city', 'notes'];
  const sets = fields.map(f => `${f} = ?`).join(', ');
  const vals = fields.map(f => stringFields.includes(f) ? sanitize(b[f]) : b[f]);
  await c.env.DB.prepare(`UPDATE jobs SET ${sets}, updated_at = datetime('now') WHERE id = ?`).bind(...vals, c.req.param('id')).run();
  return c.json({ ok: true });
});

// ─── Invoice Helpers ─────────────────────────────────────
const PAYMENT_TERMS_DAYS: Record<string, number> = { due_on_receipt: 0, net_10: 10, net_15: 15, net_20: 20, net_30: 30, net_45: 45, net_60: 60 };

function calcDueDate(issueDate: string, terms: string): string {
  const d = new Date(issueDate);
  d.setDate(d.getDate() + (PAYMENT_TERMS_DAYS[terms] ?? 30));
  return d.toISOString().split('T')[0];
}

async function genInvoiceNum(db: D1Database, attempt = 0): Promise<string> {
  const now = new Date();
  const prefix = `PF-${String(now.getFullYear()).slice(2)}${String(now.getMonth() + 1).padStart(2, '0')}`;
  const r = await db.prepare(`SELECT MAX(CAST(substr(invoice_number, -4) AS INTEGER)) as max_seq FROM invoices WHERE invoice_number LIKE ?`).bind(prefix + '-%').first<{max_seq: number | null}>();
  return `${prefix}-${String((r?.max_seq ?? 0) + 1 + attempt).padStart(4, '0')}`;
}

async function recalcInvoice(db: D1Database, invoiceId: string): Promise<void> {
  const items = await db.prepare('SELECT SUM(total) as s FROM invoice_items WHERE invoice_id = ?').bind(invoiceId).first<{s:number}>();
  const inv = await db.prepare('SELECT tax_rate FROM invoices WHERE id = ?').bind(invoiceId).first<{tax_rate:number}>();
  const subtotal = items?.s ?? 0;
  const taxAmt = subtotal * (inv?.tax_rate ?? 0.0825);
  const total = subtotal + taxAmt;
  await db.prepare('UPDATE invoices SET subtotal = ?, tax_amount = ?, total = ?, updated_at = datetime(\'now\') WHERE id = ?').bind(subtotal, taxAmt, total, invoiceId).run();
}

// ─── Invoices ────────────────────────────────────────────
app.get('/invoices', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const cid = c.req.query('customer_id');
  const status = c.req.query('status');
  let sql = 'SELECT i.*, c.name as customer_name, c.email as customer_email, c.phone as customer_phone, c.address as customer_address, c.city as customer_city FROM invoices i LEFT JOIN customers c ON i.customer_id = c.id WHERE 1=1';
  const params: any[] = [];
  if (cid) { sql += ' AND i.customer_id = ?'; params.push(cid); }
  if (status) { sql += ' AND i.status = ?'; params.push(status); }
  sql += ' ORDER BY i.created_at DESC';
  const rows = await c.env.DB.prepare(sql).bind(...params).all();
  return c.json(rows.results);
});

app.get('/invoices/public/:token', async (c) => {
  const inv = await c.env.DB.prepare('SELECT i.*, c.name as customer_name, c.email as customer_email, c.phone as customer_phone, c.address as customer_address, c.city as customer_city FROM invoices i LEFT JOIN customers c ON i.customer_id = c.id WHERE i.share_token = ?').bind(c.req.param('token')).first();
  if (!inv) return c.json({ error: 'Not found' }, 404);
  const items = await c.env.DB.prepare('SELECT * FROM invoice_items WHERE invoice_id = ? ORDER BY rowid').bind((inv as any).id).all();
  const payments = await c.env.DB.prepare('SELECT * FROM payments WHERE invoice_id = ? ORDER BY payment_date DESC').bind((inv as any).id).all();
  const settings = await c.env.DB.prepare('SELECT key, value FROM settings').all();
  const cfg: Record<string, string> = {};
  for (const r of settings.results as any[]) cfg[r.key] = r.value;
  return c.json({ ...inv, items: items.results, payments: payments.results, company: cfg });
});

app.get('/invoices/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const inv = await c.env.DB.prepare('SELECT i.*, c.name as customer_name, c.email as customer_email, c.phone as customer_phone, c.address as customer_address, c.city as customer_city FROM invoices i LEFT JOIN customers c ON i.customer_id = c.id WHERE i.id = ?').bind(c.req.param('id')).first();
  if (!inv) return c.json({ error: 'Not found' }, 404);
  const items = await c.env.DB.prepare('SELECT * FROM invoice_items WHERE invoice_id = ? ORDER BY rowid').bind(c.req.param('id')).all();
  const payments = await c.env.DB.prepare('SELECT * FROM payments WHERE invoice_id = ? ORDER BY payment_date DESC').bind(c.req.param('id')).all();
  const settings = await c.env.DB.prepare('SELECT key, value FROM settings').all();
  const cfg: Record<string, string> = {};
  for (const r of settings.results as any[]) cfg[r.key] = r.value;
  return c.json({ ...inv, items: items.results, payments: payments.results, company: cfg });
});

app.post('/invoices', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = uid();
  const shareToken = crypto.randomUUID();
  const issueDate = b.issue_date || new Date().toISOString().split('T')[0];
  const terms = b.payment_terms || 'net_30';
  const dueDate = b.due_date || calcDueDate(issueDate, terms);
  const subtotal = b.subtotal || 0;
  const taxRate = b.tax_rate ?? 0.0825;
  const taxAmt = subtotal * taxRate;
  const total = subtotal + taxAmt;
  let inserted = false;
  for (let attempt = 0; attempt < 5; attempt++) {
    const num = await genInvoiceNum(c.env.DB, attempt);
    try {
      await c.env.DB.prepare(
        'INSERT INTO invoices (id, job_id, customer_id, invoice_number, status, subtotal, tax_rate, tax_amount, total, due_date, issue_date, payment_terms, sales_rep, notes, share_token, amount_paid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)'
      ).bind(id, b.job_id || null, b.customer_id, num, 'draft', subtotal, taxRate, taxAmt, total, dueDate, issueDate, terms, b.sales_rep || null, sanitize(b.notes || ''), shareToken).run();
      inserted = true;
      break;
    } catch (e: any) {
      if (!e.message?.includes('UNIQUE constraint') || attempt === 4) throw e;
    }
  }
  if (!inserted) throw new Error('Failed to generate unique invoice number after 5 attempts');

  if (b.items && Array.isArray(b.items)) {
    for (const item of b.items) {
      const iid = uid();
      const itemTotal = (item.quantity || 1) * (item.unit_price || 0);
      await c.env.DB.prepare(
        'INSERT INTO invoice_items (id, invoice_id, description, type, quantity, unit_price, total) VALUES (?, ?, ?, ?, ?, ?, ?)'
      ).bind(iid, id, sanitize(item.description), item.type || 'labor', item.quantity || 1, item.unit_price || 0, itemTotal).run();
    }
    await recalcInvoice(c.env.DB, id);
  }
  const final = await c.env.DB.prepare('SELECT * FROM invoices WHERE id = ?').bind(id).first();
  return c.json(final);
});

app.put('/invoices/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const allowed = ['status', 'subtotal', 'tax_rate', 'tax_amount', 'total', 'due_date', 'paid_date', 'notes', 'payment_terms', 'sales_rep', 'customer_id', 'issue_date'];
  const fields = allowed.filter(f => b[f] !== undefined);
  if (!fields.length) return c.json({ error: 'No fields' }, 400);
  const stringFields = ['notes', 'sales_rep'];
  const sets = fields.map(f => `${f} = ?`).join(', ');
  const vals = fields.map(f => stringFields.includes(f) ? sanitize(b[f]) : b[f]);
  await c.env.DB.prepare(`UPDATE invoices SET ${sets}, updated_at = datetime('now') WHERE id = ?`).bind(...vals, c.req.param('id')).run();
  if (b.tax_rate !== undefined) await recalcInvoice(c.env.DB, c.req.param('id'));
  return c.json({ ok: true });
});

app.delete('/invoices/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  await c.env.DB.prepare('DELETE FROM invoice_items WHERE invoice_id = ?').bind(c.req.param('id')).run();
  await c.env.DB.prepare('DELETE FROM payments WHERE invoice_id = ?').bind(c.req.param('id')).run();
  await c.env.DB.prepare('DELETE FROM invoices WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

app.post('/invoices/:id/send', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const invId = c.req.param('id');
  const inv = await c.env.DB.prepare(
    'SELECT i.*, c.name as customer_name, c.email as customer_email FROM invoices i LEFT JOIN customers c ON i.customer_id = c.id WHERE i.id = ?'
  ).bind(invId).first() as any;
  if (!inv) return c.json({ error: 'Invoice not found' }, 404);

  // Update status to sent
  await c.env.DB.prepare("UPDATE invoices SET status = 'sent', updated_at = datetime('now') WHERE id = ? AND status = 'draft'").bind(invId).run();

  const b = await c.req.json().catch(() => ({})) as any;
  const method = b.method || 'email'; // 'email' | 'sms' | 'both'
  const results: any = { status_updated: true };

  // Email via Resend
  if ((method === 'email' || method === 'both') && c.env.RESEND_API_KEY && inv.customer_email) {
    try {
      const viewUrl = `${c.env.SITE_URL || 'https://profinishusa.com'}/api/invoices/public/${inv.share_token}`;
      const emailResp = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${c.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from: 'Pro Finish <invoices@profinishusa.com>',
          to: [inv.customer_email],
          subject: `Invoice ${inv.invoice_number} from Pro Finish Custom Carpentry`,
          html: `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
            <div style="background:#1B4D8E;color:white;padding:20px;text-align:center"><h1 style="margin:0;font-size:24px">PRO FINISH</h1><p style="margin:4px 0 0;opacity:.8">Custom Carpentry</p></div>
            <div style="padding:30px;background:#fff">
              <p>Hi ${sanitize(inv.customer_name || 'Customer')},</p>
              <p>Here is your invoice <strong>${inv.invoice_number}</strong> for <strong>$${(inv.total || 0).toFixed(2)}</strong>.</p>
              <p>Due date: <strong>${inv.due_date || 'Upon receipt'}</strong></p>
              <div style="text-align:center;margin:30px 0">
                <a href="${viewUrl}" style="background:#FFD700;color:#0D2847;padding:14px 32px;text-decoration:none;font-weight:bold;border-radius:8px;display:inline-block">View Invoice</a>
              </div>
              <p style="color:#666;font-size:14px">If you have any questions, call Adam at (432) 466-5310.</p>
            </div>
            <div style="text-align:center;padding:16px;color:#999;font-size:12px">Pro Finish Custom Carpentry | Big Spring, TX</div>
          </div>`,
        }),
      });
      results.email = { sent: emailResp.ok, status: emailResp.status };
    } catch (e: any) {
      results.email = { sent: false, error: e.message };
    }
  }

  // SMS via Twilio
  if ((method === 'sms' || method === 'both') && c.env.TWILIO_ACCOUNT_SID && inv.customer_phone) {
    try {
      const phone = inv.customer_phone.replace(/\D/g, '');
      const to = phone.startsWith('1') ? '+' + phone : '+1' + phone;
      const viewUrl = `${c.env.SITE_URL || 'https://profinishusa.com'}/api/invoices/public/${inv.share_token}`;
      const body = `Pro Finish Invoice ${inv.invoice_number}: $${(inv.total || 0).toFixed(2)} due ${inv.due_date || 'upon receipt'}. View: ${viewUrl}`;
      const params = new URLSearchParams({ To: to, From: c.env.TWILIO_PHONE_NUMBER || '', Body: body });
      const smsResp = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${c.env.TWILIO_ACCOUNT_SID}/Messages.json`, {
        method: 'POST', body: params,
        headers: { 'Authorization': 'Basic ' + btoa(c.env.TWILIO_ACCOUNT_SID + ':' + c.env.TWILIO_AUTH_TOKEN), 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      results.sms = { sent: smsResp.ok, status: smsResp.status };
    } catch (e: any) {
      results.sms = { sent: false, error: e.message };
    }
  }

  return c.json(results);
});

app.post('/invoices/:id/void', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  await c.env.DB.prepare("UPDATE invoices SET status = 'void', updated_at = datetime('now') WHERE id = ?").bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

app.get('/invoices/:id/items', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const rows = await c.env.DB.prepare('SELECT * FROM invoice_items WHERE invoice_id = ? ORDER BY rowid').bind(c.req.param('id')).all();
  return c.json(rows.results);
});

app.post('/invoices/:id/items', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const iid = uid();
  const itemTotal = (b.quantity || 1) * (b.unit_price || 0);
  await c.env.DB.prepare(
    'INSERT INTO invoice_items (id, invoice_id, description, type, quantity, unit_price, total) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(iid, c.req.param('id'), sanitize(b.description), b.type || 'labor', b.quantity || 1, b.unit_price || 0, itemTotal).run();
  await recalcInvoice(c.env.DB, c.req.param('id'));
  return c.json({ id: iid, total: itemTotal });
});

app.delete('/invoices/:id/items/:itemId', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  await c.env.DB.prepare('DELETE FROM invoice_items WHERE id = ? AND invoice_id = ?').bind(c.req.param('itemId'), c.req.param('id')).run();
  await recalcInvoice(c.env.DB, c.req.param('id'));
  return c.json({ ok: true });
});

// ─── Payments ────────────────────────────────────────────
app.get('/invoices/:id/payments', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const rows = await c.env.DB.prepare('SELECT * FROM payments WHERE invoice_id = ? ORDER BY payment_date DESC').bind(c.req.param('id')).all();
  return c.json(rows.results);
});

app.post('/payments', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  if (!b.invoice_id || !b.amount) return c.json({ error: 'invoice_id and amount required' }, 400);
  const amt = Number(b.amount);
  if (isNaN(amt) || amt <= 0 || amt > 999999) return c.json({ error: 'amount must be between 0.01 and 999999' }, 400);
  const id = uid();
  await c.env.DB.prepare(
    'INSERT INTO payments (id, invoice_id, amount, payment_method, payment_date, reference_number, collected_by, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, b.invoice_id, b.amount, b.payment_method || 'check', b.payment_date || new Date().toISOString().split('T')[0], b.reference_number || null, sanitize(b.collected_by || ''), sanitize(b.notes || '')).run();
  // Update invoice amount_paid and status
  const paid = await c.env.DB.prepare('SELECT SUM(amount) as s FROM payments WHERE invoice_id = ?').bind(b.invoice_id).first<{s:number}>();
  const inv = await c.env.DB.prepare('SELECT total FROM invoices WHERE id = ?').bind(b.invoice_id).first<{total:number}>();
  const totalPaid = paid?.s ?? 0;
  let newStatus = 'sent';
  if (totalPaid >= (inv?.total ?? 0)) newStatus = 'paid';
  else if (totalPaid > 0) newStatus = 'partial';
  await c.env.DB.prepare("UPDATE invoices SET amount_paid = ?, status = ?, updated_at = datetime('now') WHERE id = ? AND status != 'void'").bind(totalPaid, newStatus, b.invoice_id).run();
  return c.json({ id, amount_paid: totalPaid, status: newStatus });
});

// ─── Expenses ────────────────────────────────────────────
app.get('/expenses', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const jid = c.req.query('job_id');
  let sql = 'SELECT * FROM expenses WHERE 1=1';
  const params: any[] = [];
  if (jid) { sql += ' AND job_id = ?'; params.push(jid); }
  sql += ' ORDER BY expense_date DESC';
  const rows = await c.env.DB.prepare(sql).bind(...params).all();
  return c.json(rows.results);
});

app.post('/expenses', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = uid();
  await c.env.DB.prepare(
    'INSERT INTO expenses (id, job_id, category, vendor, description, amount, receipt_url, receipt_data, expense_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, b.job_id || null, b.category, b.vendor || null, b.description || null, b.amount, b.receipt_url || null, b.receipt_data || null, b.expense_date || null).run();
  return c.json({ id });
});

// ─── Reviews ─────────────────────────────────────────────
app.get('/reviews', async (c) => {
  const approved = c.req.query('approved');
  let sql = 'SELECT r.*, c.name as customer_name FROM reviews r LEFT JOIN customers c ON r.customer_id = c.id';
  if (approved === '1') sql += ' WHERE r.approved = 1';
  sql += ' ORDER BY r.created_at DESC';
  const rows = await c.env.DB.prepare(sql).all();
  return c.json(rows.results);
});

// Public review stats (no auth — for homepage widget + AggregateRating schema)
app.get('/reviews/stats', async (c) => {
  const [stats, recent] = await Promise.all([
    c.env.DB.prepare('SELECT COUNT(*) as count, COALESCE(AVG(rating), 0) as avg_rating FROM reviews WHERE approved = 1').first() as Promise<any>,
    c.env.DB.prepare("SELECT r.rating, r.text, r.created_at, c.name as customer_name FROM reviews r LEFT JOIN customers c ON r.customer_id = c.id WHERE r.approved = 1 ORDER BY r.created_at DESC LIMIT 6").all(),
  ]);
  return c.json({
    count: stats?.count || 0,
    avg_rating: Math.round((stats?.avg_rating || 0) * 10) / 10,
    recent: recent.results,
  });
});

app.post('/reviews', async (c) => {
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  if (!checkRateLimit(ip)) return c.json({ error: 'Too many requests' }, 429);
  const b = await c.req.json();
  // Validate rating range (1-5 stars)
  const rating = Number(b.rating);
  if (!rating || rating < 1 || rating > 5 || !Number.isInteger(rating)) {
    return c.json({ error: 'rating must be an integer between 1 and 5' }, 400);
  }
  if (!b.text || typeof b.text !== 'string' || b.text.trim().length < 5) {
    return c.json({ error: 'review text is required (min 5 characters)' }, 400);
  }
  const id = uid();
  const photoUrl = b.photo_url ? maxLen(b.photo_url, 500) : null;
  if (photoUrl && !/^https?:\/\/.+/i.test(photoUrl)) return c.json({ error: 'photo_url must be a valid URL' }, 400);
  await c.env.DB.prepare(
    'INSERT INTO reviews (id, customer_id, job_id, rating, text, photo_url, approved) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, b.customer_id || null, b.job_id || null, rating, sanitize(maxLen(b.text, 2000)), photoUrl, 0).run();
  return c.json({ id });
});

app.put('/reviews/:id/approve', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  await c.env.DB.prepare('UPDATE reviews SET approved = 1 WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

// ─── Review request (send SMS to customer after job) ─────
app.post('/reviews/request/:jobId', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const jobId = c.req.param('jobId');
  const job = await c.env.DB.prepare('SELECT j.*, c.name as customer_name, c.phone as customer_phone FROM jobs j LEFT JOIN customers c ON j.customer_id = c.id WHERE j.id = ?').bind(jobId).first() as any;
  if (!job) return c.json({ error: 'Job not found' }, 404);
  if (!job.customer_phone) return c.json({ error: 'Customer has no phone number' }, 400);

  // Generate review token
  const token = uid() + uid();
  await c.env.DB.prepare("UPDATE jobs SET review_token = ?, review_sent_at = datetime('now') WHERE id = ?").bind(token, jobId).run();

  const reviewUrl = `${c.env.SITE_URL || 'https://profinishusa.com'}/review.html?token=${token}`;

  if (c.env.TWILIO_ACCOUNT_SID && c.env.TWILIO_AUTH_TOKEN && c.env.TWILIO_PHONE_NUMBER) {
    const msg = `Hi ${job.customer_name}! Thank you for choosing Pro Finish Custom Carpentry. We'd love your feedback — it takes 30 seconds:\n${reviewUrl}\n\n- Adam McLemore`;
    const params = new URLSearchParams({ To: job.customer_phone, From: c.env.TWILIO_PHONE_NUMBER, Body: msg.slice(0, 1600) });
    const smsResp = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${c.env.TWILIO_ACCOUNT_SID}/Messages.json`, {
      method: 'POST', body: params,
      headers: { 'Authorization': 'Basic ' + btoa(c.env.TWILIO_ACCOUNT_SID + ':' + c.env.TWILIO_AUTH_TOKEN), 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    return c.json({ ok: smsResp.ok, review_url: reviewUrl });
  }
  return c.json({ ok: true, review_url: reviewUrl, note: 'Twilio not configured — share link manually' });
});

// Public: get job info for review page (no auth, token-gated)
app.get('/reviews/by-token/:token', async (c) => {
  const token = c.req.param('token');
  if (!token || token.length < 16) return c.json({ error: 'Invalid token' }, 400);
  const job = await c.env.DB.prepare(
    'SELECT j.id, j.title, j.description, j.review_token, c.name as customer_name FROM jobs j LEFT JOIN customers c ON j.customer_id = c.id WHERE j.review_token = ?'
  ).bind(token).first() as any;
  if (!job) return c.json({ error: 'Invalid or expired review link' }, 404);
  return c.json({ job_id: job.id, title: job.title, customer_name: job.customer_name });
});

// Public: submit review via token
app.post('/reviews/submit', async (c) => {
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  if (!checkRateLimit(ip)) return c.json({ error: 'Too many requests' }, 429);
  const b = await c.req.json();
  if (!b.token || b.token.length < 16) return c.json({ error: 'Invalid token' }, 400);
  const rating = Number(b.rating);
  if (!rating || rating < 1 || rating > 5 || !Number.isInteger(rating)) return c.json({ error: 'rating must be 1-5' }, 400);
  if (!b.text || typeof b.text !== 'string' || b.text.trim().length < 5) return c.json({ error: 'Please write at least a short review' }, 400);

  const job = await c.env.DB.prepare('SELECT id, customer_id FROM jobs WHERE review_token = ?').bind(b.token).first() as any;
  if (!job) return c.json({ error: 'Invalid or expired review link' }, 404);

  const id = uid();
  await c.env.DB.prepare(
    'INSERT INTO reviews (id, customer_id, job_id, rating, text, approved) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(id, job.customer_id, job.id, rating, sanitize(maxLen(b.text, 2000)), 0).run();

  // Invalidate the token so it can't be reused
  await c.env.DB.prepare("UPDATE jobs SET review_token = NULL WHERE id = ?").bind(job.id).run();

  // Notify Adam
  if (c.env.TWILIO_ACCOUNT_SID && c.env.TWILIO_AUTH_TOKEN && c.env.TWILIO_PHONE_NUMBER) {
    try {
      const msg = `New ${rating}-star review received! "${b.text.slice(0, 100)}..." — check owner dashboard to approve.`;
      const params = new URLSearchParams({ To: c.env.ADAM_PHONE, From: c.env.TWILIO_PHONE_NUMBER, Body: msg });
      await fetch(`https://api.twilio.com/2010-04-01/Accounts/${c.env.TWILIO_ACCOUNT_SID}/Messages.json`, {
        method: 'POST', body: params,
        headers: { 'Authorization': 'Basic ' + btoa(c.env.TWILIO_ACCOUNT_SID + ':' + c.env.TWILIO_AUTH_TOKEN), 'Content-Type': 'application/x-www-form-urlencoded' },
      });
    } catch {}
  }

  return c.json({ ok: true, message: 'Thank you for your review! It means a lot to us.' });
});

// ─── Appointments ────────────────────────────────────────
app.get('/appointments', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const date = c.req.query('date');
  const month = c.req.query('month');
  let sql = 'SELECT a.*, c.name as customer_name, c.phone as customer_phone, j.title as job_title FROM appointments a LEFT JOIN customers c ON a.customer_id = c.id LEFT JOIN jobs j ON a.job_id = j.id WHERE 1=1';
  const params: any[] = [];
  if (date) { sql += ' AND a.date = ?'; params.push(date); }
  if (month) { sql += ' AND a.date LIKE ?'; params.push(month + '%'); }
  sql += ' ORDER BY a.date, a.time_start';
  const rows = await c.env.DB.prepare(sql).bind(...params).all();
  return c.json(rows.results);
});

app.post('/appointments', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = uid();
  await c.env.DB.prepare(
    'INSERT INTO appointments (id, customer_id, job_id, title, description, service_type, date, time_start, time_end, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, b.customer_id || null, b.job_id || null, sanitize(b.title), sanitize(b.description || ''), sanitize(b.service_type || ''), b.date, b.time_start || null, b.time_end || null, b.status || 'scheduled').run();
  return c.json({ id });
});

app.put('/appointments/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const fields = ['title', 'date', 'time_start', 'time_end', 'status', 'weather_alert'].filter(f => b[f] !== undefined);
  if (!fields.length) return c.json({ error: 'No fields' }, 400);
  const sets = fields.map(f => `${f} = ?`).join(', ');
  const vals = fields.map(f => b[f]);
  await c.env.DB.prepare(`UPDATE appointments SET ${sets} WHERE id = ?`).bind(...vals, c.req.param('id')).run();
  return c.json({ ok: true });
});

// ─── Chat Sessions ───────────────────────────────────────
app.post('/chat/session', async (c) => {
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  if (!checkRateLimit(ip)) return c.json({ error: 'Too many requests' }, 429);
  // Require auth or valid customer_id to prevent session pollution
  const user = verifyFirebaseAuth(c.req.raw, 'echo-prime-ai');
  const apiKey = c.req.header('X-Echo-API-Key');
  const b = await c.req.json();
  if (!user && !(apiKey && apiKey === c.env.ECHO_API_KEY)) {
    // Allow unauthenticated only if customer_id is provided (widget creates session for logged-in user)
    if (!b.customer_id || typeof b.customer_id !== 'string' || b.customer_id.length < 8) {
      return c.json({ error: 'Authentication or valid customer_id required' }, 401);
    }
  }
  const id = uid();
  const msgs = Array.isArray(b.messages) ? b.messages.slice(-50) : [];
  const emoLog = Array.isArray(b.emotion_log) ? b.emotion_log.slice(-50) : [];
  await c.env.DB.prepare(
    'INSERT INTO chat_sessions (id, customer_id, messages, emotion_log) VALUES (?, ?, ?, ?)'
  ).bind(id, b.customer_id || null, maxLen(JSON.stringify(msgs), 32000), maxLen(JSON.stringify(emoLog), 16000)).run();
  return c.json({ id });
});

app.put('/chat/session/:id', async (c) => {
  // Require auth — prevent unauthorized chat message modification
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  await c.env.DB.prepare(
    'UPDATE chat_sessions SET messages = ?, emotion_log = ?, summary = ?, updated_at = datetime("now") WHERE id = ?'
  ).bind(JSON.stringify(b.messages || []), JSON.stringify(b.emotion_log || []), b.summary || null, c.req.param('id')).run();
  return c.json({ ok: true });
});

// ─── Subcontractors ──────────────────────────────────────
app.get('/subcontractors', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const trade = c.req.query('trade');
  let sql = 'SELECT * FROM subcontractors WHERE 1=1';
  const params: any[] = [];
  if (trade) { sql += ' AND trade = ?'; params.push(trade); }
  sql += ' ORDER BY rating DESC';
  const rows = await c.env.DB.prepare(sql).bind(...params).all();
  return c.json(rows.results);
});

app.post('/subcontractors', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = uid();
  await c.env.DB.prepare(
    'INSERT INTO subcontractors (id, name, trade, phone, email, rating, notes) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, b.name, b.trade, b.phone || null, b.email || null, b.rating || 5, b.notes || null).run();
  return c.json({ id });
});

// ─── Time Entries ────────────────────────────────────────
app.get('/time', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const jid = c.req.query('job_id');
  const week = c.req.query('week');
  let sql = 'SELECT t.*, j.title as job_title FROM time_entries t LEFT JOIN jobs j ON t.job_id = j.id WHERE 1=1';
  const params: any[] = [];
  if (jid) { sql += ' AND t.job_id = ?'; params.push(jid); }
  if (week) { sql += ' AND t.date >= ? AND t.date < date(?, "+7 days")'; params.push(week, week); }
  sql += ' ORDER BY t.date DESC, t.start_time DESC';
  const rows = await c.env.DB.prepare(sql).bind(...params).all();
  return c.json(rows.results);
});

app.post('/time/start', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = uid();
  const now = new Date().toISOString().slice(11, 16);
  await c.env.DB.prepare(
    'INSERT INTO time_entries (id, job_id, worker_name, date, start_time, hourly_rate) VALUES (?, ?, ?, date("now"), ?, ?)'
  ).bind(id, b.job_id, b.worker_name || 'Adam', now, b.hourly_rate || 75).run();
  return c.json({ id, start_time: now });
});

app.post('/time/stop/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const now = new Date().toISOString().slice(11, 16);
  const entry = await c.env.DB.prepare('SELECT start_time, hourly_rate FROM time_entries WHERE id = ?').bind(c.req.param('id')).first() as any;
  if (!entry) return c.json({ error: 'Not found' }, 404);
  const [sh, sm] = entry.start_time.split(':').map(Number);
  const [eh, em] = now.split(':').map(Number);
  const hours = Math.round(((eh * 60 + em) - (sh * 60 + sm)) / 60 * 100) / 100;
  await c.env.DB.prepare('UPDATE time_entries SET end_time = ?, hours = ? WHERE id = ?').bind(now, hours, c.req.param('id')).run();
  return c.json({ end_time: now, hours, cost: hours * (entry.hourly_rate || 75) });
});

// ─── Permits ─────────────────────────────────────────────
app.get('/permits', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const rows = await c.env.DB.prepare('SELECT p.*, j.title as job_title FROM permits p LEFT JOIN jobs j ON p.job_id = j.id ORDER BY p.expiration_date').all();
  return c.json(rows.results);
});

app.post('/permits', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = uid();
  await c.env.DB.prepare(
    'INSERT INTO permits (id, job_id, permit_number, type, status, jurisdiction, filed_date, expiration_date, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, b.job_id || null, b.permit_number || null, b.type, b.status || 'pending', b.jurisdiction || null, b.filed_date || null, b.expiration_date || null, b.notes || null).run();
  return c.json({ id });
});

// ─── Blog Posts ──────────────────────────────────────────
app.get('/blog', async (c) => {
  const status = c.req.query('status') || 'published';
  const rows = await c.env.DB.prepare('SELECT * FROM blog_posts WHERE status = ? ORDER BY published_at DESC').bind(status).all();
  return c.json(rows.results);
});

// Blog RSS Feed (must be above :idOrSlug to prevent slug-matching)
app.get('/blog/feed.xml', async (c) => {
  const posts = await c.env.DB.prepare("SELECT title, slug, excerpt, published_at, author FROM blog_posts WHERE status = 'published' ORDER BY published_at DESC LIMIT 20").all();
  const siteUrl = c.env.SITE_URL || 'https://profinishusa.com';
  const items = (posts.results as any[]).map((p: any) => `<item>
    <title><![CDATA[${p.title}]]></title>
    <link>${siteUrl}/blog/${p.slug}</link>
    <description><![CDATA[${p.excerpt || ''}]]></description>
    <pubDate>${p.published_at ? new Date(p.published_at).toUTCString() : ''}</pubDate>
    <author>${p.author || 'Pro Finish'}</author>
  </item>`).join('\n');
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
  <title>Pro Finish Custom Carpentry Blog</title>
  <link>${siteUrl}/blog</link>
  <description>Expert carpentry tips, project showcases, and home improvement advice from Big Spring, TX</description>
  <language>en-us</language>
  <atom:link href="${siteUrl}/api/blog/feed.xml" rel="self" type="application/rss+xml"/>
  ${items}
</channel>
</rss>`;
  return new Response(xml, { headers: { 'Content-Type': 'application/xml; charset=utf-8', 'Cache-Control': 'public, max-age=3600' } });
});

app.get('/blog/:idOrSlug', async (c) => {
  const param = c.req.param('idOrSlug');
  const row = await c.env.DB.prepare('SELECT * FROM blog_posts WHERE id = ? OR slug = ?').bind(param, param).first();
  return row ? c.json(row) : c.json({ error: 'Not found' }, 404);
});

app.post('/blog', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = uid();
  const slug = (b.title || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  // Blog content is admin-authored HTML — sanitize title/excerpt/tags but preserve content HTML
  await c.env.DB.prepare(
    'INSERT INTO blog_posts (id, title, slug, content, excerpt, status, author, tags, seo_title, seo_description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, sanitize(b.title), slug, b.content || '', sanitize(b.excerpt || ''), b.status || 'draft', sanitize(b.author || 'Belle'), sanitize(b.tags || ''), sanitize(b.seo_title || b.title), sanitize(b.seo_description || b.excerpt || '')).run();
  return c.json({ id, slug });
});

app.put('/blog/:id/publish', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  await c.env.DB.prepare('UPDATE blog_posts SET status = "published", published_at = datetime("now"), updated_at = datetime("now") WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

app.put('/blog/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const fields: string[] = [];
  const vals: any[] = [];
  if (b.title !== undefined) { fields.push('title = ?'); vals.push(sanitize(b.title)); }
  if (b.content !== undefined) { fields.push('content = ?'); vals.push(b.content); }
  if (b.excerpt !== undefined) { fields.push('excerpt = ?'); vals.push(sanitize(b.excerpt)); }
  if (b.tags !== undefined) { fields.push('tags = ?'); vals.push(sanitize(b.tags)); }
  if (b.author !== undefined) { fields.push('author = ?'); vals.push(sanitize(b.author)); }
  if (b.seo_title !== undefined) { fields.push('seo_title = ?'); vals.push(sanitize(b.seo_title)); }
  if (b.seo_description !== undefined) { fields.push('seo_description = ?'); vals.push(sanitize(b.seo_description)); }
  if (b.status !== undefined) { fields.push('status = ?'); vals.push(b.status); }
  if (!fields.length) return c.json({ error: 'No fields to update' }, 400);
  fields.push("updated_at = datetime('now')");
  vals.push(c.req.param('id'));
  await c.env.DB.prepare(`UPDATE blog_posts SET ${fields.join(', ')} WHERE id = ?`).bind(...vals).run();
  return c.json({ ok: true });
});

app.delete('/blog/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  await c.env.DB.prepare('DELETE FROM blog_posts WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

// ─── Referrals ───────────────────────────────────────────
app.get('/referrals', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const rows = await c.env.DB.prepare(
    'SELECT r.*, c1.name as referrer_name, c2.name as referred_name FROM referrals r LEFT JOIN customers c1 ON r.referrer_id = c1.id LEFT JOIN customers c2 ON r.referred_id = c2.id ORDER BY r.created_at DESC'
  ).all();
  return c.json(rows.results);
});

app.post('/referrals/track', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const referrer = await c.env.DB.prepare('SELECT id FROM customers WHERE referral_code = ?').bind(b.referral_code).first() as any;
  if (!referrer) return c.json({ error: 'Invalid referral code' }, 400);
  const id = uid();
  await c.env.DB.prepare(
    'INSERT INTO referrals (id, referrer_id, referred_id) VALUES (?, ?, ?)'
  ).bind(id, referrer.id, b.referred_id).run();
  return c.json({ id, referrer_id: referrer.id });
});

// ─── Follow-Ups ──────────────────────────────────────────
app.get('/follow-ups', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const status = c.req.query('status') || 'pending';
  const rows = await c.env.DB.prepare(
    'SELECT f.*, c.name as customer_name, c.phone as customer_phone FROM follow_ups f LEFT JOIN customers c ON f.customer_id = c.id WHERE f.status = ? ORDER BY f.scheduled_at'
  ).bind(status).all();
  return c.json(rows.results);
});

app.post('/follow-ups', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = uid();
  await c.env.DB.prepare(
    'INSERT INTO follow_ups (id, customer_id, job_id, type, step, scheduled_at, channel, message) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, b.customer_id, b.job_id || null, b.type, b.step || 1, b.scheduled_at, b.channel || 'sms', b.message || null).run();
  return c.json({ id });
});

// ─── Promotions ──────────────────────────────────────────
app.get('/promotions', async (c) => {
  const active = c.req.query('active');
  let sql = 'SELECT * FROM promotions';
  if (active === '1') sql += ' WHERE active = 1';
  sql += ' ORDER BY created_at DESC';
  const rows = await c.env.DB.prepare(sql).all();
  return c.json(rows.results);
});

app.post('/promotions', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = uid();
  await c.env.DB.prepare(
    'INSERT INTO promotions (id, title, description, discount_type, discount_value, promo_code, active, start_date, end_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, b.title, b.description || null, b.discount_type || 'percent', b.discount_value || 10, b.promo_code || null, b.active || 0, b.start_date || null, b.end_date || null).run();
  return c.json({ id });
});

// ─── NPS ─────────────────────────────────────────────────
app.post('/nps', async (c) => {
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  if (!checkRateLimit(ip)) return c.json({ error: 'Too many requests' }, 429);
  const b = await c.req.json();
  // Validate NPS score range (0-10)
  const score = Number(b.score);
  if (isNaN(score) || score < 0 || score > 10 || !Number.isInteger(score)) {
    return c.json({ error: 'score must be an integer between 0 and 10' }, 400);
  }
  const id = uid();
  let action = 'none';
  if (score >= 9) action = 'ask_google_review';
  else if (score >= 7) action = 'ask_improvement';
  else action = 'alert_adam';
  await c.env.DB.prepare(
    'INSERT INTO nps_responses (id, customer_id, job_id, score, comment, follow_up_action) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(id, b.customer_id || null, b.job_id || null, score, sanitize(maxLen(b.comment || '', 1000)), action).run();
  return c.json({ id, follow_up_action: action });
});

app.get('/nps/stats', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const rows = await c.env.DB.prepare('SELECT score FROM nps_responses').all();
  const scores = (rows.results as any[]).map(r => r.score);
  const total = scores.length;
  if (!total) return c.json({ nps: 0, promoters: 0, passives: 0, detractors: 0, total: 0 });
  const promoters = scores.filter(s => s >= 9).length;
  const detractors = scores.filter(s => s <= 6).length;
  const nps = Math.round(((promoters - detractors) / total) * 100);
  return c.json({ nps, promoters, passives: total - promoters - detractors, detractors, total });
});

// ─── Progress Photos ─────────────────────────────────────
app.get('/progress/:job_id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const rows = await c.env.DB.prepare('SELECT * FROM progress_photos WHERE job_id = ? ORDER BY created_at').bind(c.req.param('job_id')).all();
  return c.json(rows.results);
});

app.post('/progress', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = uid();
  const key = `profinish/projects/${b.job_id}/progress/${Date.now()}.jpg`;
  if (b.photo_base64) {
    const bytes = Uint8Array.from(atob(b.photo_base64), c => c.charCodeAt(0));
    await c.env.R2.put(key, bytes, { httpMetadata: { contentType: 'image/jpeg' } });
  }
  const photoUrl = b.photo_url || key;
  await c.env.DB.prepare(
    'INSERT INTO progress_photos (id, job_id, photo_url, caption) VALUES (?, ?, ?, ?)'
  ).bind(id, b.job_id, photoUrl, b.caption || null).run();
  return c.json({ id, photo_url: photoUrl });
});

// ─── Hardware Orders ─────────────────────────────────────
app.get('/hardware-orders', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const rows = await c.env.DB.prepare('SELECT * FROM hardware_orders ORDER BY created_at DESC').all();
  return c.json(rows.results);
});

app.post('/hardware-orders', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = uid();
  await c.env.DB.prepare(
    'INSERT INTO hardware_orders (id, store, items, status, job_id, total_estimate) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(id, b.store, JSON.stringify(b.items), b.status || 'pending', b.job_id || null, b.total_estimate || null).run();
  return c.json({ id });
});

// ─── Twilio ──────────────────────────────────────────────
app.post('/twilio/call', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const { SID, TOKEN, FROM } = { SID: c.env.TWILIO_ACCOUNT_SID, TOKEN: c.env.TWILIO_AUTH_TOKEN, FROM: c.env.TWILIO_PHONE_NUMBER };
  if (!SID || !TOKEN || !FROM) return c.json({ error: 'Twilio not configured' }, 503);
  const b = await c.req.json();
  const twiml = `<Response><Say voice="Polly.Joanna">Hey Adam, this is Belle from Pro Finish. ${sanitize(b.reason) || 'You have a new lead.'}. Customer ${sanitize(b.customer_name) || 'unknown'} at ${sanitize(b.customer_phone) || 'unknown number'}. Have a great day!</Say></Response>`;
  const params = new URLSearchParams({ To: c.env.ADAM_PHONE, From: FROM, Twiml: twiml });
  const resp = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${SID}/Calls.json`, {
    method: 'POST', body: params,
    headers: { 'Authorization': 'Basic ' + btoa(SID + ':' + TOKEN), 'Content-Type': 'application/x-www-form-urlencoded' }
  });
  return c.json({ ok: true, status: resp.status });
});

app.post('/twilio/sms', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const { SID, TOKEN, FROM } = { SID: c.env.TWILIO_ACCOUNT_SID, TOKEN: c.env.TWILIO_AUTH_TOKEN, FROM: c.env.TWILIO_PHONE_NUMBER };
  if (!SID || !TOKEN || !FROM) return c.json({ error: 'Twilio not configured' }, 503);
  const b = await c.req.json();
  const params = new URLSearchParams({ To: b.to, From: FROM, Body: b.body });
  const resp = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${SID}/Messages.json`, {
    method: 'POST', body: params,
    headers: { 'Authorization': 'Basic ' + btoa(SID + ':' + TOKEN), 'Content-Type': 'application/x-www-form-urlencoded' }
  });
  return c.json({ ok: true, status: resp.status });
});

// ─── Weather ─────────────────────────────────────────────
app.get('/weather', async (c) => {
  try {
    // Big Spring, TX coordinates
    const pointResp = await fetch('https://api.weather.gov/points/32.2507,-101.4821', {
      headers: { 'User-Agent': 'ProFinishCarpentry/1.0 (profinishcartx@gmail.com)' }
    });
    const pointData: any = await pointResp.json();
    const forecastUrl = pointData.properties?.forecast;
    if (!forecastUrl) return c.json({ error: 'Could not get forecast URL' }, 500);
    const fcResp = await fetch(forecastUrl, {
      headers: { 'User-Agent': 'ProFinishCarpentry/1.0 (profinishcartx@gmail.com)' }
    });
    const fcData: any = await fcResp.json();
    return c.json(fcData.properties?.periods || []);
  } catch (e) {
    return c.json({ error: 'Weather service unavailable' }, 503);
  }
});

// ─── Receipt OCR (via Azure GPT-5.2 vision) ─────────────
app.post('/receipt/scan', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  if (!b.image_base64) return c.json({ error: 'No image' }, 400);
  // Store in R2
  const key = `profinish/receipts/${Date.now()}.jpg`;
  const bytes = Uint8Array.from(atob(b.image_base64), ch => ch.charCodeAt(0));
  await c.env.R2.put(key, bytes, { httpMetadata: { contentType: 'image/jpeg' } });
  // Use Claude vision to extract receipt data (FREE via OAuth proxy)
  try {
    const claudeResp = await fetch(CLAUDE_PROXY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Echo-API-Key': CLAUDE_PROXY_KEY },
      body: JSON.stringify({
        model: 'claude-haiku-4-5',
        system: 'You are a receipt OCR assistant. Extract data and return ONLY valid JSON.',
        messages: [{
          role: 'user',
          content: [
            { type: 'text', text: 'Extract from this receipt: vendor name, total amount, date, and list of items with prices. Return ONLY JSON: {"vendor":"","total":0,"date":"","items":[{"name":"","price":0}]}' },
            { type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: b.image_base64 } }
          ]
        }],
        max_tokens: 512,
      }),
    });
    if (!claudeResp.ok) {
      return c.json({ receipt_url: key, vendor: '', total: 0, date: '', items: [], error: `Vision error ${claudeResp.status}` });
    }
    const claudeData: any = await claudeResp.json();
    const content = claudeData.content?.[0]?.text || '{}';
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    const parsed = jsonMatch ? JSON.parse(jsonMatch[0]) : {};
    return c.json({ ...parsed, receipt_url: key });
  } catch {
    return c.json({ receipt_url: key, vendor: '', total: 0, date: '', items: [] });
  }
});

// ─── Dashboard Aggregations ──────────────────────────────
app.get('/dashboard/owner', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const [jobs, invoices, expenses, reviews, appointments, nps, time, subs] = await Promise.all([
    c.env.DB.prepare('SELECT status, COUNT(*) as count, SUM(actual_cost) as revenue FROM jobs GROUP BY status').all(),
    c.env.DB.prepare("SELECT status, COUNT(*) as count, SUM(total) as total FROM invoices GROUP BY status").all(),
    c.env.DB.prepare("SELECT category, SUM(amount) as total FROM expenses GROUP BY category").all(),
    c.env.DB.prepare("SELECT COUNT(*) as count, AVG(rating) as avg_rating FROM reviews WHERE approved = 1").first(),
    c.env.DB.prepare("SELECT COUNT(*) as count FROM appointments WHERE date >= date('now') AND status = 'scheduled'").first(),
    c.env.DB.prepare('SELECT score FROM nps_responses').all(),
    c.env.DB.prepare("SELECT SUM(hours) as total_hours, SUM(hours * hourly_rate) as total_labor FROM time_entries WHERE date >= date('now', '-30 days')").first(),
    c.env.DB.prepare("SELECT * FROM subscriptions WHERE status IN ('active', 'planned') ORDER BY monthly_cost DESC").all(),
  ]);
  const npsScores = (nps.results as any[]).map(r => r.score);
  const npsTotal = npsScores.length;
  const npsScore = npsTotal ? Math.round((((npsScores.filter(s => s >= 9).length) - (npsScores.filter(s => s <= 6).length)) / npsTotal) * 100) : 0;
  const subsList = subs.results as any[];
  const monthlyCost = subsList.reduce((sum: number, s: any) => sum + (s.monthly_cost || 0), 0);

  return c.json({
    jobs: jobs.results,
    invoices: invoices.results,
    expenses: expenses.results,
    reviews,
    upcoming_appointments: appointments,
    nps: { score: npsScore, total: npsTotal },
    time_30d: time,
    subscriptions: {
      services: subsList,
      total_monthly: Math.round(monthlyCost * 100) / 100,
      total_annual: Math.round(monthlyCost * 12 * 100) / 100,
    },
  });
});

app.get('/dashboard/user/:uid', async (c) => {
  const fuid = c.req.param('uid');
  // SECURITY: Verify requesting user owns this UID (prevent IDOR)
  const user = verifyFirebaseAuth(c.req.raw, 'echo-prime-ai');
  const apiKey = c.req.header('X-Echo-API-Key');
  const isApiKey = apiKey && apiKey === c.env.ECHO_API_KEY;
  if (!isApiKey) {
    if (!user) return c.json({ error: 'Authentication required' }, 401);
    const ownerEmails = [c.env.OWNER_EMAIL || 'adam@profinishusa.com', 'traxtoolandpro@gmail.com', 'adam@profinishusa.com', 'bmcii1976@gmail.com'];
    if (user.uid !== fuid && !ownerEmails.includes(user.email)) {
      return c.json({ error: 'Forbidden — you can only view your own dashboard' }, 403);
    }
  }
  const customer = await c.env.DB.prepare('SELECT * FROM customers WHERE firebase_uid = ?').bind(fuid).first();
  if (!customer) return c.json({ error: 'Customer not found' }, 404);
  const cid = (customer as any).id;
  const [jobs, appointments, reviews, chatSessions] = await Promise.all([
    c.env.DB.prepare('SELECT * FROM jobs WHERE customer_id = ? ORDER BY created_at DESC').bind(cid).all(),
    c.env.DB.prepare("SELECT * FROM appointments WHERE customer_id = ? AND date >= date('now') ORDER BY date").bind(cid).all(),
    c.env.DB.prepare('SELECT * FROM reviews WHERE customer_id = ? ORDER BY created_at DESC').bind(cid).all(),
    c.env.DB.prepare('SELECT id, summary, created_at FROM chat_sessions WHERE customer_id = ? ORDER BY created_at DESC LIMIT 10').bind(cid).all(),
  ]);
  return c.json({ customer, jobs: jobs.results, appointments: appointments.results, reviews: reviews.results, chat_sessions: chatSessions.results });
});

// ─── R2 Upload (JSON base64 or multipart form) ──────────
app.post('/upload', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const ct = c.req.header('content-type') || '';
  if (ct.includes('multipart/form-data')) {
    const form = await c.req.formData();
    const file = form.get('file') as File | null;
    if (!file) return c.json({ error: 'file required' }, 400);
    const key = 'profinish/uploads/' + Date.now() + '-' + file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
    const buf = await file.arrayBuffer();
    await c.env.R2.put(key, buf, { httpMetadata: { contentType: file.type || 'application/octet-stream' } });
    const url = 'https://pub-media.echo-op.com/' + key;
    return c.json({ key, url, filename: file.name });
  }
  const b = await c.req.json();
  if (!b.key || !b.data_base64) return c.json({ error: 'key and data_base64 required' }, 400);
  const bytes = Uint8Array.from(atob(b.data_base64), ch => ch.charCodeAt(0));
  await c.env.R2.put(b.key, bytes, { httpMetadata: { contentType: b.content_type || 'application/octet-stream' } });
  return c.json({ key: b.key });
});

// ─── PDF Estimate Generation (Phase 15) ─────────────────
app.post('/estimate/pdf', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const { job_id } = b;
  if (!job_id) return c.json({ error: 'job_id required' }, 400);

  const job = await c.env.DB.prepare('SELECT j.*, c.name as customer_name, c.email, c.phone, c.address FROM jobs j LEFT JOIN customers c ON j.customer_id = c.id WHERE j.id = ?').bind(job_id).first() as any;
  if (!job) return c.json({ error: 'Job not found' }, 404);

  const items = await c.env.DB.prepare('SELECT * FROM invoice_items WHERE invoice_id IN (SELECT id FROM invoices WHERE job_id = ?)').bind(job_id).all();
  const lineItems = items.results || [];

  // Generate HTML estimate (rendered as PDF-ready printable page)
  const total = lineItems.reduce((sum: number, i: any) => sum + ((i.quantity || 1) * (i.unit_price || 0)), 0);
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Pro Finish Estimate #${job_id}</title>
<style>
  body{font-family:Arial,sans-serif;max-width:800px;margin:0 auto;padding:40px;color:#333}
  .header{display:flex;justify-content:space-between;border-bottom:3px solid #1B4D8E;padding-bottom:20px;margin-bottom:30px}
  .logo-side h1{color:#1B4D8E;font-size:24px;margin:0}
  .logo-side p{color:#666;margin:4px 0}
  .est-label{background:#1B4D8E;color:#FFD700;padding:10px 20px;font-size:20px;font-weight:bold;text-align:center}
  .info-grid{display:grid;grid-template-columns:1fr 1fr;gap:30px;margin-bottom:30px}
  .info-box h3{color:#1B4D8E;font-size:14px;margin:0 0 8px;text-transform:uppercase;letter-spacing:1px}
  .info-box p{margin:2px 0;font-size:14px}
  table{width:100%;border-collapse:collapse;margin:20px 0}
  th{background:#1B4D8E;color:white;padding:10px;text-align:left;font-size:13px}
  td{padding:10px;border-bottom:1px solid #ddd;font-size:14px}
  .total-row td{font-weight:bold;font-size:16px;border-top:2px solid #1B4D8E}
  .terms{background:#f8f9fa;padding:20px;border-radius:6px;margin-top:30px;font-size:12px;color:#666}
  .terms h3{color:#1B4D8E;font-size:14px;margin-top:0}
  .sig-area{margin-top:40px;display:grid;grid-template-columns:1fr 1fr;gap:40px}
  .sig-line{border-top:1px solid #333;margin-top:40px;padding-top:4px;font-size:12px;color:#666}
  .footer{text-align:center;margin-top:40px;color:#999;font-size:11px;border-top:1px solid #eee;padding-top:20px}
</style></head><body>
<div class="header">
  <div class="logo-side"><h1>PRO FINISH</h1><p>Custom Carpentry</p><p>Big Spring, TX</p><p>(432) 466-5310</p><p>profinishcartx@gmail.com</p></div>
  <div class="est-label">ESTIMATE</div>
</div>
<div class="info-grid">
  <div class="info-box"><h3>Customer</h3><p><strong>${job.customer_name || 'Customer'}</strong></p><p>${job.email || ''}</p><p>${job.phone || ''}</p><p>${job.address || ''}</p></div>
  <div class="info-box"><h3>Estimate Details</h3><p><strong>Date:</strong> ${new Date().toLocaleDateString()}</p><p><strong>Estimate #:</strong> ${job_id.slice(0,8).toUpperCase()}</p><p><strong>Service:</strong> ${job.service_type || job.title || ''}</p><p><strong>Valid For:</strong> 30 days</p></div>
</div>
<h3 style="color:#1B4D8E">Scope of Work</h3>
<p>${job.description || 'Custom carpentry services as discussed.'}</p>
<table>
  <thead><tr><th>Item</th><th>Qty</th><th>Unit Price</th><th>Total</th></tr></thead>
  <tbody>${lineItems.length > 0 ? lineItems.map((i: any) => `<tr><td>${i.description}</td><td>${i.quantity || 1}</td><td>$${(i.unit_price || 0).toFixed(2)}</td><td>$${((i.quantity || 1) * (i.unit_price || 0)).toFixed(2)}</td></tr>`).join('') : `<tr><td>${job.title || 'Carpentry Services'}</td><td>1</td><td>$${(job.estimated_cost || 0).toFixed(2)}</td><td>$${(job.estimated_cost || 0).toFixed(2)}</td></tr>`}
  <tr class="total-row"><td colspan="3" style="text-align:right">TOTAL</td><td>$${(total || job.estimated_cost || 0).toFixed(2)}</td></tr>
  </tbody>
</table>
<div class="terms"><h3>Terms & Conditions</h3>
<p>1. This estimate is valid for 30 days from the date above.</p>
<p>2. Payment: 50% deposit upon acceptance, balance due upon completion.</p>
<p>3. Any changes to scope will be documented as a change order with adjusted pricing.</p>
<p>4. Pro Finish Custom Carpentry warrants all workmanship for 1 year from completion.</p>
<p>5. Customer is responsible for clearing work area before scheduled start date.</p></div>
<div class="sig-area">
  <div><div class="sig-line">Customer Signature / Date</div></div>
  <div><div class="sig-line">Adam McLemore, Pro Finish / Date</div></div>
</div>
<div class="footer"><p>Pro Finish Custom Carpentry | Big Spring, TX | (432) 466-5310 | profinishusa.com</p></div>
</body></html>`;

  // Store HTML estimate to R2
  const key = `profinish/estimates/${job_id}.html`;
  await c.env.R2.put(key, html, { httpMetadata: { contentType: 'text/html' } });

  return c.json({ key, html_url: c.env.SITE_URL + '/api/estimate/' + job_id, html });
});

// Serve estimate HTML for printing/PDF
app.get('/estimate/:job_id', async (c) => {
  const key = `profinish/estimates/${c.req.param('job_id')}.html`;
  const obj = await c.env.R2.get(key);
  if (!obj) return c.json({ error: 'Estimate not found' }, 404);
  const html = await obj.text();
  return c.html(html);
});

// ─── Subscriptions / Cost Tracker ────────────────────────
app.get('/subscriptions', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const rows = await c.env.DB.prepare('SELECT * FROM subscriptions ORDER BY monthly_cost DESC').all();
  const subs = rows.results as any[];
  const active = subs.filter(s => s.status === 'active' || s.status === 'planned');
  const totalMonthly = active.reduce((sum: number, s: any) => sum + (s.monthly_cost || 0), 0);
  const totalAnnual = totalMonthly * 12;
  return c.json({
    subscriptions: subs,
    summary: {
      total_monthly: Math.round(totalMonthly * 100) / 100,
      total_annual: Math.round(totalAnnual * 100) / 100,
      active_count: active.length,
      free_count: active.filter((s: any) => s.monthly_cost === 0).length,
      paid_count: active.filter((s: any) => s.monthly_cost > 0).length,
    }
  });
});

app.get('/subscriptions/cost', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const rows = await c.env.DB.prepare("SELECT * FROM subscriptions WHERE status IN ('active', 'planned') ORDER BY monthly_cost DESC").all();
  const subs = rows.results as any[];
  const totalMonthly = subs.reduce((sum: number, s: any) => sum + (s.monthly_cost || 0), 0);
  const byCategory: Record<string, number> = {};
  for (const s of subs) {
    byCategory[s.category] = (byCategory[s.category] || 0) + (s.monthly_cost || 0);
  }
  return c.json({
    total_monthly: Math.round(totalMonthly * 100) / 100,
    total_annual: Math.round(totalMonthly * 12 * 100) / 100,
    total_daily: Math.round(totalMonthly / 30 * 100) / 100,
    by_category: byCategory,
    services: subs.map((s: any) => ({
      name: s.service_name,
      provider: s.provider,
      monthly: s.monthly_cost,
      status: s.status,
      category: s.category,
    })),
    as_of: new Date().toISOString(),
  });
});

app.post('/subscriptions', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = b.id || ('sub_' + uid());
  await c.env.DB.prepare(
    'INSERT OR REPLACE INTO subscriptions (id, service_name, provider, monthly_cost, billing_cycle, status, account_email, start_date, next_billing_date, category, notes, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime("now"))'
  ).bind(id, b.service_name, b.provider, b.monthly_cost || 0, b.billing_cycle || 'monthly', b.status || 'active',
    b.account_email || null, b.start_date || null, b.next_billing_date || null, b.category || 'software', b.notes || null
  ).run();
  return c.json({ id });
});

app.put('/subscriptions/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const fields = ['service_name', 'provider', 'monthly_cost', 'billing_cycle', 'status', 'account_email', 'next_billing_date', 'category', 'notes'].filter(f => b[f] !== undefined);
  if (!fields.length) return c.json({ error: 'No fields' }, 400);
  const sets = fields.map(f => `${f} = ?`).join(', ');
  const vals = fields.map(f => b[f]);
  await c.env.DB.prepare(`UPDATE subscriptions SET ${sets}, updated_at = datetime('now') WHERE id = ?`).bind(...vals, c.req.param('id')).run();
  return c.json({ ok: true });
});

app.delete('/subscriptions/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  await c.env.DB.prepare('DELETE FROM subscriptions WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
});

// ─── Adam AI Chat (Claude Hybrid Proxy primary — FREE) ─────
const BELLE_SYSTEM_PROMPT = `You are Adam AI, the friendly and knowledgeable AI assistant for Pro Finish Custom Carpentry in Big Spring, TX. Owner: Adam McLemore. You help customers:
1. Get free estimates and project advice for all services
2. Schedule visits with Adam
3. Answer questions about services: trim carpentry, cabinet installation, flooring (hardwood, laminate, LVP, tile), framing, decking, remodeling
4. Service area: Big Spring, Midland, Odessa, and the Permian Basin
5. Phone: (432) 466-5310
6. All work is owner-operated — Adam personally does the work
7. Free estimates on all projects
8. Licensed and insured in Texas

Be warm, professional, and knowledgeable about carpentry and construction. Keep responses concise (2-4 sentences unless giving detailed project advice). When customers ask about pricing, explain that every project is unique and offer a free estimate. Suggest scheduling a visit for accurate quotes.

IMPORTANT: You have INFINITE MEMORY. You remember every conversation with every customer. If given previous context, reference it naturally. Remember names, project details, preferences, and quotes discussed. Make returning customers feel recognized.`;

const CLAUDE_PROXY_URL = 'https://claude-proxy.echo-op.com/v1/messages';
const CLAUDE_PROXY_KEY = 'echo-omega-prime-forge-x-2026';

app.post('/belle/chat', async (c) => {
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  if (!checkRateLimit(ip)) return c.json({ error: 'Too many requests' }, 429);
  const body = await c.req.json();

  // Build system prompt + optional brain context
  let systemContent = BELLE_SYSTEM_PROMPT;
  if (body.context) systemContent += maxLen(body.context, 4000);

  // Build messages array (user/assistant only — Claude API takes system separately)
  let messages: Array<{role: string; content: string}> = [];

  // Support both formats: {messages: [...]} and {message: "...", history: [...]}
  if (body.messages && body.messages.length) {
    const nonSystem = body.messages.filter((m: any) => m.role !== 'system').slice(-20);
    messages.push(...nonSystem.map((m: any) => ({ role: m.role, content: maxLen(m.content, 4000) })));
  } else if (body.message) {
    if (body.history && body.history.length) {
      messages.push(...body.history.slice(-20).map((m: any) => ({ role: m.role, content: maxLen(m.content, 4000) })));
    }
    messages.push({ role: 'user', content: maxLen(body.message, 4000) });
  } else {
    return c.json({ error: 'No message provided' }, 400);
  }

  const maxTokens = Math.min(body.max_tokens || 512, 1024);

  // Primary: Claude Hybrid Proxy (Haiku 4.5 — fast, FREE via OAuth)
  try {
    const claudeResp = await fetch(CLAUDE_PROXY_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Echo-API-Key': CLAUDE_PROXY_KEY,
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5',
        system: systemContent,
        messages,
        max_tokens: maxTokens,
      }),
    });
    if (claudeResp.ok) {
      const data: any = await claudeResp.json();
      const reply = data.content?.[0]?.text || '';
      return c.json({ reply, provider: 'claude', model: 'claude-haiku-4-5' });
    }
    const errText = await claudeResp.text();
    return c.json({ error: 'LLM error', status: claudeResp.status, detail: errText }, 502);
  } catch (e: any) {
    return c.json({ error: 'Chat failed', detail: e.message }, 500);
  }
});

// ─── Adam AI Vision (photo analysis — Claude Hybrid Proxy) ─
app.post('/belle/vision', async (c) => {
  const body = await c.req.json();
  const imageUrl = body.image_url;
  const imageBase64 = body.image_base64;
  const prompt = maxLen(body.prompt || 'Analyze this room photo for a carpentry contractor. Identify: current condition, what work is needed, estimated scope. Be specific about materials and labor.', 2000);

  if (!imageUrl && !imageBase64) return c.json({ error: 'image_url or image_base64 required' }, 400);

  // Claude vision uses content blocks with image source
  const imageSource = imageBase64
    ? { type: 'base64' as const, media_type: 'image/jpeg' as const, data: imageBase64 }
    : { type: 'url' as const, url: imageUrl };

  const userContent = [
    { type: 'image', source: imageSource },
    { type: 'text', text: prompt },
  ];

  try {
    const resp = await fetch(CLAUDE_PROXY_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Echo-API-Key': CLAUDE_PROXY_KEY,
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5',
        messages: [{ role: 'user', content: userContent }],
        max_tokens: 512,
      }),
    });
    if (!resp.ok) {
      const errText = await resp.text();
      return c.json({ error: 'Vision error', status: resp.status, detail: errText }, 502);
    }
    const data: any = await resp.json();
    const reply = data.content?.[0]?.text || '';
    return c.json({ reply, provider: 'claude', model: 'claude-haiku-4-5' });
  } catch (e: any) {
    return c.json({ error: 'Vision failed', detail: e.message }, 500);
  }
});

// ─── Adam AI aliases (renamed from Belle) ─────────────────
app.post('/adam/chat', async (c) => {
  // Forward to /belle/chat handler
  const url = new URL(c.req.url);
  url.pathname = '/belle/chat';
  return app.fetch(new Request(url.toString(), { method: 'POST', headers: c.req.raw.headers, body: c.req.raw.body }), c.env, c.executionCtx);
});
app.post('/adam/vision', async (c) => {
  const url = new URL(c.req.url);
  url.pathname = '/belle/vision';
  return app.fetch(new Request(url.toString(), { method: 'POST', headers: c.req.raw.headers, body: c.req.raw.body }), c.env, c.executionCtx);
});

// ═══════════════════════════════════════════════════════════
// ─── DOCUMENT DELIVERY (proxied via service binding)
// Universal Worker: echo-document-delivery (service binding: DOC_DELIVERY)
// ═══════════════════════════════════════════════════════════

const DOC_DELIVERY_BASE = 'https://echo-document-delivery.bmcii1976.workers.dev';

function docFetch(env: Env, path: string, init?: RequestInit): Promise<Response> {
  return env.DOC_DELIVERY.fetch(new Request('https://doc/' + path.replace(/^\//, ''), {
    ...init,
    headers: { 'Content-Type': 'application/json', 'X-Tenant-Key': env.DOC_TENANT_KEY || '', ...(init?.headers || {}) },
  }));
}

// ─── Generate: loads local data, forwards to universal Worker ────
app.post('/documents/generate', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();

  const docType = (b.type || 'INVOICE').toUpperCase();
  const sourceId = b.source_id || b.invoice_id || b.job_id;
  if (!sourceId) return c.json({ error: 'source_id required' }, 400);

  let payload: any;

  if (docType === 'INVOICE' || docType === 'RECEIPT' || docType === 'STATEMENT') {
    const inv = await c.env.DB.prepare(
      'SELECT i.*, c.name as customer_name, c.email as customer_email, c.phone as customer_phone, c.address as customer_address, c.city as customer_city FROM invoices i LEFT JOIN customers c ON i.customer_id = c.id WHERE i.id = ?'
    ).bind(sourceId).first() as any;
    if (!inv) return c.json({ error: 'Invoice not found' }, 404);
    const items = await c.env.DB.prepare('SELECT * FROM invoice_items WHERE invoice_id = ? ORDER BY rowid').bind(sourceId).all();

    payload = {
      doc_type: docType,
      doc_number: inv.invoice_number || sourceId.slice(0, 8).toUpperCase(),
      date: inv.issue_date || new Date().toISOString().split('T')[0],
      due_date: inv.due_date,
      customer_name: inv.customer_name || 'Customer',
      customer_email: inv.customer_email || '',
      customer_phone: inv.customer_phone || '',
      customer_address: [inv.customer_address, inv.customer_city].filter(Boolean).join(', '),
      items: (items.results as any[]).map((it: any) => ({
        description: it.description, qty: it.quantity || 1, rate: it.unit_price || 0, amount: it.total || 0,
      })),
      subtotal: inv.subtotal || 0,
      tax_rate: inv.tax_rate || 0,
      tax_amount: inv.tax_amount || 0,
      total: inv.total || 0,
      amount_paid: docType === 'RECEIPT' ? inv.total : (inv.amount_paid || 0),
      notes: inv.notes || '',
      payment_terms: inv.payment_terms === 'net_30' ? 'Net 30 — Payment due within 30 days of invoice date.' :
                     inv.payment_terms === 'net_15' ? 'Net 15 — Payment due within 15 days.' :
                     inv.payment_terms === 'due_on_receipt' ? 'Due on receipt.' : '',
      source_id: sourceId,
    };
  } else {
    const job = await c.env.DB.prepare(
      'SELECT j.*, c.name as customer_name, c.email as customer_email, c.phone as customer_phone, c.address as customer_address, c.city as customer_city FROM jobs j LEFT JOIN customers c ON j.customer_id = c.id WHERE j.id = ?'
    ).bind(sourceId).first() as any;
    if (!job) return c.json({ error: 'Job not found' }, 404);

    const estTotal = parseFloat(job.estimated_cost_high || job.estimated_cost_low || job.actual_cost) || 0;
    const now = new Date();
    const docNum = `PF-${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}`;

    payload = {
      doc_type: docType,
      doc_number: docNum,
      date: now.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }),
      service_date: job.scheduled_date || 'TBD',
      customer_name: job.customer_name || 'Customer',
      customer_email: job.customer_email || '',
      customer_phone: job.customer_phone || '',
      customer_address: [job.customer_address || job.address, job.customer_city || job.city].filter(Boolean).join(', '),
      job_title: job.title || '',
      service_type: job.service_type || '',
      items: [{ description: (job.service_type || 'Service') + ' — ' + (job.title || 'Project'), qty: 1, rate: estTotal, amount: estTotal }],
      subtotal: estTotal,
      total: estTotal,
      source_id: sourceId,
    };
  }

  // Forward to universal document delivery Worker via service binding
  const resp = await docFetch(c.env, '/documents/generate', {
    method: 'POST', body: JSON.stringify(payload),
  });
  return c.json(await resp.json(), resp.status as any);
});

// ─── Proxy: document view, list, detail, email, SMS, settings ────
app.get('/documents/view/:token', async (c) => {
  return c.redirect(DOC_DELIVERY_BASE + '/view/' + c.req.param('token'), 302);
});

app.get('/documents', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const url = new URL(c.req.url);
  const resp = await docFetch(c.env, '/documents' + url.search);
  return c.json(await resp.json(), resp.status as any);
});

app.get('/documents/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const resp = await docFetch(c.env, '/documents/' + c.req.param('id'));
  return c.json(await resp.json(), resp.status as any);
});

app.post('/documents/deliver/email', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const resp = await docFetch(c.env, '/deliver/email', {
    method: 'POST', body: JSON.stringify(await c.req.json()),
  });
  return c.json(await resp.json(), resp.status as any);
});

app.post('/documents/deliver/sms', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const resp = await docFetch(c.env, '/deliver/sms', {
    method: 'POST', body: JSON.stringify(await c.req.json()),
  });
  return c.json(await resp.json(), resp.status as any);
});

app.post('/documents/deliver/email-pdf', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const resp = await docFetch(c.env, '/deliver/email-pdf', {
    method: 'POST', body: JSON.stringify(await c.req.json()),
  });
  return c.json(await resp.json(), resp.status as any);
});

app.get('/documents/settings', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const resp = await docFetch(c.env, '/settings');
  return c.json(await resp.json(), resp.status as any);
});

app.put('/documents/settings', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const resp = await docFetch(c.env, '/settings', {
    method: 'PUT', body: JSON.stringify(await c.req.json()),
  });
  return c.json(await resp.json(), resp.status as any);
});

// ═══ Change Orders ═══════════════════════════════════════
app.get('/change-orders', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const jobId = c.req.query('job_id');
  const sql = jobId
    ? 'SELECT co.*, j.title as job_title FROM change_orders co LEFT JOIN jobs j ON co.job_id = j.id WHERE co.job_id = ? ORDER BY co.created_at DESC'
    : 'SELECT co.*, j.title as job_title FROM change_orders co LEFT JOIN jobs j ON co.job_id = j.id ORDER BY co.created_at DESC';
  const rows = jobId ? await c.env.DB.prepare(sql).bind(jobId).all() : await c.env.DB.prepare(sql).all();
  return c.json(rows.results);
});

app.post('/change-orders', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = uid();
  await c.env.DB.prepare(
    'INSERT INTO change_orders (id, job_id, title, description, reason, cost_impact, time_impact_days, requested_by) VALUES (?,?,?,?,?,?,?,?)'
  ).bind(id, b.job_id, sanitize(b.title), sanitize(b.description || ''), sanitize(b.reason || ''), b.cost_impact || 0, b.time_impact_days || 0, sanitize(b.requested_by || 'Adam')).run();
  return c.json({ ok: true, id }, 201);
});

app.put('/change-orders/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const { id } = c.req.param();
  const b = await c.req.json();
  const sets: string[] = [];
  const vals: any[] = [];
  if (b.status !== undefined) { sets.push('status = ?'); vals.push(b.status); }
  if (b.approved_by !== undefined) { sets.push('approved_by = ?'); vals.push(sanitize(b.approved_by)); }
  if (b.status === 'approved') { sets.push("approved_at = datetime('now')"); }
  if (b.cost_impact !== undefined) { sets.push('cost_impact = ?'); vals.push(b.cost_impact); }
  if (b.description !== undefined) { sets.push('description = ?'); vals.push(sanitize(b.description)); }
  sets.push("updated_at = datetime('now')");
  vals.push(id);
  await c.env.DB.prepare(`UPDATE change_orders SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
  // If approved, update the job's estimated cost
  if (b.status === 'approved') {
    const co = await c.env.DB.prepare('SELECT job_id, cost_impact FROM change_orders WHERE id = ?').bind(id).first() as any;
    if (co?.job_id && co.cost_impact) {
      await c.env.DB.prepare('UPDATE jobs SET estimated_cost_high = COALESCE(estimated_cost_high, 0) + ?, updated_at = datetime("now") WHERE id = ?').bind(co.cost_impact, co.job_id).run();
    }
  }
  return c.json({ ok: true });
});

// ═══ Materials Inventory ═════════════════════════════════
app.get('/materials', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const cat = c.req.query('category');
  const low = c.req.query('low_stock');
  let sql = 'SELECT * FROM materials';
  const conditions: string[] = [];
  const vals: any[] = [];
  if (cat) { conditions.push('category = ?'); vals.push(cat); }
  if (low === '1') { conditions.push('quantity_on_hand <= reorder_level'); }
  if (conditions.length) sql += ' WHERE ' + conditions.join(' AND ');
  sql += ' ORDER BY name';
  const rows = await c.env.DB.prepare(sql).bind(...vals).all();
  return c.json(rows.results);
});

app.post('/materials', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = uid();
  await c.env.DB.prepare(
    'INSERT INTO materials (id, name, category, unit, unit_cost, quantity_on_hand, reorder_level, preferred_vendor, sku, notes) VALUES (?,?,?,?,?,?,?,?,?,?)'
  ).bind(id, sanitize(b.name), b.category || 'wood', b.unit || 'board_ft', b.unit_cost || 0, b.quantity_on_hand || 0, b.reorder_level || 0, sanitize(b.preferred_vendor || ''), sanitize(b.sku || ''), sanitize(b.notes || '')).run();
  return c.json({ ok: true, id }, 201);
});

app.put('/materials/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const { id } = c.req.param();
  const b = await c.req.json();
  const sets: string[] = [];
  const vals: any[] = [];
  for (const k of ['name', 'category', 'unit', 'preferred_vendor', 'sku', 'notes']) {
    if (b[k] !== undefined) { sets.push(`${k} = ?`); vals.push(sanitize(b[k])); }
  }
  for (const k of ['unit_cost', 'quantity_on_hand', 'reorder_level']) {
    if (b[k] !== undefined) { sets.push(`${k} = ?`); vals.push(b[k]); }
  }
  sets.push("updated_at = datetime('now')");
  vals.push(id);
  await c.env.DB.prepare(`UPDATE materials SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
  return c.json({ ok: true });
});

// Material usage tracking
app.get('/material-usage', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const jobId = c.req.query('job_id');
  const sql = jobId
    ? 'SELECT mu.*, m.name as material_name, m.unit, m.category FROM material_usage mu JOIN materials m ON mu.material_id = m.id WHERE mu.job_id = ? ORDER BY mu.used_date DESC'
    : 'SELECT mu.*, m.name as material_name, m.unit, m.category FROM material_usage mu JOIN materials m ON mu.material_id = m.id ORDER BY mu.used_date DESC LIMIT 100';
  const rows = jobId ? await c.env.DB.prepare(sql).bind(jobId).all() : await c.env.DB.prepare(sql).all();
  return c.json(rows.results);
});

app.post('/material-usage', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = uid();
  // Get current unit cost
  const mat = await c.env.DB.prepare('SELECT unit_cost, quantity_on_hand FROM materials WHERE id = ?').bind(b.material_id).first() as any;
  const costAtTime = mat?.unit_cost || 0;
  await c.env.DB.prepare(
    'INSERT INTO material_usage (id, job_id, material_id, quantity_used, cost_at_time, notes) VALUES (?,?,?,?,?,?)'
  ).bind(id, b.job_id, b.material_id, b.quantity_used, costAtTime, sanitize(b.notes || '')).run();
  // Deduct from inventory
  if (mat) {
    await c.env.DB.prepare('UPDATE materials SET quantity_on_hand = MAX(0, quantity_on_hand - ?), updated_at = datetime("now") WHERE id = ?').bind(b.quantity_used, b.material_id).run();
  }
  return c.json({ ok: true, id, cost: costAtTime * b.quantity_used }, 201);
});

// ═══ Warranties ═══════════════════════════════════════════
app.get('/warranties', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const jobId = c.req.query('job_id');
  const status = c.req.query('status');
  let sql = 'SELECT w.*, j.title as job_title, cu.name as customer_name FROM warranties w LEFT JOIN jobs j ON w.job_id = j.id LEFT JOIN customers cu ON w.customer_id = cu.id';
  const conditions: string[] = [];
  const vals: any[] = [];
  if (jobId) { conditions.push('w.job_id = ?'); vals.push(jobId); }
  if (status) { conditions.push('w.status = ?'); vals.push(status); }
  if (conditions.length) sql += ' WHERE ' + conditions.join(' AND ');
  sql += ' ORDER BY w.end_date ASC';
  const rows = await c.env.DB.prepare(sql).bind(...vals).all();
  return c.json(rows.results);
});

app.post('/warranties', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = uid();
  const startDate = b.start_date || new Date().toISOString().split('T')[0];
  const months = b.duration_months || 12;
  const endDate = new Date(new Date(startDate).getTime() + months * 30.44 * 86400000).toISOString().split('T')[0];
  await c.env.DB.prepare(
    'INSERT INTO warranties (id, job_id, customer_id, type, duration_months, start_date, end_date, terms, status) VALUES (?,?,?,?,?,?,?,?,?)'
  ).bind(id, b.job_id, b.customer_id, b.type || 'workmanship', months, startDate, endDate, sanitize(b.terms || '1-year warranty on all workmanship'), 'active').run();
  return c.json({ ok: true, id, end_date: endDate }, 201);
});

// Warranty claims (public — customers can submit)
app.get('/warranty-claims', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const warrantyId = c.req.query('warranty_id');
  const sql = warrantyId
    ? 'SELECT wc.*, w.type as warranty_type, w.job_id FROM warranty_claims wc JOIN warranties w ON wc.warranty_id = w.id WHERE wc.warranty_id = ? ORDER BY wc.created_at DESC'
    : 'SELECT wc.*, w.type as warranty_type, w.job_id FROM warranty_claims wc JOIN warranties w ON wc.warranty_id = w.id ORDER BY wc.created_at DESC';
  const rows = warrantyId ? await c.env.DB.prepare(sql).bind(warrantyId).all() : await c.env.DB.prepare(sql).all();
  return c.json(rows.results);
});

app.post('/warranty-claims', async (c) => {
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  if (!checkRateLimit(ip)) return c.json({ error: 'Too many requests' }, 429);
  const b = await c.req.json();
  const id = uid();
  // Verify warranty is active
  const warranty = await c.env.DB.prepare('SELECT * FROM warranties WHERE id = ? AND status = "active"').bind(b.warranty_id).first();
  if (!warranty) return c.json({ error: 'Warranty not found or expired' }, 404);
  await c.env.DB.prepare(
    'INSERT INTO warranty_claims (id, warranty_id, description, photo_urls) VALUES (?,?,?,?)'
  ).bind(id, b.warranty_id, sanitize(maxLen(b.description, 2000)), maxLen(b.photo_urls || '', 2000)).run();
  return c.json({ ok: true, id }, 201);
});

app.put('/warranty-claims/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const { id } = c.req.param();
  const b = await c.req.json();
  const sets: string[] = [];
  const vals: any[] = [];
  if (b.status !== undefined) { sets.push('status = ?'); vals.push(b.status); }
  if (b.resolution !== undefined) { sets.push('resolution = ?'); vals.push(sanitize(b.resolution)); }
  if (b.status === 'resolved') { sets.push("resolved_at = datetime('now')"); }
  vals.push(id);
  await c.env.DB.prepare(`UPDATE warranty_claims SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
  return c.json({ ok: true });
});

// ═══ Portfolio Gallery ════════════════════════════════════
// Public — no auth needed for viewing
app.get('/portfolio', async (c) => {
  const cat = c.req.query('category');
  const featured = c.req.query('featured');
  let sql = 'SELECT p.*, j.title as job_title, j.service_type FROM portfolio p LEFT JOIN jobs j ON p.job_id = j.id WHERE p.published = 1';
  const vals: any[] = [];
  if (cat) { sql += ' AND p.category = ?'; vals.push(cat); }
  if (featured === '1') { sql += ' AND p.featured = 1'; }
  sql += ' ORDER BY p.display_order, p.created_at DESC';
  const rows = await c.env.DB.prepare(sql).bind(...vals).all();
  return c.json(rows.results);
});

app.post('/portfolio', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = uid();
  await c.env.DB.prepare(
    'INSERT INTO portfolio (id, job_id, title, description, category, before_photo_url, after_photo_url, additional_photos, featured, display_order, published) VALUES (?,?,?,?,?,?,?,?,?,?,?)'
  ).bind(id, b.job_id || null, sanitize(b.title), sanitize(b.description || ''), b.category || 'custom_carpentry', b.before_photo_url || '', b.after_photo_url || '', b.additional_photos || '', b.featured ? 1 : 0, b.display_order || 0, b.published ? 1 : 0).run();
  return c.json({ ok: true, id }, 201);
});

app.put('/portfolio/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const { id } = c.req.param();
  const b = await c.req.json();
  const sets: string[] = [];
  const vals: any[] = [];
  for (const k of ['title', 'description', 'category', 'before_photo_url', 'after_photo_url', 'additional_photos']) {
    if (b[k] !== undefined) { sets.push(`${k} = ?`); vals.push(k === 'title' || k === 'description' ? sanitize(b[k]) : b[k]); }
  }
  for (const k of ['featured', 'published', 'display_order']) {
    if (b[k] !== undefined) { sets.push(`${k} = ?`); vals.push(typeof b[k] === 'boolean' ? (b[k] ? 1 : 0) : b[k]); }
  }
  vals.push(id);
  await c.env.DB.prepare(`UPDATE portfolio SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
  return c.json({ ok: true });
});

app.delete('/portfolio/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const { id } = c.req.param();
  await c.env.DB.prepare('DELETE FROM portfolio WHERE id = ?').bind(id).run();
  return c.json({ ok: true });
});

// ═══ QC Checklists ════════════════════════════════════════
app.get('/qc', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const rows = await c.env.DB.prepare('SELECT q.*, j.title as job_title FROM qc_checklists q LEFT JOIN jobs j ON q.job_id = j.id ORDER BY q.created_at DESC LIMIT 100').all();
  return c.json(rows.results);
});

app.get('/qc/:job_id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const { job_id } = c.req.param();
  const rows = await c.env.DB.prepare('SELECT * FROM qc_checklists WHERE job_id = ? ORDER BY created_at DESC').bind(job_id).all();
  return c.json(rows.results);
});

app.post('/qc', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = uid();
  await c.env.DB.prepare(
    'INSERT INTO qc_checklists (id, job_id, type, items, completed_by, notes) VALUES (?,?,?,?,?,?)'
  ).bind(id, b.job_id, b.type || 'final_walkthrough', JSON.stringify(b.items || []), sanitize(b.completed_by || 'Adam'), sanitize(b.notes || '')).run();
  return c.json({ ok: true, id }, 201);
});

app.put('/qc/:id/sign', async (c) => {
  // Customer signature — validate signature_name required + non-empty signature data
  const { id } = c.req.param();
  const b = await c.req.json();
  if (!b.signature_url || typeof b.signature_url !== 'string' || b.signature_url.length < 10) {
    return c.json({ error: 'signature_url is required' }, 400);
  }
  if (!b.customer_name || typeof b.customer_name !== 'string' || b.customer_name.trim().length < 2) {
    return c.json({ error: 'customer_name is required (min 2 characters)' }, 400);
  }
  // Verify QC record exists before updating
  const qc = await c.env.DB.prepare('SELECT id, customer_signed FROM qc_checklists WHERE id = ?').bind(id).first();
  if (!qc) return c.json({ error: 'QC checklist not found' }, 404);
  if ((qc as any).customer_signed === 1) return c.json({ error: 'Already signed' }, 409);
  await c.env.DB.prepare(
    "UPDATE qc_checklists SET customer_signed = 1, customer_signature_url = ?, completed_at = datetime('now') WHERE id = ?"
  ).bind(sanitize(b.signature_url), id).run();
  return c.json({ ok: true });
});

// ═══ Enhanced Job Status Workflow ═════════════════════════
app.put('/jobs/:id/advance', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const { id } = c.req.param();
  const job = await c.env.DB.prepare('SELECT status FROM jobs WHERE id = ?').bind(id).first() as any;
  if (!job) return c.json({ error: 'Job not found' }, 404);
  const workflow: Record<string, string> = {
    estimate: 'quote_sent',
    quote_sent: 'approved',
    approved: 'scheduled',
    scheduled: 'in_progress',
    in_progress: 'inspection',
    inspection: 'final_payment',
    final_payment: 'completed'
  };
  const next = workflow[job.status];
  if (!next) return c.json({ error: `Cannot advance from status: ${job.status}` }, 400);
  const sets: string[] = ['status = ?', "updated_at = datetime('now')"];
  const vals: any[] = [next];
  if (next === 'in_progress') sets.push("start_date = COALESCE(start_date, date('now'))");
  if (next === 'completed') sets.push("completion_date = date('now')");
  vals.push(id);
  await c.env.DB.prepare(`UPDATE jobs SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
  return c.json({ ok: true, previous: job.status, current: next });
});

// ═══ Dashboard Enhancement ═══════════════════════════════
app.get('/dashboard/materials', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const lowStock = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM materials WHERE quantity_on_hand <= reorder_level').first() as any;
  const totalValue = await c.env.DB.prepare('SELECT SUM(quantity_on_hand * unit_cost) as total FROM materials').first() as any;
  const categories = await c.env.DB.prepare('SELECT category, COUNT(*) as cnt, SUM(quantity_on_hand * unit_cost) as value FROM materials GROUP BY category').all();
  return c.json({
    low_stock_count: lowStock?.cnt || 0,
    total_inventory_value: totalValue?.total || 0,
    by_category: categories.results
  });
});

app.get('/dashboard/warranties', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const active = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM warranties WHERE status = "active"').first() as any;
  const expiringSoon = await c.env.DB.prepare("SELECT COUNT(*) as cnt FROM warranties WHERE status = 'active' AND end_date <= date('now', '+30 days')").first() as any;
  const openClaims = await c.env.DB.prepare("SELECT COUNT(*) as cnt FROM warranty_claims WHERE status IN ('submitted', 'in_progress')").first() as any;
  return c.json({
    active_warranties: active?.cnt || 0,
    expiring_30_days: expiringSoon?.cnt || 0,
    open_claims: openClaims?.cnt || 0
  });
});

// ═══ Business Overview Stats ═════════════════════════════
app.get('/dashboard/overview', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const [customers, jobs, activeJobs, revenue, appointments, reviews, pendingInvoices, expenses] = await Promise.all([
    c.env.DB.prepare('SELECT COUNT(*) as cnt FROM customers').first() as Promise<any>,
    c.env.DB.prepare('SELECT COUNT(*) as cnt FROM jobs').first() as Promise<any>,
    c.env.DB.prepare("SELECT COUNT(*) as cnt FROM jobs WHERE status IN ('in_progress','scheduled','approved')").first() as Promise<any>,
    c.env.DB.prepare("SELECT COALESCE(SUM(amount),0) as total FROM payments WHERE status = 'completed'").first() as Promise<any>,
    c.env.DB.prepare("SELECT COUNT(*) as cnt FROM appointments WHERE date >= date('now') AND status = 'scheduled'").first() as Promise<any>,
    c.env.DB.prepare('SELECT COUNT(*) as cnt, COALESCE(AVG(rating),0) as avg FROM reviews WHERE approved = 1').first() as Promise<any>,
    c.env.DB.prepare("SELECT COUNT(*) as cnt, COALESCE(SUM(total),0) as total FROM invoices WHERE status IN ('sent','viewed','partial')").first() as Promise<any>,
    c.env.DB.prepare("SELECT COALESCE(SUM(amount),0) as total FROM expenses WHERE date >= date('now','start of month')").first() as Promise<any>,
  ]);
  return c.json({
    total_customers: customers?.cnt || 0,
    total_jobs: jobs?.cnt || 0,
    active_jobs: activeJobs?.cnt || 0,
    total_revenue: revenue?.total || 0,
    upcoming_appointments: appointments?.cnt || 0,
    review_count: reviews?.cnt || 0,
    avg_rating: Math.round((reviews?.avg || 0) * 10) / 10,
    outstanding_invoices: { count: pendingInvoices?.cnt || 0, total: pendingInvoices?.total || 0 },
    monthly_expenses: expenses?.total || 0,
  });
});

// ═══ Recent Activity Feed ════════════════════════════════
app.get('/dashboard/activity', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const limit = Math.min(Number(c.req.query('limit')) || 20, 50);
  // Union recent events from multiple tables
  const sql = `
    SELECT 'job' as type, id, title as label, status, created_at FROM jobs
    UNION ALL
    SELECT 'appointment' as type, id, title as label, status, created_at FROM appointments
    UNION ALL
    SELECT 'payment' as type, id, 'Payment $' || amount as label, status, created_at FROM payments
    UNION ALL
    SELECT 'review' as type, id, 'Review by ' || customer_name as label, CAST(rating as TEXT), created_at FROM reviews
    ORDER BY created_at DESC LIMIT ?
  `;
  const rows = await c.env.DB.prepare(sql).bind(limit).all();
  return c.json(rows.results);
});

// ═══ Revenue Analytics ══════════════════════════════════
app.get('/dashboard/revenue', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const months = Math.min(Number(c.req.query('months')) || 12, 24);

  // Monthly revenue for last N months
  const monthly = await c.env.DB.prepare(`
    SELECT strftime('%Y-%m', created_at) as month,
           COALESCE(SUM(amount), 0) as revenue,
           COUNT(*) as payment_count
    FROM payments WHERE status = 'completed'
      AND created_at >= date('now', '-' || ? || ' months')
    GROUP BY month ORDER BY month
  `).bind(months).all();

  // This month vs last month
  const [thisMonth, lastMonth] = await Promise.all([
    c.env.DB.prepare("SELECT COALESCE(SUM(amount),0) as total FROM payments WHERE status='completed' AND created_at >= date('now','start of month')").first() as Promise<any>,
    c.env.DB.prepare("SELECT COALESCE(SUM(amount),0) as total FROM payments WHERE status='completed' AND created_at >= date('now','start of month','-1 month') AND created_at < date('now','start of month')").first() as Promise<any>,
  ]);

  // Top services by revenue (from jobs)
  const topServices = await c.env.DB.prepare(`
    SELECT j.category, COUNT(*) as job_count,
           COALESCE(SUM(p.amount), 0) as revenue
    FROM jobs j LEFT JOIN payments p ON p.job_id = j.id AND p.status = 'completed'
    WHERE j.category IS NOT NULL
    GROUP BY j.category ORDER BY revenue DESC LIMIT 8
  `).all();

  return c.json({
    monthly: monthly.results,
    this_month: thisMonth?.total || 0,
    last_month: lastMonth?.total || 0,
    growth_pct: lastMonth?.total > 0 ? Math.round(((thisMonth?.total - lastMonth?.total) / lastMonth?.total) * 100) : null,
    top_services: topServices.results,
  });
});

// ═══ Customer Search ════════════════════════════════════
app.get('/customers/search', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const q = (c.req.query('q') || '').trim();
  if (q.length < 2) return c.json({ error: 'Search query must be at least 2 characters' }, 400);
  const pattern = `%${q}%`;
  const rows = await c.env.DB.prepare(
    `SELECT id, name, email, phone, city, created_at FROM customers
     WHERE name LIKE ? OR email LIKE ? OR phone LIKE ? OR address LIKE ?
     ORDER BY name LIMIT 25`
  ).bind(pattern, pattern, pattern, pattern).all();
  return c.json(rows.results);
});

// ═══ Job Pipeline Stats ═════════════════════════════════
app.get('/dashboard/pipeline', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;

  const [pipeline, avgDuration, recentCompleted] = await Promise.all([
    // Jobs grouped by status
    c.env.DB.prepare(`
      SELECT status, COUNT(*) as count,
             COALESCE(SUM(estimated_cost), 0) as total_value
      FROM jobs GROUP BY status
    `).all(),
    // Average job duration (completed jobs only)
    c.env.DB.prepare(`
      SELECT AVG(julianday(updated_at) - julianday(created_at)) as avg_days
      FROM jobs WHERE status = 'completed'
    `).first() as Promise<any>,
    // Last 5 completed jobs
    c.env.DB.prepare(`
      SELECT id, title, category, estimated_cost, created_at, updated_at
      FROM jobs WHERE status = 'completed'
      ORDER BY updated_at DESC LIMIT 5
    `).all(),
  ]);

  return c.json({
    pipeline: pipeline.results,
    avg_completion_days: avgDuration?.avg_days ? Math.round(avgDuration.avg_days) : null,
    recent_completed: recentCompleted.results,
  });
});

// ═══ Upcoming Schedule ══════════════════════════════════
app.get('/dashboard/schedule', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const days = Math.min(Number(c.req.query('days')) || 14, 60);

  const [appointments, scheduledJobs] = await Promise.all([
    c.env.DB.prepare(`
      SELECT id, title, date, time, customer_name, status, notes
      FROM appointments
      WHERE date >= date('now') AND date <= date('now', '+' || ? || ' days')
        AND status = 'scheduled'
      ORDER BY date, time LIMIT 50
    `).bind(days).all(),
    c.env.DB.prepare(`
      SELECT id, title, category, customer_id, status, start_date, estimated_cost
      FROM jobs
      WHERE status IN ('scheduled', 'approved')
        AND start_date IS NOT NULL
        AND start_date >= date('now')
        AND start_date <= date('now', '+' || ? || ' days')
      ORDER BY start_date LIMIT 50
    `).bind(days).all(),
  ]);

  return c.json({
    appointments: appointments.results,
    scheduled_jobs: scheduledJobs.results,
    total_upcoming: (appointments.results?.length || 0) + (scheduledJobs.results?.length || 0),
  });
});


// ═══ Public Booking (customer self-scheduling) ═══════════
// Available time slots for next N days
app.get('/booking/slots', async (c) => {
  const days = Math.min(Number(c.req.query('days')) || 14, 30);
  // Get business settings
  const settingsRows = await c.env.DB.prepare("SELECT key, value FROM settings WHERE key IN ('booking_enabled', 'booking_advance_days', 'booking_slots_per_day', 'business_hours')").all();
  const cfg: Record<string, string> = {};
  for (const r of settingsRows.results as any[]) cfg[r.key] = r.value;
  if (cfg.booking_enabled === '0') return c.json({ error: 'Online booking is currently disabled' }, 503);

  const maxAdvance = Number(cfg.booking_advance_days) || 30;
  const slotsPerDay = Number(cfg.booking_slots_per_day) || 3;
  const effectiveDays = Math.min(days, maxAdvance);

  // Get already-booked appointment dates in range
  const booked = await c.env.DB.prepare(
    "SELECT date, COUNT(*) as cnt FROM appointments WHERE date >= date('now') AND date <= date('now', '+' || ? || ' days') AND status != 'cancelled' GROUP BY date"
  ).bind(effectiveDays).all();
  const bookedMap: Record<string, number> = {};
  for (const r of booked.results as any[]) bookedMap[r.date] = r.cnt;

  // Generate available slots (skip weekends)
  const slots: Array<{ date: string; day: string; available: number }> = [];
  const today = new Date();
  for (let i = 1; i <= effectiveDays; i++) {
    const d = new Date(today);
    d.setDate(d.getDate() + i);
    const dow = d.getDay();
    if (dow === 0 || dow === 6) continue; // skip weekends
    const dateStr = d.toISOString().split('T')[0];
    const used = bookedMap[dateStr] || 0;
    const avail = Math.max(0, slotsPerDay - used);
    if (avail > 0) {
      slots.push({ date: dateStr, day: d.toLocaleDateString('en-US', { weekday: 'long', month: 'short', day: 'numeric' }), available: avail });
    }
  }
  return c.json({ slots, service_area: 'Big Spring, Midland, Odessa & the Permian Basin' });
});

// Public booking request (rate-limited, no auth)
app.post('/booking/request', async (c) => {
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  if (!checkRateLimit(ip)) return c.json({ error: 'Too many requests' }, 429);
  const b = await c.req.json();

  // Validation
  if (!b.name || typeof b.name !== 'string' || b.name.trim().length < 2) return c.json({ error: 'name required (min 2 chars)' }, 400);
  if (!b.phone || typeof b.phone !== 'string' || b.phone.replace(/\D/g, '').length < 7) return c.json({ error: 'valid phone required' }, 400);
  if (!b.date || !/^\d{4}-\d{2}-\d{2}$/.test(b.date)) return c.json({ error: 'date required (YYYY-MM-DD)' }, 400);
  if (!b.service_type || typeof b.service_type !== 'string') return c.json({ error: 'service_type required' }, 400);

  // Validate date is not in the past
  const reqDate = new Date(b.date + 'T12:00:00');
  if (reqDate < new Date()) return c.json({ error: 'Cannot book in the past' }, 400);

  // Check slot availability
  const existing = await c.env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM appointments WHERE date = ? AND status != 'cancelled'"
  ).bind(b.date).first() as any;
  const slotsPerDay = 3; // default
  if ((existing?.cnt || 0) >= slotsPerDay) return c.json({ error: 'No availability on this date, please try another day' }, 409);

  // Find or create customer
  let customerId = null;
  if (b.email) {
    const existingCust = await c.env.DB.prepare('SELECT id FROM customers WHERE email = ? OR phone = ?').bind(b.email, b.phone).first() as any;
    customerId = existingCust?.id;
  }
  if (!customerId && b.phone) {
    const existingCust = await c.env.DB.prepare('SELECT id FROM customers WHERE phone = ?').bind(b.phone).first() as any;
    customerId = existingCust?.id;
  }
  if (!customerId) {
    customerId = uid();
    const refCode = 'PF' + customerId.slice(0, 6).toUpperCase();
    await c.env.DB.prepare(
      'INSERT INTO customers (id, name, email, phone, referral_code, preferred_language) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(customerId, sanitize(maxLen(b.name, 200)), sanitize(maxLen(b.email || '', 254)), sanitize(maxLen(b.phone, 30)), refCode, 'en').run();
  }

  // Update customer address if provided
  if (b.address && customerId) {
    await c.env.DB.prepare("UPDATE customers SET address = ? WHERE id = ? AND (address IS NULL OR address = '')").bind(sanitize(maxLen(b.address, 500)), customerId).run();
  }

  // Create appointment
  const apptId = uid();
  const desc = [b.description || '', b.address ? 'Address: ' + b.address : ''].filter(Boolean).join('\n');
  await c.env.DB.prepare(
    'INSERT INTO appointments (id, customer_id, title, description, service_type, date, status) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(apptId, customerId, sanitize(maxLen(b.service_type + ' — ' + b.name, 200)), sanitize(maxLen(desc, 1000)), sanitize(maxLen(b.service_type, 100)), b.date, 'pending').run();

  // Notify Adam via SMS if Twilio is configured
  if (c.env.TWILIO_ACCOUNT_SID && c.env.TWILIO_AUTH_TOKEN && c.env.TWILIO_PHONE_NUMBER) {
    try {
      const msg = `New booking request!\n${b.name} - ${b.phone}\nService: ${b.service_type}\nDate: ${b.date}\n${b.address ? 'Address: ' + b.address + '\n' : ''}${b.description || ''}`;
      const params = new URLSearchParams({ To: c.env.ADAM_PHONE, From: c.env.TWILIO_PHONE_NUMBER, Body: msg.slice(0, 1600) });
      await fetch(`https://api.twilio.com/2010-04-01/Accounts/${c.env.TWILIO_ACCOUNT_SID}/Messages.json`, {
        method: 'POST', body: params,
        headers: { 'Authorization': 'Basic ' + btoa(c.env.TWILIO_ACCOUNT_SID + ':' + c.env.TWILIO_AUTH_TOKEN), 'Content-Type': 'application/x-www-form-urlencoded' },
      });
    } catch {}
  }

  return c.json({ ok: true, appointment_id: apptId, customer_id: customerId, message: 'Booking request received! Adam will confirm your appointment shortly.' });
});

app.onError((err, c) => {
  if (err.message?.includes('JSON')) {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  console.error(`[profinish-api] ${err.message}`);
  return c.json({ error: 'Internal server error' }, 500);
});

app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
});

export default app;
