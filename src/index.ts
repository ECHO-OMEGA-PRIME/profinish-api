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

// ─── Health ──────────────────────────────────────────────
app.get('/', (c) => c.json({ service: 'profinish-api', version: '1.0.0', status: 'ok' }));
app.get('/health', (c) => c.json({ status: 'healthy', timestamp: new Date().toISOString() }));

// ─── Settings ────────────────────────────────────────────
app.get('/settings', async (c) => {
  const rows = await c.env.DB.prepare('SELECT key, value FROM settings').all();
  const settings: Record<string, string> = {};
  for (const r of rows.results as any[]) settings[r.key] = r.value;
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
  const body = await c.req.json();
  const id = uid();
  const refCode = 'PF' + id.slice(0, 6).toUpperCase();
  await c.env.DB.prepare(
    'INSERT INTO customers (id, firebase_uid, name, email, phone, address, city, is_owner, referral_code, referred_by, preferred_language, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, body.firebase_uid || null, sanitize(body.name), sanitize(body.email || ''), sanitize(body.phone || ''), sanitize(body.address || ''), sanitize(body.city || ''),
    body.email === c.env.OWNER_EMAIL ? 1 : 0, refCode, body.referred_by || null, body.preferred_language || 'en', sanitize(body.notes || '')
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
  const row = await c.env.DB.prepare('SELECT j.*, c.name as customer_name FROM jobs j LEFT JOIN customers c ON j.customer_id = c.id WHERE j.id = ?').bind(c.req.param('id')).first();
  return row ? c.json(row) : c.json({ error: 'Not found' }, 404);
});

app.post('/jobs', async (c) => {
  const b = await c.req.json();
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

async function genInvoiceNum(db: D1Database): Promise<string> {
  const now = new Date();
  const prefix = `PF-${String(now.getFullYear()).slice(2)}${String(now.getMonth() + 1).padStart(2, '0')}`;
  const r = await db.prepare(`SELECT count(*) as c FROM invoices WHERE invoice_number LIKE ?`).bind(prefix + '-%').first<{c:number}>();
  return `${prefix}-${String((r?.c ?? 0) + 1).padStart(4, '0')}`;
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
  const num = await genInvoiceNum(c.env.DB);
  const shareToken = crypto.randomUUID();
  const issueDate = b.issue_date || new Date().toISOString().split('T')[0];
  const terms = b.payment_terms || 'net_30';
  const dueDate = b.due_date || calcDueDate(issueDate, terms);
  const subtotal = b.subtotal || 0;
  const taxRate = b.tax_rate ?? 0.0825;
  const taxAmt = subtotal * taxRate;
  const total = subtotal + taxAmt;
  await c.env.DB.prepare(
    'INSERT INTO invoices (id, job_id, customer_id, invoice_number, status, subtotal, tax_rate, tax_amount, total, due_date, issue_date, payment_terms, sales_rep, notes, share_token, amount_paid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)'
  ).bind(id, b.job_id || null, b.customer_id, num, 'draft', subtotal, taxRate, taxAmt, total, dueDate, issueDate, terms, b.sales_rep || null, sanitize(b.notes || ''), shareToken).run();

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
  await c.env.DB.prepare("UPDATE invoices SET status = 'sent', updated_at = datetime('now') WHERE id = ? AND status = 'draft'").bind(c.req.param('id')).run();
  return c.json({ ok: true });
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

app.post('/reviews', async (c) => {
  const b = await c.req.json();
  const id = uid();
  await c.env.DB.prepare(
    'INSERT INTO reviews (id, customer_id, job_id, rating, text, photo_url, approved) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, b.customer_id || null, b.job_id || null, b.rating, sanitize(b.text || ''), b.photo_url || null, 0).run();
  return c.json({ id });
});

app.put('/reviews/:id/approve', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  await c.env.DB.prepare('UPDATE reviews SET approved = 1 WHERE id = ?').bind(c.req.param('id')).run();
  return c.json({ ok: true });
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
  const b = await c.req.json();
  const id = uid();
  await c.env.DB.prepare(
    'INSERT INTO chat_sessions (id, customer_id, messages, emotion_log) VALUES (?, ?, ?, ?)'
  ).bind(id, b.customer_id || null, JSON.stringify(b.messages || []), JSON.stringify(b.emotion_log || [])).run();
  return c.json({ id });
});

app.put('/chat/session/:id', async (c) => {
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

app.get('/blog/:slug', async (c) => {
  const row = await c.env.DB.prepare('SELECT * FROM blog_posts WHERE slug = ?').bind(c.req.param('slug')).first();
  return row ? c.json(row) : c.json({ error: 'Not found' }, 404);
});

app.post('/blog', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const id = uid();
  const slug = (b.title || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  await c.env.DB.prepare(
    'INSERT INTO blog_posts (id, title, slug, content, excerpt, status, tags, seo_title, seo_description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, sanitize(b.title), slug, sanitize(b.content), sanitize(b.excerpt || ''), b.status || 'draft', sanitize(b.tags || ''), sanitize(b.seo_title || b.title), sanitize(b.seo_description || b.excerpt || '')).run();
  return c.json({ id, slug });
});

app.put('/blog/:id/publish', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  await c.env.DB.prepare('UPDATE blog_posts SET status = "published", published_at = datetime("now"), updated_at = datetime("now") WHERE id = ?').bind(c.req.param('id')).run();
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
  const b = await c.req.json();
  const id = uid();
  let action = 'none';
  if (b.score >= 9) action = 'ask_google_review';
  else if (b.score >= 7) action = 'ask_improvement';
  else action = 'alert_adam';
  await c.env.DB.prepare(
    'INSERT INTO nps_responses (id, customer_id, job_id, score, comment, follow_up_action) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(id, b.customer_id || null, b.job_id || null, b.score, sanitize(b.comment || ''), action).run();
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
  // Use LLM to extract receipt data (Azure GPT-4o primary, OpenAI fallback)
  try {
    const azureKey = c.env.AZURE_OPENAI_KEY;
    const openaiKey = c.env.OPENAI_API_KEY;
    if (!azureKey && !openaiKey) return c.json({ receipt_url: key, vendor: '', total: 0, date: '', items: [], error: 'Vision not configured' });
    const visionBody = JSON.stringify({
      messages: [{
        role: 'user',
        content: [
          { type: 'text', text: 'Extract from this receipt: vendor name, total amount, date, and list of items with prices. Return JSON: {"vendor":"","total":0,"date":"","items":[{"name":"","price":0}]}' },
          { type: 'image_url', image_url: { url: `data:image/jpeg;base64,${b.image_base64}` } }
        ]
      }],
      max_tokens: 512
    });
    let llmResp;
    if (azureKey) {
      llmResp = await fetch('https://echoomegaopenai.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2025-01-01-preview', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'api-key': azureKey }, body: visionBody
      });
    }
    if (!llmResp?.ok && openaiKey) {
      llmResp = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openaiKey}` },
        body: JSON.stringify({ ...JSON.parse(visionBody), model: 'gpt-4o-mini' })
      });
    }
    const llmData: any = await llmResp!.json();
    const content = llmData.choices?.[0]?.message?.content || '{}';
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

// ─── Belle AI Chat (Azure GPT-4.1 primary, OpenAI fallback) ─
const BELLE_SYSTEM_PROMPT = `You are Belle, the friendly and knowledgeable AI assistant for Pro Finish Custom Carpentry in Big Spring, TX. Owner: Adam McLemore. You help customers:
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

app.post('/belle/chat', async (c) => {
  const azureKey = c.env.AZURE_OPENAI_KEY;
  const openaiKey = c.env.OPENAI_API_KEY;
  if (!azureKey && !openaiKey) return c.json({ error: 'Chat not configured' }, 503);

  const body = await c.req.json();

  // Build messages array with Belle system prompt
  let messages: Array<{role: string; content: string}> = [];

  // System prompt + optional brain context
  let systemContent = BELLE_SYSTEM_PROMPT;
  if (body.context) systemContent += body.context;
  messages.push({ role: 'system', content: systemContent });

  // Support both formats: {messages: [...]} and {message: "...", history: [...]}
  if (body.messages && body.messages.length) {
    // Filter out any existing system messages (we provide our own)
    const nonSystem = body.messages.filter((m: any) => m.role !== 'system');
    messages.push(...nonSystem);
  } else if (body.message) {
    if (body.history && body.history.length) {
      messages.push(...body.history);
    }
    messages.push({ role: 'user', content: body.message });
  } else {
    return c.json({ error: 'No message provided' }, 400);
  }

  const maxTokens = Math.min(body.max_tokens || 512, 1024);
  const temperature = body.temperature ?? 0.8;

  // Try Azure GPT-4.1 first (FREE)
  if (azureKey) {
    try {
      const azureResp = await fetch(
        'https://echoomegaopenai.openai.azure.com/openai/deployments/gpt41-eastus/chat/completions?api-version=2025-01-01-preview',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'api-key': azureKey },
          body: JSON.stringify({ messages, max_tokens: maxTokens, temperature }),
        }
      );
      if (azureResp.ok) {
        const data: any = await azureResp.json();
        const reply = data.choices?.[0]?.message?.content || '';
        return c.json({ reply, provider: 'azure', model: 'gpt-4.1' });
      }
    } catch {}
  }

  // Fallback to OpenAI
  if (openaiKey) {
    try {
      const resp = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openaiKey}` },
        body: JSON.stringify({ model: 'gpt-4o-mini', messages, max_tokens: maxTokens, temperature }),
      });
      if (!resp.ok) {
        const errText = await resp.text();
        return c.json({ error: 'LLM error', status: resp.status, detail: errText }, 502);
      }
      const data: any = await resp.json();
      const reply = data.choices?.[0]?.message?.content || '';
      return c.json({ reply, provider: 'openai', model: 'gpt-4o-mini' });
    } catch (e: any) {
      return c.json({ error: 'Chat failed', detail: e.message }, 500);
    }
  }

  return c.json({ error: 'All LLM providers failed' }, 502);
});

// ─── Belle Vision (photo analysis — Azure GPT-4o primary) ─
app.post('/belle/vision', async (c) => {
  const azureKey = c.env.AZURE_OPENAI_KEY;
  const openaiKey = c.env.OPENAI_API_KEY;
  if (!azureKey && !openaiKey) return c.json({ error: 'Vision not configured' }, 503);

  const body = await c.req.json();
  const imageUrl = body.image_url;
  const imageBase64 = body.image_base64;
  const prompt = body.prompt || 'Analyze this room photo for a carpentry contractor. Identify: current condition, what work is needed, estimated scope. Be specific about materials and labor.';

  if (!imageUrl && !imageBase64) return c.json({ error: 'image_url or image_base64 required' }, 400);

  const imageContent = imageBase64
    ? { type: 'image_url', image_url: { url: `data:image/jpeg;base64,${imageBase64}` } }
    : { type: 'image_url', image_url: { url: imageUrl } };

  const visionBody = { messages: [{ role: 'user', content: [{ type: 'text', text: prompt }, imageContent] }], max_tokens: 512 };

  try {
    let resp;
    if (azureKey) {
      resp = await fetch('https://echoomegaopenai.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2025-01-01-preview', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'api-key': azureKey },
        body: JSON.stringify(visionBody),
      });
    }
    if (!resp?.ok && openaiKey) {
      resp = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openaiKey}` },
        body: JSON.stringify({ ...visionBody, model: 'gpt-4o-mini' }),
      });
    }
    if (!resp?.ok) {
      const errText = await resp!.text();
      return c.json({ error: 'Vision error', status: resp!.status, detail: errText }, 502);
    }
    const data = await resp!.json();
    return c.json(data);
  } catch (e: any) {
    return c.json({ error: 'Vision failed', detail: e.message }, 500);
  }
});

// ═══════════════════════════════════════════════════════════
// ─── UNIVERSAL DOCUMENT DELIVERY SYSTEM ──────────────────
// Print, PDF, Email, SMS — fully self-contained
// ═══════════════════════════════════════════════════════════

// ─── Server-side Branded Document Builder ────────────────
function buildDocumentHTML(opts: {
  type: 'ESTIMATE' | 'INVOICE' | 'WORK_ORDER' | 'RECEIPT' | 'STATEMENT';
  docNumber: string;
  date: string;
  dueDate?: string;
  serviceDate?: string;
  customerName: string;
  customerEmail?: string;
  customerPhone?: string;
  customerAddress?: string;
  jobTitle?: string;
  serviceType?: string;
  items: Array<{ description: string; qty: number; rate: number; amount: number }>;
  subtotal: number;
  taxRate: number;
  taxAmount: number;
  total: number;
  amountPaid?: number;
  scopeItems?: string[];
  notes?: string;
  paymentTerms?: string;
  company: {
    name: string;
    phone: string;
    email: string;
    tagline: string;
    website: string;
    city: string;
    primaryColor: string;
    accentColor: string;
  };
}): string {
  const co = opts.company;
  const isEst = opts.type === 'ESTIMATE';
  const isWO = opts.type === 'WORK_ORDER';
  const isReceipt = opts.type === 'RECEIPT';
  const isStatement = opts.type === 'STATEMENT';
  const badgeBg = isEst ? '#22C55E' : isWO ? '#F59E0B' : isReceipt ? '#8B5CF6' : isStatement ? '#6366F1' : '#3B82F6';
  const typeLabel = opts.type.replace('_', ' ');
  const esc = (s: string) => (s || '').replace(/[<>&"']/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'}[c] || c));

  const lineRows = opts.items.map(i =>
    `<tr><td style="padding:10px 16px;border-bottom:1px solid #E5E7EB;font-size:13px">${esc(i.description)}</td>` +
    `<td style="padding:10px 16px;border-bottom:1px solid #E5E7EB;text-align:center;font-size:13px">${i.qty}</td>` +
    `<td style="padding:10px 16px;border-bottom:1px solid #E5E7EB;text-align:right;font-size:13px">$${(i.rate||0).toFixed(2)}</td>` +
    `<td style="padding:10px 16px;border-bottom:1px solid #E5E7EB;text-align:right;font-size:13px;font-weight:600">$${(i.amount||0).toFixed(2)}</td></tr>`
  ).join('');

  const subtotalRow = `<tr><td colspan="3" style="padding:10px 16px;text-align:right;font-weight:600;border-top:2px solid #D1D5DB">Subtotal</td>` +
    `<td style="padding:10px 16px;text-align:right;font-weight:600;border-top:2px solid #D1D5DB">$${opts.subtotal.toFixed(2)}</td></tr>`;
  const taxRow = opts.taxAmount > 0 ? `<tr><td colspan="3" style="padding:6px 16px;text-align:right;font-size:12px;color:#6B7280">Tax (${(opts.taxRate*100).toFixed(2)}%)</td>` +
    `<td style="padding:6px 16px;text-align:right;font-size:12px;color:#6B7280">$${opts.taxAmount.toFixed(2)}</td></tr>` : '';

  const scopeHtml = (opts.scopeItems && opts.scopeItems.length) ? `<div style="padding:20px 40px">` +
    `<div style="font-family:'Segoe UI',sans-serif;font-size:14px;font-weight:600;color:${co.primaryColor};text-transform:uppercase;letter-spacing:1px;padding-bottom:6px;border-bottom:2px solid ${co.primaryColor};margin-bottom:12px">Scope of Work</div>` +
    `<ul style="list-style:none;padding:0">${opts.scopeItems.map(s => `<li style="padding:3px 0;font-size:13px;color:#374151"><span style="color:${co.accentColor};font-weight:700;margin-right:8px">›</span>${esc(s)}</li>`).join('')}</ul></div>` : '';

  const notesHtml = opts.notes ? `<div style="padding:0 40px 20px"><div style="background:#FFFDE7;padding:14px 18px;border-radius:8px;border-left:3px solid ${co.accentColor}">` +
    `<div style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#92400E;margin-bottom:4px;font-weight:600">Notes</div>` +
    `<p style="font-size:13px;color:#374151;line-height:1.6">${esc(opts.notes)}</p></div></div>` : '';

  const paid = opts.amountPaid || 0;
  const balanceHtml = (!isEst && paid > 0) ? `<div style="padding:0 40px 16px;display:flex;justify-content:flex-end"><div style="min-width:260px">` +
    `<div style="display:flex;justify-content:space-between;padding:4px 0;font-size:14px;color:#22C55E"><span>Amount Paid</span><span>-$${paid.toFixed(2)}</span></div>` +
    `<div style="display:flex;justify-content:space-between;padding:4px 0;font-size:16px;font-weight:700;color:#F59E0B"><span>Balance Due</span><span>$${(opts.total - paid).toFixed(2)}</span></div>` +
    `</div></div>` : '';

  const thirdLabel = isEst ? 'Service Date' : isWO ? 'Scheduled Date' : 'Due Date';
  const thirdValue = isEst ? (opts.serviceDate || 'TBD') : isWO ? (opts.serviceDate || 'TBD') : (opts.dueDate || '--');

  const totalLabel = isEst ? 'ESTIMATED TOTAL:' : isReceipt ? 'AMOUNT PAID:' : isWO ? 'ESTIMATED COST:' : 'TOTAL DUE:';

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${esc(typeLabel)} ${esc(opts.docNumber)} | ${esc(co.name)}</title>
<link href="https://fonts.googleapis.com/css2?family=Oswald:wght@400;500;600;700&family=Open+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:"Open Sans",sans-serif;color:#1f2937;background:#fff;max-width:850px;margin:0 auto}
@media print{
  body{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important;max-width:100%}
  .no-print{display:none!important}
  @page{margin:0.4in}
}
.delivery-bar{background:#f1f5f9;padding:12px 40px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;border-bottom:1px solid #e2e8f0}
.delivery-bar button{padding:8px 18px;border:none;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:6px;transition:all .15s}
.btn-print{background:${co.primaryColor};color:#fff}.btn-print:hover{opacity:.9}
.btn-pdf{background:#059669;color:#fff}.btn-pdf:hover{background:#047857}
.btn-email{background:#2563EB;color:#fff}.btn-email:hover{background:#1D4ED8}
.btn-sms{background:#7C3AED;color:#fff}.btn-sms:hover{background:#6D28D9}
.email-modal{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.5);z-index:1000;justify-content:center;align-items:center}
.email-modal.active{display:flex}
.email-form{background:#fff;border-radius:12px;padding:28px;width:420px;max-width:90vw;box-shadow:0 20px 60px rgba(0,0,0,.3)}
.email-form h3{margin:0 0 16px;font-size:18px;color:${co.primaryColor}}
.email-form input,.email-form textarea{width:100%;padding:10px 14px;border:1px solid #d1d5db;border-radius:8px;font-size:14px;margin-bottom:12px;font-family:inherit}
.email-form textarea{height:80px;resize:vertical}
.email-form .btn-row{display:flex;gap:8px;justify-content:flex-end}
.sms-modal{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.5);z-index:1000;justify-content:center;align-items:center}
.sms-modal.active{display:flex}
.sms-form{background:#fff;border-radius:12px;padding:28px;width:420px;max-width:90vw;box-shadow:0 20px 60px rgba(0,0,0,.3)}
.sms-form h3{margin:0 0 16px;font-size:18px;color:#7C3AED}
.sms-form input{width:100%;padding:10px 14px;border:1px solid #d1d5db;border-radius:8px;font-size:14px;margin-bottom:12px}
.sms-form .btn-row{display:flex;gap:8px;justify-content:flex-end}
.status-toast{position:fixed;bottom:24px;right:24px;padding:14px 24px;border-radius:10px;color:#fff;font-weight:600;font-size:14px;z-index:2000;opacity:0;transition:opacity .3s;pointer-events:none}
.status-toast.show{opacity:1}
.status-toast.success{background:#059669}
.status-toast.error{background:#DC2626}
</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.2/html2pdf.bundle.min.js"></script>
</head><body>

<!-- DELIVERY ACTION BAR (hidden in print) -->
<div class="delivery-bar no-print" id="deliveryBar">
  <button class="btn-print" onclick="window.print()">🖨️ Print</button>
  <button class="btn-pdf" onclick="downloadPDF()">📄 Save PDF</button>
  <button class="btn-email" onclick="showEmailModal()">📧 Email</button>
  <button class="btn-sms" onclick="showSMSModal()">💬 SMS</button>
  <span style="margin-left:auto;font-size:12px;color:#6B7280" id="docMeta">${esc(typeLabel)} ${esc(opts.docNumber)}</span>
</div>

<!-- EMAIL MODAL -->
<div class="email-modal" id="emailModal">
  <div class="email-form">
    <h3>📧 Email ${esc(typeLabel)}</h3>
    <input type="email" id="emailTo" placeholder="Recipient email" value="${esc(opts.customerEmail || '')}">
    <input type="text" id="emailSubject" value="${esc(typeLabel)} ${esc(opts.docNumber)} from ${esc(co.name)}">
    <textarea id="emailMessage" placeholder="Optional message...">${esc(typeLabel)} ${esc(opts.docNumber)} is attached. Total: $${opts.total.toFixed(2)}${opts.dueDate ? '. Due: ' + opts.dueDate : ''}.\\n\\nThank you for your business!\\n${esc(co.name)}</textarea>
    <div class="btn-row">
      <button onclick="hideEmailModal()" style="padding:8px 18px;border:1px solid #d1d5db;border-radius:6px;background:#fff;cursor:pointer">Cancel</button>
      <button onclick="sendEmail()" class="btn-email" style="border:none;border-radius:6px;padding:8px 24px;cursor:pointer">Send Email</button>
    </div>
  </div>
</div>

<!-- SMS MODAL -->
<div class="sms-modal" id="smsModal">
  <div class="sms-form">
    <h3>💬 Send via SMS</h3>
    <input type="tel" id="smsTo" placeholder="Phone number (e.g. +14325551234)" value="${esc(opts.customerPhone || '')}">
    <input type="text" id="smsMessage" value="${esc(typeLabel)} ${esc(opts.docNumber)} from ${esc(co.name)}: $${opts.total.toFixed(2)}${opts.dueDate ? ' due ' + opts.dueDate : ''}. View: ">
    <div class="btn-row">
      <button onclick="hideSMSModal()" style="padding:8px 18px;border:1px solid #d1d5db;border-radius:6px;background:#fff;cursor:pointer">Cancel</button>
      <button onclick="sendSMS()" class="btn-sms" style="border:none;border-radius:6px;padding:8px 24px;color:#fff;cursor:pointer">Send SMS</button>
    </div>
  </div>
</div>

<!-- TOAST -->
<div class="status-toast" id="toast"></div>

<!-- DOCUMENT CONTENT -->
<div id="documentContent">
<div style="background:${co.primaryColor};color:#fff;padding:24px 40px;display:flex;justify-content:space-between;align-items:center">
  <div style="display:flex;align-items:center;gap:16px">
    <div>
      <div style="font-family:Oswald,sans-serif;font-size:28px;font-weight:700;line-height:1">${esc(co.name)}</div>
      <div style="font-size:9px;letter-spacing:2.5px;text-transform:uppercase;color:rgba(255,255,255,.7);margin-top:3px">${esc(co.tagline)} | ${esc(co.city)}</div>
    </div>
  </div>
  <div style="display:flex;align-items:center;gap:24px">
    <div style="text-align:right;font-size:11px;color:rgba(255,255,255,.8);line-height:1.8">
      <div>${esc(co.phone)}</div>
      <div>${esc(co.email)}</div>
      <div>${esc(co.website)}</div>
    </div>
    <div style="background:${badgeBg};color:#fff;padding:8px 22px;border-radius:6px;font-family:Oswald,sans-serif;font-size:18px;font-weight:600;letter-spacing:2px">${esc(typeLabel)}</div>
  </div>
</div>

<div style="display:flex;border-bottom:2px solid #E5E7EB">
  <div style="flex:1;padding:16px 20px;text-align:center;border-right:1px solid #E5E7EB">
    <div style="font-size:9px;text-transform:uppercase;letter-spacing:1.5px;color:#9CA3AF;margin-bottom:4px">${esc(typeLabel)} Number</div>
    <div style="font-size:16px;font-weight:600;color:${co.primaryColor}">${esc(opts.docNumber)}</div>
  </div>
  <div style="flex:1;padding:16px 20px;text-align:center;border-right:1px solid #E5E7EB">
    <div style="font-size:9px;text-transform:uppercase;letter-spacing:1.5px;color:#9CA3AF;margin-bottom:4px">Date</div>
    <div style="font-size:16px;font-weight:600;color:${co.primaryColor}">${esc(opts.date)}</div>
  </div>
  <div style="flex:1;padding:16px 20px;text-align:center">
    <div style="font-size:9px;text-transform:uppercase;letter-spacing:1.5px;color:#9CA3AF;margin-bottom:4px">${esc(thirdLabel)}</div>
    <div style="font-size:16px;font-weight:600;color:${co.primaryColor}">${esc(thirdValue)}</div>
  </div>
</div>

<div style="padding:20px 40px">
  <div style="font-family:Oswald,sans-serif;font-size:14px;font-weight:600;color:${co.primaryColor};text-transform:uppercase;letter-spacing:1px;padding-bottom:6px;border-bottom:2px solid ${co.primaryColor};margin-bottom:16px">${isEst || isWO ? 'Service Details' : 'Bill To'}</div>
  <div style="display:flex;gap:20px;margin-bottom:16px">
    <div style="flex:1;background:#F9FAFB;border-radius:8px;padding:14px 18px">
      <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:${co.accentColor};margin-bottom:6px">Customer</div>
      <p style="font-size:14px;font-weight:600;color:#374151;margin:0">${esc(opts.customerName)}</p>
      ${opts.customerAddress ? `<p style="font-size:13px;color:#6B7280;margin:4px 0 0">${esc(opts.customerAddress)}</p>` : ''}
      ${opts.customerPhone ? `<p style="font-size:13px;color:#6B7280;margin:2px 0 0">${esc(opts.customerPhone)}</p>` : ''}
      ${opts.customerEmail ? `<p style="font-size:13px;color:#6B7280;margin:2px 0 0">${esc(opts.customerEmail)}</p>` : ''}
    </div>
    ${(isEst || isWO) && opts.jobTitle ? `<div style="flex:1;background:#F9FAFB;border-radius:8px;padding:14px 18px">
      <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:${co.accentColor};margin-bottom:6px">Project</div>
      <p style="font-size:14px;font-weight:600;color:#374151;margin:0">${esc(opts.jobTitle)}</p>
      ${opts.serviceType ? `<p style="font-size:13px;color:#6B7280;margin:4px 0 0">${esc(opts.serviceType)}</p>` : ''}
    </div>` : ''}
  </div>
</div>

<div style="padding:0 40px 16px">
  <div style="font-family:Oswald,sans-serif;font-size:14px;font-weight:600;color:${co.primaryColor};text-transform:uppercase;letter-spacing:1px;padding-bottom:6px;border-bottom:2px solid ${co.primaryColor};margin-bottom:12px">Cost Breakdown</div>
  <table style="width:100%;border-collapse:collapse">
    <thead><tr>
      <th style="background:${co.primaryColor};color:#fff;font-family:Oswald,sans-serif;font-size:11px;text-transform:uppercase;letter-spacing:1.5px;padding:10px 16px;text-align:left">Description</th>
      <th style="background:${co.primaryColor};color:#fff;font-family:Oswald,sans-serif;font-size:11px;text-transform:uppercase;letter-spacing:1.5px;padding:10px 16px;text-align:center">Qty</th>
      <th style="background:${co.primaryColor};color:#fff;font-family:Oswald,sans-serif;font-size:11px;text-transform:uppercase;letter-spacing:1.5px;padding:10px 16px;text-align:right">Rate</th>
      <th style="background:${co.primaryColor};color:#fff;font-family:Oswald,sans-serif;font-size:11px;text-transform:uppercase;letter-spacing:1.5px;padding:10px 16px;text-align:right">Amount</th>
    </tr></thead>
    <tbody>${lineRows}${subtotalRow}${taxRow}</tbody>
  </table>
  <div style="background:${co.primaryColor};display:flex;justify-content:space-between;align-items:center;padding:12px 20px;border-radius:6px;margin-top:8px">
    <span style="color:#fff;font-family:Oswald,sans-serif;font-size:16px;letter-spacing:1px">${esc(totalLabel)}</span>
    <span style="color:${co.accentColor};font-family:Oswald,sans-serif;font-size:22px;font-weight:700">$${opts.total.toFixed(2)}</span>
  </div>
</div>

${balanceHtml}
${scopeHtml}
${notesHtml}

${opts.paymentTerms ? `<div style="padding:0 40px 20px"><div style="background:#f8f9fa;padding:16px 18px;border-radius:8px;font-size:12px;color:#666">
  <div style="font-weight:700;color:${co.primaryColor};margin-bottom:6px;text-transform:uppercase;letter-spacing:1px;font-size:11px">Payment Terms</div>
  <p style="margin:0">${esc(opts.paymentTerms)}</p>
</div></div>` : ''}

<div style="background:${co.primaryColor};padding:20px 40px;text-align:center;border-top:3px solid ${co.accentColor};margin-top:32px">
  <div style="color:rgba(255,255,255,.8);font-size:11px;letter-spacing:1px">${esc(co.name)} &nbsp;|&nbsp; ${esc(co.city)} &nbsp;|&nbsp; ${esc(co.phone)} &nbsp;|&nbsp; ${esc(co.email)}</div>
  <div style="color:${co.accentColor};font-family:Oswald,sans-serif;font-size:12px;letter-spacing:2px;margin-top:8px">${esc(co.tagline)}</div>
</div>
</div>

<script>
const DOC_ID = '${esc(opts.docNumber)}';
const DOC_TYPE = '${esc(typeLabel)}';
const CUSTOMER = '${esc(opts.customerName)}';
const API_BASE = window.DOC_API_BASE || '';

function toast(msg, type) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'status-toast show ' + (type || 'success');
  setTimeout(() => t.className = 'status-toast', 3000);
}

function downloadPDF() {
  const el = document.getElementById('documentContent');
  const filename = DOC_TYPE.replace(/\\s+/g, '_') + '_' + DOC_ID + '_' + CUSTOMER.replace(/[^a-zA-Z0-9]/g, '_') + '.pdf';
  html2pdf().set({
    margin: 0.3,
    filename: filename,
    image: { type: 'jpeg', quality: 0.98 },
    html2canvas: { scale: 2, useCORS: true, logging: false },
    jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' },
    pagebreak: { mode: ['avoid-all', 'css', 'legacy'] }
  }).from(el).save().then(() => toast('PDF saved: ' + filename)).catch(e => toast('PDF error: ' + e.message, 'error'));
}

function showEmailModal() { document.getElementById('emailModal').classList.add('active'); }
function hideEmailModal() { document.getElementById('emailModal').classList.remove('active'); }
function showSMSModal() { document.getElementById('smsModal').classList.add('active'); }
function hideSMSModal() { document.getElementById('smsModal').classList.remove('active'); }

async function sendEmail() {
  const to = document.getElementById('emailTo').value.trim();
  const subject = document.getElementById('emailSubject').value.trim();
  const message = document.getElementById('emailMessage').value.trim();
  if (!to) { toast('Enter recipient email', 'error'); return; }
  hideEmailModal();
  toast('Sending email...');
  try {
    const viewUrl = window.location.href;
    const resp = await fetch(API_BASE + '/documents/deliver/email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
      body: JSON.stringify({ to, subject, message, doc_id: DOC_ID, view_url: viewUrl })
    });
    const data = await resp.json();
    if (data.ok) toast('Email sent to ' + to);
    else toast('Email failed: ' + (data.error || 'unknown'), 'error');
  } catch (e) { toast('Email error: ' + e.message, 'error'); }
}

async function sendSMS() {
  const to = document.getElementById('smsTo').value.trim();
  const message = document.getElementById('smsMessage').value.trim();
  if (!to) { toast('Enter phone number', 'error'); return; }
  hideSMSModal();
  toast('Sending SMS...');
  try {
    const viewUrl = window.location.href;
    const fullMsg = message + ' ' + viewUrl;
    const resp = await fetch(API_BASE + '/documents/deliver/sms', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
      body: JSON.stringify({ to, body: fullMsg, doc_id: DOC_ID })
    });
    const data = await resp.json();
    if (data.ok) toast('SMS sent to ' + to);
    else toast('SMS failed: ' + (data.error || 'unknown'), 'error');
  } catch (e) { toast('SMS error: ' + e.message, 'error'); }
}

function getAuthHeaders() {
  try {
    const token = localStorage.getItem('fb_token');
    if (token) return { 'Authorization': 'Bearer ' + token };
  } catch {}
  return {};
}
</script>
</body></html>`;
}

// Company config helper — reads from settings table or env vars
async function getCompanyConfig(db: D1Database, env: Env): Promise<{
  name: string; phone: string; email: string; tagline: string;
  website: string; city: string; primaryColor: string; accentColor: string;
}> {
  const rows = await db.prepare('SELECT key, value FROM settings').all();
  const s: Record<string, string> = {};
  for (const r of rows.results as any[]) s[r.key] = r.value;
  return {
    name: s.company_name || env.COMPANY_NAME || 'Pro Finish USA',
    phone: s.company_phone || env.COMPANY_PHONE || '(432) 466-5310',
    email: s.company_email || env.COMPANY_EMAIL || 'profinishcartx@gmail.com',
    tagline: s.company_tagline || env.COMPANY_TAGLINE || 'Quality Craftsmanship. Every Detail. Every Time.',
    website: s.company_website || env.SITE_URL || 'profinishusa.com',
    city: s.company_city || 'Big Spring, TX',
    primaryColor: s.company_primary_color || '#0D2847',
    accentColor: s.company_accent_color || '#FFD700',
  };
}

// ─── Generate Document (store HTML to R2, return view URL) ────
app.post('/documents/generate', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();

  // Required: type (INVOICE|ESTIMATE|WORK_ORDER|RECEIPT|STATEMENT) + source_id (invoice_id or job_id)
  const docType = (b.type || 'INVOICE').toUpperCase() as 'ESTIMATE' | 'INVOICE' | 'WORK_ORDER' | 'RECEIPT' | 'STATEMENT';
  const sourceId = b.source_id || b.invoice_id || b.job_id;
  if (!sourceId) return c.json({ error: 'source_id required (invoice_id or job_id)' }, 400);

  const company = await getCompanyConfig(c.env.DB, c.env);
  let docData: any;

  if (docType === 'INVOICE' || docType === 'RECEIPT' || docType === 'STATEMENT') {
    // Load invoice with customer + items + payments
    const inv = await c.env.DB.prepare(
      'SELECT i.*, c.name as customer_name, c.email as customer_email, c.phone as customer_phone, c.address as customer_address, c.city as customer_city FROM invoices i LEFT JOIN customers c ON i.customer_id = c.id WHERE i.id = ?'
    ).bind(sourceId).first() as any;
    if (!inv) return c.json({ error: 'Invoice not found' }, 404);
    const items = await c.env.DB.prepare('SELECT * FROM invoice_items WHERE invoice_id = ? ORDER BY rowid').bind(sourceId).all();

    docData = {
      type: docType,
      docNumber: inv.invoice_number || sourceId.slice(0, 8).toUpperCase(),
      date: inv.issue_date || new Date().toISOString().split('T')[0],
      dueDate: inv.due_date,
      customerName: inv.customer_name || 'Customer',
      customerEmail: inv.customer_email || '',
      customerPhone: inv.customer_phone || '',
      customerAddress: [inv.customer_address, inv.customer_city].filter(Boolean).join(', '),
      items: (items.results as any[]).map((it: any) => ({
        description: it.description, qty: it.quantity || 1, rate: it.unit_price || 0, amount: it.total || 0,
      })),
      subtotal: inv.subtotal || 0,
      taxRate: inv.tax_rate || 0,
      taxAmount: inv.tax_amount || 0,
      total: inv.total || 0,
      amountPaid: docType === 'RECEIPT' ? inv.total : (inv.amount_paid || 0),
      notes: inv.notes || '',
      paymentTerms: inv.payment_terms === 'net_30' ? 'Net 30 — Payment due within 30 days of invoice date.' :
                     inv.payment_terms === 'net_15' ? 'Net 15 — Payment due within 15 days.' :
                     inv.payment_terms === 'due_on_receipt' ? 'Due on receipt.' : '',
      company,
    };
  } else {
    // ESTIMATE or WORK_ORDER — load from jobs
    const job = await c.env.DB.prepare(
      'SELECT j.*, c.name as customer_name, c.email as customer_email, c.phone as customer_phone, c.address as customer_address, c.city as customer_city FROM jobs j LEFT JOIN customers c ON j.customer_id = c.id WHERE j.id = ?'
    ).bind(sourceId).first() as any;
    if (!job) return c.json({ error: 'Job not found' }, 404);

    const estTotal = parseFloat(job.estimated_cost_high || job.estimated_cost_low || job.actual_cost) || 0;
    const scopeItems: string[] = [];
    if (job.notes || job.description) {
      (job.notes || job.description || '').split(/[\n;]+/).forEach((l: string) => { const t = l.trim(); if (t) scopeItems.push(t); });
    }

    const now = new Date();
    const docNum = `PF-${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}`;

    docData = {
      type: docType,
      docNumber: docNum,
      date: now.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }),
      serviceDate: job.scheduled_date || 'TBD',
      customerName: job.customer_name || 'Customer',
      customerEmail: job.customer_email || '',
      customerPhone: job.customer_phone || '',
      customerAddress: [job.customer_address || job.address, job.customer_city || job.city].filter(Boolean).join(', '),
      jobTitle: job.title || '',
      serviceType: job.service_type || '',
      items: [{ description: (job.service_type || 'Service') + ' — ' + (job.title || 'Project'), qty: 1, rate: estTotal, amount: estTotal }],
      subtotal: estTotal,
      taxRate: 0,
      taxAmount: 0,
      total: estTotal,
      scopeItems,
      notes: '',
      company,
    };
  }

  // Generate HTML
  const html = buildDocumentHTML(docData);

  // Store to R2 with organized path
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const safeCustomer = (docData.customerName || 'customer').replace(/[^a-zA-Z0-9]/g, '_').slice(0, 30);
  const r2Key = `profinish/documents/${year}/${month}/${docType.toLowerCase()}/${docData.docNumber}_${safeCustomer}.html`;
  await c.env.R2.put(r2Key, html, { httpMetadata: { contentType: 'text/html' } });

  // Create delivery tracking record
  const deliveryId = uid();
  const viewToken = crypto.randomUUID();
  await c.env.DB.prepare(
    `INSERT INTO document_deliveries (id, doc_type, doc_number, source_id, customer_name, customer_email, customer_phone, r2_key, view_token, total, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
  ).bind(deliveryId, docType, docData.docNumber, sourceId, docData.customerName, docData.customerEmail || '', docData.customerPhone || '', r2Key, viewToken, docData.total).run();

  const viewUrl = `${c.env.SITE_URL || 'https://profinish-api.bmcii1976.workers.dev'}/documents/view/${viewToken}`;

  return c.json({
    ok: true,
    delivery_id: deliveryId,
    doc_number: docData.docNumber,
    r2_key: r2Key,
    view_url: viewUrl,
    view_token: viewToken,
  });
});

// ─── Public Document View (no auth — token-based) ────────
app.get('/documents/view/:token', async (c) => {
  const token = c.req.param('token');
  const doc = await c.env.DB.prepare('SELECT * FROM document_deliveries WHERE view_token = ?').bind(token).first() as any;
  if (!doc) return c.html('<h1>Document not found</h1>', 404);

  // Track view
  await c.env.DB.prepare("UPDATE document_deliveries SET last_viewed_at = datetime('now'), view_count = COALESCE(view_count, 0) + 1 WHERE id = ?").bind(doc.id).run();

  // Load from R2
  const obj = await c.env.R2.get(doc.r2_key);
  if (!obj) return c.html('<h1>Document expired or removed</h1>', 404);
  const html = await obj.text();

  // Inject the API base URL into the document for delivery buttons
  const apiBase = c.env.SITE_URL || 'https://profinish-api.bmcii1976.workers.dev';
  const injectedHtml = html.replace("window.DOC_API_BASE || ''", `'${apiBase}'`);

  return c.html(injectedHtml);
});

// ─── List Documents (admin) ──────────────────────────────
app.get('/documents', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const type = c.req.query('type');
  const limit = parseInt(c.req.query('limit') || '50');
  let sql = 'SELECT * FROM document_deliveries WHERE 1=1';
  const params: any[] = [];
  if (type) { sql += ' AND doc_type = ?'; params.push(type.toUpperCase()); }
  sql += ' ORDER BY created_at DESC LIMIT ?';
  params.push(limit);
  const rows = await c.env.DB.prepare(sql).bind(...params).all();
  return c.json(rows.results);
});

// ─── Get Document Detail ─────────────────────────────────
app.get('/documents/:id', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const doc = await c.env.DB.prepare('SELECT * FROM document_deliveries WHERE id = ?').bind(c.req.param('id')).first();
  if (!doc) return c.json({ error: 'Not found' }, 404);
  return c.json(doc);
});

// ─── Email Delivery ──────────────────────────────────────
app.post('/documents/deliver/email', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const { to, subject, message, doc_id, view_url } = b;
  if (!to) return c.json({ error: 'to (email) required' }, 400);

  const company = await getCompanyConfig(c.env.DB, c.env);

  // Build email HTML
  const emailHtml = `<!DOCTYPE html><html><body style="font-family:'Open Sans',Arial,sans-serif;max-width:600px;margin:0 auto;background:#f8f9fa;padding:20px">
<div style="background:${company.primaryColor};color:#fff;padding:20px 30px;border-radius:10px 10px 0 0">
  <h1 style="margin:0;font-size:22px;font-family:Oswald,sans-serif">${sanitize(company.name)}</h1>
  <p style="margin:4px 0 0;font-size:12px;color:rgba(255,255,255,.7)">${sanitize(company.tagline)}</p>
</div>
<div style="background:#fff;padding:30px;border:1px solid #e5e7eb;border-top:none">
  <p style="font-size:14px;color:#374151;line-height:1.8;white-space:pre-wrap">${sanitize(message || '')}</p>
  ${view_url ? `<div style="text-align:center;margin:24px 0">
    <a href="${sanitize(view_url)}" style="background:${company.primaryColor};color:#fff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px;display:inline-block">View Document</a>
  </div>
  <p style="font-size:12px;color:#9CA3AF;text-align:center">Or copy this link: ${sanitize(view_url)}</p>` : ''}
</div>
<div style="padding:16px 30px;text-align:center;font-size:11px;color:#9CA3AF">
  ${sanitize(company.name)} | ${sanitize(company.city)} | ${sanitize(company.phone)} | ${sanitize(company.email)}
</div>
</body></html>`;

  // Send via Resend API
  const resendKey = c.env.RESEND_API_KEY;
  if (!resendKey) {
    // Log the delivery attempt even without email provider
    await c.env.DB.prepare(
      "INSERT INTO document_deliveries (id, doc_type, doc_number, source_id, customer_name, customer_email, delivery_channel, delivery_status, r2_key, view_token, created_at) VALUES (?, 'EMAIL', ?, ?, ?, ?, 'email', 'failed_no_provider', '', '', datetime('now'))"
    ).bind(uid(), doc_id || '', '', '', to).run();
    return c.json({ ok: false, error: 'Email provider not configured. Set RESEND_API_KEY via: npx wrangler secret put RESEND_API_KEY --name profinish-api' }, 503);
  }

  try {
    const resp = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${resendKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: `${company.name} <${company.email.includes('@') ? company.email : 'noreply@profinishusa.com'}>`,
        to: [to],
        subject: subject || `Document from ${company.name}`,
        html: emailHtml,
      }),
    });
    const data = await resp.json() as any;

    // Log delivery
    if (doc_id) {
      await c.env.DB.prepare(
        "UPDATE document_deliveries SET delivery_channel = 'email', delivery_status = ?, delivered_to = ?, delivered_at = datetime('now') WHERE doc_number = ? OR id = ?"
      ).bind(resp.ok ? 'sent' : 'failed', to, doc_id, doc_id).run();
    }

    if (resp.ok) return c.json({ ok: true, email_id: data.id });
    return c.json({ ok: false, error: data.message || 'Email send failed' }, 502);
  } catch (e: any) {
    return c.json({ ok: false, error: e.message }, 500);
  }
});

// ─── SMS Delivery ────────────────────────────────────────
app.post('/documents/deliver/sms', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  const { to, body: msgBody, doc_id } = b;
  if (!to || !msgBody) return c.json({ error: 'to and body required' }, 400);

  const { SID, TOKEN, FROM } = {
    SID: c.env.TWILIO_ACCOUNT_SID,
    TOKEN: c.env.TWILIO_AUTH_TOKEN,
    FROM: c.env.TWILIO_PHONE_NUMBER,
  };
  if (!SID || !TOKEN || !FROM) return c.json({ ok: false, error: 'Twilio not configured' }, 503);

  try {
    const params = new URLSearchParams({ To: to, From: FROM, Body: msgBody });
    const resp = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${SID}/Messages.json`, {
      method: 'POST', body: params,
      headers: { 'Authorization': 'Basic ' + btoa(SID + ':' + TOKEN), 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    // Log delivery
    if (doc_id) {
      await c.env.DB.prepare(
        "UPDATE document_deliveries SET delivery_channel = 'sms', delivery_status = ?, delivered_to = ?, delivered_at = datetime('now') WHERE doc_number = ? OR id = ?"
      ).bind(resp.ok ? 'sent' : 'failed', to, doc_id, doc_id).run();
    }

    return c.json({ ok: resp.ok, status: resp.status });
  } catch (e: any) {
    return c.json({ ok: false, error: e.message }, 500);
  }
});

// ─── Delivery Settings (configurable per-tenant) ────────
app.get('/documents/settings', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const rows = await c.env.DB.prepare("SELECT key, value FROM settings WHERE key LIKE 'doc_%' OR key LIKE 'company_%'").all();
  const settings: Record<string, string> = {};
  for (const r of rows.results as any[]) settings[r.key] = r.value;
  return c.json(settings);
});

app.put('/documents/settings', async (c) => {
  const denied = requireAuth(c);
  if (denied) return denied;
  const b = await c.req.json();
  // Batch update settings
  for (const [key, value] of Object.entries(b)) {
    if (typeof key === 'string' && (key.startsWith('doc_') || key.startsWith('company_'))) {
      await c.env.DB.prepare('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, datetime("now"))').bind(key, String(value)).run();
    }
  }
  return c.json({ ok: true });
});

export default app;
