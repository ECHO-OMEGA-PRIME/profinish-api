-- Pro Finish API — D1 Schema
-- All tables for jobs, invoices, reviews, scheduling, expenses, settings

CREATE TABLE IF NOT EXISTS customers (
  id TEXT PRIMARY KEY,
  firebase_uid TEXT UNIQUE,
  name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  address TEXT,
  city TEXT,
  is_owner INTEGER DEFAULT 0,
  referral_code TEXT UNIQUE,
  referred_by TEXT,
  preferred_language TEXT DEFAULT 'en',
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  customer_id TEXT REFERENCES customers(id),
  title TEXT NOT NULL,
  description TEXT,
  service_type TEXT,
  status TEXT DEFAULT 'estimate',
  estimated_cost_low REAL,
  estimated_cost_high REAL,
  actual_cost REAL,
  labor_cost REAL,
  materials_cost REAL,
  address TEXT,
  city TEXT,
  is_outdoor INTEGER DEFAULT 0,
  scheduled_date TEXT,
  start_date TEXT,
  completion_date TEXT,
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS invoices (
  id TEXT PRIMARY KEY,
  job_id TEXT REFERENCES jobs(id),
  customer_id TEXT REFERENCES customers(id),
  invoice_number TEXT UNIQUE,
  status TEXT DEFAULT 'draft',
  subtotal REAL DEFAULT 0,
  tax_rate REAL DEFAULT 0.0825,
  tax_amount REAL DEFAULT 0,
  total REAL DEFAULT 0,
  amount_paid REAL DEFAULT 0,
  due_date TEXT,
  issue_date TEXT DEFAULT (date('now')),
  paid_date TEXT,
  payment_terms TEXT DEFAULT 'net_30',
  sales_rep TEXT,
  share_token TEXT,
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS payments (
  id TEXT PRIMARY KEY,
  invoice_id TEXT REFERENCES invoices(id),
  amount REAL NOT NULL,
  method TEXT DEFAULT 'check',
  reference_number TEXT,
  payment_date TEXT DEFAULT (date('now')),
  collected_by TEXT,
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS invoice_items (
  id TEXT PRIMARY KEY,
  invoice_id TEXT REFERENCES invoices(id),
  description TEXT NOT NULL,
  type TEXT DEFAULT 'labor',
  quantity REAL DEFAULT 1,
  unit_price REAL DEFAULT 0,
  total REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS expenses (
  id TEXT PRIMARY KEY,
  job_id TEXT REFERENCES jobs(id),
  category TEXT NOT NULL,
  vendor TEXT,
  description TEXT,
  amount REAL NOT NULL,
  receipt_url TEXT,
  receipt_data TEXT,
  expense_date TEXT DEFAULT (date('now')),
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS reviews (
  id TEXT PRIMARY KEY,
  customer_id TEXT REFERENCES customers(id),
  job_id TEXT REFERENCES jobs(id),
  rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
  text TEXT,
  photo_url TEXT,
  approved INTEGER DEFAULT 0,
  pushed_to_google INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS appointments (
  id TEXT PRIMARY KEY,
  customer_id TEXT REFERENCES customers(id),
  job_id TEXT REFERENCES jobs(id),
  title TEXT NOT NULL,
  description TEXT,
  service_type TEXT,
  date TEXT NOT NULL,
  time_start TEXT,
  time_end TEXT,
  status TEXT DEFAULT 'scheduled',
  reminder_sent INTEGER DEFAULT 0,
  weather_alert TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS chat_sessions (
  id TEXT PRIMARY KEY,
  customer_id TEXT,
  messages TEXT,
  emotion_log TEXT,
  summary TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS subcontractors (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  trade TEXT NOT NULL,
  phone TEXT,
  email TEXT,
  rating INTEGER DEFAULT 5,
  notes TEXT,
  available INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS permits (
  id TEXT PRIMARY KEY,
  job_id TEXT REFERENCES jobs(id),
  permit_number TEXT,
  type TEXT NOT NULL,
  status TEXT DEFAULT 'pending',
  jurisdiction TEXT,
  filed_date TEXT,
  expiration_date TEXT,
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS referrals (
  id TEXT PRIMARY KEY,
  referrer_id TEXT REFERENCES customers(id),
  referred_id TEXT REFERENCES customers(id),
  referrer_discount_applied INTEGER DEFAULT 0,
  referred_discount_applied INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS blog_posts (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  slug TEXT UNIQUE,
  content TEXT NOT NULL,
  excerpt TEXT,
  status TEXT DEFAULT 'draft',
  author TEXT DEFAULT 'Belle',
  tags TEXT,
  seo_title TEXT,
  seo_description TEXT,
  published_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS follow_ups (
  id TEXT PRIMARY KEY,
  customer_id TEXT REFERENCES customers(id),
  job_id TEXT REFERENCES jobs(id),
  type TEXT NOT NULL,
  step INTEGER DEFAULT 1,
  status TEXT DEFAULT 'pending',
  scheduled_at TEXT NOT NULL,
  sent_at TEXT,
  channel TEXT DEFAULT 'sms',
  message TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS time_entries (
  id TEXT PRIMARY KEY,
  job_id TEXT REFERENCES jobs(id),
  worker_name TEXT DEFAULT 'Adam',
  date TEXT DEFAULT (date('now')),
  start_time TEXT,
  end_time TEXT,
  hours REAL,
  hourly_rate REAL DEFAULT 75,
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS promotions (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT,
  discount_type TEXT DEFAULT 'percent',
  discount_value REAL DEFAULT 10,
  promo_code TEXT UNIQUE,
  active INTEGER DEFAULT 0,
  start_date TEXT,
  end_date TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS nps_responses (
  id TEXT PRIMARY KEY,
  customer_id TEXT REFERENCES customers(id),
  job_id TEXT REFERENCES jobs(id),
  score INTEGER NOT NULL CHECK(score >= 0 AND score <= 10),
  comment TEXT,
  follow_up_action TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS progress_photos (
  id TEXT PRIMARY KEY,
  job_id TEXT REFERENCES jobs(id),
  photo_url TEXT NOT NULL,
  caption TEXT,
  notified INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS hardware_orders (
  id TEXT PRIMARY KEY,
  store TEXT NOT NULL,
  items TEXT NOT NULL,
  status TEXT DEFAULT 'pending',
  job_id TEXT REFERENCES jobs(id),
  total_estimate REAL,
  created_at TEXT DEFAULT (datetime('now'))
);

-- Default settings
INSERT OR IGNORE INTO settings (key, value) VALUES
  ('belle_chat', '1'),
  ('belle_voice', '1'),
  ('wake_word', '1'),
  ('spanish_language', '0'),
  ('auto_follow_ups', '1'),
  ('twilio_calls', '1'),
  ('sms_reminders', '1'),
  ('whatsapp', '0'),
  ('review_requests', '1'),
  ('seasonal_promo', '0'),
  ('blog_seo', '0'),
  ('photo_ai', '1'),
  ('referral_program', '1'),
  ('weather_alerts', '1'),
  ('progress_sharing', '1'),
  ('nps_surveys', '1'),
  ('receipt_scanning', '1'),
  ('permit_tracking', '0'),
  ('social_feed', '0'),
  ('blade_3d', '1'),
  ('active_promo_id', '');

CREATE TABLE IF NOT EXISTS subscriptions (
  id TEXT PRIMARY KEY,
  service_name TEXT NOT NULL,
  provider TEXT NOT NULL,
  monthly_cost REAL NOT NULL DEFAULT 0,
  billing_cycle TEXT DEFAULT 'monthly',
  status TEXT DEFAULT 'active',
  account_email TEXT,
  start_date TEXT DEFAULT (date('now')),
  next_billing_date TEXT,
  category TEXT DEFAULT 'software',
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Default subscription tracking
INSERT OR IGNORE INTO subscriptions (id, service_name, provider, monthly_cost, category, status, notes) VALUES
  ('sub_claude', 'Belle AI (Claude Max)', 'Anthropic', 100.00, 'ai', 'planned', 'Primary AI for Belle chat via subprocess'),
  ('sub_zoho', 'Business Email', 'Zoho Mail', 1.00, 'email', 'planned', 'adam@profinishusa.com + aliases'),
  ('sub_twilio', 'SMS & Voice', 'Twilio', 20.00, 'communication', 'planned', 'Customer notifications, Belle calls Adam'),
  ('sub_domain', 'Domain Registration', 'GoDaddy', 1.50, 'hosting', 'active', 'profinishusa.com annual (~$18/yr)'),
  ('sub_cloudflare', 'DNS & Security', 'Cloudflare', 0.00, 'hosting', 'planned', 'Free plan — DNS, WAF, CDN'),
  ('sub_vercel', 'Website Hosting', 'Vercel', 0.00, 'hosting', 'active', 'Free plan — auto-deploy from GitHub'),
  ('sub_firebase', 'User Authentication', 'Firebase', 0.00, 'auth', 'planned', 'Free tier — email/Google/phone login'),
  ('sub_azure', 'AI Fallback (GPT-4.1)', 'Microsoft Azure', 0.00, 'ai', 'active', 'FREE until May 2026'),
  ('sub_elevenlabs', 'Voice (Belle TTS)', 'ElevenLabs', 5.00, 'ai', 'planned', 'Starter plan for Nova voice'),
  ('sub_openweather', 'Weather Data', 'NWS/OpenWeather', 0.00, 'data', 'active', 'Free — National Weather Service API');

-- Document Delivery System
CREATE TABLE IF NOT EXISTS document_deliveries (
  id TEXT PRIMARY KEY,
  doc_type TEXT NOT NULL DEFAULT 'INVOICE',
  doc_number TEXT,
  source_id TEXT,
  customer_name TEXT,
  customer_email TEXT,
  customer_phone TEXT,
  r2_key TEXT,
  view_token TEXT UNIQUE,
  total REAL DEFAULT 0,
  delivery_channel TEXT,
  delivery_status TEXT DEFAULT 'generated',
  delivered_to TEXT,
  delivered_at TEXT,
  last_viewed_at TEXT,
  view_count INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_doc_deliveries_token ON document_deliveries(view_token);
CREATE INDEX IF NOT EXISTS idx_doc_deliveries_type ON document_deliveries(doc_type);
CREATE INDEX IF NOT EXISTS idx_doc_deliveries_source ON document_deliveries(source_id);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_jobs_customer ON jobs(customer_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_invoices_customer ON invoices(customer_id);
CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(status);
CREATE INDEX IF NOT EXISTS idx_appointments_date ON appointments(date);
CREATE INDEX IF NOT EXISTS idx_reviews_approved ON reviews(approved);
CREATE INDEX IF NOT EXISTS idx_follow_ups_scheduled ON follow_ups(scheduled_at);
CREATE INDEX IF NOT EXISTS idx_blog_posts_status ON blog_posts(status);
CREATE INDEX IF NOT EXISTS idx_time_entries_job ON time_entries(job_id);
CREATE INDEX IF NOT EXISTS idx_expenses_job ON expenses(job_id);
