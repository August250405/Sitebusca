'use strict';

require('dotenv').config();

const express     = require('express');
const helmet      = require('helmet');
const cors        = require('cors');
const compression = require('compression');
const rateLimit   = require('express-rate-limit');
const morgan      = require('morgan');
const crypto      = require('crypto');
const path        = require('path');
const fs          = require('fs');
const NodeCache   = require('node-cache');
const Database    = require('better-sqlite3');

/* ============================================================
   CONFIGURAÇÃO
   ============================================================ */
const PORT          = parseInt(process.env.PORT || '3000', 10);
const NODE_ENV      = process.env.NODE_ENV || 'development';
const GEOAPIFY_KEY  = process.env.GEOAPIFY_API_KEY;
const TOKEN_SECRET  = process.env.TOKEN_SECRET || crypto.randomBytes(48).toString('hex');
const REQUIRE_TOKEN = process.env.REQUIRE_TOKEN !== 'false';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

const TOKEN_TTL_MS     = 15 * 60 * 1000;
const UPSTREAM_TIMEOUT = 12_000;
const CACHE_TTL_SEC    = 300;

/* Caminho ABSOLUTO para a pasta public (funciona em qualquer SO) */
const PUBLIC_PATH = path.join(__dirname, 'public');
const INDEX_PATH  = path.join(PUBLIC_PATH, 'index.html');

/* ============================================================
   VALIDAÇÕES INICIAIS
   ============================================================ */
if (!GEOAPIFY_KEY) {
  console.error('\n[FATAL] GEOAPIFY_API_KEY não definida.');
  console.error('        Configure a variável de ambiente no servidor.\n');
  process.exit(1);
}

/* Aviso se o index.html não existir (não fatal em dev) */
if (!fs.existsSync(INDEX_PATH)) {
  console.warn(`\n[AVISO] ${INDEX_PATH} não encontrado.`);
  console.warn('        O dashboard web não vai carregar até o arquivo existir.\n');
}

/* ============================================================
   BANCO DE DADOS — SQLite
   ============================================================ */
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'localleads.db');
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS searches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    location TEXT NOT NULL,
    category TEXT NOT NULL,
    radius INTEGER NOT NULL,
    center_lat REAL,
    center_lon REAL,
    center_formatted TEXT,
    total_results INTEGER DEFAULT 0,
    with_phone INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS establishments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id INTEGER NOT NULL,
    place_id TEXT,
    name TEXT,
    phone TEXT,
    address1 TEXT,
    address2 TEXT,
    city TEXT,
    state TEXT,
    postcode TEXT,
    primary_category TEXT,
    categories TEXT,
    lat REAL,
    lon REAL,
    distance REAL,
    FOREIGN KEY(search_id) REFERENCES searches(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_estab_search ON establishments(search_id);
  CREATE INDEX IF NOT EXISTS idx_estab_place ON establishments(place_id);

  CREATE TABLE IF NOT EXISTS leads_status (
    place_id TEXT PRIMARY KEY,
    status TEXT DEFAULT 'novo',
    notes TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

console.log(`[DB] SQLite em ${DB_PATH}`);

/* ============================================================
   APP + MIDDLEWARES
   ============================================================ */
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'", "'unsafe-inline'"],
      styleSrc:       ["'self'", "'unsafe-inline'"],
      imgSrc:         ["'self'", 'data:', 'blob:'],
      connectSrc:     ["'self'"],
      fontSrc:        ["'self'"],
      objectSrc:      ["'none'"],
      baseUri:        ["'self'"],
      frameAncestors: ["'none'"],
      formAction:     ["'self'"],
      upgradeInsecureRequests: NODE_ENV === 'production' ? [] : null,
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'same-origin' },
  referrerPolicy: { policy: 'no-referrer' },
  hsts: NODE_ENV === 'production'
    ? { maxAge: 31536000, includeSubDomains: true, preload: true }
    : false,
}));

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.length === 0) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error('Origem não autorizada pelo CORS'));
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'X-Auth-Token'],
  maxAge: 600,
}));

app.use(compression());
app.use(morgan(NODE_ENV === 'production'
  ? ':remote-addr - :method :url :status :res[content-length] - :response-time ms'
  : 'dev'));

app.use(express.json({ limit: '4mb' }));

/* ============================================================
   RATE LIMIT
   ============================================================ */
const limiterGlobal = rateLimit({
  windowMs: 60 * 1000, max: 120,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Muitas requisições. Aguarde um instante.' },
});
const limiterApi = rateLimit({
  windowMs: 60 * 1000, max: 25,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Limite de consultas atingido (25/min). Aguarde.' },
});
const limiterToken = rateLimit({
  windowMs: 60 * 1000, max: 10,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Muitas requisições de sessão. Aguarde.' },
});
app.use(limiterGlobal);

/* ============================================================
   CACHE
   ============================================================ */
const cache = new NodeCache({ stdTTL: CACHE_TTL_SEC, checkperiod: 60, useClones: false, maxKeys: 500 });

function cacheGet(key) {
  const v = cache.get(key);
  if (v) console.log(`[CACHE HIT] ${key.slice(0, 80)}`);
  return v;
}
function cacheSet(key, val) { cache.set(key, val); }

/* ============================================================
   TOKENS HMAC
   ============================================================ */
function signToken(ip) {
  const exp = Date.now() + TOKEN_TTL_MS;
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(`${ip}|${exp}`).digest('hex');
  return `${exp}.${sig}`;
}
function verifyToken(token, ip) {
  if (typeof token !== 'string' || token.length > 200) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [expStr, sig] = parts;
  const exp = parseInt(expStr, 10);
  if (!Number.isFinite(exp) || exp < Date.now()) return false;
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(`${ip}|${exp}`).digest('hex');
  if (sig.length !== expected.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  } catch { return false; }
}
function requireToken(req, res, next) {
  if (!REQUIRE_TOKEN) return next();
  const token = req.headers['x-auth-token'] || req.query._t;
  if (!verifyToken(token, req.ip)) {
    return res.status(401).json({ error: 'Sessão expirada. Recarregue a página.' });
  }
  next();
}

app.get('/api/token', limiterToken, (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.json({ token: signToken(req.ip), ttl: TOKEN_TTL_MS });
});

/* ============================================================
   VALIDAÇÃO
   ============================================================ */
const CATEGORY_RE = /^[a-z_]{2,40}(\.[a-z_]{2,40}){0,3}$/;
const FILTER_RE   = /^circle:-?\d{1,3}(\.\d{1,8})?,-?\d{1,3}(\.\d{1,8})?,\d{1,7}$/;

function sanitizeText(s, maxLen = 200) {
  if (typeof s !== 'string') return null;
  const t = s.replace(/[\x00-\x1F\x7F]/g, '').trim();
  if (!t || t.length > maxLen) return null;
  return t;
}
function validInt(v, min, max) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) && n >= min && n <= max ? n : null;
}

/* ============================================================
   PROXY GEOAPIFY
   ============================================================ */
async function callGeoapify(pathname, params) {
  const url = new URL('https://api.geoapify.com' + pathname);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, String(v));
  }
  url.searchParams.set('apiKey', GEOAPIFY_KEY);

  const ctrl = new AbortController();
  const to = setTimeout(() => ctrl.abort(), UPSTREAM_TIMEOUT);

  try {
    const r = await fetch(url, { signal: ctrl.signal });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      const msg = data.message || `Erro upstream (${r.status})`;
      const err = new Error(msg);
      err.status = r.status;
      throw err;
    }
    return data;
  } catch (e) {
    if (e.name === 'AbortError') {
      const err = new Error('A Geoapify demorou para responder. Tente novamente.');
      err.status = 504;
      throw err;
    }
    throw e;
  } finally {
    clearTimeout(to);
  }
}

/* ============================================================
   ROTAS GEOAPIFY
   ============================================================ */
app.get('/api/geocode', limiterApi, requireToken, async (req, res) => {
  try {
    const text  = sanitizeText(req.query.text, 200);
    const limit = Math.min(validInt(req.query.limit, 1, 5) || 1, 5);
    if (!text) return res.status(400).json({ error: 'Parâmetro "text" inválido ou ausente.' });

    const key = `geo:${text.toLowerCase()}:${limit}`;
    const cached = cacheGet(key);
    if (cached) return res.json(cached);

    const data = await callGeoapify('/v1/geocode/search', { text, limit, lang: 'pt' });
    cacheSet(key, data);
    res.json(data);
  } catch (err) {
    console.error('[geocode]', err.message);
    res.status(err.status || 500).json({ error: err.message || 'Erro interno' });
  }
});

app.get('/api/places', limiterApi, requireToken, async (req, res) => {
  try {
    const categories = sanitizeText(req.query.categories, 200);
    const filter     = sanitizeText(req.query.filter, 120);
    const limit      = Math.min(validInt(req.query.limit, 1, 500) || 100, 500);

    if (!categories || !CATEGORY_RE.test(categories)) {
      return res.status(400).json({ error: 'Categoria inválida.' });
    }
    if (!filter || !FILTER_RE.test(filter)) {
      return res.status(400).json({ error: 'Filtro de localização inválido.' });
    }

    const key = `plc:${categories}:${filter}:${limit}`;
    const cached = cacheGet(key);
    if (cached) return res.json(cached);

    const data = await callGeoapify('/v2/places', { categories, filter, limit, lang: 'pt' });
    cacheSet(key, data);
    res.json(data);
  } catch (err) {
    console.error('[places]', err.message);
    res.status(err.status || 500).json({ error: err.message || 'Erro interno' });
  }
});

/* ============================================================
   ROTAS DE HISTÓRICO
   ============================================================ */
app.post('/api/searches', limiterApi, requireToken, (req, res) => {
  try {
    const { query, center, results } = req.body || {};
    if (!query || !center || !Array.isArray(results)) {
      return res.status(400).json({ error: 'Payload inválido' });
    }
    const location = sanitizeText(query.location, 200);
    const category = sanitizeText(query.category, 100);
    const radius = validInt(query.radius, 100, 100000);
    if (!location || !category || !radius) {
      return res.status(400).json({ error: 'Parâmetros da busca inválidos' });
    }

    const withPhone = results.filter(r => r.phone).length;

    const insertSearch = db.prepare(`
      INSERT INTO searches (location, category, radius, center_lat, center_lon, center_formatted, total_results, with_phone)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const insertEstab = db.prepare(`
      INSERT INTO establishments
      (search_id, place_id, name, phone, address1, address2, city, state, postcode, primary_category, categories, lat, lon, distance)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const tx = db.transaction((data) => {
      const info = insertSearch.run(
        data.query.location,
        data.query.category,
        data.query.radius,
        data.center.lat,
        data.center.lon,
        data.center.formatted || '',
        data.results.length,
        withPhone
      );
      const searchId = info.lastInsertRowid;
      for (const r of data.results) {
        insertEstab.run(
          searchId,
          String(r.id || '').slice(0, 200),
          String(r.name || '').slice(0, 300),
          r.phone || null,
          String(r.address1 || '').slice(0, 300),
          String(r.address2 || '').slice(0, 300),
          String(r.city || '').slice(0, 100),
          String(r.state || '').slice(0, 100),
          String(r.postcode || '').slice(0, 20),
          String(r.primaryCategory || '').slice(0, 100),
          (r.categories || []).join(',').slice(0, 500),
          r.lat, r.lon, r.distance
        );
      }
      return searchId;
    });

    const searchId = tx({ query: { location, category, radius }, center, results });
    res.json({ ok: true, id: searchId });
  } catch (err) {
    console.error('[POST /api/searches]', err);
    res.status(500).json({ error: 'Erro ao salvar busca' });
  }
});

app.get('/api/searches', limiterApi, requireToken, (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT id, location, category, radius, center_formatted, total_results, with_phone, created_at
      FROM searches ORDER BY created_at DESC LIMIT 100
    `).all();
    res.json({ searches: rows });
  } catch (err) {
    console.error('[GET /api/searches]', err);
    res.status(500).json({ error: 'Erro ao buscar histórico' });
  }
});

app.get('/api/searches/:id', limiterApi, requireToken, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'ID inválido' });

    const search = db.prepare('SELECT * FROM searches WHERE id = ?').get(id);
    if (!search) return res.status(404).json({ error: 'Busca não encontrada' });

    const establishments = db.prepare('SELECT * FROM establishments WHERE search_id = ? ORDER BY distance ASC').all(id);

    const statuses = db.prepare('SELECT place_id, status, notes FROM leads_status').all();
    const statusMap = Object.fromEntries(statuses.map(s => [s.place_id, s]));

    const merged = establishments.map(e => ({
      ...e,
      lead_status: statusMap[e.place_id]?.status || 'novo',
      lead_notes: statusMap[e.place_id]?.notes || ''
    }));

    res.json({ search, establishments: merged });
  } catch (err) {
    console.error('[GET /api/searches/:id]', err);
    res.status(500).json({ error: 'Erro ao buscar detalhes' });
  }
});

app.patch('/api/leads/:place_id', limiterApi, requireToken, (req, res) => {
  try {
    const placeId = String(req.params.place_id || '').slice(0, 200);
    if (!placeId) return res.status(400).json({ error: 'place_id inválido' });

    const { status, notes } = req.body || {};
    const validStatuses = ['novo', 'contatado', 'interessado', 'cliente', 'descartado'];
    if (status && !validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Status inválido' });
    }

    db.prepare(`
      INSERT INTO leads_status (place_id, status, notes, updated_at)
      VALUES (?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(place_id) DO UPDATE SET
        status = COALESCE(excluded.status, leads_status.status),
        notes = COALESCE(excluded.notes, leads_status.notes),
        updated_at = CURRENT_TIMESTAMP
    `).run(placeId, status || 'novo', notes != null ? String(notes).slice(0, 2000) : '');

    res.json({ ok: true });
  } catch (err) {
    console.error('[PATCH /api/leads]', err);
    res.status(500).json({ error: 'Erro ao atualizar lead' });
  }
});

app.get('/api/stats', limiterApi, requireToken, (req, res) => {
  try {
    const totalSearches = db.prepare('SELECT COUNT(*) AS c FROM searches').get().c;
    const totalEstab    = db.prepare('SELECT COUNT(*) AS c FROM establishments').get().c;
    const uniquePlaces  = db.prepare('SELECT COUNT(DISTINCT place_id) AS c FROM establishments').get().c;
    const byStatus = db.prepare('SELECT status, COUNT(*) AS c FROM leads_status GROUP BY status').all();
    res.json({ totalSearches, totalEstablishments: totalEstab, uniquePlaces, leadsByStatus: byStatus });
  } catch (err) {
    console.error('[stats]', err);
    res.status(500).json({ error: 'Erro ao buscar estatísticas' });
  }
});

/* ============================================================
   HEALTH
   ============================================================ */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: Math.round(process.uptime()),
    cache: { keys: cache.keys().length, hits: cache.getStats().hits },
    tokenRequired: REQUIRE_TOKEN,
    db: { searches: db.prepare('SELECT COUNT(*) AS c FROM searches').get().c },
    public: fs.existsSync(INDEX_PATH) ? 'ok' : 'missing'
  });
});

/* ============================================================
   STATIC + SPA FALLBACK  ← PARTE CORRIGIDA
   ============================================================ */
app.use(express.static(PUBLIC_PATH, {
  maxAge: NODE_ENV === 'production' ? '1h' : 0,
  etag: true,
  index: 'index.html'
}));

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(INDEX_PATH, (err) => {
    if (err) {
      console.error('[STATIC] index.html não encontrado em', INDEX_PATH);
      res.status(500).json({
        error: 'index.html não encontrado no servidor.',
        procurado_em: INDEX_PATH,
        dica: 'Confirme que o arquivo public/index.html existe no repositório.'
      });
    }
  });
});

/* ============================================================
   ERROR HANDLER
   ============================================================ */
app.use((err, req, res, next) => {
  console.error('[ERRO]', err.message);
  if (err.message && err.message.includes('CORS')) {
    return res.status(403).json({ error: 'Origem não autorizada.' });
  }
  res.status(500).json({ error: 'Erro interno do servidor.' });
});

/* ============================================================
   BOOT
   ============================================================ */
if (process.env.VERCEL) {
  module.exports = app;
} else {
  const server = app.listen(PORT, () => {
    console.log('');
    console.log('  ◉  LocalLeads Proxy');
    console.log('  ─────────────────────────────────────────');
    console.log(`  ▸ Ambiente : ${NODE_ENV}`);
    console.log(`  ▸ Porta    : ${PORT}`);
    console.log(`  ▸ Tokens   : ${REQUIRE_TOKEN ? 'obrigatórios' : 'desativados'}`);
    console.log(`  ▸ CORS     : ${ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS.join(', ') : 'qualquer origem'}`);
    console.log(`  ▸ API key  : ${GEOAPIFY_KEY.slice(0, 6)}…${GEOAPIFY_KEY.slice(-4)} (protegida)`);
    console.log(`  ▸ DB       : ${DB_PATH}`);
    console.log(`  ▸ Public   : ${PUBLIC_PATH}`);
    console.log(`  ▸ Index    : ${fs.existsSync(INDEX_PATH) ? 'encontrado ✅' : 'NÃO ENCONTRADO ❌'}`);
    console.log('  ─────────────────────────────────────────');
    console.log('');
  });

  ['SIGTERM', 'SIGINT'].forEach(sig => {
    process.on(sig, () => {
      console.log(`\n[${sig}] Encerrando servidor…`);
      server.close(() => process.exit(0));
      setTimeout(() => process.exit(1), 5000);
    });
  });
}

process.on('unhandledRejection', (e) => console.error('[unhandledRejection]', e));
process.on('uncaughtException',  (e) => console.error('[uncaughtException]', e));
