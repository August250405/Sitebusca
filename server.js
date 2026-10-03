'use strict';

require('dotenv').config();

const express    = require('express');
const helmet     = require('helmet');
const cors       = require('cors');
const compression = require('compression');
const rateLimit  = require('express-rate-limit');
const morgan     = require('morgan');
const crypto     = require('crypto');
const path       = require('path');
const NodeCache  = require('node-cache');

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

const TOKEN_TTL_MS       = 15 * 60 * 1000; // 15 minutos
const UPSTREAM_TIMEOUT   = 12_000;         // 12 segundos
const CACHE_TTL_SEC      = 300;            // 5 minutos

/* ============================================================
   VALIDAÇÕES INICIAIS
   ============================================================ */
if (!GEOAPIFY_KEY) {
  console.error('\n[FATAL] GEOAPIFY_API_KEY não definida.');
  console.error('        Copie .env.example → .env e preencha a chave.\n');
  process.exit(1);
}

if (NODE_ENV === 'production') {
  if (!process.env.TOKEN_SECRET) {
    console.warn('\n[AVISO] TOKEN_SECRET não definida em produção.');
    console.warn('        Tokens serão invalidados a cada reinício do servidor.\n');
  }
  if (ALLOWED_ORIGINS.length === 0) {
    console.warn('\n[AVISO] ALLOWED_ORIGINS vazio em produção — CORS aberto para qualquer origem.\n');
  }
}

/* ============================================================
   APP
   ============================================================ */
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

/* ---------- Helmet: cabeçalhos de segurança ---------- */
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'", "'unsafe-inline'"],   // necessário para o dashboard
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

/* ---------- CORS restrito ---------- */
app.use(cors({
  origin(origin, cb) {
    // chamadas server-to-server / curl não têm origin
    if (!origin) return cb(null, true);
    // se ALLOWED_ORIGINS vazio → permite tudo (só útil em dev)
    if (ALLOWED_ORIGINS.length === 0) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error('Origem não autorizada pelo CORS'));
  },
  methods: ['GET'],
  allowedHeaders: ['Content-Type', 'X-Auth-Token'],
  maxAge: 600,
}));

/* ---------- Compressão + logs ---------- */
app.use(compression());
app.use(morgan(NODE_ENV === 'production'
  ? ':remote-addr - :method :url :status :res[content-length] - :response-time ms'
  : 'dev'));

/* ---------- Parser com limite de payload ---------- */
app.use(express.json({ limit: '4kb' }));

/* ============================================================
   RATE LIMITING (3 níveis)
   ============================================================ */
const limiterGlobal = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas requisições. Aguarde um instante.' },
});

const limiterApi = rateLimit({
  windowMs: 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Limite de consultas atingido (25/min). Aguarde.' },
});

const limiterToken = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas requisições de sessão. Aguarde.' },
});

app.use(limiterGlobal);

/* ============================================================
   CACHE (evita bater na Geoapify em consultas repetidas)
   ============================================================ */
const cache = new NodeCache({
  stdTTL: CACHE_TTL_SEC,
  checkperiod: 60,
  useClones: false,
  maxKeys: 500,
});

function cacheGet(key) {
  const v = cache.get(key);
  if (v) console.log(`[CACHE HIT] ${key.slice(0, 80)}`);
  return v;
}
function cacheSet(key, val) {
  cache.set(key, val);
}

/* ============================================================
   TOKENS HMAC (vinculados ao IP do cliente)
   ============================================================ */
function signToken(ip) {
  const exp = Date.now() + TOKEN_TTL_MS;
  const sig = crypto.createHmac('sha256', TOKEN_SECRET)
    .update(`${ip}|${exp}`)
    .digest('hex');
  return `${exp}.${sig}`;
}

function verifyToken(token, ip) {
  if (typeof token !== 'string' || token.length > 200) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;

  const [expStr, sig] = parts;
  const exp = parseInt(expStr, 10);
  if (!Number.isFinite(exp) || exp < Date.now()) return false;

  const expected = crypto.createHmac('sha256', TOKEN_SECRET)
    .update(`${ip}|${exp}`)
    .digest('hex');

  if (sig.length !== expected.length) return false;
  try {
    return crypto.timingSafeEqual(
      Buffer.from(sig, 'hex'),
      Buffer.from(expected, 'hex')
    );
  } catch {
    return false;
  }
}

function requireToken(req, res, next) {
  if (!REQUIRE_TOKEN) return next();
  const token = req.headers['x-auth-token'] || req.query._t;
  if (!verifyToken(token, req.ip)) {
    return res.status(401).json({ error: 'Sessão expirada. Recarregue a página.' });
  }
  next();
}

/* Endpoint para o navegador obter um token de curta duração */
app.get('/api/token', limiterToken, (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.json({
    token: signToken(req.ip),
    ttl: TOKEN_TTL_MS,
  });
});

/* ============================================================
   VALIDAÇÃO / SANITIZAÇÃO
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
   PROXY PARA A GEOAPIFY
   ============================================================ */
async function callGeoapify(pathname, params) {
  const url = new URL('https://api.geoapify.com' + pathname);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') {
      url.searchParams.set(k, String(v));
    }
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
   ROTAS DA API
   ============================================================ */

/* ---------- GET /api/geocode ---------- */
app.get('/api/geocode', limiterApi, requireToken, async (req, res) => {
  try {
    const text  = sanitizeText(req.query.text, 200);
    const limit = Math.min(validInt(req.query.limit, 1, 5) || 1, 5);
    const lang  = 'pt';

    if (!text) {
      return res.status(400).json({ error: 'Parâmetro "text" inválido ou ausente.' });
    }

    const key = `geo:${text.toLowerCase()}:${limit}`;
    const cached = cacheGet(key);
    if (cached) return res.json(cached);

    const data = await callGeoapify('/v1/geocode/search', { text, limit, lang });
    cacheSet(key, data);
    res.json(data);
  } catch (err) {
    console.error('[geocode]', err.message);
    res.status(err.status || 500).json({ error: err.message || 'Erro interno' });
  }
});

/* ---------- GET /api/places ---------- */
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

    const data = await callGeoapify('/v2/places', {
      categories,
      filter,
      limit,
      lang: 'pt',
    });
    cacheSet(key, data);
    res.json(data);
  } catch (err) {
    console.error('[places]', err.message);
    res.status(err.status || 500).json({ error: err.message || 'Erro interno' });
  }
});

/* ============================================================
   HEALTH CHECK
   ============================================================ */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: Math.round(process.uptime()),
    cache: { keys: cache.keys().length, hits: cache.getStats().hits },
    tokenRequired: REQUIRE_TOKEN,
  });
});

/* ============================================================
   ARQUIVOS ESTÁTICOS (o dashboard)
   ============================================================ */
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: NODE_ENV === 'production' ? '1h' : 0,
  etag: true,
}));

/* SPA fallback — qualquer rota desconhecida entrega o index */
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/* ============================================================
   HANDLERS DE ERRO
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
const server = app.listen(PORT, () => {
  console.log('');
  console.log('  ◉  LocalLeads Proxy');
  console.log('  ─────────────────────────────────────────');
  console.log(`  ▸ Ambiente : ${NODE_ENV}`);
  console.log(`  ▸ Porta    : ${PORT}`);
  console.log(`  ▸ Tokens   : ${REQUIRE_TOKEN ? 'obrigatórios' : 'desativados'}`);
  console.log(`  ▸ CORS     : ${ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS.join(', ') : 'qualquer origem (dev)'}`);
  console.log(`  ▸ API key  : ${GEOAPIFY_KEY.slice(0, 6)}…${GEOAPIFY_KEY.slice(-4)} (protegida)`);
  console.log('  ─────────────────────────────────────────');
  console.log('');
});

/* Graceful shutdown */
['SIGTERM', 'SIGINT'].forEach(sig => {
  process.on(sig, () => {
    console.log(`\n[${sig}] Encerrando servidor…`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000);
  });
});

process.on('unhandledRejection', (e) => console.error('[unhandledRejection]', e));
process.on('uncaughtException',  (e) => console.error('[uncaughtException]', e));