require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const { randomUUID, timingSafeEqual, createHmac } = require('crypto');
const fetch = require('node-fetch');
const QRCode = require('qrcode');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { encrypt, decrypt } = require('./lib_crypto');

const COUNTRIES = [
  { code: 'AE', name_ru: 'ОАЭ', flag: '🇦🇪' },
  { code: 'AL', name_ru: 'Албания', flag: '🇦🇱' },
  { code: 'AM', name_ru: 'Армения', flag: '🇦🇲' },
  { code: 'AR', name_ru: 'Аргентина', flag: '🇦🇷' },
  { code: 'AT', name_ru: 'Австрия', flag: '🇦🇹' },
  { code: 'AU', name_ru: 'Австралия', flag: '🇦🇺' },
  { code: 'AZ', name_ru: 'Азербайджан', flag: '🇦🇿' },
  { code: 'BA', name_ru: 'Босния и Герцеговина', flag: '🇧🇦' },
  { code: 'BE', name_ru: 'Бельгия', flag: '🇧🇪' },
  { code: 'BG', name_ru: 'Болгария', flag: '🇧🇬' },
  { code: 'BH', name_ru: 'Бахрейн', flag: '🇧🇭' },
  { code: 'BR', name_ru: 'Бразилия', flag: '🇧🇷' },
  { code: 'BY', name_ru: 'Беларусь', flag: '🇧🇾' },
  { code: 'CA', name_ru: 'Канада', flag: '🇨🇦' },
  { code: 'CH', name_ru: 'Швейцария', flag: '🇨🇭' },
  { code: 'CL', name_ru: 'Чили', flag: '🇨🇱' },
  { code: 'CN', name_ru: 'Китай', flag: '🇨🇳' },
  { code: 'CO', name_ru: 'Колумбия', flag: '🇨🇴' },
  { code: 'CR', name_ru: 'Коста-Рика', flag: '🇨🇷' },
  { code: 'CY', name_ru: 'Кипр', flag: '🇨🇾' },
  { code: 'CZ', name_ru: 'Чехия', flag: '🇨🇿' },
  { code: 'DE', name_ru: 'Германия', flag: '🇩🇪' },
  { code: 'DK', name_ru: 'Дания', flag: '🇩🇰' },
  { code: 'EE', name_ru: 'Эстония', flag: '🇪🇪' },
  { code: 'EG', name_ru: 'Египет', flag: '🇪🇬' },
  { code: 'ES', name_ru: 'Испания', flag: '🇪🇸' },
  { code: 'FI', name_ru: 'Финляндия', flag: '🇫🇮' },
  { code: 'FR', name_ru: 'Франция', flag: '🇫🇷' },
  { code: 'GB', name_ru: 'Великобритания', flag: '🇬🇧' },
  { code: 'GE', name_ru: 'Грузия', flag: '🇬🇪' },
  { code: 'GR', name_ru: 'Греция', flag: '🇬🇷' },
  { code: 'HK', name_ru: 'Гонконг', flag: '🇭🇰' },
  { code: 'HR', name_ru: 'Хорватия', flag: '🇭🇷' },
  { code: 'HU', name_ru: 'Венгрия', flag: '🇭🇺' },
  { code: 'ID', name_ru: 'Индонезия', flag: '🇮🇩' },
  { code: 'IE', name_ru: 'Ирландия', flag: '🇮🇪' },
  { code: 'IL', name_ru: 'Израиль', flag: '🇮🇱' },
  { code: 'IN', name_ru: 'Индия', flag: '🇮🇳' },
  { code: 'IQ', name_ru: 'Ирак', flag: '🇮🇶' },
  { code: 'IS', name_ru: 'Исландия', flag: '🇮🇸' },
  { code: 'IT', name_ru: 'Италия', flag: '🇮🇹' },
  { code: 'JO', name_ru: 'Иордания', flag: '🇯🇴' },
  { code: 'JP', name_ru: 'Япония', flag: '🇯🇵' },
  { code: 'KG', name_ru: 'Кыргызстан', flag: '🇰🇬' },
  { code: 'KR', name_ru: 'Южная Корея', flag: '🇰🇷' },
  { code: 'KW', name_ru: 'Кувейт', flag: '🇰🇼' },
  { code: 'KZ', name_ru: 'Казахстан', flag: '🇰🇿' },
  { code: 'LT', name_ru: 'Литва', flag: '🇱🇹' },
  { code: 'LU', name_ru: 'Люксембург', flag: '🇱🇺' },
  { code: 'LV', name_ru: 'Латвия', flag: '🇱🇻' },
  { code: 'MA', name_ru: 'Марокко', flag: '🇲🇦' },
  { code: 'MD', name_ru: 'Молдова', flag: '🇲🇩' },
  { code: 'ME', name_ru: 'Черногория', flag: '🇲🇪' },
  { code: 'MK', name_ru: 'Северная Македония', flag: '🇲🇰' },
  { code: 'MT', name_ru: 'Мальта', flag: '🇲🇹' },
  { code: 'MX', name_ru: 'Мексика', flag: '🇲🇽' },
  { code: 'MY', name_ru: 'Малайзия', flag: '🇲🇾' },
  { code: 'NG', name_ru: 'Нигерия', flag: '🇳🇬' },
  { code: 'NL', name_ru: 'Нидерланды', flag: '🇳🇱' },
  { code: 'NO', name_ru: 'Норвегия', flag: '🇳🇴' },
  { code: 'NZ', name_ru: 'Новая Зеландия', flag: '🇳🇿' },
  { code: 'OM', name_ru: 'Оман', flag: '🇴🇲' },
  { code: 'PA', name_ru: 'Панама', flag: '🇵🇦' },
  { code: 'PE', name_ru: 'Перу', flag: '🇵🇪' },
  { code: 'PH', name_ru: 'Филиппины', flag: '🇵🇭' },
  { code: 'PK', name_ru: 'Пакистан', flag: '🇵🇰' },
  { code: 'PL', name_ru: 'Польша', flag: '🇵🇱' },
  { code: 'PT', name_ru: 'Португалия', flag: '🇵🇹' },
  { code: 'QA', name_ru: 'Катар', flag: '🇶🇦' },
  { code: 'RO', name_ru: 'Румыния', flag: '🇷🇴' },
  { code: 'RS', name_ru: 'Сербия', flag: '🇷🇸' },
  { code: 'RU', name_ru: 'Россия', flag: '🇷🇺' },
  { code: 'SA', name_ru: 'Саудовская Аравия', flag: '🇸🇦' },
  { code: 'SE', name_ru: 'Швеция', flag: '🇸🇪' },
  { code: 'SG', name_ru: 'Сингапур', flag: '🇸🇬' },
  { code: 'SI', name_ru: 'Словения', flag: '🇸🇮' },
  { code: 'SK', name_ru: 'Словакия', flag: '🇸🇰' },
  { code: 'TH', name_ru: 'Таиланд', flag: '🇹🇭' },
  { code: 'TJ', name_ru: 'Таджикистан', flag: '🇹🇯' },
  { code: 'TR', name_ru: 'Турция', flag: '🇹🇷' },
  { code: 'TW', name_ru: 'Тайвань', flag: '🇹🇼' },
  { code: 'UA', name_ru: 'Украина', flag: '🇺🇦' },
  { code: 'US', name_ru: 'США', flag: '🇺🇸' },
  { code: 'UZ', name_ru: 'Узбекистан', flag: '🇺🇿' },
  { code: 'VN', name_ru: 'Вьетнам', flag: '🇻🇳' },
  { code: 'ZA', name_ru: 'ЮАР', flag: '🇿🇦' }
];

function getCountryFlag(countryName) {
  const found = COUNTRIES.find(c => c.name_ru === countryName);
  return found?.flag || '🌐';
}

function getNodeDisplayName(node) {
  const base = String(node?.country_name_ru || node?.name || 'Узел').trim();
  const suffix = String(node?.label_suffix || '').trim();

  if (!suffix) return base;
  if (/^\d+$/.test(suffix)) return `${base}-${suffix}`;

  return `${base} ${suffix}`;
}

function getNodePublicName(node) {
  const name = getNodeDisplayName(node);
  const flag = node?.country_flag || getCountryFlag(node?.country_name_ru || node?.name);
  return `${flag} ${name}`.trim();
}

const app = express();
const db = new Database('./data/app.db');


function assertKnownIdentifier(value) {
  const clean = String(value || '');
  if (!/^[A-Za-z0-9_]+$/.test(clean)) throw new Error(`Unsafe database identifier: ${clean}`);
  return clean;
}

function columnExists(table, column) {
  const safeTable = assertKnownIdentifier(table);
  return db.prepare(`PRAGMA table_info(${safeTable})`).all().some(row => row.name === column);
}

function addColumnIfMissing(table, column, definition) {
  const safeTable = assertKnownIdentifier(table);
  const safeColumn = assertKnownIdentifier(column);
  if (columnExists(safeTable, safeColumn)) return;
  db.prepare(`ALTER TABLE ${safeTable} ADD COLUMN ${safeColumn} ${definition}`).run();
}

function backfillSchemaDefaults() {
  try { db.prepare("UPDATE clients SET display_name = login WHERE (display_name IS NULL OR display_name = '') AND login IS NOT NULL").run(); } catch (_) {}
  try { db.prepare("UPDATE clients SET comment = '' WHERE comment IS NULL").run(); } catch (_) {}
  try { db.prepare("UPDATE clients SET flow = '' WHERE flow IS NULL").run(); } catch (_) {}
  try { db.prepare("UPDATE nodes SET panel_path = '' WHERE panel_path IS NULL").run(); } catch (_) {}
  try { db.prepare("UPDATE nodes SET sub_base_url = '' WHERE sub_base_url IS NULL").run(); } catch (_) {}
  try { db.prepare("UPDATE nodes SET label_suffix = '' WHERE label_suffix IS NULL").run(); } catch (_) {}
  try { db.prepare("UPDATE client_nodes SET remote_sub_url = '' WHERE remote_sub_url IS NULL").run(); } catch (_) {}

  try {
    const rows = db.prepare("SELECT id, uuid, sub_slug FROM clients WHERE sub_slug IS NULL OR sub_slug = ''").all();
    const existing = new Set(db.prepare("SELECT sub_slug FROM clients WHERE sub_slug IS NOT NULL AND sub_slug != ''").all().map(r => String(r.sub_slug)));
    const update = db.prepare('UPDATE clients SET sub_slug = ? WHERE id = ?');
    for (const row of rows) {
      let slug = String(row.uuid || '').replace(/-/g, '').slice(0, 16).toLowerCase();
      if (!slug || existing.has(slug)) {
        do { slug = randomUUID().replace(/-/g, '').slice(0, 16); } while (existing.has(slug));
      }
      existing.add(slug);
      update.run(slug, row.id);
    }
  } catch (_) {}
}

const PORT = Number(process.env.PORT || 3000);
const APP_SECRET = process.env.APP_SECRET || 'change-me';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-session-secret';
const ADMIN_BIND_SESSION_TO_IP = String(process.env.ADMIN_BIND_SESSION_TO_IP || '0') === '1';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const DEFAULT_SUBSCRIPTION_NAME = process.env.SUBSCRIPTION_NAME || 'VPN';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';
const PANEL_ACCESS_KEY = String(process.env.PANEL_ACCESS_KEY || '').trim();
const TRUST_PROXY = String(process.env.TRUST_PROXY || '').toLowerCase() === '1' || String(process.env.TRUST_PROXY || '').toLowerCase() === 'true';
const SESSION_SECURE = String(process.env.SESSION_SECURE || '').toLowerCase() === '1' || String(process.env.SESSION_SECURE || '').toLowerCase() === 'true';
const LOGIN_MAX_ATTEMPTS = Number(process.env.LOGIN_MAX_ATTEMPTS || 5);
const LOGIN_LOCK_MINUTES = Number(process.env.LOGIN_LOCK_MINUTES || 15);
const INSTALL_BIND_IP = String(process.env.INSTALL_BIND_IP || '').trim();
const APP_DIR_HINT = process.env.APP_DIR || '/opt/3xui-aggregator';
const BACKUP_DIR_HINT = process.env.BACKUP_DIR || '/opt/3xui-backups';

if (TRUST_PROXY) app.set('trust proxy', 1);

const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 12000);
const SUBSCRIPTION_STATS_TIMEOUT_MS = Number(process.env.SUBSCRIPTION_STATS_TIMEOUT_MS || 3500);

async function fetchWithTimeout(url, options = {}, timeoutMs = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      ...options,
      signal: options.signal || controller.signal
    });
  } finally {
    clearTimeout(timer);
  }
}

function toAsciiHeaderFilename(value, fallback = 'subscription') {
  const text = String(value || '').trim();
  const cleaned = text
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^A-Za-z0-9._-]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 120);

  return cleaned || fallback;
}

function setAttachmentDispositionHeader(res, unicodeFileName, fallbackBaseName = 'subscription') {
  // Node.js rejects non-Latin-1 characters in ordinary header values.
  // Emoji/Cyrillic names such as "⚡Aero⚡.json" must therefore be sent
  // with an ASCII fallback in `filename=` and the real UTF-8 name in
  // RFC 5987 `filename*=`. Otherwise /json subscriptions crash with 502.
  const original = String(unicodeFileName || `${fallbackBaseName}.txt`).replace(/[\r\n]/g, '_');
  const ext = (original.match(/\.([A-Za-z0-9]{1,12})$/) || [])[1] || 'txt';
  const fallback = `${toAsciiHeaderFilename(original.replace(/\.[^.]*$/, ''), fallbackBaseName)}.${ext}`
    .replace(/[\\";\r\n]/g, '_');

  res.setHeader(
    'Content-Disposition',
    `attachment; filename="${fallback}"; filename*=UTF-8''${encodeURIComponent(original)}`
  );
}

function setSubscriptionNoCacheHeaders(res, subscriptionName = 'VPN', ext = 'txt') {
  const safeName = String(subscriptionName || 'VPN').trim() || 'VPN';
  const base64Title = Buffer.from(safeName).toString('base64');
  const fileName = `${safeName}.${ext}`;
  const intervalHours = getSubscriptionUpdateIntervalHours();
  const clientAutoUpdate = getSetting('subscription_client_auto_update_enabled', '1') !== '0';

  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
  res.setHeader('X-Accel-Buffering', 'no');
  res.setHeader('Profile-Title', `base64:${base64Title}`);
  res.setHeader('Subscription-Title', `base64:${base64Title}`);
  // Эти заголовки не зависят от Happ Provider ID: они нужны, чтобы клиенты,
  // которые умеют читать период обновления подписки, снова видели автообновление.
  if (clientAutoUpdate) {
    res.setHeader('Profile-Update-Interval', String(intervalHours));
    res.setHeader('Subscription-Update-Interval', String(intervalHours));
    res.setHeader('Subscription-Auto-Update-Enable', '1');
    res.setHeader('Auto-Update', String(intervalHours));
  }
  setAttachmentDispositionHeader(res, fileName, 'subscription');
}

function safeFileSegment(value, fallback = 'panel') {
  const text = String(value || '').trim().toLowerCase();
  const safe = text
    .replace(/^https?:\/\//i, '')
    .replace(/\/+$/g, '')
    .replace(/[^a-z0-9а-яё._-]+/giu, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
  return safe || fallback;
}

function getRequestPanelHost(req) {
  const forwardedHost = TRUST_PROXY ? String(req.headers['x-forwarded-host'] || '').split(',')[0].trim() : '';
  const hostHeader = String(forwardedHost || req.headers.host || '').trim();
  if (hostHeader) return hostHeader;

  try {
    return new URL(BASE_URL).host || 'localhost';
  } catch (_) {
    return 'localhost';
  }
}

function getBackupPanelIdentity(req) {
  return safeFileSegment(getRequestPanelHost(req), safeFileSegment(BASE_URL, 'panel'));
}

function buildBackupFileName(req, ext = 'json') {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const panelId = getBackupPanelIdentity(req);
  return `3xui-aggregator-backup-${stamp}-${panelId}.${ext}`;
}


app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: './data' }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: SESSION_SECURE,
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
}));

function safeTokenEquals(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  if (left.length !== right.length || right.length === 0) return false;
  return timingSafeEqual(left, right);
}

const PANEL_REMEMBER_COOKIE = 'agg_panel_access';
const PANEL_REMEMBER_DAYS = 30;

function parseCookies(req) {
  const raw = String(req.headers.cookie || '');
  const out = {};
  raw.split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (key) out[key] = decodeURIComponent(value || '');
  });
  return out;
}

function signPanelRememberToken(accessKey) {
  if (!accessKey) return '';
  return createHmac('sha256', SESSION_SECRET)
    .update('panel-access:' + String(accessKey))
    .digest('hex');
}

function hasValidPanelRememberCookie(req, accessKey) {
  const token = parseCookies(req)[PANEL_REMEMBER_COOKIE] || '';
  const expected = signPanelRememberToken(accessKey);
  return safeTokenEquals(token, expected);
}

function setPanelRememberCookie(res, accessKey) {
  const token = signPanelRememberToken(accessKey);
  if (!token) return;
  res.cookie(PANEL_REMEMBER_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: SESSION_SECURE,
    maxAge: PANEL_REMEMBER_DAYS * 24 * 60 * 60 * 1000
  });
}

function isPublicSubscriptionPath(pathname) {
  return pathname.startsWith('/sub/')
    || pathname.startsWith('/json/')
    || pathname.startsWith('/happ/')
    || pathname.startsWith('/happ-routing/')
    || pathname.startsWith('/happ-routing-json/')
    || pathname.startsWith('/open/')
    || pathname === '/qr'
    || pathname === '/healthz';
}

function isStaticAssetPath(pathname) {
  return pathname.startsWith('/css/')
    || pathname.startsWith('/js/')
    || pathname.startsWith('/img/')
    || pathname === '/favicon.ico';
}

function requirePanelAccessKey(req, res, next) {
  const accessKey = getCurrentPanelAccessKey();
  if (!accessKey) return next();
  if (isPublicSubscriptionPath(req.path) || isStaticAssetPath(req.path)) return next();

  // Если пользователь уже прошёл обычный вход, secret-key больше не нужен для
  // переходов внутри панели. Иначе после успешного /login браузер попадал на
  // /dashboard уже без параметра key и получал 404.
  if (req.session?.userId) return next();
  if (req.session?.panelAccessGranted === true) return next();

  if (hasValidPanelRememberCookie(req, accessKey)) {
    req.session.panelAccessGranted = true;
    return next();
  }

  const providedKey = String(req.query.key || req.query.panel_key || req.headers['x-panel-key'] || '').trim();
  if (safeTokenEquals(providedKey, accessKey)) {
    req.session.panelAccessGranted = true;
    setPanelRememberCookie(res, accessKey);

    // /mobile-login специально не очищаем на уровне middleware: этот маршрут
    // ставит долгий cookie и сам перенаправляет пользователя. Его удобно
    // сохранять ярлыком на телефоне.
    if (req.path === '/mobile-login') return next();

    if (req.method === 'GET' && (req.query.key || req.query.panel_key)) {
      const cleanUrl = req.originalUrl
        .replace(/([?&])(key|panel_key)=[^&]*&?/g, '$1')
        .replace(/[?&]$/, '')
        .replace('?&', '?');
      return res.redirect(cleanUrl || '/login');
    }

    return next();
  }

  return res.status(404).send('Not found');
}

app.use(requirePanelAccessKey);

function buildLoginRedirectPath(message = '') {
  const params = new URLSearchParams();
  const accessKey = getCurrentPanelAccessKey();
  if (accessKey) params.set('key', accessKey);
  if (message) params.set('message', message);
  const query = params.toString();
  return query ? `/login?${query}` : '/login';
}

function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS app_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS nodes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      panel_url TEXT NOT NULL,
      panel_path TEXT DEFAULT '',
      sub_base_url TEXT DEFAULT '',
      username TEXT NOT NULL,
      password_enc TEXT NOT NULL,
      inbound_id INTEGER NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      last_status TEXT DEFAULT 'unknown',
      last_error TEXT DEFAULT '',
      country_code TEXT DEFAULT '',
      country_name_ru TEXT DEFAULT '',
      country_flag TEXT DEFAULT '',
      label_suffix TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      login TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL,
      uuid TEXT NOT NULL,
      sub_slug TEXT UNIQUE NOT NULL,
      duration_days INTEGER NOT NULL DEFAULT 0,
      traffic_gb INTEGER NOT NULL DEFAULT 0,
      limit_ip INTEGER NOT NULL DEFAULT 1,
      expiry_time INTEGER NOT NULL DEFAULT 0,
      enabled INTEGER NOT NULL DEFAULT 1,
      comment TEXT NOT NULL DEFAULT '',
      flow TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS client_nodes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id INTEGER NOT NULL,
      node_id INTEGER NOT NULL,
      remote_email TEXT NOT NULL,
      remote_uuid TEXT NOT NULL,
      remote_sub_url TEXT DEFAULT '',
      traffic_gb INTEGER NOT NULL DEFAULT 0,
      limit_ip INTEGER DEFAULT NULL,
      upload_bytes INTEGER NOT NULL DEFAULT 0,
      download_bytes INTEGER NOT NULL DEFAULT 0,
      used_bytes INTEGER NOT NULL DEFAULT 0,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(client_id, node_id)
    );

    CREATE TABLE IF NOT EXISTS node_inbound_cache (
      node_id INTEGER PRIMARY KEY,
      inbound_id INTEGER NOT NULL,
      inbound_json TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  addColumnIfMissing('nodes', 'panel_path', "TEXT DEFAULT ''");
  addColumnIfMissing('nodes', 'sub_base_url', "TEXT DEFAULT ''");
  addColumnIfMissing('nodes', 'country_code', "TEXT DEFAULT ''");
  addColumnIfMissing('nodes', 'country_name_ru', "TEXT DEFAULT ''");
  addColumnIfMissing('nodes', 'country_flag', "TEXT DEFAULT ''");
  addColumnIfMissing('nodes', 'label_suffix', "TEXT DEFAULT ''");
  addColumnIfMissing('nodes', 'enabled', 'INTEGER NOT NULL DEFAULT 1');
  addColumnIfMissing('nodes', 'last_status', "TEXT DEFAULT 'unknown'");
  addColumnIfMissing('nodes', 'last_error', "TEXT DEFAULT ''");

  addColumnIfMissing('clients', 'display_name', "TEXT NOT NULL DEFAULT ''");
  addColumnIfMissing('clients', 'uuid', "TEXT NOT NULL DEFAULT ''");
  addColumnIfMissing('clients', 'sub_slug', "TEXT NOT NULL DEFAULT ''");
  addColumnIfMissing('clients', 'duration_days', 'INTEGER NOT NULL DEFAULT 0');
  addColumnIfMissing('clients', 'traffic_gb', 'INTEGER NOT NULL DEFAULT 0');
  addColumnIfMissing('clients', 'limit_ip', 'INTEGER NOT NULL DEFAULT 1');
  addColumnIfMissing('clients', 'expiry_time', 'INTEGER NOT NULL DEFAULT 0');
  addColumnIfMissing('clients', 'enabled', 'INTEGER NOT NULL DEFAULT 1');
  addColumnIfMissing('clients', 'comment', "TEXT NOT NULL DEFAULT ''");
  addColumnIfMissing('clients', 'flow', "TEXT NOT NULL DEFAULT ''");

  addColumnIfMissing('client_nodes', 'remote_sub_url', "TEXT DEFAULT ''");
  addColumnIfMissing('client_nodes', 'traffic_gb', 'INTEGER NOT NULL DEFAULT 0');
  addColumnIfMissing('client_nodes', 'limit_ip', 'INTEGER DEFAULT NULL');
  addColumnIfMissing('client_nodes', 'upload_bytes', 'INTEGER NOT NULL DEFAULT 0');
  addColumnIfMissing('client_nodes', 'download_bytes', 'INTEGER NOT NULL DEFAULT 0');
  addColumnIfMissing('client_nodes', 'used_bytes', 'INTEGER NOT NULL DEFAULT 0');
  addColumnIfMissing('client_nodes', 'enabled', 'INTEGER NOT NULL DEFAULT 1');

  backfillSchemaDefaults();

  const existingAdmin = db.prepare('SELECT id FROM app_users WHERE username = ?').get(ADMIN_USERNAME);
  if (!existingAdmin) {
    const passwordHash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
    db.prepare('INSERT INTO app_users (username, password_hash) VALUES (?, ?)').run(ADMIN_USERNAME, passwordHash);
  }

  const existingSubName = db.prepare('SELECT value FROM app_settings WHERE key = ?').get('subscription_name');
  if (!existingSubName) {
    db.prepare('INSERT INTO app_settings (key, value) VALUES (?, ?)').run('subscription_name', DEFAULT_SUBSCRIPTION_NAME);
  }

  const existingAllowedIps = db.prepare('SELECT value FROM app_settings WHERE key = ?').get('admin_allowed_ips');
  if (!existingAllowedIps) {
    db.prepare('INSERT INTO app_settings (key, value) VALUES (?, ?)').run('admin_allowed_ips', '');
  }

  const defaultSettings = [
    ['show_sub_links', '1'],
    ['subscription_show_limits', '1'],
    ['subscription_userinfo_header', '1'],
    ['subscription_live_usage', '1'],
    ['subscription_update_interval_hours', '1'],
    ['subscription_client_auto_update_enabled', '1'],
    ['happ_provider_id', ''],
    ['json_mux_enabled', '0'],
    ['json_sniffing_enabled', '0'],
    ['happ_app_controls_enabled', '0'],
    ['happ_ping_tcp', '1'],
    ['happ_ping_result_icon', '1'],
    ['happ_fragmentation_enabled', '0'],
    ['happ_noises_enabled', '0'],
    ['happ_mux_enabled', '0'],
    ['happ_subscription_auto_update_enabled', '1'],
    ['happ_update_on_open_enabled', '0'],
    ['happ_ping_on_open_enabled', '1'],
    ['happ_subscriptions_collapse_enabled', '1'],
    ['happ_expand_now_enabled', '0'],
    ['happ_check_url_via_proxy_enabled', '0'],
    ['happ_sniffing_enabled', '0'],
    ['happ_force_apply_on_update_enabled', '0'],
    ['show_happ_links', '0'],
    ['json_mux_enabled', '0'],
    ['json_sniffing_enabled', '0'],
    ['update_repo_url', 'https://github.com/dagmagnat/3xui-Aggregator'],
    ['telegram_backup_enabled', '0'],
    ['telegram_backup_locked', '1'],
    ['telegram_backup_bot_token', ''],
    ['telegram_backup_chat_id', '']
  ];

  for (const [key, value] of defaultSettings) {
    const existing = db.prepare('SELECT value FROM app_settings WHERE key = ?').get(key);
    if (!existing) db.prepare('INSERT INTO app_settings (key, value) VALUES (?, ?)').run(key, value);
  }
}

initDb();
ensureMissingAppSettings();
applyHappSafeDefaultMigration();
syncDeploymentPublicUrlSettings();

function getClientIp(req) {
  const raw = TRUST_PROXY
    ? String(req.headers['x-forwarded-for'] || req.ip || req.socket.remoteAddress || '')
    : String(req.socket.remoteAddress || req.ip || '');

  return raw
    .split(',')[0]
    .trim()
    .replace(/^::ffff:/, '');
}

function parseAllowedIps() {
  const raw = getSetting('admin_allowed_ips', '');
  return String(raw || '')
    .split(/[\s,;]+/)
    .map(v => v.trim())
    .filter(Boolean);
}

function isAdminIpAllowed(req) {
  const allowed = parseAllowedIps();
  if (!allowed.length) return true;
  return allowed.includes(getClientIp(req));
}

function requireAllowedAdminIp(req, res, next) {
  if (isAdminIpAllowed(req)) return next();
  return res.status(403).send('Access denied: this IP is not allowed for admin panel.');
}

const loginFailures = new Map();

function loginFailureKey(req, username) {
  return `${getClientIp(req)}:${String(username || '').toLowerCase()}`;
}

function getLoginFailure(req, username) {
  const key = loginFailureKey(req, username);
  const item = loginFailures.get(key);
  if (!item) return { key, count: 0, lockedUntil: 0 };
  if (item.lockedUntil && Date.now() > item.lockedUntil) {
    loginFailures.delete(key);
    return { key, count: 0, lockedUntil: 0 };
  }
  return { key, ...item };
}

function requireAuth(req, res, next) {
  if (!isAdminIpAllowed(req)) {
    return req.session.destroy(() => res.status(403).send('Access denied: this IP is not allowed for admin panel.'));
  }

  if (!req.session.userId) return res.redirect(buildLoginRedirectPath());
  const now = Date.now();
  const currentIp = getClientIp(req);
  const lastActivity = Number(req.session.lastActivity || 0);
  const loginIp = String(req.session.loginIp || '');

  if (ADMIN_BIND_SESSION_TO_IP && loginIp && currentIp && loginIp !== currentIp) {
    return req.session.destroy(() => res.redirect(buildLoginRedirectPath()));
  }

  if (lastActivity && now - lastActivity > 30 * 24 * 60 * 60 * 1000) {
    return req.session.destroy(() => res.redirect(buildLoginRedirectPath()));
  }

  req.session.loginIp = currentIp;
  req.session.lastActivity = now;
  next();
}

function htmlEscape(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function normalizeSearchText(value) {
  return String(value ?? '')
    .normalize('NFKC')
    .trim()
    .replace(/\s+/g, ' ')
    .toLocaleLowerCase('ru-RU');
}

const escapeHtml = htmlEscape;

function formatServerErrorPage(title, err) {
  const message = htmlEscape(err?.message || err || 'Unknown error');
  const stack = htmlEscape(err?.stack || '');
  return `<!doctype html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${htmlEscape(title)} — ошибка</title>
  <style>
    body{font-family:Arial,sans-serif;background:#f6f7fb;color:#111827;padding:24px;line-height:1.5}
    .box{max-width:980px;margin:0 auto;background:white;border:1px solid #e5e7eb;border-radius:14px;padding:20px;box-shadow:0 8px 24px rgba(15,23,42,.08)}
    code,pre{background:#111827;color:#e5e7eb;border-radius:10px;padding:10px;display:block;overflow:auto;white-space:pre-wrap}
    .muted{color:#6b7280}.btn{display:inline-block;margin-top:12px;padding:10px 14px;border-radius:10px;background:#2563eb;color:white;text-decoration:none}
  </style>
</head>
<body>
  <div class="box">
    <h1>${htmlEscape(title)}</h1>
    <p>Страница не смогла отрисоваться. Точная ошибка уже записана в лог контейнера.</p>
    <p class="muted">Команда для проверки:</p>
    <code>docker logs --tail=200 3xui-aggregator</code>
    <p class="muted">Ошибка:</p>
    <code>${message}</code>
    ${stack ? `<details><summary>Stack trace</summary><pre>${stack}</pre></details>` : ''}
    <a class="btn" href="/dashboard">На главную</a>
  </div>
</body>
</html>`;
}

function renderClientsFallbackPage(res, params, err) {
  const clients = Array.isArray(params?.clients) ? params.clients : [];
  const baseUrl = String(params?.baseUrl || '').replace(/\/+$/, '');
  const rows = clients.map(client => {
    const slug = htmlEscape(client.sub_slug || '');
    const jsonUrl = slug ? `${baseUrl}/json/${slug}` : '';
    return `<tr>
      <td>${htmlEscape(client.id)}</td>
      <td>${htmlEscape(client.display_name || client.login || '')}</td>
      <td>${htmlEscape(client.login || '')}</td>
      <td>${htmlEscape(client.comment || '')}</td>
      <td>${client.enabled !== 0 ? 'Включён' : 'Отключён'}</td>
      <td>${jsonUrl ? `<code>${htmlEscape(jsonUrl)}</code>` : '-'}</td>
    </tr>`;
  }).join('');

  console.error('Clients EJS render failed, fallback page used:', err);
  return res.status(500).send(`<!doctype html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Клиенты — аварийный режим</title>
  <style>
    body{font-family:Arial,sans-serif;background:#f6f7fb;color:#111827;padding:24px;line-height:1.5}
    .box{max-width:1200px;margin:0 auto;background:white;border:1px solid #e5e7eb;border-radius:14px;padding:20px;box-shadow:0 8px 24px rgba(15,23,42,.08)}
    table{border-collapse:collapse;width:100%;margin-top:16px}td,th{border-bottom:1px solid #e5e7eb;padding:9px;text-align:left;vertical-align:top}
    code{background:#111827;color:#e5e7eb;border-radius:8px;padding:5px 7px;display:inline-block}.muted{color:#6b7280}.err{background:#fef2f2;color:#991b1b;border:1px solid #fecaca;border-radius:10px;padding:12px}.btn{display:inline-block;margin:8px 8px 0 0;padding:10px 14px;border-radius:10px;background:#2563eb;color:white;text-decoration:none}
  </style>
</head>
<body>
  <div class="box">
    <h1>Клиенты</h1>
    <div class="err">Основной шаблон страницы клиентов упал, поэтому открыт аварийный список. Пришли лог <code>docker logs --tail=200 3xui-aggregator</code>, если эта страница появится снова.</div>
    <p class="muted">Ошибка шаблона: <code>${htmlEscape(err?.message || err || 'Unknown error')}</code></p>
    <a class="btn" href="/dashboard">На главную</a>
    <a class="btn" href="/settings">Настройки</a>
    <h2>Всего клиентов: ${clients.length}</h2>
    <table>
      <thead><tr><th>ID</th><th>Имя</th><th>Логин</th><th>Комментарий</th><th>Статус</th><th>JSON</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="6">Клиентов пока нет.</td></tr>'}</tbody>
    </table>
  </div>
</body>
</html>`);
}

function render(res, view, params = {}) {
  const data = {
    ...params,
    currentPath: res.req.path
  };

  res.render(view, data, (err, html) => {
    if (!err) return res.send(html);

    console.error(`Render failed for view "${view}":`, err);

    if (view === 'clients') {
      return renderClientsFallbackPage(res, data, err);
    }

    return res.status(500).send(formatServerErrorPage(`Ошибка страницы ${view}`, err));
  });
}

function getSetting(key, fallback = '') {
  const row = db.prepare('SELECT value FROM app_settings WHERE key = ?').get(key);
  return row?.value ?? fallback;
}

function setSetting(key, value) {
  db.prepare(`
    INSERT INTO app_settings (key, value, updated_at)
    VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(key) DO UPDATE SET
      value = excluded.value,
      updated_at = CURRENT_TIMESTAMP
  `).run(key, String(value ?? ''));
}

function ensureMissingAppSettings() {
  const defaults = [
    ['show_sub_links', '1'],
    ['subscription_show_limits', '1'],
    ['subscription_userinfo_header', '1'],
    ['subscription_live_usage', '1'],
    ['subscription_update_interval_hours', '1'],
    ['subscription_client_auto_update_enabled', '1'],
    ['happ_provider_id', ''],
    ['json_mux_enabled', '0'],
    ['json_sniffing_enabled', '0'],
    ['happ_app_controls_enabled', '0'],
    ['happ_ping_tcp', '1'],
    ['happ_ping_result_icon', '1'],
    ['happ_fragmentation_enabled', '0'],
    ['happ_noises_enabled', '0'],
    ['happ_mux_enabled', '0'],
    ['happ_subscription_auto_update_enabled', '1'],
    ['happ_update_on_open_enabled', '0'],
    ['happ_ping_on_open_enabled', '1'],
    ['happ_subscriptions_collapse_enabled', '1'],
    ['happ_expand_now_enabled', '0'],
    ['happ_check_url_via_proxy_enabled', '0'],
    ['happ_sniffing_enabled', '0'],
    ['happ_force_apply_on_update_enabled', '0'],
    ['show_happ_links', '0'],
    ['json_mux_enabled', '0'],
    ['json_sniffing_enabled', '0'],
    ['update_repo_url', 'https://github.com/dagmagnat/3xui-Aggregator'],
    ['telegram_backup_enabled', '0'],
    ['telegram_backup_locked', '1'],
    ['telegram_backup_bot_token', ''],
    ['telegram_backup_chat_id', ''],
    ['panel_public_url', process.env.PANEL_PUBLIC_URL || BASE_URL],
    ['sub_public_url', process.env.SUB_PUBLIC_URL || BASE_URL],
    ['sub_url_mode', process.env.SUB_URL_MODE || 'custom'],
    ['panel_access_key', PANEL_ACCESS_KEY]
  ];

  for (const [key, value] of defaults) {
    const existing = db.prepare('SELECT value FROM app_settings WHERE key = ?').get(key);
    if (!existing) {
      db.prepare('INSERT INTO app_settings (key, value) VALUES (?, ?)').run(key, value);
      continue;
    }

    // После восстановления старого backup ключ мог отсутствовать или быть пустым.
    // Если в .env есть PANEL_ACCESS_KEY, аккуратно подставляем его, не трогая
    // вручную заданные значения.
    if (key === 'panel_access_key' && !String(existing.value || '').trim() && String(value || '').trim()) {
      setSetting(key, value);
    }
  }
}

function applyHappSafeDefaultMigration() {
  const marker = 'happ_safe_defaults_migrated_v12';
  if (getSetting(marker, '') === '1') return;

  // Старые сборки включали Happ/MUX/fragmentation/noises по умолчанию.
  // Это могло ломать интернет у клиентов и упираться в лимиты happ-proxy.com.
  // Один раз переводим существующую установку в безопасный режим: обычная JSON
  // подписка без Happ-управления. Кто хочет Provider-функции, включит их вручную.
  const safeOff = [
    'happ_app_controls_enabled',
    'happ_fragmentation_enabled',
    'happ_noises_enabled',
    'happ_mux_enabled',
    'happ_check_url_via_proxy_enabled',
    'happ_sniffing_enabled',
    'happ_force_apply_on_update_enabled',
    'happ_expand_now_enabled',
    'show_happ_links'
  ];
  for (const key of safeOff) setSetting(key, '0');
  setSetting('happ_update_on_open_enabled', '0');
  setSetting('happ_ping_on_open_enabled', '1');
  setSetting('happ_subscriptions_collapse_enabled', '1');
  setSetting('happ_subscription_auto_update_enabled', '1');
  setSetting('subscription_client_auto_update_enabled', '1');
  setSetting(marker, '1');
}

function syncDeploymentPublicUrlSettings() {
  const envPanelUrl = normalizePublicUrl(process.env.PANEL_PUBLIC_URL || BASE_URL, BASE_URL);
  const envSubUrl = normalizePublicUrl(process.env.SUB_PUBLIC_URL || envPanelUrl || BASE_URL, envPanelUrl || BASE_URL);
  const envMode = String(process.env.SUB_URL_MODE || 'custom').trim() || 'custom';
  const fingerprint = `${envPanelUrl}|${envSubUrl}|${envMode}`;
  const current = getSetting('install_public_url_fingerprint', '');

  if (!envPanelUrl || current === fingerprint) return;

  // При смене режима через install.sh/agg .env меняется, а старая база может
  // хранить старые URL (например, :3030). Синхронизируем один раз на новый
  // fingerprint, чтобы настройки панели совпадали с текущей установкой.
  setSetting('panel_public_url', envPanelUrl);
  setSetting('sub_public_url', envSubUrl);
  setSetting('sub_url_mode', ['custom', 'panel', 'panel_without_port'].includes(envMode) ? envMode : 'custom');
  setSetting('install_public_url_fingerprint', fingerprint);
}

function normalizeRootUrl(panelUrl, panelPath) {
  let url = String(panelUrl || '').trim().replace(/\/+$/, '');
  let path = String(panelPath || '').trim();

  if (path && !path.startsWith('/')) path = `/${path}`;

  return `${url}${path}`.replace(/\/+$/, '');
}

function normalizePublicUrl(value, fallback = '') {
  let url = String(value || '').trim();
  if (!url) url = String(fallback || '').trim();
  url = url.replace(/\/+$/, '');
  if (!url) return '';
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
  try {
    const parsed = new URL(url);
    parsed.pathname = parsed.pathname.replace(/\/+$/, '');
    parsed.search = '';
    parsed.hash = '';
    return parsed.toString().replace(/\/+$/, '');
  } catch (_) {
    return String(fallback || BASE_URL || `http://localhost:${PORT}`).trim().replace(/\/+$/, '');
  }
}

function stripPortFromPublicUrl(value) {
  const normalized = normalizePublicUrl(value, BASE_URL);
  try {
    const parsed = new URL(normalized);
    parsed.port = '';
    parsed.search = '';
    parsed.hash = '';
    return parsed.toString().replace(/\/+$/, '');
  } catch (_) {
    return normalized;
  }
}

function getSettingRaw(key) {
  return db.prepare('SELECT value FROM app_settings WHERE key = ?').get(key);
}

function getPanelPublicUrl() {
  return normalizePublicUrl(getSetting('panel_public_url', process.env.PANEL_PUBLIC_URL || BASE_URL), process.env.PANEL_PUBLIC_URL || BASE_URL);
}

function getCurrentPanelAccessKey() {
  return String(getSetting('panel_access_key', PANEL_ACCESS_KEY) || '').trim();
}

function getSubscriptionUrlMode() {
  const mode = String(getSetting('sub_url_mode', process.env.SUB_URL_MODE || 'custom') || 'custom').trim();
  return ['custom', 'panel', 'panel_without_port'].includes(mode) ? mode : 'custom';
}

function getPublicSubBaseUrl() {
  const mode = getSubscriptionUrlMode();
  if (mode === 'panel') return getPanelPublicUrl();
  if (mode === 'panel_without_port') return stripPortFromPublicUrl(getPanelPublicUrl());
  return normalizePublicUrl(getSetting('sub_public_url', process.env.SUB_PUBLIC_URL || BASE_URL), process.env.SUB_PUBLIC_URL || BASE_URL);
}

function buildPublicSubUrl(slug) {
  if (!slug) return '';
  return `${getPublicSubBaseUrl()}/sub/${slug}`;
}

function buildPublicJsonUrl(slug) {
  if (!slug) return '';
  return `${getPublicSubBaseUrl()}/json/${slug}`;
}

function buildPublicHappUrl(slug) {
  if (!slug) return '';
  return `${getPublicSubBaseUrl()}/happ/${slug}`;
}

function normalizeSubscriptionBaseUrl(node) {
  return getPublicSubBaseUrl();
}

function buildNativeSubUrl(node, subId) {
  return buildPublicSubUrl(subId);
}

function buildNativeJsonUrl(node, subId) {
  return buildPublicJsonUrl(subId);
}

async function safeJson(response) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

function extractCookieHeader(response) {
  if (!response || !response.headers) return '';

  if (typeof response.headers.raw === 'function') {
    const rawCookies = response.headers.raw()['set-cookie'] || [];
    return rawCookies.map(c => c.split(';')[0]).join('; ');
  }

  if (typeof response.headers.get === 'function') {
    const cookie = response.headers.get('set-cookie');
    if (cookie) return cookie.split(';')[0];
  }

  return '';
}

function safeParseJsonField(value, fallback = {}) {
  if (value === null || value === undefined) return fallback;
  if (typeof value === 'object') return value;

  const text = String(value).trim();
  if (!text) return fallback;

  try {
    return JSON.parse(text);
  } catch {
    return fallback;
  }
}

async function loginNode(node, timeoutMs = FETCH_TIMEOUT_MS) {
  const rootUrl = normalizeRootUrl(node.panel_url, node.panel_path);
  const password = decrypt(node.password_enc, APP_SECRET);

  const body = new URLSearchParams({
    username: node.username,
    password
  });

  const response = await fetchWithTimeout(`${rootUrl}/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json, text/plain, */*'
    },
    body: body.toString(),
    redirect: 'manual'
  }, timeoutMs);

  const cookie = extractCookieHeader(response);
  const data = await safeJson(response);

  if (!cookie) {
    throw new Error(data?.msg || `Login failed (${response.status})`);
  }

  return { rootUrl, cookie };
}

async function apiGet(node, path, timeoutMs = FETCH_TIMEOUT_MS) {
  const { rootUrl, cookie } = await loginNode(node, timeoutMs);

  const response = await fetchWithTimeout(`${rootUrl}${path}`, {
    headers: {
      'Accept': 'application/json',
      'Cookie': cookie
    }
  }, timeoutMs);

  const data = await safeJson(response);

  if (!response.ok) {
    throw new Error(data?.msg || `GET ${path} failed (${response.status})`);
  }

  return data;
}

async function apiPost(node, path, body, asForm = false) {
  const { rootUrl, cookie } = await loginNode(node);

  let headers = {
    'Accept': 'application/json',
    'Cookie': cookie
  };

  let payload;

  if (asForm) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    payload = new URLSearchParams(flattenForm(body)).toString();
  } else {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }

  const response = await fetchWithTimeout(`${rootUrl}${path}`, {
    method: 'POST',
    headers,
    body: payload
  });

  const data = await safeJson(response);

  if (!response.ok || data?.success === false) {
    throw new Error(data?.msg || `POST ${path} failed (${response.status})`);
  }

  return data;
}

function flattenForm(obj, prefix = '', out = {}) {
  Object.entries(obj).forEach(([key, value]) => {
    const formKey = prefix ? `${prefix}[${key}]` : key;

    if (Array.isArray(value)) {
      value.forEach((item, index) => {
        if (typeof item === 'object' && item !== null) {
          flattenForm(item, `${formKey}[${index}]`, out);
        } else {
          out[`${formKey}[${index}]`] = item;
        }
      });
    } else if (typeof value === 'object' && value !== null) {
      flattenForm(value, formKey, out);
    } else {
      out[formKey] = value;
    }
  });

  return out;
}

function getCachedInbound(node) {
  const row = db.prepare('SELECT inbound_json FROM node_inbound_cache WHERE node_id = ? AND inbound_id = ?')
    .get(Number(node.id), Number(node.inbound_id));

  if (!row || !row.inbound_json) return null;
  return safeParseJsonField(row.inbound_json, null);
}

function saveInboundCache(node, inbound) {
  if (!node || !node.id || !inbound) return;

  db.prepare(`
    INSERT INTO node_inbound_cache (node_id, inbound_id, inbound_json, updated_at)
    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(node_id) DO UPDATE SET
      inbound_id = excluded.inbound_id,
      inbound_json = excluded.inbound_json,
      updated_at = CURRENT_TIMESTAMP
  `).run(Number(node.id), Number(node.inbound_id), JSON.stringify(inbound));
}

async function getInbound(node, timeoutMs = FETCH_TIMEOUT_MS) {
  const data = await apiGet(node, `/panel/api/inbounds/get/${node.inbound_id}`, timeoutMs);
  const inbound = data.obj || data;
  saveInboundCache(node, inbound);
  return inbound;
}

async function getInboundFast(node) {
  const cached = getCachedInbound(node);
  if (cached) return cached;

  const data = await apiGet(node, `/panel/api/inbounds/get/${node.inbound_id}`);
  const inbound = data.obj || data;
  saveInboundCache(node, inbound);
  return inbound;
}


function parseInboundJsonField(value, fallback = {}) {
  if (value && typeof value === 'object') return value;
  const text = String(value || '').trim();
  if (!text) return fallback;
  try { return JSON.parse(text); } catch { return fallback; }
}

function stringifyInboundField(value) {
  return JSON.stringify(value ?? {});
}

function extractInboundEditorValues(inbound) {
  if (!inbound) return null;
  const stream = parseInboundJsonField(inbound.streamSettings, {});
  const sniffing = parseInboundJsonField(inbound.sniffing, {});
  const reality = stream.realitySettings || {};
  const xhttp = stream.xhttpSettings || {};
  const sockopt = stream.sockopt || {};
  const serverNames = Array.isArray(reality.serverNames) ? reality.serverNames : [];
  const shortIds = Array.isArray(reality.shortIds) ? reality.shortIds : [];
  return {
    id: inbound.id,
    remark: inbound.remark || inbound.tag || '',
    port: inbound.port || '',
    protocol: inbound.protocol || '',
    network: stream.network || '',
    security: stream.security || '',
    sni: serverNames[0] || reality.serverName || '',
    fingerprint: reality.fingerprint || '',
    publicKey: reality.publicKey || '',
    shortId: shortIds[0] || reality.shortId || '',
    spiderX: reality.spiderX || '/',
    xhttpHost: xhttp.host || '',
    xhttpPath: xhttp.path || '/xhttp',
    xhttpMode: xhttp.mode || 'stream-one',
    scMaxConcurrentPosts: xhttp.scMaxConcurrentPosts || 10,
    scMaxEachPostBytes: xhttp.scMaxEachPostBytes || 1000000,
    scMinPostsIntervalMs: xhttp.scMinPostsIntervalMs || 30,
    dialerProxy: sockopt.dialerProxy || '',
    sniffingEnabled: sniffing.enabled !== false,
    sniffingDestOverride: Array.isArray(sniffing.destOverride) ? sniffing.destOverride.join(', ') : '',
    raw: inbound
  };
}

async function updateInboundBasicSettings(node, form) {
  const inbound = await getInbound(node, 15000);
  const stream = parseInboundJsonField(inbound.streamSettings, {});
  const sniffing = parseInboundJsonField(inbound.sniffing, {});
  const reality = stream.realitySettings || {};
  const port = Number(form.inbound_port || inbound.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Порт inbound должен быть от 1 до 65535');

  inbound.port = port;
  if (form.inbound_remark !== undefined) inbound.remark = String(form.inbound_remark || inbound.remark || '').trim();

  if (stream.security === 'reality' || Object.keys(reality).length) {
    stream.realitySettings = reality;
    const sni = String(form.inbound_sni || '').trim();
    const shortId = String(form.inbound_short_id || '').trim();
    const spiderX = String(form.inbound_spider_x || '/').trim() || '/';
    const fingerprint = String(form.inbound_fingerprint || '').trim();
    if (sni) {
      reality.serverName = sni;
      reality.serverNames = [sni];
    }
    if (shortId) {
      reality.shortId = shortId;
      reality.shortIds = [shortId];
    }
    reality.spiderX = spiderX;
    if (fingerprint) reality.fingerprint = fingerprint;
  }

  if (String(stream.network || '').toLowerCase() === 'xhttp') {
    const xhttp = stream.xhttpSettings || {};
    xhttp.host = String(form.inbound_xhttp_host || '').trim();
    xhttp.path = String(form.inbound_xhttp_path || xhttp.path || '/xhttp').trim() || '/xhttp';
    xhttp.mode = String(form.inbound_xhttp_mode || xhttp.mode || 'stream-one').trim() || 'stream-one';
    const scParts = String(form.inbound_xhttp_sc || '').split(/[,;\s]+/).map(v => Number(v)).filter(Number.isFinite);
    xhttp.scMaxConcurrentPosts = Math.max(1, Math.floor(scParts[0] || xhttp.scMaxConcurrentPosts || 10));
    xhttp.scMaxEachPostBytes = Math.max(1, Math.floor(scParts[1] || xhttp.scMaxEachPostBytes || 1000000));
    xhttp.scMinPostsIntervalMs = Math.max(0, Math.floor(scParts[2] || xhttp.scMinPostsIntervalMs || 30));
    stream.xhttpSettings = xhttp;

    if (form.inbound_xhttp_fragment === '1') {
      stream.sockopt = stream.sockopt || {};
      stream.sockopt.dialerProxy = 'fragment';
    } else if (stream.sockopt) {
      delete stream.sockopt.dialerProxy;
      if (!Object.keys(stream.sockopt).length) delete stream.sockopt;
    }
  }

  sniffing.enabled = form.inbound_sniffing_enabled === '1';
  const dest = String(form.inbound_sniffing_dest || '').split(/[\n,;]+/).map(v => v.trim()).filter(Boolean);
  if (dest.length) sniffing.destOverride = dest;

  inbound.streamSettings = stringifyInboundField(stream);
  inbound.sniffing = stringifyInboundField(sniffing);

  const payload = { ...inbound };
  const updatePath = `/panel/api/inbounds/update/${encodeURIComponent(inbound.id || node.inbound_id)}`;
  let data;
  try {
    // Newer 3x-ui versions accept JSON here. JSON is safer for nested/stringified
    // streamSettings/sniffing than flattening everything as a form.
    data = await apiPost(node, updatePath, payload, false);
  } catch (jsonErr) {
    // Older/forked builds may still expect application/x-www-form-urlencoded.
    // Keep a fallback so editing nodes does not break across 3x-ui versions.
    data = await apiPost(node, updatePath, payload, true);
  }
  try {
    const fresh = await getInbound(node, 15000);
    saveInboundCache(node, fresh || inbound);
  } catch (_) {
    saveInboundCache(node, inbound);
  }
  return data;
}

async function getInbounds(node) {
  const data = await apiGet(node, '/panel/api/inbounds/list');
  return data.obj || data;
}

function getPayloadClientEmail(payload) {
  try {
    const settings = safeParseJsonField(payload?.settings, {});
    const clients = Array.isArray(settings.clients) ? settings.clients : [];
    return String(clients[0]?.email || '').trim();
  } catch (_) {
    return '';
  }
}

function enrich3xuiError(node, err, payload = null) {
  const raw = String(err?.message || err || 'unknown error');
  const nodeName = getNodePublicName(node);
  const duplicateMatch = raw.match(/Duplicate email:\s*([^);]+)/i);

  if (duplicateMatch) {
    const email = String(duplicateMatch[1] || getPayloadClientEmail(payload) || '').trim();
    const message = email
      ? `На узле ${nodeName} уже есть клиент с email ${email}. Агрегатор сравнивает email без учёта регистра: user005 и User005 считаются одним клиентом. Проверь или удали дубль в 3x-ui.`
      : `На узле ${nodeName} уже есть клиент с таким email. Проверь или удали дубль в 3x-ui.`;
    const enriched = new Error(message);
    enriched.originalMessage = raw;
    enriched.code = 'DUPLICATE_EMAIL';
    return enriched;
  }

  let message = raw;
  const code = String(err?.code || '').toUpperCase();
  const name = String(err?.name || '');

  if (name === 'AbortError' || /aborted|timeout|timed out/i.test(raw)) {
    message = 'узел не ответил за отведённое время';
  } else if (code === 'ECONNREFUSED' || /ECONNREFUSED/i.test(raw)) {
    message = 'невозможно подключиться к панели 3x-ui: соединение отклонено';
  } else if (code === 'ENOTFOUND' || code === 'EAI_AGAIN' || /ENOTFOUND|EAI_AGAIN/i.test(raw)) {
    message = 'не удалось найти домен или IP узла';
  } else if (/401|403|unauthorized|forbidden|login failed/i.test(raw)) {
    message = '3x-ui не приняла авторизацию. Проверь логин, пароль и путь панели';
  }

  const enriched = new Error(`${nodeName}: ${message}`);
  enriched.originalMessage = raw;
  return enriched;
}

async function addClient(node, payload) {
  try {
    return await apiPost(node, '/panel/api/inbounds/addClient', payload, true);
  } catch (err) {
    throw enrich3xuiError(node, err, payload);
  }
}

async function updateClient(node, clientUuid, payload) {
  try {
    return await apiPost(node, `/panel/api/inbounds/updateClient/${encodeURIComponent(clientUuid)}`, payload, true);
  } catch (err) {
    throw enrich3xuiError(node, err, payload);
  }
}

async function deleteClient(node, clientUuid, email) {
  try {
    return await apiPost(
      node,
      `/panel/api/inbounds/${node.inbound_id}/delClient/${encodeURIComponent(clientUuid)}`,
      {},
      true
    );
  } catch {
    return apiPost(
      node,
      `/panel/api/inbounds/${node.inbound_id}/delClientByEmail/${encodeURIComponent(email)}`,
      {},
      true
    );
  }
}

async function checkNode(node) {
  try {
    await apiGet(node, '/panel/api/server/status');
    await getInbounds(node);

    db.prepare('UPDATE nodes SET last_status = ?, last_error = ? WHERE id = ?')
      .run('online', '', node.id);

    return { ok: true, status: 'online' };
  } catch (err) {
    db.prepare('UPDATE nodes SET last_status = ?, last_error = ? WHERE id = ?')
      .run('offline', String(err.message || err), node.id);

    return { ok: false, status: 'offline', error: String(err.message || err) };
  }
}

function decodeMaybeBase64Subscription(text) {
  const raw = String(text || '').trim();

  if (!raw) return '';
  if (raw.includes('://')) return raw;

  try {
    const normalized = raw.replace(/\s+/g, '');
    const decoded = Buffer.from(normalized, 'base64').toString('utf8').trim();
    if (decoded.includes('://')) return decoded;
  } catch (_) {}

  return raw;
}

async function fetchSubscriptionLines(url) {
  const response = await fetchWithTimeout(url, {
    headers: {
      'User-Agent': 'Mozilla/5.0',
      'Accept': 'text/plain,*/*'
    },
    redirect: 'follow'
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch subscription (${response.status})`);
  }

  const text = decodeMaybeBase64Subscription(await response.text());

  return text
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
    .filter(line => (
      line.startsWith('vless://') ||
      line.startsWith('vmess://') ||
      line.startsWith('trojan://') ||
      line.startsWith('ss://') ||
      line.startsWith('hysteria://') ||
      line.startsWith('hy2://') ||
      line.startsWith('tuic://')
    ));
}

async function buildSubscriptionEntryForRow(row, clientRow, includeOffline = true) {
  try {
    if (Number(row.node_enabled) !== 1) return null;
    if (Number(row.client_node_enabled) !== 1) return null;
    if (!includeOffline && row.last_status === 'offline') return null;

    let inbound = getCachedInbound(row);

    if (!inbound) {
      try {
        inbound = await getInboundFast(row);
      } catch (err) {
        console.error(`No cached inbound and node is unavailable (${row.node_id}):`, err.message);
        return null;
      }
    }

    const subscriptionInfo = await getSubscriptionNodeInfo(row, clientRow, inbound);
    inbound = subscriptionInfo.inbound || inbound;

    const baseNodeName = getNodePublicName(row);
    const visibleNodeName = buildNodeLimitRemark(baseNodeName, subscriptionInfo);
    const stream = safeParseJsonField(inbound.streamSettings, {});
    let subUrl = '';

    if (inbound.protocol === 'vless' && stream.security === 'reality') {
      subUrl = buildVlessRealityLink(
        row,
        inbound,
        row.remote_uuid || clientRow.uuid,
        clientRow.display_name,
        visibleNodeName
      );
    }

    if (!subUrl) return null;

    return {
      line: subUrl,
      nodeId: row.node_id,
      nodeName: visibleNodeName,
      baseNodeName,
      subscriptionInfo
    };
  } catch (err) {
    console.error('Build subscription line failed:', err.message);
    return null;
  }
}

async function buildSubscriptionEntries(clientRow, includeOffline = true) {
  // Подписка/JSON должны открываться быстро: Happ может зависать, если ждать каждый узел последовательно.
  // Поэтому узлы собираются параллельно, а live-статистика имеет короткий timeout.
  const mappedRows = db.prepare(`
    SELECT
      cn.id AS client_node_id,
      cn.remote_sub_url,
      cn.remote_uuid,
      cn.remote_email,
      cn.traffic_gb AS client_node_traffic_gb,
      cn.enabled AS client_node_enabled,
      n.id AS id,
      n.id AS node_id,
      n.name,
      n.panel_url,
      n.panel_path,
      n.sub_base_url,
      n.username,
      n.password_enc,
      n.inbound_id,
      n.enabled AS node_enabled,
      n.last_status,
      n.last_error,
      n.country_code,
      n.country_name_ru,
      n.country_flag,
      n.label_suffix
    FROM client_nodes cn
    JOIN nodes n ON n.id = cn.node_id
    WHERE cn.client_id = ?
    ORDER BY n.id DESC, cn.id ASC
  `).all(clientRow.id);

  const rows = mappedRows;
  const seen = new Set();
  const results = await Promise.all(rows.map(row => buildSubscriptionEntryForRow(row, clientRow, includeOffline)));
  const entries = [];

  for (const entry of results) {
    if (!entry || !entry.line) continue;
    if (seen.has(entry.line)) continue;
    seen.add(entry.line);
    entries.push(entry);
  }

  return entries;
}

async function buildSubscriptionLines(clientRow, includeOffline = true) {
  const entries = await buildSubscriptionEntries(clientRow, includeOffline);
  return entries.map(e => e.line);
}

function buildVlessRealityLink(node, inbound, uuid, displayName, nodeName) {
  const streamSettings = safeParseJsonField(inbound.streamSettings, {});
  const settings = safeParseJsonField(inbound.settings, {});
  const realitySettings = streamSettings?.realitySettings || {};
  const realityInner = realitySettings?.settings || {};

  const panelUrl = new URL(node.panel_url);
  const host = panelUrl.hostname;
  const port = inbound.port || panelUrl.port || 443;

  const pbk =
    realityInner?.publicKey ||
    realitySettings?.publicKey ||
    '';

  const sni =
    realitySettings?.serverNames?.[0] ||
    realityInner?.serverNames?.[0] ||
    realitySettings?.serverName ||
    realityInner?.serverName ||
    realitySettings?.targetSni ||
    '';

  const sid =
    realitySettings?.shortIds?.[0] ||
    realityInner?.shortIds?.[0] ||
    realitySettings?.shortId ||
    realityInner?.shortId ||
    '';

  const fp =
    realityInner?.fingerprint ||
    realitySettings?.fingerprint ||
    streamSettings?.fingerprint ||
    'chrome';

  const flow =
    settings?.clients?.find(c => c.id === uuid)?.flow ||
    settings?.clients?.[0]?.flow ||
    '';

  const network = streamSettings.network || 'tcp';
  const query = new URLSearchParams({
    type: network,
    security: 'reality',
    pbk,
    fp,
    sni,
    sid,
    spx: realitySettings?.spiderX || realityInner?.spiderX || '/'
  });

  if (String(network).toLowerCase() === 'xhttp') {
    const xhttp = streamSettings.xhttpSettings || {};
    if (xhttp.path) query.set('path', xhttp.path);
    if (xhttp.host) query.set('host', xhttp.host);
    if (xhttp.mode) query.set('mode', xhttp.mode);
    if (xhttp.scMaxConcurrentPosts !== undefined) query.set('scMaxConcurrentPosts', String(xhttp.scMaxConcurrentPosts));
    if (xhttp.scMaxEachPostBytes !== undefined) query.set('scMaxEachPostBytes', String(xhttp.scMaxEachPostBytes));
    if (xhttp.scMinPostsIntervalMs !== undefined) query.set('scMinPostsIntervalMs', String(xhttp.scMinPostsIntervalMs));
    if (streamSettings.sockopt?.dialerProxy) query.set('dialerProxy', streamSettings.sockopt.dialerProxy);
  }

  if (flow) query.set('flow', flow);

  const remark = encodeURIComponent(nodeName || getNodePublicName(node));
  return `vless://${uuid}@${host}:${port}?${query.toString()}#${remark}`;
}

function buildRemoteClientRecord(node, inbound, remoteClient) {
  const c = remoteClient || {};
  const uuid = String(c.id || c.uuid || c.clientId || c.client_id || '').trim();
  const email = String(c.email || c.login || c.name || '').trim();
  const stat = findClientStat(inbound, uuid, email) || {};

  const subId = String(
    c.subId || c.sub_id || stat.subId || stat.sub_id || randomUUID().replace(/-/g, '').slice(0, 16)
  ).trim();

  const totalRaw = firstPositiveNumber(
    fieldValue(c, ['totalGB', 'total', 'trafficLimit', 'limit']),
    fieldValue(stat, ['totalGB', 'total', 'trafficLimit', 'limit'])
  );
  const expiryRaw = firstPositiveNumber(
    fieldValue(c, ['expiryTime', 'expiry_time', 'expire', 'expireTime']),
    fieldValue(stat, ['expiryTime', 'expiry_time', 'expire', 'expireTime'])
  );
  const limitIpRaw = firstNonEmpty(
    fieldValue(c, ['limitIp', 'limit_ip', 'ipLimit']),
    fieldValue(stat, ['limitIp', 'limit_ip', 'ipLimit']),
    1
  );
  const enabledRaw = firstNonEmpty(
    fieldValue(c, ['enable', 'enabled']),
    fieldValue(stat, ['enable', 'enabled']),
    true
  );

  const resetRaw = fieldValue(c, ['reset', 'resetTraffic', 'reset_traffic'], 0);
  const resetNumber = Number(resetRaw || 0);

  const uploadBytes = clampByteNumber(fieldValue(stat, ['up', 'upload', 'uplink', 'uploadBytes', 'uplinkBytes'], 0));
  const downloadBytes = clampByteNumber(fieldValue(stat, ['down', 'download', 'downlink', 'downloadBytes', 'downlinkBytes'], 0));
  const totalGB = normalizeRemoteTrafficLimitBytes(totalRaw);
  const expiryTime = normalizeRemoteEpochMillis(expiryRaw);

  return {
    uuid,
    email,
    limitIp: Math.max(0, Number(limitIpRaw ?? 1)),
    expiryTime,
    flow: c.flow || stat.flow || '',
    enable: !(enabledRaw === false || Number(enabledRaw) === 0),
    subId,
    tgId: c.tgId || c.tg_id || stat.tgId || stat.tg_id || '',
    reset: Number.isFinite(resetNumber) && resetNumber > 0 ? Math.ceil(resetNumber) : 0,
    comment: String(c.comment || c.remark || c.description || stat.comment || stat.remark || '').trim(),
    totalGB,
    uploadBytes,
    downloadBytes,
    usedBytes: clampByteNumber(uploadBytes + downloadBytes),
    originalSub: buildNativeSubUrl(node, subId),
    originalJson: buildNativeJsonUrl(node, subId)
  };
}

async function importClientsFromNode(node) {
  const inbound = await getInbound(node);
  const settings = safeParseJsonField(inbound.settings, {});
  const clients = Array.isArray(settings.clients) ? settings.clients : [];

  return clients
    .map(c => buildRemoteClientRecord(node, inbound, c))
    .filter(c => c.uuid && c.email);
}

function makeUniqueLogin(baseLogin, existingId = 0) {
  const base = String(baseLogin || 'imported').trim() || 'imported';
  let login = base;
  let i = 2;

  while (true) {
    const existing = db.prepare('SELECT id FROM clients WHERE LOWER(login) = LOWER(?)').get(login);

    if (!existing || Number(existing.id) === Number(existingId)) {
      return login;
    }

    login = `${base}_${i}`;
    i++;
  }
}

function getKnownLocalLoginValues() {
  const values = [];
  for (const row of db.prepare("SELECT login FROM clients WHERE login IS NOT NULL AND login != ''").all()) {
    values.push(row.login);
  }
  for (const row of db.prepare("SELECT remote_email FROM client_nodes WHERE remote_email IS NOT NULL AND remote_email != ''").all()) {
    values.push(row.remote_email);
  }
  return values;
}

function getNextAutoLogin(extraLogins = []) {
  const values = [...getKnownLocalLoginValues(), ...(Array.isArray(extraLogins) ? extraLogins : [])];
  let maxNumber = 0;

  for (const value of values) {
    const match = String(value || '').trim().match(/^user(\d+)$/i);
    if (match) maxNumber = Math.max(maxNumber, Number(match[1]));
  }

  return `user${String(maxNumber + 1).padStart(3, '0')}`;
}

function listRemoteClientsFromInbound(inbound) {
  const settings = safeParseJsonField(inbound?.settings, {});
  return Array.isArray(settings.clients) ? settings.clients : [];
}

async function collectRemoteLoginsForNodes(nodeIds) {
  const ids = uniqueList((nodeIds || []).map(v => Number(v)).filter(v => Number.isInteger(v) && v > 0));
  const emails = [];
  const records = [];

  for (const nodeId of ids) {
    const node = db.prepare('SELECT * FROM nodes WHERE id = ?').get(nodeId);
    if (!node) throw new Error(`Узел ${nodeId} не найден`);

    try {
      const inbound = await getInbound(node);
      for (const remote of listRemoteClientsFromInbound(inbound)) {
        const email = getRemoteClientEmail(remote);
        if (!email) continue;
        emails.push(email);
        records.push({ node, remote, email });
      }
    } catch (err) {
      throw new Error(`Не удалось проверить клиентов на узле ${getNodePublicName(node)}: ${err.message || err}`);
    }
  }

  return { emails, records };
}

function findCaseInsensitiveClientOwner(login, exceptClientId = 0) {
  const clean = String(login || '').trim();
  if (!clean) return null;
  return db.prepare('SELECT id, login FROM clients WHERE LOWER(login) = LOWER(?) AND id != ?')
    .get(clean, Number(exceptClientId || 0)) || null;
}

function getRemoteClientDiffs(remote, expected = {}) {
  const diffs = [];
  const expectedUuid = String(expected.uuid || '').trim();
  const expectedEmail = String(expected.email || expected.login || '').trim();
  const expectedLimitIp = expected.limitIp ?? expected.limit_ip;
  const expectedTotalGb = expected.trafficGb ?? expected.traffic_gb;
  const expectedExpiry = expected.expiryTime ?? expected.expiry_time;

  if (expectedUuid && remote?.id && !sameText(remote.id, expectedUuid)) diffs.push('UUID отличается');
  if (expectedEmail && getRemoteClientEmail(remote) && !isSameLogin(getRemoteClientEmail(remote), expectedEmail)) diffs.push('логин отличается');

  if (expectedLimitIp !== undefined && expectedLimitIp !== null && remote?.limitIp !== undefined && Number(remote.limitIp) !== Number(expectedLimitIp)) {
    diffs.push('IP-лимит отличается');
  }

  if (expectedTotalGb !== undefined && expectedTotalGb !== null && remote?.totalGB !== undefined) {
    const remoteGb = trafficGbFromRemoteValue(remote.totalGB);
    if (Number(remoteGb) !== Number(expectedTotalGb)) diffs.push('ГБ отличаются');
  }

  if (expectedExpiry !== undefined && expectedExpiry !== null && remote?.expiryTime !== undefined) {
    const left = normalizeRemoteEpochMillis(remote.expiryTime || 0);
    const right = normalizeRemoteEpochMillis(expectedExpiry || 0);
    if (left !== right) diffs.push('дата окончания отличается');
  }

  return diffs;
}

function makeRemoteClientConflictError(node, login, remote, expected = {}) {
  const remoteEmail = getRemoteClientEmail(remote) || String(login || '').trim() || 'клиент';
  const diffs = getRemoteClientDiffs(remote, expected);
  const diffText = diffs.length ? ` Отличия: ${diffs.join(', ')}.` : '';
  return new Error(`На узле ${getNodePublicName(node)} уже есть клиент ${remoteEmail}. Агрегатор сравнивает логины без учёта регистра, поэтому ${remoteEmail} и ${login} считаются одним клиентом.${diffText} Создание или перезапись пропущены. Проверь клиента в оригинальной 3x-ui панели.`);
}

function isSameRemoteClient(remote, expectedUuid, expectedEmail) {
  if (!remote) return false;
  const remoteUuid = String(remote?.id || '').trim();
  if (expectedUuid && remoteUuid && sameText(remoteUuid, expectedUuid)) return true;
  if (!expectedUuid && expectedEmail && isSameLogin(getRemoteClientEmail(remote), expectedEmail)) return true;
  return false;
}

function toTotalGbBytes(gb) {
  const n = Math.max(0, Number(gb || 0));
  return n > 0 ? Math.floor(n * 1024 * 1024 * 1024) : 0;
}

function fromTotalGbBytes(bytes) {
  const n = Math.max(0, Number(bytes || 0));
  return n > 0 ? Math.round(n / 1024 / 1024 / 1024) : 0;
}

function fieldValue(obj, names, fallback = undefined) {
  if (!obj || typeof obj !== 'object') return fallback;

  for (const name of names) {
    if (!Object.prototype.hasOwnProperty.call(obj, name)) continue;
    const value = obj[name];
    if (value === null || value === undefined || value === '') continue;
    return value;
  }

  return fallback;
}

function firstNonEmpty(...values) {
  for (const value of values) {
    if (value === null || value === undefined || value === '') continue;
    return value;
  }
  return undefined;
}

function firstPositiveNumber(...values) {
  for (const value of values) {
    if (value === null || value === undefined || value === '') continue;
    const n = Number(value);
    if (Number.isFinite(n) && n > 0) return value;
  }
  return firstNonEmpty(...values);
}

function nullablePositiveInteger(value) {
  if (value === null || value === undefined || value === '') return null;
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  return Math.max(0, Math.floor(n));
}

function normalizeRemoteTrafficLimitBytes(value) {
  if (value === null || value === undefined || value === '') return 0;
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return 0;

  // 3x-ui usually stores totalGB in bytes. If a fork/export returns plain GB,
  // small values are treated as GB to avoid losing limits like 50.
  if (n > 1024 * 1024) return Math.floor(n);
  return toTotalGbBytes(n);
}

function trafficGbFromRemoteValue(value) {
  return fromTotalGbBytes(normalizeRemoteTrafficLimitBytes(value));
}

function normalizeRemoteEpochMillis(value) {
  if (value === null || value === undefined || value === '') return 0;

  if (typeof value === 'string' && !/^\d+(\.\d+)?$/.test(value.trim())) {
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
  }

  return normalizeEpochMillis(value);
}

function daysLeftFromExpiry(expiryTimeMs) {
  const expiry = normalizeRemoteEpochMillis(expiryTimeMs);
  if (!expiry) return 0;
  const diff = expiry - Date.now();
  if (diff <= 0) return 0;
  return Math.ceil(diff / (24 * 60 * 60 * 1000));
}

function durationDaysFromRemoteClient(rc, existingClient = null) {
  const expiry = normalizeRemoteEpochMillis(rc?.expiryTime || 0);
  if (!expiry) return 0;

  const left = daysLeftFromExpiry(expiry);
  const resetDays = Math.max(0, Number(rc?.reset || 0));
  const existingDays = Math.max(0, Number(existingClient?.duration_days || 0));

  // 3x-ui reliably stores the final expiry date. Some forks also keep reset days.
  // If the client already existed in the aggregator, keep the larger known term so
  // the UI can show "left/issued" instead of overwriting it with only days left.
  return Math.ceil(Math.max(left, resetDays, existingDays));
}

function expiryAtMidnightAfterDays(days, baseMs = Date.now()) {
  const n = Math.max(0, Number(days || 0));
  if (!Number.isFinite(n) || n <= 0) return 0;

  const base = normalizeEpochMillis(baseMs) || Date.now();
  const d = new Date(base);
  d.setDate(d.getDate() + Math.ceil(n));
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}


function normalizeEpochMillis(value) {
  const n = Number(value || 0);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return n < 10000000000 ? Math.floor(n * 1000) : Math.floor(n);
}

function toEpochSeconds(value) {
  const ms = normalizeEpochMillis(value);
  return ms > 0 ? Math.floor(ms / 1000) : 0;
}

function clampByteNumber(value) {
  const n = Number(value || 0);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.floor(n);
}

function numericField(obj, names, fallback = 0) {
  if (!obj || typeof obj !== 'object') return fallback;

  for (const name of names) {
    if (!Object.prototype.hasOwnProperty.call(obj, name)) continue;
    const value = obj[name];
    if (value === null || value === undefined || value === '') continue;
    const n = Number(value);
    if (Number.isFinite(n)) return n;
  }

  return fallback;
}

function normalizeObjectArray(value) {
  const parsed = typeof value === 'string' ? safeParseJsonField(value, []) : value;
  if (Array.isArray(parsed)) return parsed.filter(v => v && typeof v === 'object');
  if (parsed && typeof parsed === 'object') return Object.values(parsed).filter(v => v && typeof v === 'object');
  return [];
}

function sameText(a, b) {
  return String(a || '').trim().toLowerCase() === String(b || '').trim().toLowerCase();
}

function normalizeLoginKey(value) {
  return String(value || '').trim().toLowerCase();
}

function isSameLogin(a, b) {
  const left = normalizeLoginKey(a);
  const right = normalizeLoginKey(b);
  return Boolean(left && right && left === right);
}

function getRemoteClientEmail(remote) {
  return String(remote?.email || remote?.login || remote?.name || '').trim();
}

function findClientStat(inbound, uuid, email) {
  const stats = [
    ...normalizeObjectArray(inbound?.clientStats),
    ...normalizeObjectArray(inbound?.client_stats),
    ...normalizeObjectArray(inbound?.stats),
    ...normalizeObjectArray(inbound?.clientTraffics)
  ];

  const cleanUuid = String(uuid || '').trim();
  const cleanEmail = String(email || '').trim();

  return stats.find(s => cleanEmail && sameText(s.email, cleanEmail)) ||
         stats.find(s => cleanUuid && (sameText(s.uuid, cleanUuid) || sameText(s.clientId, cleanUuid) || sameText(s.id, cleanUuid))) ||
         null;
}

function extractTrafficInfoFromInbound(inbound, uuid, email) {
  const settings = safeParseJsonField(inbound?.settings, {});
  const clientCfg = findRemoteClient(settings, uuid, email) || {};
  const stat = findClientStat(inbound, uuid, email) || {};

  const uploadBytes = clampByteNumber(numericField(stat, ['up', 'upload', 'uplink', 'uploadBytes', 'uplinkBytes'], 0));
  const downloadBytes = clampByteNumber(numericField(stat, ['down', 'download', 'downlink', 'downloadBytes', 'downlinkBytes'], 0));
  const totalBytes = normalizeRemoteTrafficLimitBytes(firstPositiveNumber(
    fieldValue(clientCfg, ['totalGB', 'total', 'trafficLimit', 'limit']),
    fieldValue(stat, ['total', 'totalGB', 'trafficLimit', 'limit'])
  ));
  const expiryTimeMs = normalizeRemoteEpochMillis(firstPositiveNumber(
    fieldValue(clientCfg, ['expiryTime', 'expiry_time', 'expire', 'expireTime']),
    fieldValue(stat, ['expiryTime', 'expiry_time', 'expire', 'expireTime'])
  ));

  const enabledValue = stat.enable ?? stat.enabled ?? clientCfg.enable ?? clientCfg.enabled;
  const enabled = enabledValue === undefined ? true : !(enabledValue === false || Number(enabledValue) === 0);

  return {
    uploadBytes,
    downloadBytes,
    usedBytes: clampByteNumber(uploadBytes + downloadBytes),
    totalBytes,
    expiryTimeMs,
    enabled
  };
}

function extractTrafficInfoFromClientTraffic(stat) {
  const uploadBytes = clampByteNumber(numericField(stat, ['up', 'upload', 'uplink', 'uploadBytes', 'uplinkBytes'], 0));
  const downloadBytes = clampByteNumber(numericField(stat, ['down', 'download', 'downlink', 'downloadBytes', 'downlinkBytes'], 0));
  const totalBytes = normalizeRemoteTrafficLimitBytes(firstPositiveNumber(
    fieldValue(stat, ['total', 'totalGB', 'trafficLimit', 'limit']),
    0
  ));
  const expiryTimeMs = normalizeRemoteEpochMillis(firstPositiveNumber(
    fieldValue(stat, ['expiryTime', 'expiry_time', 'expire', 'expireTime']),
    0
  ));
  const enabledValue = stat?.enable ?? stat?.enabled;
  const enabled = enabledValue === undefined ? true : !(enabledValue === false || Number(enabledValue) === 0);

  return {
    uploadBytes,
    downloadBytes,
    usedBytes: clampByteNumber(uploadBytes + downloadBytes),
    totalBytes,
    expiryTimeMs,
    enabled
  };
}

function mergeTrafficInfo(primary, fallback) {
  const a = primary || {};
  const b = fallback || {};
  const uploadBytes = clampByteNumber(a.uploadBytes ?? b.uploadBytes ?? 0);
  const downloadBytes = clampByteNumber(a.downloadBytes ?? b.downloadBytes ?? 0);
  const totalBytes = clampByteNumber(a.totalBytes || b.totalBytes || 0);
  const expiryTimeMs = normalizeEpochMillis(a.expiryTimeMs || b.expiryTimeMs || 0);
  const enabled = a.enabled !== undefined ? a.enabled : (b.enabled !== undefined ? b.enabled : true);

  return {
    uploadBytes,
    downloadBytes,
    usedBytes: clampByteNumber(uploadBytes + downloadBytes),
    totalBytes,
    expiryTimeMs,
    enabled
  };
}

function pickClientTrafficObject(payload, email) {
  const wanted = String(email || '').trim().toLowerCase();
  const source = payload?.obj ?? payload?.data ?? payload?.result ?? payload;
  const candidates = normalizeObjectArray(source);

  if (!candidates.length && source && typeof source === 'object') return source;
  if (!wanted) return candidates[0] || null;

  return candidates.find(item => String(item?.email || item?.login || item?.name || '').trim().toLowerCase() === wanted) ||
    candidates[0] ||
    null;
}

async function getClientTrafficFromApi(node, email, timeoutMs = SUBSCRIPTION_STATS_TIMEOUT_MS) {
  const cleanEmail = String(email || '').trim();
  if (!cleanEmail) return null;

  const encoded = encodeURIComponent(cleanEmail);
  const paths = [
    `/panel/api/inbounds/getClientTraffics/${encoded}`,
    `/panel/api/inbounds/getClientTraffics/${cleanEmail}`
  ];
  let lastError = null;

  for (const apiPath of uniqueList(paths)) {
    try {
      const data = await apiGet(node, apiPath, timeoutMs);
      const stat = pickClientTrafficObject(data, cleanEmail);
      if (!stat) return null;
      return extractTrafficInfoFromClientTraffic(stat);
    } catch (err) {
      lastError = err;
    }
  }

  if (lastError) throw lastError;
  return null;
}

function getClientNodeLimitGb(row) {
  // Источник истины для отображения лимита в подписке — локальная привязка
  // client_nodes.traffic_gb. 0 или пусто означает безлимит именно на этом узле.
  const value = row?.client_node_traffic_gb ?? row?.traffic_gb ?? 0;
  const n = Number(value || 0);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return n;
}

function getClientNodeLimitBytes(clientRow, row, remoteTotalBytes = 0) {
  // Не подтягиваем remoteTotalBytes для безлимитных узлов: иначе старый/общий
  // лимит из 3x-ui может случайно появиться возле всех регионов.
  const nodeGb = getClientNodeLimitGb(row);
  return nodeGb > 0 ? toTotalGbBytes(nodeGb) : 0;
}

function getClientNodeExpiryMs(clientRow, remoteExpiryMs = 0) {
  // Дата подписки в агрегаторе должна быть главным источником для Happ/подписок.
  // При обновлении из выбранного 3x-ui она копируется в clients.expiry_time;
  // remoteExpiryMs используем только как fallback, если локальной даты нет.
  const local = normalizeEpochMillis(clientRow?.expiry_time || 0);
  if (local > 0) return local;
  return normalizeEpochMillis(remoteExpiryMs);
}

function formatCompactNumber(value, digits = 1) {
  const n = Math.max(0, Number(value || 0));
  const maximumFractionDigits = n >= 10 ? 0 : digits;
  return new Intl.NumberFormat('ru-RU', { maximumFractionDigits }).format(n);
}

function formatTrafficShort(bytes) {
  const n = clampByteNumber(bytes);
  const gb = n / 1024 / 1024 / 1024;
  if (gb >= 1) return `${formatCompactNumber(gb)} ГБ`;
  const mb = n / 1024 / 1024;
  return `${formatCompactNumber(mb, 0)} МБ`;
}

function formatTrafficPair(usedBytes, totalBytes) {
  const usedGb = clampByteNumber(usedBytes) / 1024 / 1024 / 1024;
  const totalGb = clampByteNumber(totalBytes) / 1024 / 1024 / 1024;
  return `${formatCompactNumber(usedGb)}/${formatCompactNumber(totalGb)} ГБ`;
}

function getDaysLeftText(expiryTimeMs) {
  const expiry = normalizeEpochMillis(expiryTimeMs);
  if (!expiry) return '∞ дн.';

  const diff = expiry - Date.now();
  if (diff <= 0) return '0 дн.';

  const days = Math.ceil(diff / (24 * 60 * 60 * 1000));
  return `${days} дн.`;
}

function shouldShowSubscriptionLimits() {
  return getSetting('subscription_show_limits', '1') !== '0';
}

function shouldSendSubscriptionUserInfo() {
  return getSetting('subscription_userinfo_header', '1') !== '0';
}

function shouldRefreshSubscriptionUsage() {
  return getSetting('subscription_live_usage', '1') !== '0';
}

function getSubscriptionUpdateIntervalHours() {
  const n = Number(getSetting('subscription_update_interval_hours', '1'));
  if (!Number.isFinite(n) || n <= 0) return 1;
  return Math.min(168, Math.max(1, Math.floor(n)));
}

function getHappProviderId() {
  return String(getSetting('happ_provider_id', '') || '').trim();
}

function isHappAppControlsEnabled() {
  return getSetting('happ_app_controls_enabled', '0') === '1' && getHappProviderId().length > 0;
}

function isHappAppControlsCheckboxEnabled() {
  return getSetting('happ_app_controls_enabled', '0') === '1';
}

function isHappSettingEnabled(key, fallback = '1') {
  return getSetting(key, fallback) !== '0';
}

function getHappBehaviorOptions() {
  return {
    autoUpdate: isHappSettingEnabled('happ_subscription_auto_update_enabled', '1'),
    updateOnOpen: isHappSettingEnabled('happ_update_on_open_enabled', '0'),
    pingOnOpen: isHappSettingEnabled('happ_ping_on_open_enabled', '1'),
    subscriptionsCollapse: isHappSettingEnabled('happ_subscriptions_collapse_enabled', '1'),
    expandNow: isHappSettingEnabled('happ_expand_now_enabled', '0'),
    checkUrlViaProxy: isHappSettingEnabled('happ_check_url_via_proxy_enabled', '0'),
    sniffing: isHappSettingEnabled('happ_sniffing_enabled', '0'),
    forceApplyOnUpdate: isHappSettingEnabled('happ_force_apply_on_update_enabled', '0')
  };
}

function getHappAppControlHeaders() {
  if (!isHappAppControlsEnabled()) return {};

  const headers = {};
  const providerId = getHappProviderId();
  if (providerId) headers.providerid = providerId;

  if (isHappSettingEnabled('happ_ping_tcp', '1')) {
    headers['ping-type'] = 'tcp';
  }
  headers['ping-result'] = isHappSettingEnabled('happ_ping_result_icon', '1') ? 'icon' : 'latency';

  const behavior = getHappBehaviorOptions();
  if (behavior.checkUrlViaProxy) {
    headers['check-url-via-proxy'] = 'https://www.gstatic.com/generate_204';
  }
  headers['subscription-ping-onopen-enabled'] = behavior.pingOnOpen ? '1' : '0';
  headers['sniffing-enable'] = behavior.sniffing ? '1' : '0';

  if (isHappSettingEnabled('happ_fragmentation_enabled', '0')) {
    headers['fragmentation-enable'] = '1';
    headers['fragmentation-packets'] = 'tlshello';
    headers['fragmentation-length'] = '50-100';
    headers['fragmentation-interval'] = '10-20';
    headers['fragmentation-maxsplit'] = '100-200';
  } else {
    headers['fragmentation-enable'] = '0';
  }

  if (isHappSettingEnabled('happ_noises_enabled', '0')) {
    headers['noises-enable'] = '1';
    headers['noises-type'] = 'rand';
    headers['noises-packet'] = '10-20';
    headers['noises-delay'] = '10-16';
    headers['noises-applyto'] = 'ipv4';
  } else {
    headers['noises-enable'] = '0';
  }

  if (isHappSettingEnabled('happ_mux_enabled', '0')) {
    headers['mux-enable'] = '1';
    headers['mux-tcp-connections'] = '100';
    headers['mux-xudp-connections'] = '200';
    headers['mux-quic'] = 'skip';
  } else {
    headers['mux-enable'] = '0';
  }

  return headers;
}

function applyHappAppControlHeaders(res) {
  const headers = getHappAppControlHeaders();
  for (const [key, value] of Object.entries(headers)) {
    res.setHeader(key, String(value));
  }
}

function getHappSubscriptionProfileHeaderMap(subscriptionName, subscriptionUpdateIntervalHours) {
  if (!isHappAppControlsEnabled()) return {};

  const behavior = getHappBehaviorOptions();
  return {
    'profile-title': `base64:${Buffer.from(String(subscriptionName || '')).toString('base64')}`,
    'subscription-title': `base64:${Buffer.from(String(subscriptionName || '')).toString('base64')}`,
    'profile-update-interval': String(subscriptionUpdateIntervalHours),
    'subscription-auto-update-enable': behavior.autoUpdate ? '1' : '0',
    'subscription-auto-update-open-enable': behavior.updateOnOpen ? '1' : '0',
    'subscription-ping-onopen-enabled': behavior.pingOnOpen ? '1' : '0',
    'subscriptions-collapse': behavior.subscriptionsCollapse ? '1' : '0',
    'subscriptions-expand-now': behavior.expandNow ? '1' : '0'
  };
}

function applyHappSubscriptionProfileHeaders(res, subscriptionName, subscriptionUpdateIntervalHours) {
  const headers = getHappSubscriptionProfileHeaderMap(subscriptionName, subscriptionUpdateIntervalHours);
  for (const [key, value] of Object.entries(headers)) {
    res.setHeader(key, String(value));
  }
}

function buildHappAppControlBodyLines() {
  const headers = getHappAppControlHeaders();
  const lines = Object.entries(headers).map(([key, value]) => {
    if (key === 'providerid') return `#providerid ${value}`;
    return `#${key}: ${value}`;
  });

  // Некоторые версии Happ читают только часть параметров из HTTP headers,
  // а при повторном обновлении подписки могут не переустанавливать локальные
  // переключатели. Дублируем настройки в теле подписки несколькими понятными
  // ключами. Неподдерживаемые комментарии безопасно игнорируются клиентом.
  if (isHappAppControlsEnabled()) {
    const behavior = getHappBehaviorOptions();
    lines.push(`#happ-force-apply-on-update: ${behavior.forceApplyOnUpdate ? '1' : '0'}`);
    lines.push(`#happ-update-on-launch: ${behavior.updateOnOpen ? '1' : '0'}`);
    lines.push(`#happ-ping-type: ${isHappSettingEnabled('happ_ping_tcp', '1') ? 'tcp' : 'url'}`);
    lines.push(`#happ-fragmentation-enabled: ${isHappSettingEnabled('happ_fragmentation_enabled', '0') ? '1' : '0'}`);
    lines.push(`#happ-noises-enabled: ${isHappSettingEnabled('happ_noises_enabled', '0') ? '1' : '0'}`);
    lines.push(`#happ-mux-enabled: ${isHappSettingEnabled('happ_mux_enabled', '0') ? '1' : '0'}`);
  }

  return lines;
}

function buildNodeLimitRemark(baseName, info) {
  if (!shouldShowSubscriptionLimits()) return baseName;

  const parts = [];
  const totalBytes = clampByteNumber(info?.totalBytes || 0);
  const usedBytes = clampByteNumber(info?.usedBytes || 0);

  // Короткий формат для клиента:
  //   Россия · 0/50 ГБ · 29 дн.
  //   Польша · ∞ · 29 дн.
  // Расход показываем только там, где на конкретном узле есть лимит.
  parts.push(totalBytes > 0 ? formatTrafficPair(usedBytes, totalBytes) : '∞');
  parts.push(getDaysLeftText(info?.expiryTimeMs || 0));

  return `${baseName} · ${parts.join(' · ')}`;
}

async function getSubscriptionNodeInfo(row, clientRow, cachedInbound = null) {
  let inbound = cachedInbound || null;
  let source = inbound ? 'cache' : 'local';
  let liveTrafficInfo = null;

  if (shouldRefreshSubscriptionUsage() && String(row?.last_status || '') !== 'offline') {
    // Не блокируем обновление подписки лишним запросом inbound, если inbound уже есть в кэше.
    // Для построения ссылки достаточно cachedInbound, а расход трафика берём отдельным быстрым API.
    if (!inbound) {
      try {
        inbound = await getInbound(row, SUBSCRIPTION_STATS_TIMEOUT_MS);
        source = 'live';
      } catch (err) {
        console.error(`Subscription usage refresh failed for node ${row?.node_id || row?.id || 'unknown'}:`, err.message);
      }
    }

    try {
      liveTrafficInfo = await getClientTrafficFromApi(
        row,
        row?.remote_email || clientRow?.login,
        SUBSCRIPTION_STATS_TIMEOUT_MS
      );
      if (liveTrafficInfo) source = 'live-traffic';
    } catch (err) {
      console.error(`Client traffic refresh failed for node ${row?.node_id || row?.id || 'unknown'}:`, err.message);
    }
  }

  if (!inbound) {
    inbound = cachedInbound || getCachedInbound(row);
    source = inbound ? 'cache' : 'local';
  }

  const inboundInfo = extractTrafficInfoFromInbound(
    inbound,
    row?.remote_uuid || clientRow?.uuid,
    row?.remote_email || clientRow?.login
  );
  const remoteInfo = mergeTrafficInfo(liveTrafficInfo, inboundInfo);

  const totalBytes = getClientNodeLimitBytes(clientRow, row, remoteInfo.totalBytes);
  const expiryTimeMs = getClientNodeExpiryMs(clientRow, remoteInfo.expiryTimeMs);
  const uploadBytes = clampByteNumber(remoteInfo.uploadBytes);
  const downloadBytes = clampByteNumber(remoteInfo.downloadBytes);
  const usedBytes = clampByteNumber(uploadBytes + downloadBytes);

  if (row?.client_node_id) {
    updateClientNodeUsage(row.client_node_id, { uploadBytes, downloadBytes, usedBytes });
  }

  return {
    inbound,
    source,
    uploadBytes,
    downloadBytes,
    usedBytes,
    totalBytes,
    expiryTimeMs,
    enabled: remoteInfo.enabled !== false
  };
}

function buildSubscriptionUserInfo(entries, clientRow) {
  if (!shouldSendSubscriptionUserInfo()) return '';

  let uploadBytes = 0;
  let downloadBytes = 0;
  let totalBytes = 0;
  const expiries = [];

  for (const entry of entries || []) {
    const info = entry?.subscriptionInfo || {};
    const entryTotal = clampByteNumber(info.totalBytes || 0);

    if (entryTotal > 0) {
      totalBytes += entryTotal;
      uploadBytes += clampByteNumber(info.uploadBytes || 0);
      downloadBytes += clampByteNumber(info.downloadBytes || 0);
    }

    const entryExpiry = normalizeEpochMillis(info.expiryTimeMs || 0);
    if (entryExpiry > 0) expiries.push(entryExpiry);
  }

  const clientExpiry = normalizeEpochMillis(clientRow?.expiry_time || 0);
  if (clientExpiry > 0) expiries.push(clientExpiry);

  const expireSeconds = expiries.length ? toEpochSeconds(Math.min(...expiries)) : 0;
  const parts = [`upload=${clampByteNumber(uploadBytes)}`, `download=${clampByteNumber(downloadBytes)}`];

  if (totalBytes > 0) parts.push(`total=${clampByteNumber(totalBytes)}`);
  if (expireSeconds > 0) parts.push(`expire=${expireSeconds}`);

  return parts.join('; ');
}

function setSubscriptionUserInfoHeaders(res, userInfoText) {
  if (userInfoText) res.setHeader('Subscription-Userinfo', userInfoText);

  // Важно: эти заголовки Happ меняют поведение приложения. Если настройка
  // "Передавать настройки Happ через подписку" выключена, не отправляем их
  // вообще. Иначе Happ продолжает менять локальные параметры даже по обычной
  // /json или /sub ссылке.
  if (!isHappAppControlsEnabled()) return;

  const intervalHours = getSubscriptionUpdateIntervalHours();
  res.setHeader('Profile-Update-Interval', String(intervalHours));
  res.setHeader('profile-update-interval', String(intervalHours));
  res.setHeader('Subscription-Update-Interval', String(intervalHours));
}


function findRemoteClient(settings, uuid, email) {
  const clients = Array.isArray(settings?.clients) ? settings.clients : [];
  uuid = String(uuid || '').trim();
  email = String(email || '').trim();
  return clients.find(c => uuid && sameText(c.id, uuid)) ||
         clients.find(c => email && sameText(c.email, email)) || null;
}

function upsertClientNodeMap(clientRow, node, rc, trafficGb) {
  const subUrl = buildNativeSubUrl(node, rc.subId || clientRow.sub_slug);
  const limitIp = nullablePositiveInteger(rc.limitIp);
  const uploadBytes = clampByteNumber(rc.uploadBytes || 0);
  const downloadBytes = clampByteNumber(rc.downloadBytes || 0);
  const usedBytes = clampByteNumber(rc.usedBytes || uploadBytes + downloadBytes);
  const old = db.prepare('SELECT * FROM client_nodes WHERE client_id = ? AND node_id = ?').get(clientRow.id, node.id);

  if (!old) {
    const info = db.prepare('INSERT INTO client_nodes (client_id,node_id,remote_email,remote_uuid,remote_sub_url,traffic_gb,limit_ip,upload_bytes,download_bytes,used_bytes,enabled) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .run(
        clientRow.id,
        node.id,
        rc.email || clientRow.login,
        rc.uuid || clientRow.uuid,
        subUrl,
        Math.max(0, Number(trafficGb || 0)),
        limitIp,
        uploadBytes,
        downloadBytes,
        usedBytes,
        rc.enable !== false ? 1 : 0
      );
    return { row: db.prepare('SELECT * FROM client_nodes WHERE id = ?').get(info.lastInsertRowid), created: true };
  }

  db.prepare('UPDATE client_nodes SET remote_email = ?, remote_uuid = ?, remote_sub_url = ?, traffic_gb = ?, limit_ip = ?, upload_bytes = ?, download_bytes = ?, used_bytes = ?, enabled = ? WHERE id = ?')
    .run(
      rc.email || clientRow.login,
      rc.uuid || clientRow.uuid,
      subUrl,
      Math.max(0, Number(trafficGb || 0)),
      limitIp,
      uploadBytes,
      downloadBytes,
      usedBytes,
      rc.enable !== false ? 1 : 0,
      old.id
    );

  return { row: db.prepare('SELECT * FROM client_nodes WHERE id = ?').get(old.id), created: false };
}
function buildClientPayloadForImport(node, inbound, rc, clientRow, oldRemote) {
  const settings = safeParseJsonField(inbound.settings, {});
  const trafficGb = fromTotalGbBytes(rc.totalGB || 0) || Number(clientRow.traffic_gb || 0);
  return {
    id: Number(node.inbound_id),
    settings: JSON.stringify({ clients: [{
      id: rc.uuid || clientRow.uuid,
      email: rc.email || clientRow.login,
      flow: rc.flow || clientRow.flow || oldRemote?.flow || settings.clients?.[0]?.flow || '',
      limitIp: Number(rc.limitIp ?? clientRow.limit_ip ?? oldRemote?.limitIp ?? 1),
      totalGB: Number(rc.totalGB || toTotalGbBytes(trafficGb)),
      expiryTime: Number(rc.expiryTime || clientRow.expiry_time || oldRemote?.expiryTime || 0),
      enable: rc.enable !== false && clientRow.enabled !== 0,
      tgId: rc.tgId || oldRemote?.tgId || '',
      subId: rc.subId || oldRemote?.subId || clientRow.sub_slug,
      reset: Number(rc.reset || clientRow.duration_days || oldRemote?.reset || 0),
      comment: String(rc.comment || clientRow.comment || oldRemote?.comment || '').trim()
    }] })
  };
}

async function ensureImportedClientOnNode(node, clientRow, rc) {
  const inbound = await getInbound(node);
  const settings = safeParseJsonField(inbound.settings, {});
  const oldRemote = findRemoteClient(settings, rc.uuid || clientRow.uuid, rc.email || clientRow.login);
  const expectedUuid = String(rc.uuid || clientRow.uuid || '').trim();
  const expectedEmail = String(rc.email || clientRow.login || '').trim();
  const trafficGb = fromTotalGbBytes(rc.totalGB || 0);

  if (oldRemote && expectedUuid && oldRemote.id && !sameText(oldRemote.id, expectedUuid) && isSameLogin(getRemoteClientEmail(oldRemote), expectedEmail)) {
    throw makeRemoteClientConflictError(node, expectedEmail, oldRemote, {
      uuid: expectedUuid,
      email: expectedEmail,
      trafficGb,
      limitIp: rc.limitIp,
      expiryTime: rc.expiryTime
    });
  }

  const payload = buildClientPayloadForImport(node, inbound, rc, clientRow, oldRemote);

  if (!oldRemote) {
    try {
      await addClient(node, payload);
      const map = upsertClientNodeMap(clientRow, node, rc, trafficGb);
      return { mapCreated: map.created, remoteCreated: true, remoteUpdated: false };
    } catch (err) {
      if (err?.code !== 'DUPLICATE_EMAIL') throw err;
      const freshInbound = await getInbound(node);
      const freshSettings = safeParseJsonField(freshInbound.settings, {});
      const fresh = findRemoteClient(freshSettings, expectedUuid, expectedEmail);
      if (!fresh) throw err;
      if (fresh.id && expectedUuid && !sameText(fresh.id, expectedUuid)) {
        throw makeRemoteClientConflictError(node, expectedEmail, fresh, {
          uuid: expectedUuid,
          email: expectedEmail,
          trafficGb,
          limitIp: rc.limitIp,
          expiryTime: rc.expiryTime
        });
      }
      await updateClient(node, fresh.id || expectedUuid, payload);
      const map = upsertClientNodeMap(clientRow, node, rc, trafficGb);
      return { mapCreated: map.created, remoteCreated: false, remoteUpdated: true };
    }
  }

  try {
    await updateClient(node, oldRemote.id || expectedUuid, payload);
    const map = upsertClientNodeMap(clientRow, node, rc, trafficGb);
    return { mapCreated: map.created, remoteCreated: false, remoteUpdated: true };
  } catch (e) {
    const freshInbound = await getInbound(node);
    const freshSettings = safeParseJsonField(freshInbound.settings, {});
    const fresh = findRemoteClient(freshSettings, expectedUuid, expectedEmail);
    if (!fresh) {
      await addClient(node, payload);
      const map = upsertClientNodeMap(clientRow, node, rc, trafficGb);
      return { mapCreated: map.created, remoteCreated: true, remoteUpdated: false };
    }
    if (fresh.id && expectedUuid && !sameText(fresh.id, expectedUuid)) {
      throw makeRemoteClientConflictError(node, expectedEmail, fresh, {
        uuid: expectedUuid,
        email: expectedEmail,
        trafficGb,
        limitIp: rc.limitIp,
        expiryTime: rc.expiryTime
      });
    }
    throw e;
  }
}

function findLocalClientByRemote(rc) {
  const uuid = String(rc?.uuid || '').trim();
  const subId = String(rc?.subId || '').trim();
  const email = String(rc?.email || '').trim();

  if (uuid) {
    const byUuid = db.prepare('SELECT * FROM clients WHERE uuid = ?').get(uuid);
    if (byUuid) return byUuid;
  }

  if (subId) {
    const bySub = db.prepare('SELECT * FROM clients WHERE sub_slug = ?').get(subId);
    if (bySub) return bySub;
  }

  if (email) {
    const byLogin = db.prepare('SELECT * FROM clients WHERE LOWER(login) = LOWER(?)').get(email);
    if (byLogin) return byLogin;
  }

  return null;
}

function chooseSubSlugForRemote(rc, existingClientId = 0) {
  const requested = String(rc?.subId || '').trim() || randomUUID().replace(/-/g, '').slice(0, 16);
  const owner = db.prepare('SELECT id FROM clients WHERE sub_slug = ?').get(requested);
  if (!owner || Number(owner.id) === Number(existingClientId)) return requested;
  return `${requested}-${randomUUID().replace(/-/g, '').slice(0, 6)}`;
}

function upsertLocalClientFromRemote(rc, sourceNode = null) {
  const remoteTrafficGb = trafficGbFromRemoteValue(rc.totalGB);
  const remoteDurationDays = durationDaysFromRemoteClient(rc, null);
  const remoteLogin = String(rc.email || '').trim() || 'imported';
  const remoteComment = String(rc.comment || '').trim();
  let clientRow = findLocalClientByRemote(rc);

  if (!clientRow) {
    const subSlug = chooseSubSlugForRemote(rc, 0);
    const info = db.prepare(`
      INSERT INTO clients (login, display_name, uuid, sub_slug, duration_days, traffic_gb, limit_ip, expiry_time, enabled, comment, flow)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      makeUniqueLogin(remoteLogin),
      remoteLogin,
      rc.uuid,
      subSlug,
      remoteDurationDays,
      remoteTrafficGb,
      Math.max(0, Number(rc.limitIp ?? 1)),
      normalizeRemoteEpochMillis(rc.expiryTime || 0),
      rc.enable !== false ? 1 : 0,
      remoteComment,
      String(rc.flow || '').trim()
    );
    clientRow = db.prepare('SELECT * FROM clients WHERE id = ?').get(info.lastInsertRowid);
    const map = sourceNode ? upsertClientNodeMap(clientRow, sourceNode, rc, remoteTrafficGb) : null;
    return { clientRow, created: true, updated: false, mapCreated: Boolean(map?.created) };
  }

  const remoteDurationDaysForExisting = durationDaysFromRemoteClient(rc, clientRow);
  const subSlug = chooseSubSlugForRemote(rc, clientRow.id);
  const newLogin = makeUniqueLogin(remoteLogin, clientRow.id);
  db.prepare(`
    UPDATE clients
    SET login = ?, display_name = ?, uuid = ?, sub_slug = ?, duration_days = ?, traffic_gb = ?, limit_ip = ?, expiry_time = ?, enabled = ?, comment = ?, flow = ?
    WHERE id = ?
  `).run(
    newLogin,
    remoteLogin,
    rc.uuid || clientRow.uuid,
    subSlug,
    remoteDurationDaysForExisting,
    remoteTrafficGb,
    Math.max(0, Number(rc.limitIp ?? clientRow.limit_ip ?? 1)),
    normalizeRemoteEpochMillis(rc.expiryTime || 0),
    rc.enable !== false ? 1 : 0,
    remoteComment || clientRow.comment || '',
    String(rc.flow || clientRow.flow || '').trim(),
    clientRow.id
  );

  clientRow = db.prepare('SELECT * FROM clients WHERE id = ?').get(clientRow.id);
  const map = sourceNode ? upsertClientNodeMap(clientRow, sourceNode, rc, remoteTrafficGb) : null;
  return { clientRow, created: false, updated: true, mapCreated: Boolean(map?.created) };
}

async function refreshLocalClientsFromSourceNode(sourceNode) {
  const remoteClients = await importClientsFromNode(sourceNode);
  let imported = 0, updated = 0, mappingsCreated = 0, failed = 0;
  const errors = [];

  for (const rc of remoteClients) {
    try {
      const result = upsertLocalClientFromRemote(rc, sourceNode);
      if (result.created) imported++;
      if (result.updated) updated++;
      if (result.mapCreated) mappingsCreated++;
    } catch (e) {
      failed++;
      const msg = `${rc.email || rc.uuid || 'client'}: ${e.message || e}`;
      errors.push(msg);
      console.error('Не удалось обновить локального клиента из узла:', msg);
    }
  }

  return { imported, updated, mappingsCreated, failed, errors: errors.slice(0, 10), totalSourceClients: remoteClients.length };
}

async function syncClientsFromSourceNode(sourceNode) {
  const allNodes = db.prepare('SELECT * FROM nodes WHERE enabled = 1 ORDER BY id ASC').all();
  if (!allNodes.length) throw new Error('Нет доступных узлов');
  const remoteClients = await importClientsFromNode(sourceNode);
  let imported = 0, updated = 0, mappingsCreated = 0, remoteCreated = 0, remoteUpdated = 0, skipped = 0, failed = 0;
  const errors = [];

  for (const rc of remoteClients) {
    let clientRow;
    try {
      const localResult = upsertLocalClientFromRemote(rc, sourceNode);
      clientRow = localResult.clientRow;
      if (localResult.created) imported++;
      if (localResult.updated) updated++;
      if (localResult.mapCreated) mappingsCreated++;
    } catch (e) {
      failed++;
      const msg = `${rc.email || rc.uuid || 'client'}: ${e.message || e}`;
      errors.push(msg);
      console.error('Не удалось импортировать клиента из узла: ' + msg);
      continue;
    }

    for (const node of allNodes) {
      try {
        const r = await ensureImportedClientOnNode(node, clientRow, rc);
        if (r.mapCreated) mappingsCreated++;
        if (r.remoteCreated) remoteCreated++;
        if (r.remoteUpdated) remoteUpdated++;
        if (Number(node.id) === Number(sourceNode.id)) skipped++;
      } catch (e) {
        failed++;
        const msg = 'Узел ' + node.id + ' (' + (node.name || node.country_name_ru || 'без имени') + '): ' + (e.message || e);
        errors.push(msg);
        console.error('Не удалось синхронизировать клиента ' + rc.email + ': ' + msg);
      }
    }
  }

  return { imported, updated, mappingsCreated, remoteCreated, remoteUpdated, skipped, failed, errors: errors.slice(0, 10), totalSourceClients: remoteClients.length };
}

async function getClientConfigFromNode(node, clientUuid, clientEmail) {
  const inbound = await getInbound(node);
  const settings = safeParseJsonField(inbound.settings, {});
  const clients = settings.clients || [];

  const clientCfg =
    clients.find(c => sameText(c.id, clientUuid)) ||
    clients.find(c => sameText(c.email, clientEmail));

  return { inbound, clientCfg };
}

function pickClientFlow(settings, uuid, fallback = '') {
  const clients = Array.isArray(settings?.clients) ? settings.clients : [];
  return clients.find(c => c.id === uuid)?.flow || fallback || clients[0]?.flow || '';
}

function findCurrentRemoteClient(settings, map, client, opts = {}) {
  const clients = Array.isArray(settings?.clients) ? settings.clients : [];
  const candidates = [
    map?.remote_uuid,
    client?.uuid,
    opts?.uuid,
    map?.remote_email,
    client?.login,
    opts?.email
  ].map(v => String(v || '').trim()).filter(Boolean);

  for (const value of candidates) {
    const byId = clients.find(c => String(c?.id || '').trim() === value);
    if (byId) return byId;
  }

  for (const value of candidates) {
    const byEmail = clients.find(c => sameText(c?.email, value));
    if (byEmail) return byEmail;
  }

  return null;
}

function updateLocalClientNodeState(node, map, values = {}) {
  const subId = values.subId || values.clientSubSlug || '';
  const remoteSubUrl = subId ? buildNativeSubUrl(node, subId) : (map.remote_sub_url || '');

  db.prepare(`
    UPDATE client_nodes
    SET remote_email = ?, remote_uuid = ?, remote_sub_url = ?, traffic_gb = ?, limit_ip = ?, upload_bytes = ?, download_bytes = ?, used_bytes = ?, enabled = ?
    WHERE id = ?
  `).run(
    values.email || map.remote_email || '',
    values.remoteUuid || map.remote_uuid || '',
    remoteSubUrl,
    Math.max(0, Number(values.trafficGb || 0)),
    values.limitIp === undefined ? map.limit_ip : nullablePositiveInteger(values.limitIp),
    clampByteNumber(values.uploadBytes ?? map.upload_bytes ?? 0),
    clampByteNumber(values.downloadBytes ?? map.download_bytes ?? 0),
    clampByteNumber(values.usedBytes ?? map.used_bytes ?? 0),
    values.nodeEnabled ? 1 : 0,
    map.id
  );
}

async function updateClientOnNode(node, map, client, opts = {}) {
  const durationDays = Math.max(0, Number(opts.duration_days ?? client.duration_days ?? 0));
  const trafficGb = Math.max(0, Number(opts.traffic_gb ?? map.traffic_gb ?? client.traffic_gb ?? 0));
  const email = String(opts.email || client.login || map.remote_email || '').trim();
  const globalEnabled = opts.enabled !== undefined ? Boolean(opts.enabled) : (client.enabled !== 0);
  const nodeEnabled = opts.node_enabled !== undefined ? Boolean(opts.node_enabled) : (map.enabled !== 0);
  const effectiveEnabled = globalEnabled && nodeEnabled;
  const fallbackSubId = opts.subId || client.sub_slug || randomUUID().replace(/-/g, '').slice(0, 16);
  const fallbackRemoteUuid = String(map.remote_uuid || client.uuid || opts.uuid || '').trim();

  // Сначала фиксируем локальное состояние агрегатора. Тогда /sub и /json сразу
  // показывают новый лимит даже если конкретный 3x-ui узел временно недоступен.
  updateLocalClientNodeState(node, map, {
    email,
    remoteUuid: fallbackRemoteUuid,
    subId: fallbackSubId,
    clientSubSlug: client.sub_slug,
    trafficGb,
    limitIp: opts.limit_ip ?? map.limit_ip ?? client.limit_ip,
    nodeEnabled
  });

  const inbound = await getInbound(node);
  const settings = safeParseJsonField(inbound.settings, {});
  const current = findCurrentRemoteClient(settings, map, client, opts) || {};
  if (current && current.id && fallbackRemoteUuid && !sameText(current.id, fallbackRemoteUuid) && isSameLogin(getRemoteClientEmail(current), email)) {
    throw makeRemoteClientConflictError(node, email, current, {
      uuid: fallbackRemoteUuid,
      email,
      trafficGb,
      limitIp: opts.limit_ip ?? map.limit_ip ?? client.limit_ip,
      expiryTime: opts.expiry_time ?? client.expiry_time
    });
  }
  const remoteUuid = String(current.id || fallbackRemoteUuid || client.uuid || '').trim();
  if (!remoteUuid) throw new Error('Не найден UUID клиента на узле');

  const limitIp = Math.max(0, Number(opts.limit_ip ?? map.limit_ip ?? client.limit_ip ?? current.limitIp ?? 1));
  const expiryTime = Math.max(0, Number(opts.expiry_time ?? client.expiry_time ?? current.expiryTime ?? 0));
  const subId = opts.subId || current.subId || fallbackSubId;
  const comment = String(opts.comment ?? client.comment ?? current.comment ?? '').trim();

  const payload = {
    id: Number(node.inbound_id),
    settings: JSON.stringify({
      clients: [{
        id: remoteUuid,
        email,
        flow: current.flow || pickClientFlow(settings, remoteUuid, client.flow || ''),
        limitIp,
        totalGB: toTotalGbBytes(trafficGb),
        expiryTime,
        enable: effectiveEnabled,
        tgId: current.tgId || '',
        subId,
        reset: durationDays > 0 && trafficGb > 0 ? durationDays : 0,
        comment
      }]
    })
  };

  await updateClient(node, remoteUuid, payload);

  updateLocalClientNodeState(node, map, {
    email,
    remoteUuid,
    subId,
    clientSubSlug: client.sub_slug,
    trafficGb,
    limitIp,
    nodeEnabled
  });

  return { ok: true, nodeId: node.id };
}

async function updateClientEverywhere(client, opts = {}) {
  const mappings = db.prepare('SELECT * FROM client_nodes WHERE client_id = ?').all(client.id);
  for (const map of mappings) {
    try {
      const node = db.prepare('SELECT * FROM nodes WHERE id = ?').get(map.node_id);
      if (!node) continue;
      await updateClientOnNode(node, map, client, opts);
    } catch (err) {
      console.error('Update remote client failed:', err.message);
    }
  }
}

function getClientNodeEffectiveLimitIp(map, client, fallback = 1) {
  if (map && map.limit_ip !== null && map.limit_ip !== undefined && map.limit_ip !== '') {
    return Math.max(0, Number(map.limit_ip || 0));
  }
  return Math.max(0, Number(client?.limit_ip ?? fallback ?? 1));
}

function getClientNodeEffectiveTrafficGb(map, client, fallback = 0) {
  if (map && map.traffic_gb !== null && map.traffic_gb !== undefined && map.traffic_gb !== '') {
    return Math.max(0, Number(map.traffic_gb || 0));
  }
  return Math.max(0, Number(client?.traffic_gb ?? fallback ?? 0));
}

function readUsageForClientNode(node, client, map, inbound = null) {
  const cachedInbound = inbound || getCachedInbound(node);
  const cachedInfo = cachedInbound
    ? extractTrafficInfoFromInbound(cachedInbound, map?.remote_uuid || client?.uuid, map?.remote_email || client?.login)
    : null;

  const uploadBytes = clampByteNumber(cachedInfo?.uploadBytes ?? map?.upload_bytes ?? 0);
  const downloadBytes = clampByteNumber(cachedInfo?.downloadBytes ?? map?.download_bytes ?? 0);
  const usedBytes = clampByteNumber(cachedInfo?.usedBytes ?? map?.used_bytes ?? uploadBytes + downloadBytes);

  return { uploadBytes, downloadBytes, usedBytes };
}

function updateClientNodeUsage(mapId, usage) {
  if (!mapId) return;
  db.prepare('UPDATE client_nodes SET upload_bytes = ?, download_bytes = ?, used_bytes = ? WHERE id = ?')
    .run(
      clampByteNumber(usage?.uploadBytes || 0),
      clampByteNumber(usage?.downloadBytes || 0),
      clampByteNumber(usage?.usedBytes || 0),
      mapId
    );
}

async function ensureAggregatorClientOnNode(node, client, opts = {}) {
  let map = db.prepare('SELECT * FROM client_nodes WHERE client_id = ? AND node_id = ?').get(client.id, node.id);
  const inbound = await getInbound(node);
  const settings = safeParseJsonField(inbound.settings, {});
  const current = findCurrentRemoteClient(settings, map || {}, client, opts) || null;

  const email = String(opts.email || client.login || map?.remote_email || current?.email || '').trim();
  if (!email) throw new Error('У клиента нет email/login');

  const expectedUuid = String(map?.remote_uuid || opts.uuid || client.uuid || '').trim();
  if (current && current.id && expectedUuid && !sameText(current.id, expectedUuid) && isSameLogin(getRemoteClientEmail(current), email)) {
    throw makeRemoteClientConflictError(node, email, current, {
      uuid: expectedUuid,
      email,
      trafficGb: opts.traffic_gb ?? getClientNodeEffectiveTrafficGb(map, client, 0),
      limitIp: opts.limit_ip ?? getClientNodeEffectiveLimitIp(map, client, current?.limitIp ?? 1),
      expiryTime: opts.expiry_time ?? client.expiry_time
    });
  }

  const remoteUuid = String(current?.id || map?.remote_uuid || client.uuid || opts.uuid || randomUUID()).trim();
  const subId = String(opts.subId || current?.subId || client.sub_slug || randomUUID().replace(/-/g, '').slice(0, 16)).trim();
  const trafficGb = Math.max(0, Number(opts.traffic_gb ?? getClientNodeEffectiveTrafficGb(map, client, 0)));
  const limitIp = Math.max(0, Number(opts.limit_ip ?? getClientNodeEffectiveLimitIp(map, client, current?.limitIp ?? 1)));
  const expiryTime = Math.max(0, Number(opts.expiry_time ?? client.expiry_time ?? current?.expiryTime ?? 0));
  const durationDays = Math.max(0, Number(opts.duration_days ?? client.duration_days ?? current?.reset ?? 0));
  const nodeEnabled = opts.node_enabled !== undefined ? Boolean(opts.node_enabled) : (map ? map.enabled !== 0 : true);
  const effectiveEnabled = (opts.enabled !== undefined ? Boolean(opts.enabled) : client.enabled !== 0) && nodeEnabled;
  const comment = String(opts.comment ?? client.comment ?? current?.comment ?? '').trim();
  const flow = current?.flow || client.flow || pickClientFlow(settings, remoteUuid, '');

  const payload = {
    id: Number(node.inbound_id),
    settings: JSON.stringify({
      clients: [{
        id: remoteUuid,
        email,
        flow,
        limitIp,
        totalGB: toTotalGbBytes(trafficGb),
        expiryTime,
        enable: effectiveEnabled,
        tgId: current?.tgId || '',
        subId,
        reset: durationDays > 0 && trafficGb > 0 ? durationDays : Number(current?.reset || 0),
        comment
      }]
    })
  };

  let remoteCreated = false;
  let remoteUpdated = false;

  if (current) {
    await updateClient(node, current.id || remoteUuid, payload);
    remoteUpdated = true;
  } else {
    try {
      await addClient(node, payload);
      remoteCreated = true;
    } catch (err) {
      const freshInbound = await getInbound(node);
      const freshSettings = safeParseJsonField(freshInbound.settings, {});
      const fresh = findCurrentRemoteClient(freshSettings, map || {}, client, { ...opts, uuid: remoteUuid, email });
      if (!fresh) throw err;
      if (fresh.id && remoteUuid && !sameText(fresh.id, remoteUuid) && isSameLogin(getRemoteClientEmail(fresh), email)) {
        throw makeRemoteClientConflictError(node, email, fresh, {
          uuid: remoteUuid,
          email,
          trafficGb,
          limitIp,
          expiryTime
        });
      }
      await updateClient(node, fresh.id || remoteUuid, payload);
      remoteUpdated = true;
    }
  }

  const usage = readUsageForClientNode(node, client, map || {}, inbound);

  if (!map) {
    const info = db.prepare('INSERT INTO client_nodes (client_id,node_id,remote_email,remote_uuid,remote_sub_url,traffic_gb,limit_ip,upload_bytes,download_bytes,used_bytes,enabled) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .run(
        client.id,
        node.id,
        email,
        remoteUuid,
        buildNativeSubUrl(node, subId),
        trafficGb,
        limitIp,
        usage.uploadBytes,
        usage.downloadBytes,
        usage.usedBytes,
        nodeEnabled ? 1 : 0
      );
    map = db.prepare('SELECT * FROM client_nodes WHERE id = ?').get(info.lastInsertRowid);
    return { mapCreated: true, remoteCreated, remoteUpdated };
  }

  updateLocalClientNodeState(node, map, {
    email,
    remoteUuid,
    subId,
    clientSubSlug: client.sub_slug,
    trafficGb,
    limitIp,
    uploadBytes: usage.uploadBytes,
    downloadBytes: usage.downloadBytes,
    usedBytes: usage.usedBytes,
    nodeEnabled
  });

  return { mapCreated: false, remoteCreated, remoteUpdated };
}

async function syncAggregatorClientsToNode(targetNode) {
  const clients = db.prepare('SELECT * FROM clients ORDER BY id ASC').all();
  let remoteCreated = 0, remoteUpdated = 0, mappingsCreated = 0, failed = 0;
  const errors = [];

  for (const client of clients) {
    try {
      const result = await ensureAggregatorClientOnNode(targetNode, client);
      if (result.mapCreated) mappingsCreated++;
      if (result.remoteCreated) remoteCreated++;
      if (result.remoteUpdated) remoteUpdated++;
    } catch (err) {
      failed++;
      const msg = `${client.login || client.id}: ${err.message || err}`;
      errors.push(msg);
      console.error('Не удалось создать/обновить клиента на узле:', msg);
    }
  }

  return { totalClients: clients.length, remoteCreated, remoteUpdated, mappingsCreated, failed, errors: errors.slice(0, 12) };
}

async function syncAggregatorClientsToAllNodes() {
  const nodes = db.prepare('SELECT * FROM nodes WHERE enabled = 1 ORDER BY id ASC').all();
  if (!nodes.length) throw new Error('Нет активных узлов');

  let totalClients = 0, remoteCreated = 0, remoteUpdated = 0, mappingsCreated = 0, failed = 0;
  const errors = [];

  for (const node of nodes) {
    const result = await syncAggregatorClientsToNode(node);
    totalClients = Math.max(totalClients, result.totalClients || 0);
    remoteCreated += result.remoteCreated || 0;
    remoteUpdated += result.remoteUpdated || 0;
    mappingsCreated += result.mappingsCreated || 0;
    failed += result.failed || 0;
    for (const error of result.errors || []) errors.push(`${getNodePublicName(node)}: ${error}`);
  }

  return { nodes: nodes.length, totalClients, remoteCreated, remoteUpdated, mappingsCreated, failed, errors: errors.slice(0, 12) };
}

async function applyNodeLimitsToAllClients(node, values = {}) {
  const clients = db.prepare('SELECT * FROM clients ORDER BY id ASC').all();
  const hasTraffic = values.traffic_gb !== undefined && values.traffic_gb !== null && String(values.traffic_gb).trim() !== '';
  const hasLimitIp = values.limit_ip !== undefined && values.limit_ip !== null && String(values.limit_ip).trim() !== '';

  if (!hasTraffic && !hasLimitIp) {
    throw new Error('Укажи ГБ или IP. Пустые поля означают не менять настройки.');
  }

  let remoteCreated = 0, remoteUpdated = 0, mappingsCreated = 0, failed = 0;
  const errors = [];

  for (const client of clients) {
    const map = db.prepare('SELECT * FROM client_nodes WHERE client_id = ? AND node_id = ?').get(client.id, node.id);
    const nextTrafficGb = hasTraffic
      ? Math.max(0, Number(values.traffic_gb || 0))
      : getClientNodeEffectiveTrafficGb(map, client, 0);
    const nextLimitIp = hasLimitIp
      ? Math.max(0, Number(values.limit_ip || 0))
      : getClientNodeEffectiveLimitIp(map, client, 1);

    try {
      const result = await ensureAggregatorClientOnNode(node, client, {
        traffic_gb: nextTrafficGb,
        limit_ip: nextLimitIp
      });
      if (result.mapCreated) mappingsCreated++;
      if (result.remoteCreated) remoteCreated++;
      if (result.remoteUpdated) remoteUpdated++;
    } catch (err) {
      failed++;
      const msg = `${client.login || client.id}: ${err.message || err}`;
      errors.push(msg);
      console.error('Не удалось применить настройки к клиенту:', msg);
    }
  }

  return { totalClients: clients.length, remoteCreated, remoteUpdated, mappingsCreated, failed, errors: errors.slice(0, 12) };
}

function getDashboardLimitRows() {
  const rows = db.prepare(`
    SELECT
      c.id AS client_id,
      c.login,
      c.display_name,
      c.comment,
      c.expiry_time,
      cn.id AS map_id,
      cn.remote_email,
      cn.remote_uuid,
      cn.traffic_gb,
      cn.upload_bytes,
      cn.download_bytes,
      cn.used_bytes,
      n.id AS node_id,
      n.inbound_id,
      n.name,
      n.country_code,
      n.country_name_ru,
      n.country_flag,
      n.label_suffix
    FROM client_nodes cn
    JOIN clients c ON c.id = cn.client_id
    JOIN nodes n ON n.id = cn.node_id
    WHERE cn.enabled = 1 AND cn.traffic_gb > 0
    ORDER BY c.expiry_time ASC, c.login ASC
  `).all();

  for (const row of rows) {
    const node = { id: row.node_id, inbound_id: row.inbound_id };
    const client = { uuid: row.remote_uuid, login: row.remote_email };
    const usage = readUsageForClientNode(node, client, row);
    row.upload_bytes = usage.uploadBytes;
    row.download_bytes = usage.downloadBytes;
    row.used_bytes = usage.usedBytes;
    row.limit_bytes = toTotalGbBytes(row.traffic_gb || 0);
    row.remaining_bytes = Math.max(0, row.limit_bytes - row.used_bytes);
    updateClientNodeUsage(row.map_id, usage);
  }

  return rows;
}

async function fetchOnlineEmailsFromNode(node) {
  let data;
  try {
    data = await apiPost(node, '/panel/api/inbounds/onlines', {}, true);
  } catch (err1) {
    try {
      data = await apiPost(node, '/panel/api/inbounds/onlines', {}, false);
    } catch (err2) {
      data = await apiGet(node, '/panel/api/inbounds/onlines');
    }
  }

  const source = data?.obj ?? data?.data ?? data?.result ?? data;
  const values = [];

  function collect(value) {
    if (value === null || value === undefined) return;
    if (Array.isArray(value)) return value.forEach(collect);
    if (typeof value === 'object') {
      const email = value.email || value.login || value.name || value.user || value.client;
      if (email) values.push(String(email).trim());
      else Object.values(value).forEach(collect);
      return;
    }
    const text = String(value).trim();
    if (text) values.push(text);
  }

  collect(source);
  return uniqueList(values.map(v => v.trim()).filter(Boolean));
}

async function getOnlineClientsForDashboard() {
  const nodes = db.prepare('SELECT * FROM nodes WHERE enabled = 1 ORDER BY id ASC').all();
  const items = new Map();
  const errors = [];

  for (const node of nodes) {
    let emails = [];
    try {
      emails = await fetchOnlineEmailsFromNode(node);
    } catch (err) {
      errors.push(`${getNodePublicName(node)}: ${err.message || err}`);
      continue;
    }

    for (const email of emails) {
      const client = db.prepare(`
        SELECT c.*
        FROM clients c
        LEFT JOIN client_nodes cn ON cn.client_id = c.id
        WHERE LOWER(c.login) = LOWER(?) OR LOWER(c.display_name) = LOWER(?) OR LOWER(cn.remote_email) = LOWER(?)
        ORDER BY c.id ASC
        LIMIT 1
      `).get(email, email, email);

      if (!client) continue;
      const key = String(client.id);
      const old = items.get(key) || { ...client, nodes: [] };
      old.nodes.push({
        id: node.id,
        name: getNodeDisplayName(node),
        publicName: getNodePublicName(node),
        countryCode: String(node.country_code || '').toLowerCase(),
        flag: node.country_flag || getCountryFlag(node.country_name_ru || node.name)
      });
      items.set(key, old);
    }
  }

  return { clients: Array.from(items.values()), errors: errors.slice(0, 8) };
}

async function deleteClientEverywhere(client, deleteMode) {
  const mappings = db.prepare('SELECT * FROM client_nodes WHERE client_id = ?').all(client.id);

  if (deleteMode === 'all') {
    for (const map of mappings) {
      try {
        const node = db.prepare('SELECT * FROM nodes WHERE id = ?').get(map.node_id);
        if (node) await deleteClient(node, map.remote_uuid, map.remote_email);
      } catch (err) {
        console.error('Delete remote client failed:', err.message);
      }
    }
  }

  if (deleteMode === 'secondary') {
    const sourceMap = mappings[0];

    for (const map of mappings) {
      if (sourceMap && map.id === sourceMap.id) continue;

      try {
        const node = db.prepare('SELECT * FROM nodes WHERE id = ?').get(map.node_id);
        if (node) await deleteClient(node, map.remote_uuid, map.remote_email);
      } catch (err) {
        console.error('Delete remote client failed:', err.message);
      }
    }
  }

  db.prepare('DELETE FROM client_nodes WHERE client_id = ?').run(client.id);
  db.prepare('DELETE FROM clients WHERE id = ?').run(client.id);
}

app.get('/', requireAuth, (req, res) => res.redirect('/dashboard'));

app.get('/mobile-login', requireAllowedAdminIp, (req, res) => {
  const accessKey = getCurrentPanelAccessKey();
  if (accessKey && req.session?.panelAccessGranted === true) setPanelRememberCookie(res, accessKey);
  if (req.session?.userId) return res.redirect('/dashboard');
  return res.redirect('/login');
});

app.get('/login', requireAllowedAdminIp, (req, res) => {
  if (req.session?.userId) return res.redirect('/dashboard');
  render(res, 'login', { error: req.query.message || null });
});

app.post('/login', requireAllowedAdminIp, (req, res) => {
  const username = String(req.body.username || '');
  const failure = getLoginFailure(req, username);

  if (failure.lockedUntil && Date.now() < failure.lockedUntil) {
    const minutes = Math.ceil((failure.lockedUntil - Date.now()) / 60000);
    return render(res, 'login', { error: `Слишком много попыток входа. Повтори через ${minutes} мин.` });
  }

  const user = db.prepare('SELECT * FROM app_users WHERE username = ?').get(username);

  if (!user || !bcrypt.compareSync(req.body.password || '', user.password_hash)) {
    const count = Number(failure.count || 0) + 1;
    const lockedUntil = count >= LOGIN_MAX_ATTEMPTS ? Date.now() + LOGIN_LOCK_MINUTES * 60 * 1000 : 0;
    loginFailures.set(failure.key, { count, lockedUntil });
    return render(res, 'login', { error: 'Неверный логин или пароль' });
  }

  loginFailures.delete(failure.key);
  const panelAccessWasGranted = req.session?.panelAccessGranted === true;
  req.session.regenerate((err) => {
    if (err) return render(res, 'login', { error: 'Не удалось создать сессию' });
    req.session.userId = user.id;
    req.session.panelAccessGranted = panelAccessWasGranted;
    req.session.loginIp = getClientIp(req);
    req.session.lastActivity = Date.now();
    req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
    if (panelAccessWasGranted) setPanelRememberCookie(res, getCurrentPanelAccessKey());
    res.redirect('/dashboard');
  });
});
app.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(() => res.redirect(buildLoginRedirectPath()));
});

app.get('/dashboard', requireAuth, async (req, res) => {
  const stats = {
    nodes: db.prepare('SELECT COUNT(*) AS c FROM nodes').get().c,
    clients: db.prepare('SELECT COUNT(*) AS c FROM clients').get().c,
    online: db.prepare("SELECT COUNT(*) AS c FROM nodes WHERE last_status = 'online'").get().c,
    offline: db.prepare("SELECT COUNT(*) AS c FROM nodes WHERE last_status = 'offline'").get().c,
  };

  const now = Date.now();
  const week = now + 7 * 24 * 60 * 60 * 1000;
  const expiringClients = db.prepare(`
    SELECT * FROM clients
    WHERE enabled = 1 AND expiry_time > ? AND expiry_time <= ?
    ORDER BY expiry_time ASC
    LIMIT 50
  `).all(now, week);

  const showOnlineClients = req.query.online === '1';
  const onlineResult = showOnlineClients
    ? await getOnlineClientsForDashboard()
    : { clients: [], errors: [] };

  const limitedClients = getDashboardLimitRows();

  render(res, 'dashboard', {
    stats,
    expiringClients,
    limitedClients,
    showOnlineClients,
    onlinePage: Math.max(1, Number(req.query.online_page || 1) || 1),
    onlinePerPage: String(req.query.online_per_page || '') === '9999' ? 9999 : 10,
    onlineClients: onlineResult.clients,
    onlineErrors: onlineResult.errors,
    now,
    baseUrl: getPublicSubBaseUrl(),
    message: req.query.message || '',
    error: req.query.error || ''
  });
});
app.get('/routing', requireAuth, (req, res) => {
  const cfg = getRoutingConfig();
  render(res, 'routing', {
    routingPresets: ROUTING_PRESETS,
    selectedPresets: cfg.presets,
    customDomainsText: (cfg.customDomains || []).join('\n'),
    customIpsText: (cfg.customIps || []).join('\n'),
    routingMode: cfg.mode || 'proxy-selected',
    exceptDomainsText: (cfg.exceptDomains || []).join('\n'),
    exceptIpsText: (cfg.exceptIps || []).join('\n'),
    geodataUrlsText: (cfg.geodataUrls || []).join('\n'),
    geositeUrl: cfg.geositeUrl || '',
    geoipUrl: cfg.geoipUrl || '',
    dnsPreset: cfg.dnsPreset || 'cloudflare-google',
    dnsCustomText: cfg.dnsCustom || '',
    routingEnabled: cfg.enabled !== false,
    routingAllNodes: cfg.allNodes !== false,
    routingExcludedNodeIds: cfg.excludedNodeIds || [],
    nodes: db.prepare('SELECT * FROM nodes WHERE enabled = 1 ORDER BY id ASC').all(),
    proxyDomains: getRoutingProxyDomains(),
    proxyIps: getRoutingProxyIps(),
    directDomains: getRoutingDirectDomains(),
    directIps: getRoutingDirectIps(),
    jsonUrlExample: `${getPublicSubBaseUrl()}/json/<slug>`,
    message: req.query.message || '',
    error: req.query.error || ''
  });
});

app.post('/routing', requireAuth, (req, res) => {
  try {
    const presetsRaw = req.body.presets;
    const selectedPresets = Array.isArray(presetsRaw) ? presetsRaw : (presetsRaw ? [presetsRaw] : []);
    const allowedPresetKeys = new Set(ROUTING_PRESETS.map(p => p.key));
    const presets = uniqueList(selectedPresets.map(v => String(v || '').trim()).filter(v => allowedPresetKeys.has(v)));
    const parsedDomains = parseRoutingLines(req.body.custom_domains || '', 'domain');
    const parsedIps = parseRoutingLines(req.body.custom_ips || '', 'ip');
    const parsedExceptDomains = parseRoutingLines(req.body.except_domains || '', 'domain');
    const parsedExceptIps = parseRoutingLines(req.body.except_ips || '', 'ip');
    const geositeUrl = String(req.body.geosite_url || '').trim();
    const geoipUrl = String(req.body.geoip_url || '').trim();
    const geodataUrls = uniqueList([geositeUrl, geoipUrl, ...parsePlainLines(req.body.geodata_urls || '')].filter(v => /^https?:\/\//i.test(v)));
    const dnsPreset = String(req.body.dns_preset || 'cloudflare-google').trim();
    const dnsCustom = parsePlainLines(req.body.dns_custom || '').join('\n');
    let excludedNodeIds = req.body.routing_excluded_node_ids || [];
    if (!Array.isArray(excludedNodeIds)) excludedNodeIds = excludedNodeIds ? [excludedNodeIds] : [];
    excludedNodeIds = uniqueList(excludedNodeIds.map(v => Number(v)).filter(v => Number.isInteger(v) && v > 0));
    const allNodes = req.body.routing_all_nodes === '1';
    const errors = [...parsedDomains.errors, ...parsedIps.errors, ...parsedExceptDomains.errors, ...parsedExceptIps.errors];
    if (errors.length) throw new Error(errors.join(' | '));
    const cfg = {
      enabled: req.body.routing_enabled === '1',
      presets,
      customDomains: parsedDomains.values,
      customIps: parsedIps.values,
      mode: req.body.routing_mode === 'proxy-except' ? 'proxy-except' : 'proxy-selected',
      exceptDomains: parsedExceptDomains.values,
      exceptIps: parsedExceptIps.values,
      geodataUrls,
      geositeUrl: /^https?:\/\//i.test(geositeUrl) ? geositeUrl : '',
      geoipUrl: /^https?:\/\//i.test(geoipUrl) ? geoipUrl : '',
      dnsPreset,
      dnsCustom,
      allNodes,
      excludedNodeIds: allNodes ? [] : excludedNodeIds
    };
    setSetting('routing_config', JSON.stringify(cfg));
    res.redirect('/routing?message=' + encodeURIComponent('Маршрутизация сохранена. Старые JSON-ссылки применят новые правила при следующем обновлении клиента.'));
  } catch (err) {
    res.redirect('/routing?error=' + encodeURIComponent(String(err.message || err)));
  }
});


function getGitValue(args, fallback = '') {
  try {
    return String(execFileSync('git', args, { cwd: APP_DIR_HINT, timeout: 8000, encoding: 'utf8' }) || '').trim();
  } catch (_) {
    return fallback;
  }
}

function getUpdateRepoSlug() {
  const raw = String(getSetting('update_repo_url', process.env.UPDATE_REPO_URL || process.env.GITHUB_REPOSITORY_URL || 'https://github.com/dagmagnat/3xui-Aggregator')).trim();
  const match = raw.match(/github\.com[:/]([^/]+)\/([^/.#?]+)(?:\.git)?/i);
  return match ? `${match[1]}/${match[2]}` : 'dagmagnat/3xui-Aggregator';
}

async function getProjectUpdateStatus(checkRemote = false) {
  const current = getGitValue(['rev-parse', '--short', 'HEAD'], process.env.BUILD_COMMIT ? String(process.env.BUILD_COMMIT).slice(0, 12) : 'unknown');
  const branch = getGitValue(['rev-parse', '--abbrev-ref', 'HEAD'], process.env.UPDATE_BRANCH || 'main');
  const repo = getUpdateRepoSlug();
  let remote = '';
  let hasUpdate = false;
  let error = '';
  if (checkRemote) {
    try {
      const apiUrl = `https://api.github.com/repos/${repo}/commits/${encodeURIComponent(branch)}`;
      const response = await fetchWithTimeout(apiUrl, {
        headers: { 'User-Agent': '3xui-aggregator-update-check', 'Accept': 'application/vnd.github+json' }
      }, 12000);
      if (!response.ok) throw new Error(`GitHub API ${response.status}`);
      const data = await response.json();
      remote = String(data?.sha || '').slice(0, 12);
      hasUpdate = Boolean(remote && current !== 'unknown' && !String(remote).startsWith(String(current).slice(0, 7)));
    } catch (err) {
      error = String(err.message || err);
    }
  }
  return { current, branch, repo, remote, hasUpdate, error };
}

app.get('/settings', requireAuth, async (req, res) => {
  const subscriptionName = getSetting('subscription_name', DEFAULT_SUBSCRIPTION_NAME);
  const currentUser = db.prepare('SELECT username FROM app_users WHERE id = ?').get(req.session.userId);
  const projectUpdateStatus = await getProjectUpdateStatus(req.query.check_update === '1');

  render(res, 'settings', {
    subscriptionName,
    adminUsername: currentUser?.username || '',
    adminAllowedIps: getSetting('admin_allowed_ips', ''),
    showSubLinks: getSetting('show_sub_links', '1') !== '0',
    showHappLinks: getSetting('show_happ_links', '0') !== '0',
    showSubscriptionLimits: getSetting('subscription_show_limits', '1') !== '0',
    sendSubscriptionUserInfo: getSetting('subscription_userinfo_header', '1') !== '0',
    refreshSubscriptionUsage: getSetting('subscription_live_usage', '1') !== '0',
    subscriptionUpdateIntervalHours: getSubscriptionUpdateIntervalHours(),
    subscriptionClientAutoUpdateEnabled: getSetting('subscription_client_auto_update_enabled', '1') !== '0',
    happProviderId: getHappProviderId(),
    jsonMuxEnabled: isJsonMuxEnabled(),
    jsonSniffingEnabled: isJsonSniffingEnabled(),
    happAppControlsEnabled: isHappAppControlsCheckboxEnabled(),
    happAppControlsEffective: isHappAppControlsEnabled(),
    happPingTcp: isHappSettingEnabled('happ_ping_tcp', '1'),
    happPingResultIcon: isHappSettingEnabled('happ_ping_result_icon', '1'),
    happFragmentationEnabled: isHappSettingEnabled('happ_fragmentation_enabled', '0'),
    happNoisesEnabled: isHappSettingEnabled('happ_noises_enabled', '0'),
    happMuxEnabled: isHappSettingEnabled('happ_mux_enabled', '0'),
    happSubscriptionAutoUpdateEnabled: isHappSettingEnabled('happ_subscription_auto_update_enabled', '1'),
    happUpdateOnOpenEnabled: isHappSettingEnabled('happ_update_on_open_enabled', '0'),
    happPingOnOpenEnabled: isHappSettingEnabled('happ_ping_on_open_enabled', '1'),
    happSubscriptionsCollapseEnabled: isHappSettingEnabled('happ_subscriptions_collapse_enabled', '1'),
    happExpandNowEnabled: isHappSettingEnabled('happ_expand_now_enabled', '0'),
    happCheckUrlViaProxyEnabled: isHappSettingEnabled('happ_check_url_via_proxy_enabled', '0'),
    happSniffingEnabled: isHappSettingEnabled('happ_sniffing_enabled', '0'),
    happForceApplyOnUpdateEnabled: isHappSettingEnabled('happ_force_apply_on_update_enabled', '0'),
    telegramBackupLocked: getSetting('telegram_backup_locked', '1') !== '0',
    telegramBackupEnabled: getSetting('telegram_backup_enabled', '0') === '1',
    telegramBackupChatId: getSetting('telegram_backup_chat_id', ''),
    panelPublicUrl: getPanelPublicUrl(),
    panelLoginUrl: `${getPanelPublicUrl()}/login${getCurrentPanelAccessKey() ? `?key=${encodeURIComponent(getCurrentPanelAccessKey())}` : ''}`,
    panelMobileLoginUrl: `${getPanelPublicUrl()}/mobile-login${getCurrentPanelAccessKey() ? `?key=${encodeURIComponent(getCurrentPanelAccessKey())}` : ''}`,
    panelAccessKey: getCurrentPanelAccessKey(),
    subUrlMode: getSubscriptionUrlMode(),
    subPublicUrl: getSetting('sub_public_url', process.env.SUB_PUBLIC_URL || BASE_URL),
    publicSubBaseUrl: getPublicSubBaseUrl(),
    publicJsonExample: `${getPublicSubBaseUrl()}/json/<slug>`,
    publicSubExample: `${getPublicSubBaseUrl()}/sub/<slug>`,
    publicHappExample: `${getPublicSubBaseUrl()}/happ/<slug>`,
    backupFileExample: buildBackupFileName(req, 'json'),
    updateRepoUrl: getSetting('update_repo_url', 'https://github.com/dagmagnat/3xui-Aggregator'),
    runtimePort: PORT,
    runtimeBindIp: INSTALL_BIND_IP,
    runtimeTrustProxy: TRUST_PROXY,
    runtimeSessionSecure: SESSION_SECURE,
    runtimeNodeEnv: process.env.NODE_ENV || '',
    appDirHint: APP_DIR_HINT,
    backupDirHint: BACKUP_DIR_HINT,
    currentIp: getClientIp(req),
    message: req.query.message || '',
    error: req.query.error || '',
    projectUpdateStatus
  });
});

app.post('/settings', requireAuth, (req, res) => {
  try {
    const subscriptionName = String(req.body.subscription_name || '').trim();
    if (!subscriptionName) throw new Error('Нужно указать название подписки');

    db.prepare(`
      INSERT INTO app_settings (key, value, updated_at)
      VALUES (?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(key) DO UPDATE SET
        value = excluded.value,
        updated_at = CURRENT_TIMESTAMP
    `).run('subscription_name', subscriptionName);

    const adminAllowedIps = String(req.body.admin_allowed_ips || '')
      .split(/[\s,;]+/)
      .map(v => v.trim())
      .filter(Boolean)
      .join('\n');

    db.prepare(`
      INSERT INTO app_settings (key, value, updated_at)
      VALUES (?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(key) DO UPDATE SET
        value = excluded.value,
        updated_at = CURRENT_TIMESTAMP
    `).run('admin_allowed_ips', adminAllowedIps);

    db.prepare(`
      INSERT INTO app_settings (key, value, updated_at)
      VALUES (?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(key) DO UPDATE SET
        value = excluded.value,
        updated_at = CURRENT_TIMESTAMP
    `).run('show_sub_links', req.body.show_sub_links === '1' ? '1' : '0');

    db.prepare(`
      INSERT INTO app_settings (key, value, updated_at)
      VALUES (?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(key) DO UPDATE SET
        value = excluded.value,
        updated_at = CURRENT_TIMESTAMP
    `).run('show_happ_links', req.body.show_happ_links === '1' ? '1' : '0');

    setSetting('update_repo_url', String(req.body.update_repo_url || 'https://github.com/dagmagnat/3xui-Aggregator').trim() || 'https://github.com/dagmagnat/3xui-Aggregator');

    const panelPublicUrl = normalizePublicUrl(req.body.panel_public_url || '', process.env.PANEL_PUBLIC_URL || BASE_URL);
    const subPublicUrl = normalizePublicUrl(req.body.sub_public_url || '', process.env.SUB_PUBLIC_URL || panelPublicUrl || BASE_URL);
    const subUrlMode = ['custom', 'panel', 'panel_without_port'].includes(String(req.body.sub_url_mode || 'custom'))
      ? String(req.body.sub_url_mode || 'custom')
      : 'custom';
    const panelAccessKey = String(req.body.panel_access_key || '').trim();
    if (panelAccessKey && panelAccessKey.length < 8) throw new Error('Secret-key должен быть минимум 8 символов или пустым для отключения');

    setSetting('panel_public_url', panelPublicUrl);
    setSetting('sub_public_url', subPublicUrl);
    setSetting('sub_url_mode', subUrlMode);
    setSetting('panel_access_key', panelAccessKey);

    setSetting('subscription_show_limits', req.body.subscription_show_limits === '1' ? '1' : '0');
    setSetting('subscription_userinfo_header', req.body.subscription_userinfo_header === '1' ? '1' : '0');
    setSetting('subscription_live_usage', req.body.subscription_live_usage === '1' ? '1' : '0');
    setSetting('subscription_client_auto_update_enabled', req.body.subscription_client_auto_update_enabled === '1' ? '1' : '0');
    setSetting('happ_provider_id', String(req.body.happ_provider_id || '').trim());
    setSetting('json_mux_enabled', req.body.json_mux_enabled === '1' ? '1' : '0');
    setSetting('json_sniffing_enabled', req.body.json_sniffing_enabled === '1' ? '1' : '0');
    setSetting('happ_app_controls_enabled', req.body.happ_app_controls_enabled === '1' ? '1' : '0');
    setSetting('happ_ping_tcp', req.body.happ_ping_tcp === '1' ? '1' : '0');
    setSetting('happ_ping_result_icon', req.body.happ_ping_result_icon === '1' ? '1' : '0');
    setSetting('happ_fragmentation_enabled', req.body.happ_fragmentation_enabled === '1' ? '1' : '0');
    setSetting('happ_noises_enabled', req.body.happ_noises_enabled === '1' ? '1' : '0');
    setSetting('happ_mux_enabled', req.body.happ_mux_enabled === '1' ? '1' : '0');
    setSetting('happ_subscription_auto_update_enabled', req.body.happ_subscription_auto_update_enabled === '1' ? '1' : '0');
    setSetting('happ_update_on_open_enabled', req.body.happ_update_on_open_enabled === '1' ? '1' : '0');
    setSetting('happ_ping_on_open_enabled', req.body.happ_ping_on_open_enabled === '1' ? '1' : '0');
    setSetting('happ_subscriptions_collapse_enabled', req.body.happ_subscriptions_collapse_enabled === '1' ? '1' : '0');
    setSetting('happ_expand_now_enabled', req.body.happ_expand_now_enabled === '1' ? '1' : '0');
    setSetting('happ_check_url_via_proxy_enabled', req.body.happ_check_url_via_proxy_enabled === '1' ? '1' : '0');
    setSetting('happ_sniffing_enabled', req.body.happ_sniffing_enabled === '1' ? '1' : '0');
    setSetting('happ_force_apply_on_update_enabled', req.body.happ_force_apply_on_update_enabled === '1' ? '1' : '0');

    const rawSubscriptionUpdateIntervalHours = Number(req.body.subscription_update_interval_hours || 1);
    if (!Number.isFinite(rawSubscriptionUpdateIntervalHours)) throw new Error('Интервал автообновления должен быть числом от 1 до 168 часов');
    const subscriptionUpdateIntervalHours = Math.min(168, Math.max(1, Math.floor(rawSubscriptionUpdateIntervalHours)));
    setSetting('subscription_update_interval_hours', String(subscriptionUpdateIntervalHours));

    const currentPassword = String(req.body.current_password || '');
    const newUsername = String(req.body.admin_username || '').trim();
    const newPassword = String(req.body.new_password || '');
    const newPassword2 = String(req.body.new_password_confirm || '');
    const user = db.prepare('SELECT * FROM app_users WHERE id = ?').get(req.session.userId);
    const usernameChanged = Boolean(user && newUsername && newUsername !== user.username);
    const wantsAccountChange = Boolean(usernameChanged || newPassword || currentPassword || newPassword2);

    if (wantsAccountChange) {
      if (!user) throw new Error('Администратор не найден');
      if (!bcrypt.compareSync(currentPassword, user.password_hash)) {
        throw new Error('Текущий пароль указан неверно');
      }

      const finalUsername = newUsername || user.username;
      const owner = db.prepare('SELECT id FROM app_users WHERE username = ? AND id != ?').get(finalUsername, user.id);
      if (owner) throw new Error('Такой логин администратора уже существует');

      let finalHash = user.password_hash;
      if (newPassword) {
        if (newPassword.length < 8) throw new Error('Новый пароль должен быть минимум 8 символов');
        if (newPassword !== newPassword2) throw new Error('Новый пароль и повтор не совпадают');
        finalHash = bcrypt.hashSync(newPassword, 12);
      }

      db.prepare('UPDATE app_users SET username = ?, password_hash = ? WHERE id = ?')
        .run(finalUsername, finalHash, user.id);
    }

    res.redirect('/settings?message=' + encodeURIComponent('Настройки сохранены'));
  } catch (err) {
    res.redirect('/settings?error=' + encodeURIComponent(String(err.message || err)));
  }
});

function exportBackupPayload(req = null) {
  const tables = ['app_users', 'app_settings', 'nodes', 'clients', 'client_nodes', 'node_inbound_cache'];
  const data = {};
  for (const table of tables) data[table] = db.prepare(`SELECT * FROM ${table}`).all();
  return {
    app: '3xui-aggregator',
    version: 2,
    created_at: new Date().toISOString(),
    panel_host: req ? getRequestPanelHost(req) : '',
    panel_identity: req ? getBackupPanelIdentity(req) : safeFileSegment(BASE_URL, 'panel'),
    data
  };
}

function tableColumns(table) {
  return db.prepare(`PRAGMA table_info(${table})`).all().map(row => row.name);
}

function ensureAdminUserExists() {
  const row = db.prepare('SELECT id FROM app_users LIMIT 1').get();
  if (row) return;
  const passwordHash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
  db.prepare('INSERT INTO app_users (username, password_hash) VALUES (?, ?)').run(ADMIN_USERNAME, passwordHash);
}

function restoreBackupPayload(payload) {
  if (!payload || payload.app !== '3xui-aggregator' || !payload.data) throw new Error('Неверный файл резервной копии');
  const deleteTables = ['node_inbound_cache', 'client_nodes', 'clients', 'nodes', 'app_settings', 'app_users'];
  const restoreTables = ['app_users', 'app_settings', 'nodes', 'clients', 'client_nodes', 'node_inbound_cache'];
  const columnCache = new Map();
  const tx = db.transaction(() => {
    for (const table of deleteTables) db.prepare(`DELETE FROM ${table}`).run();
    for (const table of restoreTables) {
      const rows = Array.isArray(payload.data[table]) ? payload.data[table] : [];
      if (!rows.length) continue;
      const allowed = new Set(columnCache.get(table) || tableColumns(table));
      columnCache.set(table, Array.from(allowed));

      for (const row of rows) {
        const clean = {};
        for (const [key, value] of Object.entries(row || {})) {
          if (allowed.has(key)) clean[key] = value;
        }
        const keys = Object.keys(clean);
        if (!keys.length) continue;
        const cols = keys.map(k => `"${k}"`).join(', ');
        const placeholders = keys.map(k => `@${k}`).join(', ');
        db.prepare(`INSERT INTO ${table} (${cols}) VALUES (${placeholders})`).run(clean);
      }
    }
  });
  tx();

  // Старые backup-файлы не знают о новых настройках panel/sub URL и secret-key.
  // После восстановления добавляем недостающие значения из текущего .env, не
  // перезаписывая клиентов, узлы и уже существующие настройки backup-файла.
  ensureAdminUserExists();
  ensureMissingAppSettings();
}

app.get('/backup/download', requireAuth, (req, res) => {
  const payload = exportBackupPayload(req);
  const fileName = buildBackupFileName(req, 'json');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  setAttachmentDispositionHeader(res, fileName, 'backup');
  res.send(JSON.stringify(payload, null, 2));
});

app.post('/backup/restore', requireAuth, bodyParser.text({ type: '*/*', limit: '50mb' }), (req, res) => {
  try {
    const text = String(req.body || '').trim();
    if (!text) throw new Error('Файл резервной копии пустой');
    restoreBackupPayload(JSON.parse(text));
    req.session.destroy(() => res.redirect(buildLoginRedirectPath('Резервная копия восстановлена. Войди заново.')));
  } catch (err) {
    res.status(400).send(String(err.message || err));
  }
});

app.get('/nodes', requireAuth, (req, res) => {
  const nodes = db.prepare('SELECT * FROM nodes ORDER BY id DESC').all();

  render(res, 'nodes', {
    nodes,
    countries: [...COUNTRIES].sort((a, b) => a.name_ru.localeCompare(b.name_ru, 'ru')),
    message: req.query.message || '',
    error: req.query.error || ''
  });
});

app.post('/nodes', requireAuth, async (req, res) => {
  try {
    const { panel_url, panel_path, username, password, inbound_id, country_code, label_suffix } = req.body;

    const country = COUNTRIES.find(c => c.code === country_code);
    if (!country) throw new Error('Страна не найдена');

    const info = db.prepare(`
      INSERT INTO nodes (
        name,
        panel_url,
        panel_path,
        sub_base_url,
        username,
        password_enc,
        inbound_id,
        country_code,
        country_name_ru,
        country_flag,
        label_suffix
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      country.name_ru,
      String(panel_url || '').trim(),
      String(panel_path || '').trim(),
      '',
      String(username || '').trim(),
      encrypt(String(password || '').trim(), APP_SECRET),
      Number(inbound_id),
      country.code,
      country.name_ru,
      country.flag,
      String(label_suffix || '').trim()
    );

    const node = db.prepare('SELECT * FROM nodes WHERE id = ?').get(info.lastInsertRowid);
    const check = await checkNode(node);
    const importClients = req.body.import_clients_from_node === '1' || req.body.add_clients_from_aggregator === '1';
    let message = check.ok ? 'Узел добавлен и проверен' : 'Узел добавлен, но проверка не прошла';
    let errorText = check.ok ? '' : String(check.error || 'узел офлайн');

    if (importClients) {
      const result = await refreshLocalClientsFromSourceNode(node);
      message += '. Импорт клиентов из узла: найдено ' + result.totalSourceClients + ', новых ' + result.imported + ', обновлено ' + result.updated + ', связей ' + result.mappingsCreated + ', ошибок ' + result.failed;
      if (result.errors && result.errors.length) errorText = [errorText, ...result.errors].filter(Boolean).join(' | ');
    }

    const qs = new URLSearchParams({ message });
    if (errorText) qs.set('error', errorText);
    res.redirect('/nodes?' + qs.toString());
  } catch (err) {
    res.redirect('/nodes?error=' + encodeURIComponent(String(err.message || err)));
  }
});

app.post('/nodes/:id/check', requireAuth, async (req, res) => {
  const node = db.prepare('SELECT * FROM nodes WHERE id = ?').get(Number(req.params.id));

  if (!node) {
    return res.redirect('/nodes?error=' + encodeURIComponent('Узел не найден'));
  }

  const result = await checkNode(node);
  const msg = result.ok ? 'Узел онлайн' : `Узел офлайн: ${result.error}`;

  res.redirect('/nodes?message=' + encodeURIComponent(msg));
});

app.post('/nodes/:id/sync-clients', requireAuth, async (req, res) => {
  const node = db.prepare('SELECT * FROM nodes WHERE id = ?').get(Number(req.params.id));
  if (!node) return res.redirect('/nodes?error=' + encodeURIComponent('Узел не найден'));

  try {
    const result = await refreshLocalClientsFromSourceNode(node);
    const message = 'Импорт клиентов из узла завершён: найдено ' + result.totalSourceClients + ', новых ' + result.imported + ', обновлено ' + result.updated + ', связей ' + result.mappingsCreated + ', ошибок ' + result.failed;
    const qs = new URLSearchParams({ message });
    if (result.errors && result.errors.length) qs.set('error', result.errors.join(' | '));
    res.redirect('/nodes?' + qs.toString());
  } catch (err) {
    res.redirect('/nodes?error=' + encodeURIComponent('Импорт клиентов из узла не удался: ' + String(err.message || err)));
  }
});


app.post('/nodes/:id/toggle', requireAuth, (req, res) => {
  try {
    const nodeId = Number(req.params.id);
    const node = db.prepare('SELECT * FROM nodes WHERE id = ?').get(nodeId);

    if (!node) {
      return res.redirect('/nodes?error=' + encodeURIComponent('Узел не найден'));
    }

    const nextEnabled = Number(node.enabled) === 1 ? 0 : 1;

    db.prepare('UPDATE nodes SET enabled = ? WHERE id = ?').run(nextEnabled, nodeId);

    const msg = nextEnabled
      ? 'Узел включён и снова будет попадать в SUB/JSON'
      : 'Узел отключён и не будет попадать в SUB/JSON';

    res.redirect('/nodes?message=' + encodeURIComponent(msg));
  } catch (err) {
    res.redirect('/nodes?error=' + encodeURIComponent(String(err.message || err)));
  }
});

app.get('/nodes/:id/edit', requireAuth, async (req, res) => {
  const node = db.prepare('SELECT * FROM nodes WHERE id = ?').get(Number(req.params.id));

  if (!node) {
    return res.redirect('/nodes?error=' + encodeURIComponent('Узел не найден'));
  }

  let inboundPreview = null;
  let loadError = '';
  try {
    const inbound = req.query.load_inbound === '1' ? await getInbound(node, 15000) : getCachedInbound(node);
    inboundPreview = extractInboundEditorValues(inbound);
  } catch (err) {
    loadError = String(err.message || err);
  }

  render(res, 'node_edit', {
    node,
    inboundPreview,
    countries: [...COUNTRIES].sort((a, b) => a.name_ru.localeCompare(b.name_ru, 'ru')),
    message: req.query.message || '',
    error: req.query.error || loadError || ''
  });
});

app.post('/nodes/:id/edit', requireAuth, async (req, res) => {
  try {
    const nodeId = Number(req.params.id);
    const existingNode = db.prepare('SELECT * FROM nodes WHERE id = ?').get(nodeId);

    if (!existingNode) {
      return res.redirect('/nodes?error=' + encodeURIComponent('Узел не найден'));
    }

    const {
      panel_url,
      panel_path,
      username,
      password,
      inbound_id,
      country_code,
      label_suffix
    } = req.body;

    const country = COUNTRIES.find(c => c.code === country_code);
    if (!country) throw new Error('Страна не найдена');

    const updatedPasswordEnc = String(password || '').trim()
      ? encrypt(String(password).trim(), APP_SECRET)
      : existingNode.password_enc;

    db.prepare(`
      UPDATE nodes
      SET
        name = ?,
        panel_url = ?,
        panel_path = ?,
        sub_base_url = ?,
        username = ?,
        password_enc = ?,
        inbound_id = ?,
        country_code = ?,
        country_name_ru = ?,
        country_flag = ?,
        label_suffix = ?
      WHERE id = ?
    `).run(
      country.name_ru,
      String(panel_url || '').trim(),
      String(panel_path || '').trim(),
      '',
      String(username || '').trim(),
      updatedPasswordEnc,
      Number(inbound_id),
      country.code,
      country.name_ru,
      country.flag,
      String(label_suffix || '').trim(),
      nodeId
    );

    const updatedNode = db.prepare('SELECT * FROM nodes WHERE id = ?').get(nodeId);
    const inboundEditorKeys = [
      'inbound_port',
      'inbound_remark',
      'inbound_sni',
      'inbound_fingerprint',
      'inbound_short_id',
      'inbound_spider_x',
      'inbound_xhttp_path',
      'inbound_xhttp_host',
      'inbound_xhttp_mode',
      'inbound_xhttp_sc',
      'inbound_xhttp_fragment',
      'inbound_sniffing_enabled',
      'inbound_sniffing_dest'
    ];
    const hasInboundEditorFields = inboundEditorKeys.some(key => Object.prototype.hasOwnProperty.call(req.body || {}, key));
    const shouldApplyInboundSettings = req.body.apply_inbound_settings === '1' || hasInboundEditorFields;
    if (shouldApplyInboundSettings) {
      await updateInboundBasicSettings(updatedNode, req.body);
    }
    await checkNode(updatedNode);

    const editMsg = shouldApplyInboundSettings ? 'Узел и параметры inbound обновлены в 3x-ui' : 'Узел обновлён';
    res.redirect('/nodes?message=' + encodeURIComponent(editMsg));
  } catch (err) {
    res.redirect('/nodes/' + req.params.id + '/edit?error=' + encodeURIComponent(String(err.message || err)));
  }
});

app.post('/nodes/:id/delete', requireAuth, (req, res) => {
  db.prepare('DELETE FROM nodes WHERE id = ?').run(Number(req.params.id));
  res.redirect('/nodes?message=' + encodeURIComponent('Узел удалён'));
});

app.get('/clients', requireAuth, (req, res) => {
  try {
  const q = String(req.query.q || '').trim();
  const qNorm = normalizeSearchText(q);
  const allClients = db.prepare(`
        SELECT c.*,
          (
            SELECT cn.remote_sub_url
            FROM client_nodes cn
            WHERE cn.client_id = c.id
              AND cn.remote_sub_url LIKE 'http%'
            ORDER BY cn.id ASC
            LIMIT 1
          ) AS source_sub_url
        FROM clients c
        ORDER BY c.id DESC
      `).all();
  const clients = qNorm
    ? allClients.filter(c => [c.login, c.display_name, c.uuid, c.comment, c.source_sub_url].some(v => normalizeSearchText(v).includes(qNorm)))
    : allClients;

  for (const client of clients) {
    client.node_limits = db.prepare(`
      SELECT
        n.id AS node_id,
        n.country_code,
        n.country_name_ru,
        n.country_flag,
        n.name,
        n.label_suffix,
        n.inbound_id,
        cn.id AS client_node_id,
        cn.remote_email,
        cn.remote_uuid,
        cn.traffic_gb,
        cn.limit_ip,
        cn.upload_bytes,
        cn.download_bytes,
        cn.used_bytes,
        CASE WHEN cn.id IS NULL THEN 0 ELSE cn.enabled END AS enabled
      FROM nodes n
      LEFT JOIN client_nodes cn ON cn.node_id = n.id AND cn.client_id = ?
      WHERE n.enabled = 1
      ORDER BY n.id ASC
    `).all(client.id);

    for (const row of client.node_limits) {
      if (!row.client_node_id) continue;
      const usage = readUsageForClientNode({ id: row.node_id, inbound_id: row.inbound_id }, client, row);
      row.upload_bytes = usage.uploadBytes;
      row.download_bytes = usage.downloadBytes;
      row.used_bytes = usage.usedBytes;
      row.limit_bytes = toTotalGbBytes(row.traffic_gb || 0);
      row.remaining_bytes = Math.max(0, row.limit_bytes - row.used_bytes);
      updateClientNodeUsage(row.client_node_id, usage);
    }
  }

  const nodes = db.prepare('SELECT * FROM nodes WHERE enabled = 1 ORDER BY id ASC').all();

  render(res, 'clients', {
    clients,
    nodes,
    message: req.query.message || '',
    error: req.query.error || '',
    baseUrl: getPublicSubBaseUrl(),
    q,
    nextLogin: getNextAutoLogin(),
    showSubLinks: getSetting('show_sub_links', '1') !== '0',
    showHappLinks: getSetting('show_happ_links', '0') !== '0'
  });
  } catch (err) {
    console.error('Clients page failed:', err);
    res.status(500).send(`Ошибка открытия списка клиентов: ${htmlEscape(String(err.message || err))}<br><br>Проверь логи командой:<br><code>docker logs --tail=100 3xui-aggregator</code>`);
  }
});

app.post('/clients', requireAuth, async (req, res) => {
  try {
    const { login, limit_ip, duration_days, traffic_gb, comment } = req.body;
    let nodeIds = req.body.node_ids || [];

    if (!Array.isArray(nodeIds)) nodeIds = [nodeIds];
    nodeIds = uniqueList(nodeIds.map(v => Number(v)).filter(v => Number.isInteger(v) && v > 0));
    if (!nodeIds.length) throw new Error('Нужно выбрать хотя бы один узел');

    const requestedLogin = String(login || '').trim();
    const remoteScan = await collectRemoteLoginsForNodes(nodeIds);
    const cleanLogin = requestedLogin || getNextAutoLogin(remoteScan.emails);
    const cleanDisplayName = cleanLogin;
    const cleanComment = String(comment || "").trim();

    const localOwner = findCaseInsensitiveClientOwner(cleanLogin, 0);
    if (localOwner) {
      throw new Error(`Логин ${cleanLogin} уже есть в агрегаторе как ${localOwner.login}. Регистр букв не учитывается.`);
    }

    const remoteConflicts = remoteScan.records.filter(item => isSameLogin(item.email, cleanLogin));
    if (remoteConflicts.length) {
      const first = remoteConflicts[0];
      throw makeRemoteClientConflictError(first.node, cleanLogin, first.remote, { email: cleanLogin });
    }

    const cleanLimitIp = Math.max(0, Number(limit_ip ?? 1));
    const cleanDurationDays = Math.max(0, Number(duration_days || 0));
    const cleanTrafficGb = Math.max(0, Number(traffic_gb || 0));
    const totalGbBytes = toTotalGbBytes(cleanTrafficGb);

    const expiryTime = cleanDurationDays > 0
      ? expiryAtMidnightAfterDays(cleanDurationDays)
      : 0;

    const uuid = randomUUID();
    const sharedSubId = randomUUID().replace(/-/g, '').slice(0, 16);
    const subSlug = sharedSubId;

    const clientInfo = db.prepare(`
      INSERT INTO clients (login, display_name, uuid, sub_slug, duration_days, traffic_gb, limit_ip, expiry_time, comment)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(cleanLogin, cleanDisplayName, uuid, subSlug, cleanDurationDays, cleanTrafficGb, cleanLimitIp, expiryTime, cleanComment);

    const clientId = clientInfo.lastInsertRowid;

    for (const nodeIdRaw of nodeIds) {
      const nodeId = Number(nodeIdRaw);
      const node = db.prepare('SELECT * FROM nodes WHERE id = ?').get(nodeId);

      if (!node) throw new Error(`Узел ${nodeId} не найден`);

      const inbound = await getInbound(node);
      const settings = safeParseJsonField(inbound.settings, {});
      const clientEmail = cleanLogin;
      const nodeTrafficRaw = req.body[`node_traffic_gb_${node.id}`];
      const nodeTrafficGb = String(nodeTrafficRaw || '').trim() === '' ? cleanTrafficGb : Math.max(0, Number(nodeTrafficRaw || 0));
      const nodeTotalGbBytes = toTotalGbBytes(nodeTrafficGb);

      const clientPayload = {
        id: Number(node.inbound_id),
        settings: JSON.stringify({
          clients: [{
            id: uuid,
            email: clientEmail,
            flow: settings.clients?.[0]?.flow || '',
            limitIp: cleanLimitIp,
            totalGB: nodeTotalGbBytes,
            expiryTime,
            enable: true,
            tgId: '',
            subId: sharedSubId,
            reset: cleanDurationDays > 0 && nodeTrafficGb > 0 ? cleanDurationDays : 0,
            comment: cleanComment
          }]
        })
      };

      await addClient(node, clientPayload);

      const subUrl = buildNativeSubUrl(node, sharedSubId);

      db.prepare(`
        INSERT INTO client_nodes (
          client_id,
          node_id,
          remote_email,
          remote_uuid,
          remote_sub_url,
          traffic_gb,
          limit_ip,
          enabled
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(clientId, node.id, clientEmail, uuid, subUrl, nodeTrafficGb, cleanLimitIp, 1);
    }

    res.redirect('/clients?message=' + encodeURIComponent('Клиент создан на выбранных узлах'));
  } catch (err) {
    res.redirect('/clients?error=' + encodeURIComponent(String(err.message || err)));
  }
});

app.post('/clients/import', requireAuth, async (req, res) => {
  try {
    const sourceNodeId = Number(req.body.node_id);
    const sourceNode = db.prepare('SELECT * FROM nodes WHERE id = ?').get(sourceNodeId);

    if (!sourceNode) throw new Error('Узел не найден');

    const result = await syncClientsFromSourceNode(sourceNode);

    const baseMessage = `Импорт завершён. Источник: ${result.totalSourceClients}, новых: ${result.imported}, обновлено: ${result.updated}, создано на узлах: ${result.remoteCreated}, обновлено на узлах: ${result.remoteUpdated}, связей: ${result.mappingsCreated}, ошибок: ${result.failed}`;
    const qs = new URLSearchParams({ message: baseMessage });
    if (result.errors && result.errors.length) qs.set('error', result.errors.join(' | '));
    res.redirect('/clients?' + qs.toString());
  } catch (err) {
    res.redirect('/clients?error=' + encodeURIComponent(String(err.message || err)));
  }
});

app.post('/clients/sync-nodes', requireAuth, async (req, res) => {
  try {
    const result = await syncAggregatorClientsToAllNodes();
    const baseMessage = `Синхронизация узлов завершена. Узлов: ${result.nodes}, клиентов: ${result.totalClients}, создано: ${result.remoteCreated}, обновлено: ${result.remoteUpdated}, связей: ${result.mappingsCreated}, ошибок: ${result.failed}`;
    const qs = new URLSearchParams({ message: baseMessage });
    if (result.errors && result.errors.length) qs.set('error', result.errors.join(' | '));
    res.redirect('/clients?' + qs.toString());
  } catch (err) {
    res.redirect('/clients?error=' + encodeURIComponent(String(err.message || err)));
  }
});

app.post('/clients/apply-to-node', requireAuth, async (req, res) => {
  try {
    const nodeId = Number(req.body.node_id);
    const node = db.prepare('SELECT * FROM nodes WHERE id = ?').get(nodeId);
    if (!node) throw new Error('Узел не найден');

    const result = await applyNodeLimitsToAllClients(node, {
      traffic_gb: req.body.traffic_gb,
      limit_ip: req.body.limit_ip
    });

    const nodeName = getNodePublicName(node);
    const baseMessage = `Настройки применены к узлу ${nodeName}. Клиентов: ${result.totalClients}, создано: ${result.remoteCreated}, обновлено: ${result.remoteUpdated}, связей: ${result.mappingsCreated}, ошибок: ${result.failed}`;
    const qs = new URLSearchParams({ message: baseMessage });
    if (result.errors && result.errors.length) qs.set('error', result.errors.join(' | '));
    res.redirect('/clients?' + qs.toString());
  } catch (err) {
    res.redirect('/clients?error=' + encodeURIComponent(String(err.message || err)));
  }
});


app.post('/clients/refresh-subscriptions', requireAuth, async (req, res) => {
  try {
    const sourceNodeId = Number(req.body.node_id);
    const sourceNode = db.prepare('SELECT * FROM nodes WHERE id = ?').get(sourceNodeId);

    if (!sourceNode) throw new Error('Узел не найден');

    const result = await refreshLocalClientsFromSourceNode(sourceNode);

    const baseMessage = `Обновление из узла завершено. Источник: ${result.totalSourceClients}, новых: ${result.imported}, обновлено: ${result.updated}, связей: ${result.mappingsCreated}, ошибок: ${result.failed}`;
    const qs = new URLSearchParams({ message: baseMessage });
    if (result.errors && result.errors.length) qs.set('error', result.errors.join(' | '));
    res.redirect('/clients?' + qs.toString());
  } catch (err) {
    res.redirect('/clients?error=' + encodeURIComponent(String(err.message || err)));
  }
});

app.post('/clients/delete-all', requireAuth, async (req, res) => {
  try {
    const deleteMode = String(req.body.delete_mode || 'aggregator');
    const clients = db.prepare('SELECT * FROM clients ORDER BY id ASC').all();

    for (const client of clients) {
      await deleteClientEverywhere(client, deleteMode);
    }

    res.redirect('/clients?message=' + encodeURIComponent('Все клиенты удалены'));
  } catch (err) {
    res.redirect('/clients?error=' + encodeURIComponent(String(err.message || err)));
  }
});

app.post('/clients/bulk-delete', requireAuth, async (req, res) => {
  try {
    let ids = req.body.client_ids || [];
    const deleteMode = String(req.body.delete_mode || 'aggregator');

    if (!Array.isArray(ids)) ids = [ids];
    ids = ids.map(Number).filter(Boolean);

    for (const id of ids) {
      const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(id);
      if (client) await deleteClientEverywhere(client, deleteMode);
    }

    res.redirect('/clients?message=' + encodeURIComponent(`Удалено клиентов: ${ids.length}`));
  } catch (err) {
    res.redirect('/clients?error=' + encodeURIComponent(String(err.message || err)));
  }
});

app.post('/clients/:id/sync', requireAuth, async (req, res) => {
  try {
    const clientId = Number(req.params.id);
    let nodeIds = req.body.node_ids || [];

    if (!Array.isArray(nodeIds)) nodeIds = [nodeIds];
    nodeIds = uniqueList(nodeIds.map(v => Number(v)).filter(v => Number.isInteger(v) && v > 0));
    if (!nodeIds.length) throw new Error('Нужно выбрать хотя бы один узел');

    const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(clientId);
    if (!client) throw new Error('Клиент не найден');

    const mappings = db.prepare(`
      SELECT * FROM client_nodes
      WHERE client_id = ?
      ORDER BY id ASC
    `).all(clientId);

    if (!mappings.length) throw new Error('У клиента нет исходного узла');

    const sourceMap = mappings[0];
    const sourceNode = db.prepare('SELECT * FROM nodes WHERE id = ?').get(sourceMap.node_id);

    if (!sourceNode) throw new Error('Исходный узел не найден');

    const { clientCfg } = await getClientConfigFromNode(sourceNode, sourceMap.remote_uuid, sourceMap.remote_email);

    for (const nodeIdRaw of nodeIds) {
      const nodeId = Number(nodeIdRaw);

      const alreadyExists = db.prepare(`
        SELECT id FROM client_nodes
        WHERE client_id = ? AND node_id = ?
      `).get(clientId, nodeId);

      if (alreadyExists) continue;

      const node = db.prepare('SELECT * FROM nodes WHERE id = ?').get(nodeId);
      if (!node) continue;

      const inbound = await getInbound(node);
      const settings = safeParseJsonField(inbound.settings, {});

      const clientEmail = sourceMap.remote_email;
      const subId = clientCfg?.subId || client.sub_slug || randomUUID().replace(/-/g, '').slice(0, 16);

      const payload = {
        id: Number(node.inbound_id),
        settings: JSON.stringify({
          clients: [{
            id: client.uuid,
            email: clientEmail,
            flow: clientCfg?.flow || settings.clients?.[0]?.flow || '',
            limitIp: clientCfg?.limitIp ?? client.limit_ip ?? 1,
            totalGB: Number(clientCfg?.totalGB || toTotalGbBytes(client.traffic_gb || 0)),
            expiryTime: normalizeRemoteEpochMillis(clientCfg?.expiryTime || client.expiry_time || 0),
            enable: clientCfg?.enable !== false && client.enabled !== 0,
            tgId: clientCfg?.tgId || '',
            subId,
            reset: clientCfg?.reset || client.duration_days || 0
          }]
        })
      };

      await addClient(node, payload);

      const subUrl = buildNativeSubUrl(node, subId);

      db.prepare(`
        INSERT INTO client_nodes (
          client_id,
          node_id,
          remote_email,
          remote_uuid,
          remote_sub_url,
          traffic_gb,
          limit_ip,
          enabled
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(clientId, node.id, clientEmail, client.uuid, subUrl, Math.max(0, Number(client.traffic_gb || 0)), Math.max(0, Number(client.limit_ip ?? 1)), 1);
    }

    res.redirect(`/clients/${clientId}`);
  } catch (err) {
    res.redirect('/clients?error=' + encodeURIComponent(String(err.message || err)));
  }
});

app.get('/clients/:id', requireAuth, async (req, res) => {
  try {
    const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(Number(req.params.id));

    if (!client) {
      return res.status(404).send('Client not found');
    }

    const mappings = db.prepare(`
      SELECT
        cn.*,
        n.id AS node_real_id,
        n.name AS node_name,
        n.country_code,
        n.country_name_ru,
        n.country_flag,
        n.label_suffix,
        n.last_status,
        n.inbound_id
      FROM client_nodes cn
      JOIN nodes n ON n.id = cn.node_id
      WHERE cn.client_id = ?
      ORDER BY cn.id ASC
    `).all(client.id);

    const lines = await buildSubscriptionLines(client, true);
    const nodes = db.prepare(`
      SELECT * FROM nodes
      WHERE enabled = 1
        AND id NOT IN (SELECT node_id FROM client_nodes WHERE client_id = ?)
      ORDER BY id ASC
    `).all(client.id);

    const sourceSubUrl =
      mappings.find(m => m.remote_sub_url && /^https?:\/\//.test(m.remote_sub_url))?.remote_sub_url || '';

    render(res, 'client_detail', {
      client,
      mappings,
      subscription: lines.join('\n'),
      baseUrl: getPublicSubBaseUrl(),
      sourceSubUrl,
      nodes,
      message: req.query.message || '',
      error: req.query.error || ''
    });
  } catch (err) {
    console.error('Client detail error:', err);
    res.status(500).send('Internal Server Error: ' + String(err.message || err));
  }
});

app.post('/clients/:id/edit', requireAuth, async (req, res) => {
  try {
    const clientId = Number(req.params.id);
    const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(clientId);
    if (!client) throw new Error('Клиент не найден');

    const login = String(req.body.login || '').trim() || client.login;
    const displayName = String(req.body.display_name || login).trim() || login;
    const limitIp = Math.max(0, Number(req.body.limit_ip ?? client.limit_ip ?? 1));
    const rawDurationDays = String(req.body.duration_days ?? '').trim();
    const durationWasChanged = rawDurationDays !== '';
    const durationDays = durationWasChanged
      ? Math.max(0, Number(rawDurationDays || 0))
      : Math.max(0, Number(client.duration_days || 0));
    const trafficGb = Math.max(0, Number(req.body.traffic_gb || 0));
    const comment = String(req.body.comment || "").trim();
    const expiryTime = durationWasChanged
      ? (durationDays > 0 ? expiryAtMidnightAfterDays(durationDays) : 0)
      : Math.max(0, Number(client.expiry_time || 0));

    const loginOwner = findCaseInsensitiveClientOwner(login, clientId);
    if (loginOwner) throw new Error(`Такой логин уже существует: ${loginOwner.login}. Регистр букв не учитывается.`);

    db.prepare(`
      UPDATE clients
      SET login = ?, display_name = ?, limit_ip = ?, duration_days = ?, traffic_gb = ?, expiry_time = ?, comment = ?
      WHERE id = ?
    `).run(login, displayName, limitIp, durationDays, trafficGb, expiryTime, comment, clientId);

    const updatedClient = db.prepare('SELECT * FROM clients WHERE id = ?').get(clientId);
    const nodesForEdit = db.prepare('SELECT * FROM nodes WHERE enabled = 1 ORDER BY id ASC').all();
    const nodeErrors = [];

    for (const node of nodesForEdit) {
      const raw = req.body[`node_traffic_gb_${node.id}`];
      const nodeTrafficGb = String(raw || '').trim() === '' ? trafficGb : Math.max(0, Number(raw || 0));
      const nodeEnabled = req.body[`node_enabled_${node.id}`] === '1';
      const map = db.prepare('SELECT * FROM client_nodes WHERE client_id = ? AND node_id = ?').get(clientId, node.id);

      try {
        if (map) {
          await updateClientOnNode(node, map, updatedClient, {
            email: login,
            limit_ip: limitIp,
            duration_days: durationDays,
            traffic_gb: nodeTrafficGb,
            expiry_time: expiryTime,
            comment,
            node_enabled: nodeEnabled
          });
          continue;
        }

        if (!nodeEnabled) continue;

        const inbound = await getInbound(node);
        const settings = safeParseJsonField(inbound.settings, {});
        const subId = updatedClient.sub_slug || randomUUID().replace(/-/g, '').slice(0, 16);
        const payload = {
          id: Number(node.inbound_id),
          settings: JSON.stringify({
            clients: [{
              id: updatedClient.uuid,
              email: login,
              flow: settings.clients?.[0]?.flow || '',
              limitIp,
              totalGB: toTotalGbBytes(nodeTrafficGb),
              expiryTime,
              enable: updatedClient.enabled !== 0,
              tgId: '',
              subId,
              reset: durationDays > 0 && nodeTrafficGb > 0 ? durationDays : 0,
              comment
            }]
          })
        };

        await addClient(node, payload);
        db.prepare(`
          INSERT INTO client_nodes (client_id, node_id, remote_email, remote_uuid, remote_sub_url, traffic_gb, limit_ip, enabled)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(clientId, node.id, login, updatedClient.uuid, buildNativeSubUrl(node, subId), nodeTrafficGb, limitIp, 1);
      } catch (err) {
        const nodeTitle = getNodePublicName(node);
        const errText = `${nodeTitle}: ${err.message || err}`;
        nodeErrors.push(errText);
        console.error('Update client node failed:', errText);
      }
    }

    const message = nodeErrors.length
      ? 'Клиент обновлён локально. Часть узлов не приняла изменения в 3x-ui.'
      : 'Клиент обновлён';
    const errorText = nodeErrors.length ? nodeErrors.slice(0, 3).join(' | ') : '';
    const back = String(req.body.back || '/clients');
    if (back === '/clients') {
      const qs = new URLSearchParams({ message });
      if (errorText) qs.set('error', errorText);
      return res.redirect('/clients?' + qs.toString());
    }
    const qs = new URLSearchParams({ message });
    if (errorText) qs.set('error', errorText);
    res.redirect('/clients/' + clientId + '?' + qs.toString());
  } catch (err) {
    const back = String(req.body.back || '/clients');
    if (back === '/clients') {
      return res.redirect('/clients?error=' + encodeURIComponent(String(err.message || err)));
    }
    res.redirect('/clients/' + req.params.id + '?error=' + encodeURIComponent(String(err.message || err)));
  }
});

app.post('/clients/:id/extend', requireAuth, async (req, res) => {
  try {
    const clientId = Number(req.params.id);
    const days = Math.max(1, Number(req.body.days || 30));
    const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(clientId);
    if (!client) throw new Error('Клиент не найден');

    const base = client.expiry_time && client.expiry_time > Date.now() ? client.expiry_time : Date.now();
    const expiryTime = expiryAtMidnightAfterDays(days, base);
    const durationDays = Math.max(0, Number(client.duration_days || days));

    db.prepare('UPDATE clients SET expiry_time = ?, duration_days = ? WHERE id = ?').run(expiryTime, durationDays, clientId);

    const updatedClient = db.prepare('SELECT * FROM clients WHERE id = ?').get(clientId);
    await updateClientEverywhere(updatedClient, { expiry_time: expiryTime, duration_days: durationDays });

    const back = String(req.body.back || '/dashboard');
    if (back === '/clients') {
      return res.redirect('/clients?message=' + encodeURIComponent('Клиент продлён'));
    }
    if (back.includes(`/clients/${clientId}`)) {
      return res.redirect(`/clients/${clientId}?message=${encodeURIComponent('Клиент продлён')}`);
    }
    res.redirect('/dashboard?message=' + encodeURIComponent('Клиент продлён'));
  } catch (err) {
    const back = String(req.body.back || '/dashboard');
    if (back === '/clients') {
      return res.redirect('/clients?error=' + encodeURIComponent(String(err.message || err)));
    }
    res.redirect('/dashboard?error=' + encodeURIComponent(String(err.message || err)));
  }
});

app.post('/clients/:id/toggle', requireAuth, async (req, res) => {
  try {
    const clientId = Number(req.params.id);
    const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(clientId);
    if (!client) throw new Error('Клиент не найден');

    const enabled = client.enabled === 1 ? 0 : 1;
    db.prepare('UPDATE clients SET enabled = ? WHERE id = ?').run(enabled, clientId);

    const updatedClient = db.prepare('SELECT * FROM clients WHERE id = ?').get(clientId);
    await updateClientEverywhere(updatedClient, { enabled: Boolean(enabled) });

    const msg = enabled ? 'Клиент включён' : 'Клиент отключён';
    const back = String(req.body.back || '');
    if (back.includes(`/clients/${clientId}`)) {
      return res.redirect(`/clients/${clientId}?message=${encodeURIComponent(msg)}`);
    }
    res.redirect(`/clients?message=${encodeURIComponent(msg)}`);
  } catch (err) {
    res.redirect('/clients?error=' + encodeURIComponent(String(err.message || err)));
  }
});

app.post('/clients/:id/delete', requireAuth, async (req, res) => {
  try {
    const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(Number(req.params.id));

    if (!client) {
      return res.redirect('/clients?error=' + encodeURIComponent('Клиент не найден'));
    }

    const deleteMode = String(req.body.delete_mode || 'all');

    await deleteClientEverywhere(client, deleteMode);

    res.redirect('/clients?message=' + encodeURIComponent('Клиент удалён'));
  } catch (err) {
    res.redirect('/clients?error=' + encodeURIComponent(String(err.message || err)));
  }
});


function buildOfficialHappTextBody(subscriptionName, subscriptionUpdateIntervalHours, subscriptionUserInfo, lines) {
  const controlLines = isHappAppControlsEnabled()
    ? [
        ...Object.entries(getHappSubscriptionProfileHeaderMap(subscriptionName, subscriptionUpdateIntervalHours)).map(([key, value]) => `#${key}: ${value}`),
        `#subscription-update-interval: ${subscriptionUpdateIntervalHours}`,
        ...buildHappAppControlBodyLines()
      ]
    : [];

  return [
    ...controlLines,
    ...(subscriptionUserInfo ? [`#subscription-userinfo: ${subscriptionUserInfo}`] : []),
    ...lines
  ].join('\n');
}

app.get('/happ/:slug', async (req, res) => {
  const client = db.prepare('SELECT * FROM clients WHERE sub_slug = ? AND enabled = 1').get(req.params.slug);

  if (!client) {
    return res.status(404).send('Subscription not found');
  }

  const entries = await buildSubscriptionEntries(client, true);
  const lines = entries.map(e => e.line);
  const subscriptionName = getSetting('subscription_name', DEFAULT_SUBSCRIPTION_NAME);
  const subscriptionUserInfo = buildSubscriptionUserInfo(entries, client);
  const subscriptionUpdateIntervalHours = getSubscriptionUpdateIntervalHours();

  setSubscriptionNoCacheHeaders(res, subscriptionName, 'txt');
  setSubscriptionUserInfoHeaders(res, subscriptionUserInfo);
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  applyHappSubscriptionProfileHeaders(res, subscriptionName, subscriptionUpdateIntervalHours);
  applyHappAppControlHeaders(res);

  res.send(buildOfficialHappTextBody(subscriptionName, subscriptionUpdateIntervalHours, subscriptionUserInfo, lines));
});

app.get('/sub/:slug', async (req, res) => {
  const client = db.prepare('SELECT * FROM clients WHERE sub_slug = ? AND enabled = 1').get(req.params.slug);

  if (!client) {
    return res.status(404).send('Subscription not found');
  }

  const entries = await buildSubscriptionEntries(client, true);
  const lines = entries.map(e => e.line);
  const subscriptionName = getSetting('subscription_name', DEFAULT_SUBSCRIPTION_NAME);
  const subscriptionUserInfo = buildSubscriptionUserInfo(entries, client);

  const subscriptionUpdateIntervalHours = getSubscriptionUpdateIntervalHours();

  setSubscriptionNoCacheHeaders(res, subscriptionName, 'txt');
  setSubscriptionUserInfoHeaders(res, subscriptionUserInfo);
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');

  applyHappSubscriptionProfileHeaders(res, subscriptionName, subscriptionUpdateIntervalHours);
  applyHappAppControlHeaders(res);

  res.send(buildOfficialHappTextBody(subscriptionName, subscriptionUpdateIntervalHours, subscriptionUserInfo, lines));
});




function getHappFragmentationConfig() {
  return {
    enabled: isHappSettingEnabled('happ_fragmentation_enabled', '0'),
    packets: 'tlshello',
    length: '50-100',
    interval: '10-20',
    maxSplit: '100-200'
  };
}

function getHappNoisesConfig() {
  return {
    enabled: isHappSettingEnabled('happ_noises_enabled', '0'),
    type: 'rand',
    packet: '10-20',
    delay: '10-16',
    applyTo: 'ip'
  };
}

function isJsonMuxEnabled() {
  return getSetting('json_mux_enabled', '0') === '1';
}

function isJsonSniffingEnabled() {
  return getSetting('json_sniffing_enabled', '0') === '1';
}

function getJsonMuxConfig() {
  return {
    enabled: true,
    concurrency: 100,
    xudpConcurrency: 200,
    xudpProxyUDP443: 'skip'
  };
}

function getHappMuxConfig() {
  const enabled = isHappSettingEnabled('happ_mux_enabled', '0');
  return {
    enabled,
    concurrency: enabled ? 100 : -1,
    xudpConcurrency: enabled ? 200 : 8,
    xudpProxyUDP443: enabled ? 'skip' : ''
  };
}

function getHappJsonControls() {
  if (!isHappAppControlsEnabled()) {
    return { enabled: false };
  }

  return {
    enabled: true,
    pingType: isHappSettingEnabled('happ_ping_tcp', '1') ? 'tcp' : 'url',
    pingResult: isHappSettingEnabled('happ_ping_result_icon', '1') ? 'icon' : 'latency',
    subscriptionUpdateIntervalHours: getSubscriptionUpdateIntervalHours(),
    subscriptionClientAutoUpdateEnabled: getSetting('subscription_client_auto_update_enabled', '1') !== '0',
    autoUpdate: getHappBehaviorOptions().autoUpdate,
    updateOnLaunch: getHappBehaviorOptions().updateOnOpen,
    connectOnLaunch: false,
    forceApplyOnUpdate: getHappBehaviorOptions().forceApplyOnUpdate,
    pingOnOpen: getHappBehaviorOptions().pingOnOpen,
    subscriptionsCollapse: getHappBehaviorOptions().subscriptionsCollapse,
    expandNow: getHappBehaviorOptions().expandNow,
    fragmentation: getHappFragmentationConfig(),
    noises: getHappNoisesConfig(),
    mux: getHappMuxConfig()
  };
}

function applyHappOutboundControls(outbound) {
  if (!outbound) return outbound;

  // This controls the generated Xray JSON itself and is independent from Happ
  // Provider settings. Keep disabled by default because MUX often breaks
  // VLESS/REALITY and newer transports on some clients.
  if (isJsonMuxEnabled()) {
    outbound.mux = getJsonMuxConfig();
  } else {
    delete outbound.mux;
  }
  outbound.streamSettings = outbound.streamSettings || {};

  return outbound;
}

function parseVlessLineToOutbound(line, index = 0) {
  const url = new URL(line);
  const q = url.searchParams;
  const tag = index === 0 ? 'proxy' : `proxy-${index + 1}`;
  const network = q.get('type') || 'tcp';
  const security = q.get('security') || 'reality';
  const flow = q.get('flow') || '';
  const fp = q.get('fp') || 'chrome';
  const pbk = q.get('pbk') || '';
  const sni = q.get('sni') || '';
  const sid = q.get('sid') || '';
  const spx = q.get('spx') || '/';

  const user = {
    id: decodeURIComponent(url.username || ''),
    encryption: 'none',
    level: 8,
    security: 'auto'
  };

  if (flow) user.flow = flow;

  const streamSettings = { network, security };
  if (String(network).toLowerCase() === 'xhttp') {
    streamSettings.xhttpSettings = {
      host: q.get('host') || '',
      mode: q.get('mode') || 'stream-one',
      path: q.get('path') || '/xhttp',
      scMaxConcurrentPosts: Number(q.get('scMaxConcurrentPosts') || 10),
      scMaxEachPostBytes: Number(q.get('scMaxEachPostBytes') || 1000000),
      scMinPostsIntervalMs: Number(q.get('scMinPostsIntervalMs') || 30)
    };
    const dialerProxy = q.get('dialerProxy') || '';
    if (dialerProxy) streamSettings.sockopt = { dialerProxy };
  } else {
    streamSettings.tcpSettings = { header: { type: 'none' } };
  }

  const outbound = {
    tag,
    protocol: 'vless',
    settings: {
      vnext: [{
        address: url.hostname,
        port: Number(url.port || 443),
        users: [user]
      }]
    },
    streamSettings
  };

  applyHappOutboundControls(outbound);

  const remark = getRemarkFromVlessLine(line);
  if (remark) outbound.remarks = remark;

  if (security === 'reality') {
    outbound.streamSettings.realitySettings = {
      show: false,
      fingerprint: fp,
      publicKey: pbk,
      serverName: sni,
      shortId: sid,
      spiderX: spx || '/',
      allowInsecure: false
    };
  }

  return outbound;
}

function getRemarkFromVlessLine(line) {
  try {
    const raw = String(line || '');
    const idx = raw.indexOf('#');
    if (idx >= 0) return decodeURIComponent(raw.slice(idx + 1)).trim();
  } catch (_) {}
  return '';
}



function uniqueList(items) {
  return [...new Set(items.filter(Boolean))];
}

function loadIplistDomains(serviceName) {
  try {
    const ipListPath = path.join(__dirname, 'data', 'ip-list.json');
    if (!fs.existsSync(ipListPath)) return [];

    const data = JSON.parse(fs.readFileSync(ipListPath, 'utf8'));
    const entry = data[serviceName];
    if (!entry || !Array.isArray(entry.domains)) return [];

    return entry.domains
      .map(domain => String(domain || '').trim().toLowerCase())
      .filter(domain => domain && !domain.endsWith('.ru'))
      .map(domain => `domain:${domain}`);
  } catch (error) {
    console.warn('Unable to load ip-list domains:', error.message);
    return [];
  }
}


// Отдельный VPN Routing для Happ отключён намеренно.
// Маршрутизация теперь передаётся только внутри /json/:slug, чтобы Happ не создавал
// свой geo-файл/профиль и не падал с ошибками geosite.dat вроде "RU".
function isHappAutoRoutingEnabled() {
  return false;
}

function buildHappRoutingLink() {
  return '';
}

const ROUTING_PROXY_DOMAINS = uniqueList([
  'geosite:youtube',
  'geosite:meta',
  'geosite:facebook',
  'geosite:instagram',
  'geosite:whatsapp',
  'geosite:openai',
  'geosite:telegram',
  'domain:fbcdn.net',
  'domain:fbsbx.com',
  'domain:messenger.com',
  'domain:m.me',
  'domain:instagram.com',
  'domain:cdninstagram.com',
  'domain:whatsapp.com',
  'domain:whatsapp.net',
  'domain:wa.me'
]);

const ROUTING_PROXY_IPS = uniqueList([
  // These are the only checked service GeoIP tags available in the target
  // /usr/local/x-ui/bin/geoip.dat. Do not add geoip:youtube/instagram/whatsapp/openai/chatgpt
  // unless they exist on the server, otherwise routing may become unreliable.
  'geoip:telegram',
  'geoip:facebook'
]);

const ROUTING_PRESETS = [
  { key: 'youtube', label: 'YouTube', domains: ['geosite:youtube'], ips: [] },
  { key: 'meta', label: 'Meta', domains: ['geosite:meta'], ips: [] },
  { key: 'facebook', label: 'Facebook', domains: ['geosite:facebook'], ips: ['geoip:facebook'] },
  { key: 'instagram', label: 'Instagram', domains: ['geosite:instagram'], ips: [] },
  { key: 'whatsapp', label: 'WhatsApp', domains: ['geosite:whatsapp'], ips: [] },
  { key: 'openai', label: 'OpenAI / ChatGPT', domains: ['geosite:openai'], ips: [] },
  { key: 'telegram', label: 'Telegram', domains: ['geosite:telegram'], ips: ['geoip:telegram'] }
];

const ROUTING_DEFAULT_CUSTOM_DOMAINS = [
  'domain:fbcdn.net',
  'domain:fbsbx.com',
  'domain:messenger.com',
  'domain:m.me',
  'domain:instagram.com',
  'domain:cdninstagram.com',
  'domain:whatsapp.com',
  'domain:whatsapp.net',
  'domain:wa.me'
];

function getDefaultRoutingConfig() {
  return {
    // New installations must not route services by default. The page keeps the
    // ready-made service cards as presets, but the owner enables only what they need.
    presets: [],
    customDomains: [],
    customIps: [],
    mode: 'proxy-selected',
    exceptDomains: [],
    exceptIps: [],
    geodataUrls: [],
    geositeUrl: '',
    geoipUrl: '',
    dnsPreset: 'cloudflare-google',
    dnsCustom: '',
    allNodes: true,
    excludedNodeIds: [],
    enabled: false,
    happAutoRoutingEnabled: false,
    defaultsVersion: 2
  };
}

function sameStringSet(a, b) {
  const left = uniqueList(Array.isArray(a) ? a.map(String) : []).sort();
  const right = uniqueList(Array.isArray(b) ? b.map(String) : []).sort();
  return left.length === right.length && left.every((v, i) => v === right[i]);
}

function isLegacyRoutingDefaultConfig(parsed) {
  if (!parsed || parsed.defaultsVersion) return false;
  return parsed.enabled !== false
    && (parsed.mode || 'proxy-selected') === 'proxy-selected'
    && sameStringSet(parsed.presets, ROUTING_PRESETS.map(p => p.key))
    && sameStringSet(parsed.customDomains, ROUTING_DEFAULT_CUSTOM_DOMAINS)
    && (!Array.isArray(parsed.customIps) || parsed.customIps.length === 0)
    && (!Array.isArray(parsed.exceptDomains) || parsed.exceptDomains.length === 0)
    && (!Array.isArray(parsed.exceptIps) || parsed.exceptIps.length === 0)
    && !parsed.geositeUrl
    && !parsed.geoipUrl;
}

function getRoutingConfig() {
  const raw = getSetting('routing_config', '');
  if (!raw) return getDefaultRoutingConfig();
  try {
    const parsed = JSON.parse(raw);
    const fallback = getDefaultRoutingConfig();
    if (isLegacyRoutingDefaultConfig(parsed)) return fallback;
    return {
      enabled: parsed.enabled === true,
      presets: Array.isArray(parsed.presets) ? parsed.presets : fallback.presets,
      customDomains: Array.isArray(parsed.customDomains) ? parsed.customDomains : fallback.customDomains,
      customIps: Array.isArray(parsed.customIps) ? parsed.customIps : fallback.customIps,
      mode: ['proxy-selected', 'proxy-except'].includes(parsed.mode) ? parsed.mode : (parsed.proxyExcept ? 'proxy-except' : fallback.mode),
      exceptDomains: Array.isArray(parsed.exceptDomains) ? parsed.exceptDomains : fallback.exceptDomains,
      exceptIps: Array.isArray(parsed.exceptIps) ? parsed.exceptIps : fallback.exceptIps,
      geodataUrls: Array.isArray(parsed.geodataUrls) ? parsed.geodataUrls : fallback.geodataUrls,
      geositeUrl: typeof parsed.geositeUrl === 'string' ? parsed.geositeUrl : (Array.isArray(parsed.geodataUrls) ? (parsed.geodataUrls.find(v => /geosite/i.test(v)) || '') : ''),
      geoipUrl: typeof parsed.geoipUrl === 'string' ? parsed.geoipUrl : (Array.isArray(parsed.geodataUrls) ? (parsed.geodataUrls.find(v => /geoip/i.test(v)) || '') : ''),
      dnsPreset: typeof parsed.dnsPreset === 'string' ? parsed.dnsPreset : fallback.dnsPreset,
      dnsCustom: typeof parsed.dnsCustom === 'string' ? parsed.dnsCustom : fallback.dnsCustom,
      allNodes: parsed.allNodes !== false,
      excludedNodeIds: Array.isArray(parsed.excludedNodeIds) ? parsed.excludedNodeIds.map(Number).filter(Boolean) : fallback.excludedNodeIds,
      happAutoRoutingEnabled: false
    };
  } catch (_) {
    return getDefaultRoutingConfig();
  }
}

function normalizeRoutingLine(value, kind) {
  let line = String(value || '').trim().toLowerCase();
  if (!line) return '';
  line = line.replace(/\s+/g, '');
  if (kind === 'domain') {
    if (/^(geosite|domain|regexp|keyword|full):.+/.test(line)) return line;
    if (/^[a-z0-9*_.-]+\.[a-z0-9_.-]+$/.test(line)) return `domain:${line.replace(/^\*\./, '')}`;
    return null;
  }
  if (kind === 'ip') {
    if (/^geoip:[a-z0-9_-]+$/.test(line)) return line;
    if (/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(line)) return line;
    if (/^[0-9a-f:]+(\/\d{1,3})?$/i.test(line) && line.includes(':')) return line;
    return null;
  }
  return null;
}

function parsePlainLines(text) {
  return uniqueList(String(text || '').split(/[\n,;]+/).map(v => v.trim()).filter(Boolean));
}

function parseRoutingLines(text, kind) {
  const errors = [];
  const values = [];
  String(text || '').split(/[\n,;]+/).map(v => v.trim()).filter(Boolean).forEach((raw, index) => {
    const normalized = normalizeRoutingLine(raw, kind);
    if (!normalized) {
      errors.push(`Строка ${index + 1}: "${raw}" не подходит для ${kind === 'domain' ? 'domain/geosite' : 'ip/geoip'}. Используй geosite:tag, domain:example.com, regexp:..., geoip:tag или CIDR.`);
    } else {
      values.push(normalized);
    }
  });
  return { values: uniqueList(values), errors };
}

function getRoutingDirectDomains() {
  const cfg = getRoutingConfig();
  if (cfg.enabled === false || cfg.mode !== 'proxy-except') return [];
  return uniqueList(cfg.exceptDomains || []);
}

function getRoutingDirectIps() {
  const cfg = getRoutingConfig();
  if (cfg.enabled === false || cfg.mode !== 'proxy-except') return [];
  return uniqueList(cfg.exceptIps || []);
}

function getRoutingProxyDomains() {
  const cfg = getRoutingConfig();
  if (cfg.enabled === false || cfg.mode === 'proxy-except') return [];
  const presetDomains = ROUTING_PRESETS.filter(p => cfg.presets.includes(p.key)).flatMap(p => p.domains);
  return uniqueList([...presetDomains, ...cfg.customDomains]);
}

function getRoutingProxyIps() {
  const cfg = getRoutingConfig();
  if (cfg.enabled === false || cfg.mode === 'proxy-except') return [];
  const presetIps = ROUTING_PRESETS.filter(p => cfg.presets.includes(p.key)).flatMap(p => p.ips);
  return uniqueList([...presetIps, ...cfg.customIps]);
}

const ROUTING_DIRECT_DOMAINS = uniqueList([
  'geosite:private',
  'geosite:category-ru',
  'geosite:apple',
  'geosite:apple-pki',
  'geosite:huawei',
  'geosite:xiaomi',
  'geosite:category-android-app-download',
  'geosite:f-droid',
  'domain:ozon.ru',
  'domain:wildberries.ru',
  'domain:wb.ru',
  'domain:yandex.ru',
  'domain:ya.ru',
  'domain:vk.com',
  'domain:gosuslugi.ru',
  'domain:sber.ru',
  'domain:tbank.ru',
  'domain:alfabank.ru',
  'domain:vtb.ru',
  'domain:mail.ru'
]);


function buildDnsServerEntry(value) {
  const text = String(value || '').trim();
  if (!text) return null;
  if (/^https:\/\//i.test(text) || /^tls:\/\//i.test(text)) return text;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(text)) return { address: text, port: 53, skipFallback: false };
  if (/^[0-9a-f:]+$/i.test(text) && text.includes(':')) return { address: text, port: 53, skipFallback: false };
  return text;
}

function getJsonDnsServers() {
  const cfg = getRoutingConfig();
  const preset = String(cfg.dnsPreset || 'cloudflare-google');
  const presets = {
    'cloudflare-google': ['1.1.1.1', '8.8.8.8'],
    cloudflare: ['1.1.1.1', '1.0.0.1'],
    google: ['8.8.8.8', '8.8.4.4'],
    quad9: ['9.9.9.9', '149.112.112.112'],
    yandex: ['77.88.8.8', '77.88.8.1'],
    doh_cloudflare: ['https://cloudflare-dns.com/dns-query'],
    doh_google: ['https://dns.google/dns-query'],
    manual: []
  };
  const base = presets[preset] || presets['cloudflare-google'];
  const custom = parsePlainLines(cfg.dnsCustom || '');
  const servers = uniqueList([...base, ...custom]).map(buildDnsServerEntry).filter(Boolean);
  return servers.length ? servers : presets['cloudflare-google'].map(buildDnsServerEntry);
}

function buildHappJsonConfigFromLine(client, line, subscriptionName, index = 0, routingEnabledForThisConfig = true) {
  const remark = getRemarkFromVlessLine(line) || `Server ${index + 1}`;
  const config = buildHappJsonConfig(client, [line], remark, routingEnabledForThisConfig);
  // HAPP and other JSON-array importers use these fields as the visible
  // subscription/server title. Keep them equal to the node remark so every
  // country/region from the node settings is shown as a separate region.
  config.remarks = remark;
  config.name = remark;
  config.ps = remark;
  config.title = remark;
  return config;
}


function buildRoutingRules() {
  const cfg = getRoutingConfig();
  if (cfg.enabled === false) {
    return [{ type: 'field', network: 'tcp,udp', outboundTag: 'direct' }];
  }

  if (cfg.mode === 'proxy-except') {
    const rules = [];
    const directDomains = getRoutingDirectDomains();
    const directIps = getRoutingDirectIps();
    if (directDomains.length) rules.push({ type: 'field', domain: directDomains, outboundTag: 'direct' });
    if (directIps.length) rules.push({ type: 'field', ip: directIps, outboundTag: 'direct' });
    rules.push({ type: 'field', network: 'tcp,udp', outboundTag: 'proxy' });
    return rules;
  }

  const rules = [];
  const proxyDomains = getRoutingProxyDomains();
  const proxyIps = getRoutingProxyIps();
  if (proxyDomains.length) rules.push({ type: 'field', domain: proxyDomains, outboundTag: 'proxy' });
  if (proxyIps.length) rules.push({ type: 'field', ip: proxyIps, outboundTag: 'proxy' });
  rules.push({ type: 'field', network: 'tcp,udp', outboundTag: 'direct' });
  return rules;
}

function isRoutingEnabledForNode(nodeId) {
  const cfg = getRoutingConfig();
  if (cfg.enabled === false) return false;
  if (cfg.allNodes === false && (cfg.excludedNodeIds || []).map(Number).includes(Number(nodeId))) return false;
  return true;
}

function buildXrayFragmentOutbound() {
  return {
    tag: 'fragment',
    protocol: 'freedom',
    settings: {
      fragment: {
        packets: 'tlshello',
        length: '50-100',
        interval: '10-20',
        maxSplit: '100-200'
      },
      noises: [{
        type: 'rand',
        packet: '10-20',
        delay: '10-16',
        applyTo: 'ipv4'
      }]
    },
    streamSettings: {
      network: 'raw',
      security: '',
      sockopt: {
        TcpNoDelay: true,
        mark: 255
      }
    }
  };
}

function configUsesFragmentOutbound(outbounds) {
  return Array.isArray(outbounds) && outbounds.some(outbound => outbound?.streamSettings?.sockopt?.dialerProxy === 'fragment');
}

function buildHappJsonConfig(client, lines, subscriptionName, routingEnabledForThisConfig = true) {
  const proxyOutbounds = lines
    .filter(line => String(line).startsWith('vless://'))
    .map((line, index) => parseVlessLineToOutbound(line, index));

  if (!proxyOutbounds.length) {
    proxyOutbounds.push({
      tag: 'proxy',
      protocol: 'freedom',
      settings: { domainStrategy: 'UseIP' }
    });
  }

  const jsonSniffingEnabled = isJsonSniffingEnabled();
  const extraOutbounds = configUsesFragmentOutbound(proxyOutbounds) ? [buildXrayFragmentOutbound()] : [];

  return {
    dns: {
      queryStrategy: 'UseIPv4',
      servers: getJsonDnsServers(),
      tag: 'dns_out'
    },
    inbounds: [
      {
        tag: 'socks',
        port: 10808,
        protocol: 'socks',
        settings: {
          auth: 'noauth',
          udp: true,
          userLevel: 8
        },
        sniffing: {
          enabled: jsonSniffingEnabled,
          destOverride: jsonSniffingEnabled ? ['http', 'tls'] : []
        }
      },
      {
        tag: 'http',
        port: 10809,
        protocol: 'http',
        settings: {
          userLevel: 8
        },
        sniffing: {
          enabled: jsonSniffingEnabled,
          destOverride: jsonSniffingEnabled ? ['http', 'tls'] : []
        }
      }
    ],
    log: {
      loglevel: 'warning'
    },
    outbounds: [
      ...proxyOutbounds,
      ...extraOutbounds,
      {
        tag: 'direct',
        protocol: 'freedom',
        settings: {
          domainStrategy: 'UseIP'
        }
      },
      {
        tag: 'block',
        protocol: 'blackhole',
        settings: {
          response: { type: 'http' }
        }
      }
    ],
    policy: {
      levels: {
        '0': {
          statsUserDownlink: true,
          statsUserUplink: true
        },
        '8': {
          connIdle: 300,
          downlinkOnly: 1,
          handshake: 4,
          uplinkOnly: 1
        }
      },
      system: {
        statsInboundDownlink: true,
        statsInboundUplink: true,
        statsOutboundDownlink: true,
        statsOutboundUplink: true
      }
    },
    remarks: subscriptionName || DEFAULT_SUBSCRIPTION_NAME,
    ...(routingEnabledForThisConfig && getRoutingConfig().enabled !== false ? {
      routing: {
        domainStrategy: 'IPIfNonMatch',
        rules: buildRoutingRules()
      }
    } : {}),
    stats: {},
    // Блок subscription отдаётся всегда: он нужен клиентам для автообновления
    // даже когда платный/Provider-режим Happ выключен.
    subscription: {
      title: subscriptionName || DEFAULT_SUBSCRIPTION_NAME,
      updateIntervalHours: getSubscriptionUpdateIntervalHours(),
      autoUpdate: getSetting('subscription_client_auto_update_enabled', '1') !== '0',
      generatedAt: new Date().toISOString(),
      ...(isHappAppControlsEnabled() ? {
        updateOnLaunch: getHappBehaviorOptions().updateOnOpen,
        pingOnOpen: getHappBehaviorOptions().pingOnOpen,
        subscriptionsCollapse: getHappBehaviorOptions().subscriptionsCollapse,
        expandNow: getHappBehaviorOptions().expandNow
      } : {})
    },
    ...(isHappAppControlsEnabled() ? {
      happ: {
        ...getHappJsonControls(),
        preferredMode: 'proxy'
      }
    } : {})
  };
}

app.get('/happ-routing/:slug', async (req, res) => {
  res.status(410).send('Happ auto routing is disabled. Use /json/:slug instead.');
});

app.get('/happ-routing-json/:slug', async (req, res) => {
  res.status(410).json({ error: 'Happ auto routing is disabled. Use /json/:slug instead.' });
});

app.get('/json/:slug', async (req, res) => {
  const client = db.prepare('SELECT * FROM clients WHERE sub_slug = ? AND enabled = 1').get(req.params.slug);

  if (!client) {
    return res.status(404).json({ error: 'Subscription not found' });
  }

  const entries = await buildSubscriptionEntries(client, true);
  const lines = entries.map(e => e.line);
  const subscriptionName = getSetting('subscription_name', DEFAULT_SUBSCRIPTION_NAME);
  const subscriptionUserInfo = buildSubscriptionUserInfo(entries, client);
  const subscriptionUpdateIntervalHours = getSubscriptionUpdateIntervalHours();
  const base64Title = Buffer.from(subscriptionName).toString('base64');

  setSubscriptionNoCacheHeaders(res, subscriptionName, 'json');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  setSubscriptionUserInfoHeaders(res, subscriptionUserInfo);
  applyHappSubscriptionProfileHeaders(res, subscriptionName, subscriptionUpdateIntervalHours);
  applyHappAppControlHeaders(res);
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  const vlessLines = lines.filter(line => String(line).startsWith('vless://'));

  if (vlessLines.length >= 1) {
    const requestedNodeRaw = String(req.query.node || '').trim();
    const singleMode = requestedNodeRaw || ['single', 'object'].includes(String(req.query.format || '').toLowerCase());

    // Default JSON subscription must be a JSON array: HAPP treats an array as
    // several configs/regions, while a single object is imported as only one
    // visible server. This was the reason only the last/random region appeared.
    if (!singleMode) {
      const vlessEntries = entries.filter(e => String(e.line).startsWith('vless://'));
      return res.json(vlessEntries.map((entry, index) => buildHappJsonConfigFromLine(client, entry.line, subscriptionName, index, isRoutingEnabledForNode(entry.nodeId))));
    }

    // Compatibility endpoint for clients that require a single Xray object:
    // /json/:slug?node=2 or /json/:slug?format=single
    const requestedNode = Number.parseInt(requestedNodeRaw || '1', 10);
    const selectedIndex = Number.isFinite(requestedNode)
      ? Math.min(Math.max(requestedNode - 1, 0), vlessLines.length - 1)
      : 0;
    const selectedEntry = entries.filter(e => String(e.line).startsWith('vless://'))[selectedIndex];
    return res.json(buildHappJsonConfigFromLine(client, selectedEntry.line, subscriptionName, selectedIndex, isRoutingEnabledForNode(selectedEntry.nodeId)));
  }

  return res.json({
    name: subscriptionName,
    remarks: subscriptionName,
    error: 'No active VLESS nodes in subscription',
    subscriptions: []
  });
});

app.get('/qr', async (req, res) => {
  try {
    const text = String(req.query.text || '').trim();
    if (!text) return res.status(400).send('Missing text');

    const svg = await QRCode.toString(text, {
      type: 'svg',
      margin: 1,
      width: 320,
      errorCorrectionLevel: 'M'
    });

    res.setHeader('Content-Type', 'image/svg+xml; charset=utf-8');
    res.send(svg);
  } catch (err) {
    res.status(500).send(String(err.message || err));
  }
});

app.get('/open/:slug', async (req, res) => {
  const client = db.prepare('SELECT * FROM clients WHERE sub_slug = ? AND enabled = 1').get(req.params.slug);
  if (!client) return res.status(404).send('Subscription not found');

  render(res, 'open_sub', {
    client,
    subUrl: buildPublicSubUrl(client.sub_slug),
    jsonUrl: buildPublicJsonUrl(client.sub_slug),
    happUrl: buildPublicHappUrl(client.sub_slug),
    baseUrl: getPublicSubBaseUrl(),
    showHappLinks: getSetting('show_happ_links', '0') !== '0'
  });
});

app.get('/healthz', async (req, res) => {
  res.json({
    ok: true,
    service: '3xui-aggregator',
    now: new Date().toISOString()
  });
});

app.get('/debug/inbound/:nodeId', requireAuth, async (req, res) => {
  try {
    const node = db.prepare('SELECT * FROM nodes WHERE id = ?').get(Number(req.params.nodeId));

    if (!node) {
      return res.status(404).json({ error: 'node not found' });
    }

    const inbound = await getInbound(node);
    res.json(inbound);
  } catch (err) {
    res.status(500).json({ error: String(err.message || err) });
  }
});

app.use((err, req, res, next) => {
  console.error('Unhandled request error:', err);
  if (res.headersSent) return next(err);
  res.status(500).send(formatServerErrorPage('Внутренняя ошибка сервера', err));
});

app.listen(PORT, () => console.log(`3xui-aggregator started on :${PORT}`));
