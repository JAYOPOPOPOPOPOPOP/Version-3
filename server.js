/**
 * Minecraft Server Website - Backend
 * Pure Node.js (no external packages)
 * Features: Register, Login, Admin Panel, Site Settings
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');
const querystring = require('querystring');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOADS_DIR = path.join(PUBLIC_DIR, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'db.json');
let JWT_SECRET = ''; // loaded below from env or data/.jwt_secret so logins survive restarts & updates

// Ensure directories
[DATA_DIR, UPLOADS_DIR].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

// Persistent login secret: set JWT_SECRET env var (best for hosts with temporary disk) or it is kept in data/.jwt_secret
JWT_SECRET = (function () {
  if (process.env.JWT_SECRET && process.env.JWT_SECRET.length >= 16) return process.env.JWT_SECRET;
  const f = path.join(DATA_DIR, '.jwt_secret');
  try { const v = fs.readFileSync(f, 'utf8').trim(); if (v.length >= 32) return v; } catch (e) {}
  const v = crypto.randomBytes(32).toString('hex');
  try { fs.writeFileSync(f, v, { mode: 0o600 }); } catch (e) {}
  return v;
})();
const SESSION_SECONDS = 365 * 24 * 60 * 60; // stay logged in for 1 year

// ---------- Database (JSON file) ----------
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = {
      users: [],
      settings: {
        siteName: 'Minecraft Server',
        serverIP: 'play.example.com',
        serverPort: '19161',
        discordLink: 'https://discord.gg/EMndPhavxk',
        logo: '',
        favicon: '',
        bgType: 'default',
        bgDefault: 0,
        bgImageUrl: '',
        bgLiveUrl: '',
        particlesEnabled: true,
        particleType: 0,
        maintenanceMode: false,
        colors: {
          bg: '#f5fffe',
          card: '#ffffff',
          accent: '#06b6d4',
          accentBright: '#22d3ee',
          text: '#0f172a',
          muted: '#64748b'
        }
      },
      sales: [],
      sessions: {},
      connectors: [],
      pages: [],
      categories: [],
      products: [],
      payments: [],
      coupons: []
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  if (!db.connectors) db.connectors = [];
  if (!db.pages) db.pages = [];
  if (!db.categories) db.categories = [];
  if (!db.products) db.products = [];
  if (!db.payments) db.payments = [];
  if (!db.coupons) db.coupons = [];
  if (!db.quickLinks) db.quickLinks = [];
  if (!db.ipBlacklist) db.ipBlacklist = [];
  if (!db.faqs) db.faqs = [];
  if (!db.tickets) db.tickets = [];
  if (!db.ranks) db.ranks = [
    { id: 'admin', name: 'Admin', isSystem: true, permissions: ['*'], productDiscounts: {} },
    { id: 'moderator', name: 'Moderator', isSystem: true, permissions: ['tickets.view', 'tickets.reply'], productDiscounts: {} },
    { id: 'support', name: 'Support', isSystem: true, permissions: ['tickets.view', 'tickets.reply'], productDiscounts: {} },
    { id: 'member', name: 'Member', isSystem: true, permissions: [], productDiscounts: {} }
  ];
  if (!db.settings) db.settings = {};
  if (db.settings.stockSystemEnabled === undefined) db.settings.stockSystemEnabled = false;
  if (db.settings.productVariantsEnabled === undefined) db.settings.productVariantsEnabled = false;
  if (db.settings.productScheduleEnabled === undefined) db.settings.productScheduleEnabled = false;
  if (db.settings.productTagsEnabled === undefined) db.settings.productTagsEnabled = false;
  if (db.settings.featuredProductsEnabled === undefined) db.settings.featuredProductsEnabled = false;
  if (!db.globalPendingCommands) db.globalPendingCommands = [];
  return db;
}

function saveDB(db) {
  // atomic write: never leaves a half-written db.json if the process stops mid-save
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

// ---------- Password hashing (scrypt) ----------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const hashVerify = crypto.scryptSync(password, salt, 64).toString('hex');
  return hash === hashVerify;
}

// ---------- Token (simple signed token) ----------

function userHasPerm(user, perm) {
  if (!user) return false;
  if (user.role === 'admin') return true;
  const db = loadDB();
  const ranks = db.ranks || [];
  const rankId = user.rankId || user.role || 'member';
  const rank = ranks.find(r => r.id === rankId) || ranks.find(r => r.id === 'member');
  if (!rank) return false;
  const perms = rank.permissions || [];
  if (perms.includes('*')) return true;
  return perms.includes(perm);
}

function createToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [data, sig] = parts;
  const expected = crypto.createHmac('sha256', JWT_SECRET).update(data).digest('base64url');
  if (sig !== expected) return null;
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString());
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

// ---------- Helpers ----------
function parseCookies(req) {
  const cookies = {};
  const header = req.headers.cookie || '';
  header.split(';').forEach(c => {
    const [k, ...v] = c.trim().split('=');
    if (k) cookies[k] = decodeURIComponent(v.join('='));
  });
  return cookies;
}

function sendJSON(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Credentials': 'true'
  });
  res.end(JSON.stringify(data));
}

function sendHTML(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

function getMime(ext) {
  const map = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.webp': 'image/webp',
    '.avif': 'image/avif',
    '.jfif': 'image/jpeg',
    '.bmp': 'image/bmp',
    '.ico': 'image/x-icon',
    '.woff2': 'font/woff2'
  };
  return map[ext] || 'application/octet-stream';
}


function calcCouponDiscount(coupon, cartLines) {
  // cartLines: [{ productId, lineTotal }]
  if (!coupon || coupon.enabled === false) return { discount: 0, reason: 'Invalid coupon' };
  if (coupon.expiresAt && new Date(coupon.expiresAt).getTime() < Date.now()) {
    return { discount: 0, reason: 'Coupon expired' };
  }
  if (coupon.maxUses != null && coupon.maxUses > 0 && (coupon.usedCount || 0) >= coupon.maxUses) {
    return { discount: 0, reason: 'Coupon usage limit reached' };
  }
  let eligible = 0;
  const scope = coupon.scope || 'all';
  const productIds = Array.isArray(coupon.productIds) ? coupon.productIds : [];
  for (const line of cartLines) {
    if (scope === 'all' || productIds.includes(line.productId)) {
      eligible += line.lineTotal;
    }
  }
  if (eligible <= 0) return { discount: 0, reason: 'Coupon not valid for these products' };
  const minOrder = parseFloat(coupon.minOrder) || 0;
  if (minOrder > 0 && eligible < minOrder) {
    return { discount: 0, reason: 'Minimum order ₹' + minOrder + ' required for this coupon' };
  }
  let discount = 0;
  if (coupon.type === 'percent') {
    discount = eligible * (parseFloat(coupon.value) || 0) / 100;
  } else {
    discount = Math.min(eligible, parseFloat(coupon.value) || 0);
  }
  discount = Math.round(discount * 100) / 100;
  return { discount, reason: null, eligible };
}

function normalizeCommand(cmd) {
  let s = String(cmd || '').trim();
  while (s.startsWith('/')) s = s.slice(1).trim();
  return s;
}

/** Replace all common player placeholders in a command */
function replacePlayerPlaceholders(cmd, playerName) {
  const name = String(playerName || 'Player').trim() || 'Player';
  let s = String(cmd || '');
  // %playername% %player% %PLAYER% {player} {playername} <player> [player]
  s = s.replace(/%playername%/gi, name);
  s = s.replace(/%player%/gi, name);
  s = s.replace(/\{playername\}/gi, name);
  s = s.replace(/\{player\}/gi, name);
  s = s.replace(/<playername>/gi, name);
  s = s.replace(/<player>/gi, name);
  s = s.replace(/\[playername\]/gi, name);
  s = s.replace(/\[player\]/gi, name);
  return s;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function readBodyLimited(req, max) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > max) { reject(new Error('File bahut badi hai')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseMultipart(buffer, boundary) {
  boundary = String(boundary || '').split(';')[0].trim().replace(/^"|"$/g, '');
  const parts = {};
  const files = {};
  const sep = Buffer.from('--' + boundary);
  let start = 0;
  while (true) {
    const idx = buffer.indexOf(sep, start);
    if (idx === -1) break;
    const next = buffer.indexOf(sep, idx + sep.length);
    if (next === -1) break;
    const part = buffer.slice(idx + sep.length, next);
    // skip leading \r\n
    let p = part;
    if (p[0] === 0x0d && p[1] === 0x0a) p = p.slice(2);
    const headerEnd = p.indexOf('\r\n\r\n');
    if (headerEnd === -1) { start = next; continue; }
    const headerStr = p.slice(0, headerEnd).toString();
    let body = p.slice(headerEnd + 4);
    // trailing \r\n
    if (body[body.length - 2] === 0x0d && body[body.length - 1] === 0x0a) {
      body = body.slice(0, -2);
    }
    const nameMatch = headerStr.match(/name="([^"]+)"/);
    const filenameMatch = headerStr.match(/filename="([^"]+)"/);
    if (nameMatch) {
      const name = nameMatch[1];
      if (filenameMatch && filenameMatch[1]) {
        files[name] = { filename: filenameMatch[1], data: body };
      } else {
        parts[name] = body.toString('utf8');
      }
    }
    start = next;
  }
  return { fields: parts, files };
}

function getAuthUser(req) {
  const cookies = parseCookies(req);
  const token = cookies.token || (req.headers.authorization || '').replace('Bearer ', '');
  const payload = verifyToken(token);
  if (!payload) return null;
  const db = loadDB();
  return db.users.find(u => u.id === payload.uid) || null;
}

// ---------- Routes ----------
async function handleAPI(req, res, pathname) {
  const method = req.method;

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Credentials': 'true'
    });
    return res.end();
  }

  // GET /api/settings - public
  if (pathname === '/api/settings' && method === 'GET') {
    const db = loadDB();
    const s = Object.assign({}, db.settings);
    // Never expose secret keys to public
    delete s.gw_razorpay_key_secret;
    delete s.gw_stripe_secret;
    delete s.gw_paypal_secret;
    delete s.gw_payu_salt;
    delete s.gw_cashfree_secret;
    delete s.gw_phonepe_salt;
    delete s.gw_paytm_key;
    // Public-safe pay info
    s.payMode = s.payMode || 'manual';
    s.gatewayProvider = s.gatewayProvider || 'razorpay';
    return sendJSON(res, 200, { success: true, settings: s });
  }

  // GET /api/server-status - live Minecraft server status
  if (pathname === '/api/server-status' && method === 'GET') {
    try {
      const db = loadDB();
      const ip = (db.settings.serverIP || '').trim();
      const port = (db.settings.serverPort || '25565').trim();
      if (!ip) {
        return sendJSON(res, 200, { success: true, online: false, players: { online: 0, max: 0 }, motd: '', version: '' });
      }
      const host = ip.includes(':') ? ip : (ip + ':' + port);
      const url = 'https://api.mcsrvstat.us/3/' + encodeURIComponent(host.replace(/^https?:\/\//, ''));
      const https = require('https');
      const data = await new Promise((resolve, reject) => {
        const req = https.get(url, { headers: { 'User-Agent': 'MC-Server-Website/1.0' }, timeout: 8000 }, (r) => {
          let body = '';
          r.on('data', c => body += c);
          r.on('end', () => {
            try { resolve(JSON.parse(body)); } catch (e) { reject(e); }
          });
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
      });
      const online = !!(data && data.online);
      const players = {
        online: (data.players && typeof data.players.online === 'number') ? data.players.online : 0,
        max: (data.players && typeof data.players.max === 'number') ? data.players.max : 0
      };
      let motd = '';
      if (data.motd) {
        if (typeof data.motd === 'string') motd = data.motd;
        else if (data.motd.clean) motd = Array.isArray(data.motd.clean) ? data.motd.clean.join(' ') : String(data.motd.clean);
      }
      return sendJSON(res, 200, {
        success: true,
        online,
        players,
        version: data.version || '',
        motd,
        ip: data.ip || ip,
        port: data.port || port
      });
    } catch (e) {
      console.error('status error', e.message);
      return sendJSON(res, 200, { success: true, online: false, players: { online: 0, max: 0 }, motd: '', version: '', error: 'unreachable' });
    }
  }

  // POST /api/register
  if (pathname === '/api/register' && method === 'POST') {
    try {
      const body = JSON.parse((await readBody(req)).toString());
      const { email, password, confirmPassword, mcUsername, mobile, address } = body;

      if (!email || !password || !confirmPassword || !mcUsername) {
        return sendJSON(res, 400, { success: false, message: 'Email, password, confirm password and Minecraft username are required' });
      }
      if (password !== confirmPassword) {
        return sendJSON(res, 400, { success: false, message: 'Password and Confirm Password do not match' });
      }
      if (password.length < 6) {
        return sendJSON(res, 400, { success: false, message: 'Password must be at least 6 characters' });
      }
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return sendJSON(res, 400, { success: false, message: 'Please enter a valid email' });
      }

      const db = loadDB();
      if (db.users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
        return sendJSON(res, 400, { success: false, message: 'This email is already registered' });
      }
      if (db.users.find(u => u.mcUsername.toLowerCase() === mcUsername.toLowerCase())) {
        return sendJSON(res, 400, { success: false, message: 'This Minecraft username is already taken' });
      }

      const isFirstUser = db.users.length === 0;
      const user = {
        id: crypto.randomUUID(),
        email: email.toLowerCase().trim(),
        password: hashPassword(password),
        mcUsername: mcUsername.trim(),
        mobile: (mobile || '').trim(),
        address: (address || '').trim(),
        role: isFirstUser ? 'admin' : 'user',
        premium: isFirstUser ? true : false,
        referralCode: (mcUsername || email).toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 16) || crypto.randomUUID().slice(0, 8),
        referredBy: null,
        createdAt: new Date().toISOString(),
        lastLogin: null
      };
      // Referral from body.ref or body.referralCode
      const refCode = String(body.ref || body.referralCode || '').trim().toLowerCase();
      if (refCode) {
        const referrer = db.users.find(u => (u.referralCode || '').toLowerCase() === refCode || (u.mcUsername || '').toLowerCase() === refCode);
        if (referrer && referrer.id !== user.id) {
          user.referredBy = referrer.id;
        }
      }
      // Ensure unique referral code
      while (db.users.some(u => u.referralCode === user.referralCode)) {
        user.referralCode = user.referralCode + Math.floor(Math.random() * 10);
      }
      db.users.push(user);
      saveDB(db);

      const token = createToken({ uid: user.id, role: user.role, exp: Date.now() + SESSION_SECONDS * 1000 });
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': `token=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_SECONDS}`
      });
      return res.end(JSON.stringify({
        success: true,
        message: isFirstUser ? 'Registration successful! You are now the admin.' : 'Register successful!',
        user: { id: user.id, email: user.email, mcUsername: user.mcUsername, role: user.role, premium: !!user.premium },
        token
      }));
    } catch (e) {
      return sendJSON(res, 500, { success: false, message: 'Server error' });
    }
  }

  // POST /api/login
  if (pathname === '/api/login' && method === 'POST') {
    try {
      const body = JSON.parse((await readBody(req)).toString());
      const { email, password } = body;
      if (!email || !password) {
        return sendJSON(res, 400, { success: false, message: 'Email and password are required' });
      }
      const db = loadDB();
      const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
      if (!user || !verifyPassword(password, user.password)) {
        return sendJSON(res, 401, { success: false, message: 'Invalid email or password' });
      }
      if (user.banned) {
        return sendJSON(res, 403, { success: false, message: 'Account banned. Contact admin.' });
      }
      user.lastLogin = new Date().toISOString();
      saveDB(db);

      const token = createToken({ uid: user.id, role: user.role, exp: Date.now() + SESSION_SECONDS * 1000 });
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': `token=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_SECONDS}`
      });
      return res.end(JSON.stringify({
        success: true,
        message: 'Login successful!',
        user: { id: user.id, email: user.email, mcUsername: user.mcUsername, role: user.role, premium: !!user.premium },
        token
      }));
    } catch (e) {
      return sendJSON(res, 500, { success: false, message: 'Server error' });
    }
  }

  // POST /api/logout
  if (pathname === '/api/logout' && method === 'POST') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': 'token=; Path=/; HttpOnly; Max-Age=0'
    });
    return res.end(JSON.stringify({ success: true, message: 'Logged out' }));
  }

  // GET /api/me
  if (pathname === '/api/me' && method === 'GET') {
    const user = getAuthUser(req);
    if (!user) return sendJSON(res, 401, { success: false, message: 'Not logged in' });
    const db = loadDB();
    const u = db.users.find(x => x.id === user.id) || user;
    if (u && !u.referralCode) {
      u.referralCode = (u.mcUsername || u.email || 'user').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 16);
      saveDB(db);
    }
    return sendJSON(res, 200, {
      success: true,
      user: {
        id: u.id,
        email: u.email,
        mcUsername: u.mcUsername,
        role: u.role,
        premium: !!u.premium || u.role === 'admin',
        mobile: u.mobile,
        address: u.address,
        referralCode: u.referralCode || null,
        referredBy: u.referredBy || null
      },
      referralLink: '/register.html?ref=' + encodeURIComponent(u.referralCode || ''),
      referralDiscountPercent: db.settings.referralDiscountPercent != null ? db.settings.referralDiscountPercent : 5
    });
  }

  // POST /api/update-profile (username + optional password, no old password)
  if (pathname === '/api/update-profile' && method === 'POST') {
    const authUser = getAuthUser(req);
    if (!authUser) return sendJSON(res, 401, { success: false, message: 'Not logged in' });
    try {
      const body = JSON.parse((await readBody(req)).toString());
      const { mcUsername, newPassword, confirmPassword } = body;
      const db = loadDB();
      const u = db.users.find(x => x.id === authUser.id);
      if (!u) return sendJSON(res, 404, { success: false, message: 'User not found' });

      if (mcUsername && mcUsername.trim()) {
        const name = mcUsername.trim();
        if (name.length < 3 || name.length > 16) {
          return sendJSON(res, 400, { success: false, message: 'Username must be 3-16 characters' });
        }
        const taken = db.users.find(x => x.id !== u.id && x.mcUsername.toLowerCase() === name.toLowerCase());
        if (taken) {
          return sendJSON(res, 400, { success: false, message: 'This Minecraft username is already taken' });
        }
        u.mcUsername = name;
      }

      if (newPassword) {
        if (newPassword.length < 6) {
          return sendJSON(res, 400, { success: false, message: 'Password must be at least 6 characters' });
        }
        if (newPassword !== confirmPassword) {
          return sendJSON(res, 400, { success: false, message: 'Password and Confirm Password do not match' });
        }
        u.password = hashPassword(newPassword);
      }

      saveDB(db);
      return sendJSON(res, 200, {
        success: true,
        message: 'Profile updated successfully',
        user: {
          id: u.id,
          email: u.email,
          mcUsername: u.mcUsername,
          role: u.role,
          premium: !!u.premium || u.role === 'admin',
          mobile: u.mobile,
          address: u.address
        }
      });
    } catch (e) {
      return sendJSON(res, 500, { success: false, message: 'Server error' });
    }
  }

  // ----- Admin routes -----
  const user = getAuthUser(req);

  // GET /api/admin/dashboard
  if (pathname === '/api/admin/dashboard' && method === 'GET') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const db = loadDB();
    const now = new Date();
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
    const weekStart = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();

    const salesToday = db.sales.filter(s => s.createdAt >= todayStart);
    const salesWeek = db.sales.filter(s => s.createdAt >= weekStart);
    const sum = arr => arr.reduce((a, s) => a + (s.amount || 0), 0);

    // Top buys (by product name)
    const buyCount = {};
    db.sales.forEach(s => {
      const name = s.product || 'Unknown';
      buyCount[name] = (buyCount[name] || 0) + 1;
    });
    const topBuys = Object.entries(buyCount)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    // Live users = users who logged in last 15 min (or total users for demo)
    const liveCutoff = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    const liveUsers = db.users.filter(u => u.lastLogin && u.lastLogin >= liveCutoff).length;

    return sendJSON(res, 200, {
      success: true,
      dashboard: {
        salesToday: sum(salesToday),
        salesTodayCount: salesToday.length,
        salesWeek: sum(salesWeek),
        salesWeekCount: salesWeek.length,
        totalUsers: db.users.length,
        liveUsers,
        topBuys,
        totalSales: sum(db.sales),
        recentSales: db.sales.slice(-10).reverse()
      }
    });
  }

  // GET /api/admin/users
  if (pathname === '/api/admin/users' && method === 'GET') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const db = loadDB();
    const list = db.users.map(u => ({
      id: u.id, email: u.email, mcUsername: u.mcUsername, role: u.role,
      rankId: u.rankId || u.role || 'member',
      mobile: u.mobile, address: u.address, createdAt: u.createdAt, lastLogin: u.lastLogin,
      premium: !!u.premium, banned: !!u.banned, balance: Number(u.balance || 0),
      referralCode: u.referralCode || null
    }));
    return sendJSON(res, 200, { success: true, users: list });
  }

  // PUT /api/admin/users/:id  — change role, premium, ban
  if (pathname.match(/^\/api\/admin\/users\/[^/]+$/) && method === 'PUT') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    try {
      const id = pathname.split('/')[4];
      const body = JSON.parse((await readBody(req)).toString());
      const db = loadDB();
      const u = db.users.find(x => x.id === id);
      if (!u) return sendJSON(res, 404, { success: false, message: 'User not found' });
      if (u.id === user.id && body.role === 'user') {
        return sendJSON(res, 400, { success: false, message: 'Cannot demote yourself' });
      }
      if (body.role !== undefined) {
        const r = String(body.role);
        u.role = r;
        u.rankId = r;
      }
      if (body.rankId !== undefined) {
        u.rankId = String(body.rankId);
        // keep role in sync for legacy checks
        if (['admin', 'moderator', 'support', 'member', 'user'].includes(u.rankId)) {
          u.role = u.rankId === 'member' ? 'user' : u.rankId;
        } else {
          u.role = 'user';
        }
      }
      if (body.premium !== undefined) u.premium = !!body.premium;
      if (body.banned !== undefined) u.banned = !!body.banned;
      if (body.balance !== undefined) {
        const b = parseFloat(body.balance);
        if (!isNaN(b) && b >= 0) u.balance = b;
      }
      if (body.addBalance !== undefined) {
        const b = parseFloat(body.addBalance);
        if (!isNaN(b)) u.balance = Math.max(0, Number(u.balance || 0) + b);
      }
      saveDB(db);
      return sendJSON(res, 200, { success: true, user: { id: u.id, role: u.role, rankId: u.rankId || u.role, premium: !!u.premium, banned: !!u.banned, balance: Number(u.balance || 0) } });
    } catch (e) {
      return sendJSON(res, 500, { success: false, message: 'Failed' });
    }
  }

  // DELETE /api/admin/users/:id
  if (pathname.match(/^\/api\/admin\/users\/[^/]+$/) && method === 'DELETE') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    try {
      const id = pathname.split('/')[4];
      if (id === user.id) return sendJSON(res, 400, { success: false, message: 'Cannot delete yourself' });
      const db = loadDB();
      const idx = db.users.findIndex(x => x.id === id);
      if (idx < 0) return sendJSON(res, 404, { success: false, message: 'Not found' });
      db.users.splice(idx, 1);
      saveDB(db);
      return sendJSON(res, 200, { success: true });
    } catch (e) {
      return sendJSON(res, 500, { success: false, message: 'Failed' });
    }
  }

  // Block banned users on login
  // (handled below in login - patch separately)

  // GET /api/admin/settings (full settings including secrets — admin only)
  if (pathname === '/api/admin/settings' && method === 'GET') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const db = loadDB();
    return sendJSON(res, 200, { success: true, settings: db.settings });
  }

  // PUT /api/admin/settings
  if (pathname === '/api/admin/settings' && method === 'PUT') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    try {
      const contentType = req.headers['content-type'] || '';
      let fields = {};
      let files = {};

      if (contentType.includes('multipart/form-data')) {
        const boundary = contentType.split('boundary=')[1];
        const buffer = await readBody(req);
        const parsed = parseMultipart(buffer, boundary);
        fields = parsed.fields;
        files = parsed.files;
      } else {
        fields = JSON.parse((await readBody(req)).toString());
      }

      const db = loadDB();
      if (fields.siteName !== undefined) db.settings.siteName = String(fields.siteName).trim();
      if (fields.serverIP !== undefined) db.settings.serverIP = String(fields.serverIP).trim();
      if (fields.serverPort !== undefined) db.settings.serverPort = String(fields.serverPort).trim();
      if (fields.discordLink !== undefined) db.settings.discordLink = String(fields.discordLink).trim();
      if (fields.upiId !== undefined) db.settings.upiId = String(fields.upiId).trim();
      // Pay System
      if (fields.payMode !== undefined) db.settings.payMode = (fields.payMode === 'gateway') ? 'gateway' : 'manual';
      if (fields.gatewayProvider !== undefined) db.settings.gatewayProvider = String(fields.gatewayProvider).trim();
      if (fields.gw_razorpay_key_id !== undefined) db.settings.gw_razorpay_key_id = String(fields.gw_razorpay_key_id).trim();
      if (fields.gw_razorpay_key_secret !== undefined) db.settings.gw_razorpay_key_secret = String(fields.gw_razorpay_key_secret).trim();
      if (fields.gw_stripe_publishable !== undefined) db.settings.gw_stripe_publishable = String(fields.gw_stripe_publishable).trim();
      if (fields.gw_stripe_secret !== undefined) db.settings.gw_stripe_secret = String(fields.gw_stripe_secret).trim();
      if (fields.gw_paypal_client_id !== undefined) db.settings.gw_paypal_client_id = String(fields.gw_paypal_client_id).trim();
      if (fields.gw_paypal_secret !== undefined) db.settings.gw_paypal_secret = String(fields.gw_paypal_secret).trim();
      if (fields.gw_payu_merchant_key !== undefined) db.settings.gw_payu_merchant_key = String(fields.gw_payu_merchant_key).trim();
      if (fields.gw_payu_salt !== undefined) db.settings.gw_payu_salt = String(fields.gw_payu_salt).trim();
      if (fields.gw_cashfree_app_id !== undefined) db.settings.gw_cashfree_app_id = String(fields.gw_cashfree_app_id).trim();
      if (fields.gw_cashfree_secret !== undefined) db.settings.gw_cashfree_secret = String(fields.gw_cashfree_secret).trim();
      if (fields.gw_phonepe_merchant_id !== undefined) db.settings.gw_phonepe_merchant_id = String(fields.gw_phonepe_merchant_id).trim();
      if (fields.gw_phonepe_salt !== undefined) db.settings.gw_phonepe_salt = String(fields.gw_phonepe_salt).trim();
      if (fields.gw_paytm_mid !== undefined) db.settings.gw_paytm_mid = String(fields.gw_paytm_mid).trim();
      
      if (fields.gw_paytm_key !== undefined) db.settings.gw_paytm_key = String(fields.gw_paytm_key).trim();
      // Sales / Promo
      if (fields.saleEnabled !== undefined) db.settings.saleEnabled = (fields.saleEnabled === true || fields.saleEnabled === 'true');
      if (fields.saleTitle !== undefined) db.settings.saleTitle = String(fields.saleTitle).trim();
      if (fields.saleSubtitle !== undefined) db.settings.saleSubtitle = String(fields.saleSubtitle).trim();
      if (fields.saleDiscountPercent !== undefined) db.settings.saleDiscountPercent = Math.max(0, Math.min(100, parseFloat(fields.saleDiscountPercent) || 0));
      if (fields.saleTopbarText !== undefined) db.settings.saleTopbarText = String(fields.saleTopbarText).trim();
      if (fields.saleTopbarBg !== undefined) db.settings.saleTopbarBg = String(fields.saleTopbarBg).trim();
      if (fields.saleBannerText !== undefined) db.settings.saleBannerText = String(fields.saleBannerText).trim();
      if (fields.saleShowTopbar !== undefined) db.settings.saleShowTopbar = (fields.saleShowTopbar === true || fields.saleShowTopbar === 'true');
      if (fields.saleShowBanner !== undefined) db.settings.saleShowBanner = (fields.saleShowBanner === true || fields.saleShowBanner === 'true');
      if (fields.saleAnimation !== undefined) db.settings.saleAnimation = String(fields.saleAnimation).trim();
      // New user discount
      if (fields.newUserEnabled !== undefined) db.settings.newUserEnabled = (fields.newUserEnabled === true || fields.newUserEnabled === 'true');
      if (fields.newUserPercent !== undefined) db.settings.newUserPercent = Math.max(0, Math.min(100, parseFloat(fields.newUserPercent) || 0));
      if (fields.newUserPopupTitle !== undefined) db.settings.newUserPopupTitle = String(fields.newUserPopupTitle).trim();
      if (fields.newUserPopupText !== undefined) db.settings.newUserPopupText = String(fields.newUserPopupText).trim();
      // Announcement
      if (fields.announceEnabled !== undefined) db.settings.announceEnabled = (fields.announceEnabled === true || fields.announceEnabled === 'true');
      if (fields.announceText !== undefined) db.settings.announceText = String(fields.announceText).trim();
      if (fields.announceLink !== undefined) db.settings.announceLink = String(fields.announceLink).trim();
      if (fields.announceBg !== undefined) db.settings.announceBg = String(fields.announceBg).trim();
      if (fields.announceFont !== undefined) db.settings.announceFont = String(fields.announceFont).trim();
      if (fields.announceFontColor !== undefined) db.settings.announceFontColor = String(fields.announceFontColor).trim();
      if (fields.announceFontSize !== undefined) db.settings.announceFontSize = String(fields.announceFontSize).trim();
      if (fields.announceAnimation !== undefined) db.settings.announceAnimation = String(fields.announceAnimation).trim();
      if (fields.announceShowBanner !== undefined) db.settings.announceShowBanner = (fields.announceShowBanner === true || fields.announceShowBanner === 'true');
      if (fields.announceStartAt !== undefined) db.settings.announceStartAt = String(fields.announceStartAt || '').trim() || null;
      if (fields.announceEndAt !== undefined) db.settings.announceEndAt = String(fields.announceEndAt || '').trim() || null;
      // Sale style extras
      if (fields.saleFont !== undefined) db.settings.saleFont = String(fields.saleFont).trim();
      if (fields.saleFontColor !== undefined) db.settings.saleFontColor = String(fields.saleFontColor).trim();
      if (fields.saleFontSize !== undefined) db.settings.saleFontSize = String(fields.saleFontSize).trim();
      if (fields.saleBannerBg !== undefined) db.settings.saleBannerBg = String(fields.saleBannerBg).trim();
      if (fields.saleTopbarFontColor !== undefined) db.settings.saleTopbarFontColor = String(fields.saleTopbarFontColor).trim();
      if (fields.saleClaimText !== undefined) db.settings.saleClaimText = String(fields.saleClaimText).trim();
      if (fields.saleClaimPageId !== undefined) db.settings.saleClaimPageId = String(fields.saleClaimPageId).trim();
      if (fields.saleClaimLink !== undefined) db.settings.saleClaimLink = String(fields.saleClaimLink).trim();
      if (fields.announceClaimText !== undefined) db.settings.announceClaimText = String(fields.announceClaimText).trim();
      if (fields.announceClaimPageId !== undefined) db.settings.announceClaimPageId = String(fields.announceClaimPageId).trim();
      if (fields.referralEnabled !== undefined) db.settings.referralEnabled = (fields.referralEnabled === true || fields.referralEnabled === 'true');
      if (fields.referralDiscountPercent !== undefined) db.settings.referralDiscountPercent = parseFloat(fields.referralDiscountPercent) || 0;
      if (fields.referralMinOrder !== undefined) db.settings.referralMinOrder = parseFloat(fields.referralMinOrder) || 0;
      if (fields.bgType !== undefined) db.settings.bgType = String(fields.bgType);
      if (fields.bgDefault !== undefined) db.settings.bgDefault = parseInt(fields.bgDefault, 10) || 0;
      if (fields.bgImageUrl !== undefined) db.settings.bgImageUrl = String(fields.bgImageUrl).trim();
      if (fields.bgLiveUrl !== undefined) db.settings.bgLiveUrl = String(fields.bgLiveUrl).trim();
      if (fields.particlesEnabled !== undefined) db.settings.particlesEnabled = (fields.particlesEnabled === true || fields.particlesEnabled === 'true');
      if (fields.particleType !== undefined) db.settings.particleType = parseInt(fields.particleType, 10) || 0;
      if (fields.maintenanceMode !== undefined) db.settings.maintenanceMode = (fields.maintenanceMode === true || fields.maintenanceMode === 'true');
      if (fields.colors !== undefined) {
        try {
          const c = typeof fields.colors === 'string' ? JSON.parse(fields.colors) : fields.colors;
          db.settings.colors = Object.assign({}, db.settings.colors || {}, c);
        } catch (e) {}
      }

      if (files.logo && files.logo.data && files.logo.data.length > 0) {
        const ext = path.extname(files.logo.filename).toLowerCase() || '.png';
        const allowed = ['.png', '.jpg', '.jpeg', '.jfif', '.gif', '.webp', '.avif', '.bmp', '.svg'];
        if (allowed.includes(ext)) {
          const filename = 'logo' + ext;
          fs.writeFileSync(path.join(UPLOADS_DIR, filename), files.logo.data);
          // Auto favicon from same logo
          const favName = 'favicon' + (ext === '.svg' ? '.svg' : '.png');
          fs.writeFileSync(path.join(UPLOADS_DIR, favName), files.logo.data);
          const ts = Date.now();
          db.settings.logo = '/uploads/' + filename + '?t=' + ts;
          db.settings.favicon = '/uploads/' + favName + '?t=' + ts;
        }
      }

      
      if (files.upiQr && files.upiQr.data && files.upiQr.data.length > 0) {
        const ext = path.extname(files.upiQr.filename).toLowerCase() || '.png';
        const allowed = ['.png', '.jpg', '.jpeg', '.jfif', '.gif', '.webp', '.avif', '.bmp'];
        if (allowed.includes(ext) && files.upiQr.data.length <= 20 * 1024 * 1024) {
          const filename = 'upi-qr' + ext;
          fs.writeFileSync(path.join(UPLOADS_DIR, filename), files.upiQr.data);
          db.settings.upiQr = '/uploads/' + filename + '?t=' + Date.now();
        }
      }

      saveDB(db);
      return sendJSON(res, 200, { success: true, message: 'Settings updated!', settings: db.settings });
    } catch (e) {
      console.error(e);
      return sendJSON(res, 500, { success: false, message: 'Failed to update settings' });
    }
  }




  // ----- Payment Gateway APIs -----
  // POST /api/pay/create-order  { items, couponCode }
  if (pathname === '/api/pay/create-order' && method === 'POST') {
    if (!user) return sendJSON(res, 401, { success: false, message: 'Login required' });
    try {
      const body = JSON.parse((await readBody(req)).toString());
      const items = body.items || [];
      const db = loadDB();
      if (!db.products) db.products = [];
      if (!db.payments) db.payments = [];
      let subtotal = 0;
      const purchased = [];
      for (const it of items) {
        const pr = db.products.find(x => x.id === it.productId);
        if (!pr) return sendJSON(res, 400, { success: false, message: 'Product not found' });
        const qty = Math.max(1, Math.min(99, parseInt(it.qty, 10) || 1));
        subtotal += (pr.price || 0) * qty;
        purchased.push({ productId: pr.id, name: pr.name, price: pr.price, qty, image: pr.image || '', commands: pr.commands || [], connectorId: pr.connectorId || null });
      }
      if (!purchased.length) return sendJSON(res, 400, { success: false, message: 'Cart empty' });
      let discount = 0;
      const couponCode = String(body.couponCode || '').trim().toUpperCase();
      // simple coupon check
      if (couponCode && db.coupons) {
        const cp = db.coupons.find(x => x.code === couponCode && x.enabled !== false);
        if (cp) {
          if (cp.type === 'percent') discount = subtotal * (parseFloat(cp.value) || 0) / 100;
          else discount = parseFloat(cp.value) || 0;
        }
      }
      const total = Math.max(0, Math.round((subtotal - discount) * 100) / 100);
      const amountPaise = Math.round(total * 100);
      if (amountPaise < 100) return sendJSON(res, 400, { success: false, message: 'Minimum amount ₹1' });

      const payMode = db.settings.payMode || 'manual';
      const provider = db.settings.gatewayProvider || 'razorpay';
      if (payMode !== 'gateway') return sendJSON(res, 400, { success: false, message: 'Gateway not enabled' });

      const paymentId = crypto.randomUUID();
      const pendingPay = {
        id: paymentId,
        userId: user.id,
        mcUsername: user.mcUsername || '',
        items: purchased,
        subtotal, discount, total,
        couponCode: couponCode || null,
        status: 'pending_gateway',
        provider,
        createdAt: new Date().toISOString()
      };

      if (provider === 'razorpay') {
        const keyId = db.settings.gw_razorpay_key_id || '';
        const keySecret = db.settings.gw_razorpay_key_secret || '';
        if (!keyId || !keySecret) return sendJSON(res, 400, { success: false, message: 'Razorpay keys not configured in admin' });
        const auth = Buffer.from(keyId + ':' + keySecret).toString('base64');
        const orderBody = JSON.stringify({
          amount: amountPaise,
          currency: 'INR',
          receipt: paymentId.slice(0, 32),
          notes: { paymentId, userId: user.id }
        });
        const rzpOrder = await new Promise((resolve, reject) => {
          const req2 = https.request({
            hostname: 'api.razorpay.com', path: '/v1/orders', method: 'POST',
            headers: { 'Authorization': 'Basic ' + auth, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(orderBody) }
          }, (res2) => {
            let d = '';
            res2.on('data', c => d += c);
            res2.on('end', () => {
              try { resolve({ status: res2.statusCode, data: JSON.parse(d) }); } catch(e) { reject(e); }
            });
          });
          req2.on('error', reject);
          req2.write(orderBody);
          req2.end();
        });
        if (rzpOrder.status >= 400 || !rzpOrder.data.id) {
          return sendJSON(res, 502, { success: false, message: 'Razorpay error: ' + (rzpOrder.data.error && rzpOrder.data.error.description || 'failed') });
        }
        pendingPay.gatewayOrderId = rzpOrder.data.id;
        db.payments.push(pendingPay);
        saveDB(db);
        return sendJSON(res, 200, {
          success: true,
          provider: 'razorpay',
          paymentId,
          orderId: rzpOrder.data.id,
          amount: amountPaise,
          currency: 'INR',
          keyId,
          total
        });
      }

      if (provider === 'stripe') {
        const secret = db.settings.gw_stripe_secret || '';
        const pub = db.settings.gw_stripe_publishable || '';
        if (!secret || !pub) return sendJSON(res, 400, { success: false, message: 'Stripe keys not configured' });
        // amount in smallest currency unit - assume INR or USD based on amount
        const params = new URLSearchParams({
          amount: String(amountPaise),
          currency: 'inr',
          'metadata[paymentId]': paymentId,
          'automatic_payment_methods[enabled]': 'true'
        });
        const stripeRes = await new Promise((resolve, reject) => {
          const req2 = https.request({
            hostname: 'api.stripe.com', path: '/v1/payment_intents', method: 'POST',
            headers: {
              'Authorization': 'Bearer ' + secret,
              'Content-Type': 'application/x-www-form-urlencoded',
              'Content-Length': Buffer.byteLength(params.toString())
            }
          }, (res2) => {
            let d = '';
            res2.on('data', ch => d += ch);
            res2.on('end', () => {
              try { resolve({ status: res2.statusCode, data: JSON.parse(d) }); } catch(e) { reject(e); }
            });
          });
          req2.on('error', reject);
          req2.write(params.toString());
          req2.end();
        });
        if (stripeRes.status >= 400 || !stripeRes.data.client_secret) {
          return sendJSON(res, 502, { success: false, message: 'Stripe error: ' + (stripeRes.data.error && stripeRes.data.error.message || 'failed') });
        }
        pendingPay.gatewayOrderId = stripeRes.data.id;
        db.payments.push(pendingPay);
        saveDB(db);
        return sendJSON(res, 200, {
          success: true,
          provider: 'stripe',
          paymentId,
          clientSecret: stripeRes.data.client_secret,
          publishableKey: pub,
          total
        });
      }

      // Other gateways: create pending payment, return instructions
      pendingPay.gatewayOrderId = 'pending-' + paymentId.slice(0, 8);
      db.payments.push(pendingPay);
      saveDB(db);
      return sendJSON(res, 200, {
        success: true,
        provider,
        paymentId,
        total,
        message: provider + ' configured. Complete payment via their checkout. Keys are saved — full auto-checkout for this provider can be enabled after testing.'
      });
    } catch (e) {
      console.error(e);
      return sendJSON(res, 500, { success: false, message: 'Create order failed: ' + (e.message || 'error') });
    }
  }

  // POST /api/pay/verify  { paymentId, razorpay_payment_id, razorpay_order_id, razorpay_signature }
  if (pathname === '/api/pay/verify' && method === 'POST') {
    if (!user) return sendJSON(res, 401, { success: false, message: 'Login required' });
    try {
      const body = JSON.parse((await readBody(req)).toString());
      const db = loadDB();
      if (!db.payments) db.payments = [];
      if (!db.connectors) db.connectors = [];
      const pay = db.payments.find(x => x.id === body.paymentId && x.userId === user.id);
      if (!pay) return sendJSON(res, 404, { success: false, message: 'Payment not found' });
      if (pay.status === 'approved') return sendJSON(res, 200, { success: true, message: 'Already approved' });

      const provider = pay.provider || db.settings.gatewayProvider || 'razorpay';
      let verified = false;

      if (provider === 'razorpay') {
        const secret = db.settings.gw_razorpay_key_secret || '';
        const orderId = body.razorpay_order_id || '';
        const paymentId = body.razorpay_payment_id || '';
        const signature = body.razorpay_signature || '';
        const expected = crypto.createHmac('sha256', secret).update(orderId + '|' + paymentId).digest('hex');
        verified = (expected === signature);
        if (verified) {
          pay.gatewayPaymentId = paymentId;
          pay.gatewaySignature = signature;
        }
      } else if (provider === 'stripe') {
        // Stripe: trust client confirmation + optionally retrieve PI
        verified = !!(body.stripe_payment_intent);
        if (verified) pay.gatewayPaymentId = body.stripe_payment_intent;
      } else {
        // Manual mark for other gateways after admin review
        return sendJSON(res, 200, { success: true, message: 'Payment recorded as pending. Admin will confirm.' });
      }

      if (!verified) return sendJSON(res, 400, { success: false, message: 'Payment verification failed' });

      // Auto-approve on successful gateway payment
      pay.status = 'approved';
      pay.reviewedAt = new Date().toISOString();
      pay.reviewedBy = 'gateway';
      const playerName = pay.mcUsername || user.mcUsername || 'Player';
      let commandsQueued = 0;
      const now = Date.now();
      const isOnline = (cx) => cx.lastSeen && (now - new Date(cx.lastSeen).getTime()) < 120000;
      if (!db.globalPendingCommands) db.globalPendingCommands = [];
      if (!db.sales) db.sales = [];
      if (!db.products) db.products = [];

      (pay.items || []).forEach(it => {
        const qty = it.qty || 1;
        const pr = db.products.find(x => x.id === it.productId);
        if (pr) pr.salesCount = (pr.salesCount || 0) + qty;
        const cmds = [];
        for (let i = 0; i < qty; i++) {
          (it.commands || (pr && pr.commands) || []).forEach(cmd => {
            cmds.push(normalizeCommand(replacePlayerPlaceholders(cmd, playerName)));
          });
        }
        const preferredId = it.connectorId || (pr && pr.connectorId) || null;
        let target = preferredId ? db.connectors.find(x => x.id === preferredId) : null;
        if (!target) {
          const online = db.connectors.filter(isOnline);
          target = online[0] || db.connectors[0] || null;
        }
        if (cmds.length) {
          if (target) {
            if (!Array.isArray(target.pendingCommands)) target.pendingCommands = [];
            cmds.forEach(command => {
              if (!command) return;
              target.pendingCommands.push({ id: crypto.randomUUID(), command, paymentId: pay.id, player: playerName, createdAt: new Date().toISOString() });
            });
          } else {
            cmds.forEach(command => {
              if (!command) return;
              db.globalPendingCommands.push({ id: crypto.randomUUID(), command, paymentId: pay.id, player: playerName, createdAt: new Date().toISOString() });
            });
          }
          commandsQueued += cmds.length;
        }
        db.sales.push({
          id: crypto.randomUUID(), product: it.name, productId: it.productId,
          amount: (it.price || 0) * qty, qty, userId: pay.userId, mcUsername: playerName,
          paymentId: pay.id, connectorId: target ? target.id : null, createdAt: new Date().toISOString()
        });
      });
      pay.commandsQueued = commandsQueued;
      saveDB(db);
      return sendJSON(res, 200, { success: true, message: 'Payment verified! Product will be delivered.', commandsQueued });
    } catch (e) {
      console.error(e);
      return sendJSON(res, 500, { success: false, message: 'Verify failed' });
    }
  }

  // ----- Connectors (Paper plugin link) -----

  // ========== Quick Links ==========
  if (pathname === '/api/admin/quick-links' && method === 'GET') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const db = loadDB();
    return sendJSON(res, 200, { success: true, quickLinks: db.quickLinks || [] });
  }
  if (pathname === '/api/admin/quick-links' && method === 'POST') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    try {
      const body = JSON.parse((await readBody(req)).toString());
      const name = String(body.name || '').trim();
      const url = String(body.url || '').trim();
      if (!name || !url) return sendJSON(res, 400, { success: false, message: 'Name and URL required' });
      const db = loadDB();
      if (!db.quickLinks) db.quickLinks = [];
      const item = { id: crypto.randomUUID(), name, url, order: db.quickLinks.length, createdAt: new Date().toISOString() };
      db.quickLinks.push(item);
      saveDB(db);
      return sendJSON(res, 200, { success: true, quickLink: item });
    } catch (e) { return sendJSON(res, 500, { success: false, message: 'Failed' }); }
  }
  if (pathname.match(/^\/api\/admin\/quick-links\/[^/]+$/) && method === 'PUT') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    try {
      const id = pathname.split('/').pop();
      const body = JSON.parse((await readBody(req)).toString());
      const db = loadDB();
      const item = (db.quickLinks || []).find(x => x.id === id);
      if (!item) return sendJSON(res, 404, { success: false, message: 'Not found' });
      if (body.name !== undefined) item.name = String(body.name).trim();
      if (body.url !== undefined) item.url = String(body.url).trim();
      if (body.order !== undefined) item.order = parseInt(body.order, 10) || 0;
      saveDB(db);
      return sendJSON(res, 200, { success: true, quickLink: item });
    } catch (e) { return sendJSON(res, 500, { success: false, message: 'Failed' }); }
  }
  if (pathname.match(/^\/api\/admin\/quick-links\/[^/]+$/) && method === 'DELETE') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const id = pathname.split('/').pop();
    const db = loadDB();
    const idx = (db.quickLinks || []).findIndex(x => x.id === id);
    if (idx === -1) return sendJSON(res, 404, { success: false, message: 'Not found' });
    db.quickLinks.splice(idx, 1);
    saveDB(db);
    return sendJSON(res, 200, { success: true });
  }
  // Public quick links
  if (pathname === '/api/quick-links' && method === 'GET') {
    const db = loadDB();
    const list = (db.quickLinks || []).slice().sort((a,b) => (a.order||0)-(b.order||0));
    return sendJSON(res, 200, { success: true, quickLinks: list });
  }

  // ========== Ranks ==========
  if (pathname === '/api/admin/ranks' && method === 'GET') {
    if (!user || !userHasPerm(user, 'ranks.manage') && user.role !== 'admin') {
      if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    }
    const db = loadDB();
    return sendJSON(res, 200, { success: true, ranks: db.ranks || [] });
  }
  if (pathname === '/api/admin/ranks' && method === 'POST') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    try {
      const body = JSON.parse((await readBody(req)).toString());
      const name = String(body.name || '').trim();
      if (!name) return sendJSON(res, 400, { success: false, message: 'Name required' });
      const db = loadDB();
      if (!db.ranks) db.ranks = [];
      const id = String(body.id || name.toLowerCase().replace(/[^a-z0-9]+/g, '-')).slice(0, 40);
      if (db.ranks.some(r => r.id === id)) return sendJSON(res, 400, { success: false, message: 'Rank id exists' });
      const rank = {
        id,
        name,
        isSystem: false,
        permissions: Array.isArray(body.permissions) ? body.permissions : [],
        productDiscounts: body.productDiscounts && typeof body.productDiscounts === 'object' ? body.productDiscounts : {},
        benefits: body.benefits && typeof body.benefits === 'object' ? body.benefits : {},
        createdAt: new Date().toISOString()
      };
      db.ranks.push(rank);
      saveDB(db);
      return sendJSON(res, 200, { success: true, rank });
    } catch (e) { return sendJSON(res, 500, { success: false, message: 'Failed' }); }
  }
  if (pathname.match(/^\/api\/admin\/ranks\/[^/]+$/) && method === 'PUT') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    try {
      const id = pathname.split('/').pop();
      const body = JSON.parse((await readBody(req)).toString());
      const db = loadDB();
      const rank = (db.ranks || []).find(r => r.id === id);
      if (!rank) return sendJSON(res, 404, { success: false, message: 'Not found' });
      if (body.name !== undefined) rank.name = String(body.name).trim();
      if (body.permissions !== undefined) rank.permissions = Array.isArray(body.permissions) ? body.permissions : rank.permissions;
      if (body.productDiscounts !== undefined && typeof body.productDiscounts === 'object') rank.productDiscounts = body.productDiscounts;
      if (body.benefits !== undefined && typeof body.benefits === 'object') rank.benefits = body.benefits;
      saveDB(db);
      return sendJSON(res, 200, { success: true, rank });
    } catch (e) { return sendJSON(res, 500, { success: false, message: 'Failed' }); }
  }
  if (pathname.match(/^\/api\/admin\/ranks\/[^/]+$/) && method === 'DELETE') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const id = pathname.split('/').pop();
    const db = loadDB();
    const rank = (db.ranks || []).find(r => r.id === id);
    if (!rank) return sendJSON(res, 404, { success: false, message: 'Not found' });
    if (rank.isSystem) return sendJSON(res, 400, { success: false, message: 'Cannot delete system rank' });
    db.ranks = db.ranks.filter(r => r.id !== id);
    // demote users on this rank to member
    (db.users || []).forEach(u => { if ((u.rankId || u.role) === id) { u.rankId = 'member'; u.role = 'member'; } });
    saveDB(db);
    return sendJSON(res, 200, { success: true });
  }

  // ========== Support Tickets ==========
  const TICKET_MAX_IMG = 25 * 1024 * 1024;
  const TICKET_IMG_EXT = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.svg', '.ico', '.tiff', '.tif', '.avif', '.heic', '.heif'];

  if (pathname === '/api/tickets' && method === 'GET') {
    // user: own tickets; staff with tickets.view: all or assigned
    if (!user) return sendJSON(res, 401, { success: false, message: 'Login required' });
    const db = loadDB();
    let list = db.tickets || [];
    if (user.role === 'admin' || userHasPerm(user, 'tickets.view')) {
      // all
    } else {
      list = list.filter(t => t.userId === user.id);
    }
    list = list.slice().sort((a, b) => new Date(b.updatedAt || b.createdAt) - new Date(a.updatedAt || a.createdAt));
    return sendJSON(res, 200, { success: true, tickets: list.map(t => ({
      id: t.id, subject: t.subject, status: t.status, priority: t.priority || 'normal',
      userId: t.userId, userEmail: t.userEmail, userName: t.userName,
      createdAt: t.createdAt, updatedAt: t.updatedAt,
      messageCount: (t.messages || []).length,
      lastMessage: (t.messages || []).slice(-1)[0] || null
    })) });
  }

  if (pathname === '/api/tickets' && method === 'POST') {
    if (!user) return sendJSON(res, 401, { success: false, message: 'Login required' });
    try {
      const contentType = req.headers['content-type'] || '';
      let fields = {}, files = {};
      if (contentType.includes('multipart/form-data')) {
        const boundary = contentType.split('boundary=')[1];
        const buffer = await readBody(req);
        const parsed = parseMultipart(buffer, boundary);
        fields = parsed.fields;
        files = parsed.files;
      } else {
        fields = JSON.parse((await readBody(req)).toString());
      }
      const subject = String(fields.subject || '').trim();
      const body = String(fields.body || fields.message || '').trim();
      if (!subject || !body) return sendJSON(res, 400, { success: false, message: 'Subject and message required' });
      const db = loadDB();
      if (!db.tickets) db.tickets = [];
      let attachments = [];
      // support multiple image fields: image, image0, image1... or attachments
      const fileKeys = Object.keys(files || {});
      for (const key of fileKeys) {
        const f = files[key];
        if (!f || !f.data || !f.data.length) continue;
        if (f.data.length > TICKET_MAX_IMG) return sendJSON(res, 400, { success: false, message: 'Image max 25MB' });
        let ext = path.extname(f.filename || '').toLowerCase() || '.png';
        if (!TICKET_IMG_EXT.includes(ext)) {
          // allow any image/* by content - still save with original ext or .bin
          if (!ext || ext.length > 8) ext = '.png';
        }
        const filename = 'ticket-' + crypto.randomUUID().slice(0, 10) + ext;
        fs.writeFileSync(path.join(UPLOADS_DIR, filename), f.data);
        attachments.push({ url: '/uploads/' + filename, name: f.filename || filename, size: f.data.length });
      }
      const ticket = {
        id: crypto.randomUUID(),
        subject,
        status: 'open',
        priority: String(fields.priority || 'normal'),
        userId: user.id,
        userEmail: user.email,
        userName: user.mcUsername || user.email,
        messages: [{
          id: crypto.randomUUID(),
          from: 'user',
          userId: user.id,
          userName: user.mcUsername || user.email,
          body,
          attachments,
          createdAt: new Date().toISOString()
        }],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      db.tickets.push(ticket);
      saveDB(db);
      return sendJSON(res, 200, { success: true, ticket });
    } catch (e) {
      console.error(e);
      return sendJSON(res, 500, { success: false, message: 'Failed to create ticket' });
    }
  }

  if (pathname.match(/^\/api\/tickets\/[^/]+$/) && method === 'GET') {
    if (!user) return sendJSON(res, 401, { success: false, message: 'Login required' });
    const id = pathname.split('/').pop();
    const db = loadDB();
    const t = (db.tickets || []).find(x => x.id === id);
    if (!t) return sendJSON(res, 404, { success: false, message: 'Not found' });
    if (t.userId !== user.id && user.role !== 'admin' && !userHasPerm(user, 'tickets.view')) {
      return sendJSON(res, 403, { success: false, message: 'Forbidden' });
    }
    return sendJSON(res, 200, { success: true, ticket: t });
  }

  if (pathname.match(/^\/api\/tickets\/[^/]+\/reply$/) && method === 'POST') {
    if (!user) return sendJSON(res, 401, { success: false, message: 'Login required' });
    const id = pathname.split('/')[3];
    try {
      const contentType = req.headers['content-type'] || '';
      let fields = {}, files = {};
      if (contentType.includes('multipart/form-data')) {
        const boundary = contentType.split('boundary=')[1];
        const buffer = await readBody(req);
        const parsed = parseMultipart(buffer, boundary);
        fields = parsed.fields;
        files = parsed.files;
      } else {
        fields = JSON.parse((await readBody(req)).toString());
      }
      const body = String(fields.body || fields.message || '').trim();
      if (!body) return sendJSON(res, 400, { success: false, message: 'Message required' });
      const db = loadDB();
      const ticket = (db.tickets || []).find(x => x.id === id);
      if (!ticket) return sendJSON(res, 404, { success: false, message: 'Not found' });
      const isStaff = user.role === 'admin' || userHasPerm(user, 'tickets.reply');
      if (ticket.userId !== user.id && !isStaff) {
        return sendJSON(res, 403, { success: false, message: 'Forbidden' });
      }
      if (ticket.status === 'closed' && !isStaff) {
        return sendJSON(res, 400, { success: false, message: 'Ticket is closed' });
      }
      let attachments = [];
      for (const key of Object.keys(files || {})) {
        const f = files[key];
        if (!f || !f.data || !f.data.length) continue;
        if (f.data.length > TICKET_MAX_IMG) return sendJSON(res, 400, { success: false, message: 'Image max 25MB' });
        let ext = path.extname(f.filename || '').toLowerCase() || '.png';
        const filename = 'ticket-' + crypto.randomUUID().slice(0, 10) + ext;
        fs.writeFileSync(path.join(UPLOADS_DIR, filename), f.data);
        attachments.push({ url: '/uploads/' + filename, name: f.filename || filename, size: f.data.length });
      }
      // Ticket owner messages = user side; staff reply only if staff AND (not owner OR explicit asStaff from admin panel)
      const isTicketOwner = ticket.userId === user.id;
      const forceStaff = fields.asStaff === 'true' || fields.asStaff === true || fields.from === 'staff';
      const fromRole = (isStaff && (!isTicketOwner || forceStaff)) ? 'staff' : 'user';
      const msg = {
        id: crypto.randomUUID(),
        from: fromRole,
        userId: user.id,
        userName: user.mcUsername || user.email,
        body,
        attachments,
        createdAt: new Date().toISOString()
      };
      ticket.messages = ticket.messages || [];
      ticket.messages.push(msg);
      ticket.updatedAt = new Date().toISOString();
      if (isStaff && ticket.status === 'open') ticket.status = 'answered';
      if (!isStaff && ticket.status === 'answered') ticket.status = 'open';
      if (fields.status && isStaff) {
        const st = String(fields.status);
        if (['open', 'answered', 'closed'].includes(st)) ticket.status = st;
      }
      saveDB(db);
      return sendJSON(res, 200, { success: true, ticket, message: msg });
    } catch (e) {
      console.error(e);
      return sendJSON(res, 500, { success: false, message: 'Failed' });
    }
  }

  if (pathname.match(/^\/api\/tickets\/[^/]+\/status$/) && method === 'PUT') {
    if (!user) return sendJSON(res, 401, { success: false, message: 'Login required' });
    if (user.role !== 'admin' && !userHasPerm(user, 'tickets.reply')) {
      return sendJSON(res, 403, { success: false, message: 'Forbidden' });
    }
    const id = pathname.split('/')[3];
    try {
      const body = JSON.parse((await readBody(req)).toString());
      const db = loadDB();
      const ticket = (db.tickets || []).find(x => x.id === id);
      if (!ticket) return sendJSON(res, 404, { success: false, message: 'Not found' });
      if (body.status && ['open', 'answered', 'closed'].includes(body.status)) {
        ticket.status = body.status;
        ticket.updatedAt = new Date().toISOString();
        saveDB(db);
      }
      return sendJSON(res, 200, { success: true, ticket });
    } catch (e) { return sendJSON(res, 500, { success: false, message: 'Failed' }); }
  }

  // Extend user PUT for rankId + balance

  // GET /api/admin/connectors
  if (pathname === '/api/admin/connectors' && method === 'GET') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const db = loadDB();
    if (!db.connectors) db.connectors = [];
    const now = Date.now();
    const list = db.connectors.map(c => ({
      id: c.id,
      name: c.name,
      code: c.code,
      connected: !!(c.lastSeen && (now - new Date(c.lastSeen).getTime()) < 120000),
      lastSeen: c.lastSeen || null,
      createdAt: c.createdAt,
      serverVersion: c.serverVersion || null,
      playersOnline: c.playersOnline || 0,
      pendingCount: Array.isArray(c.pendingCommands) ? c.pendingCommands.length : 0,
      commandLog: Array.isArray(c.commandLog) ? c.commandLog.slice(0, 10) : []
    }));
    return sendJSON(res, 200, { success: true, connectors: list });
  }

  // POST /api/admin/connectors  { name }
  if (pathname === '/api/admin/connectors' && method === 'POST') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    try {
      const body = JSON.parse((await readBody(req)).toString());
      const name = (body.name || '').trim();
      if (!name || name.length < 2) return sendJSON(res, 400, { success: false, message: 'Server name required' });
      const db = loadDB();
      if (!db.connectors) db.connectors = [];
      // unique code
      const code = 'NS-' + crypto.randomBytes(3).toString('hex').toUpperCase() + '-' +
        crypto.randomBytes(3).toString('hex').toUpperCase() + '-' +
        crypto.randomBytes(3).toString('hex').toUpperCase();
      const item = {
        id: crypto.randomUUID(),
        name,
        code,
        lastSeen: null,
        createdAt: new Date().toISOString(),
        serverVersion: null,
        playersOnline: 0,
        pendingCommands: [],
        commandLog: []
      };
      db.connectors.push(item);
      saveDB(db);
      return sendJSON(res, 200, { success: true, connector: item });
    } catch (e) {
      return sendJSON(res, 500, { success: false, message: 'Server error' });
    }
  }

  // DELETE /api/admin/connectors/:id
  if (pathname.startsWith('/api/admin/connectors/') && method === 'DELETE') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const id = pathname.split('/').pop();
    const db = loadDB();
    if (!db.connectors) db.connectors = [];
    const before = db.connectors.length;
    db.connectors = db.connectors.filter(c => c.id !== id);
    if (db.connectors.length === before) return sendJSON(res, 404, { success: false, message: 'Not found' });
    saveDB(db);
    return sendJSON(res, 200, { success: true, message: 'Deleted' });
  }

  // POST /api/connector/heartbeat  (plugin calls this — no cookie auth, uses code)
  // Also delivers pending console commands and accepts results
  if (pathname === '/api/connector/heartbeat' && method === 'POST') {
    try {
      const body = JSON.parse((await readBody(req)).toString());
      const code = (body.code || '').trim().toUpperCase();
      if (!code) return sendJSON(res, 400, { success: false, message: 'Code required' });
      const db = loadDB();
      if (!db.connectors) db.connectors = [];
      const c = db.connectors.find(x => x.code.toUpperCase() === code);
      if (!c) return sendJSON(res, 401, { success: false, message: 'Invalid code' });
      c.lastSeen = new Date().toISOString();
      if (body.version) c.serverVersion = String(body.version).slice(0, 64);
      if (typeof body.players === 'number') c.playersOnline = body.players;
      if (!Array.isArray(c.pendingCommands)) c.pendingCommands = [];
      if (!Array.isArray(c.commandLog)) c.commandLog = [];

      // Accept results from plugin for previously sent commands
      if (Array.isArray(body.results)) {
        for (const r of body.results) {
          if (!r || !r.id) continue;
          c.commandLog.unshift({
            id: r.id,
            command: r.command || '',
            success: !!r.success,
            output: String(r.output || '').slice(0, 4000),
            at: new Date().toISOString()
          });
        }
        c.commandLog = c.commandLog.slice(0, 50);
      }

      // Give pending commands to plugin (and clear them) — never send leading /
      // Also absorb global queue (orders approved when no server was linked yet)
      if (!db.globalPendingCommands) db.globalPendingCommands = [];
      if (db.globalPendingCommands.length) {
        if (!Array.isArray(c.pendingCommands)) c.pendingCommands = [];
        c.pendingCommands.push(...db.globalPendingCommands);
        db.globalPendingCommands = [];
      }
      const toSend = c.pendingCommands.slice().map(item => ({
        id: item.id,
        command: normalizeCommand(item.command)
      })).filter(item => item.command);
      c.pendingCommands = [];
      saveDB(db);
      return sendJSON(res, 200, {
        success: true,
        message: 'Connected',
        name: c.name,
        commands: toSend
      });
    } catch (e) {
      return sendJSON(res, 500, { success: false, message: 'Server error' });
    }
  }

  // POST /api/admin/connectors/:id/command  { command: "say hello" }
  if (pathname.match(/^\/api\/admin\/connectors\/[^/]+\/command$/) && method === 'POST') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    try {
      const id = pathname.split('/')[4];
      const body = JSON.parse((await readBody(req)).toString());
      const command = (body.command || '').trim();
      if (!command) return sendJSON(res, 400, { success: false, message: 'Command required' });
      if (command.length > 500) return sendJSON(res, 400, { success: false, message: 'Command too long' });
      const db = loadDB();
      if (!db.connectors) db.connectors = [];
      const c = db.connectors.find(x => x.id === id);
      if (!c) return sendJSON(res, 404, { success: false, message: 'Not found' });
      if (!Array.isArray(c.pendingCommands)) c.pendingCommands = [];
      const item = {
        id: crypto.randomUUID(),
        command,
        createdAt: new Date().toISOString()
      };
      c.pendingCommands.push(item);
      saveDB(db);
      return sendJSON(res, 200, { success: true, message: 'Command queued', item });
    } catch (e) {
      return sendJSON(res, 500, { success: false, message: 'Server error' });
    }
  }


  // ----- Store Pages -----
  // GET /api/pages  (public list)
  if (pathname === '/api/pages' && method === 'GET') {
    const db = loadDB();
    if (!db.pages) db.pages = [];
    const list = db.pages
      .slice()
      .sort((a, b) => (a.order || 0) - (b.order || 0) || String(a.createdAt || '').localeCompare(String(b.createdAt || '')))
      .map(p => ({
        id: p.id,
        title: p.title,
        slug: p.slug,
        order: p.order || 0,
        createdAt: p.createdAt
      }));
    return sendJSON(res, 200, { success: true, pages: list });
  }

  // GET /api/pages/:slug  (public single)
  if (pathname.startsWith('/api/pages/') && method === 'GET' && !pathname.startsWith('/api/admin/')) {
    const slug = decodeURIComponent(pathname.split('/').pop()).toLowerCase();
    const db = loadDB();
    if (!db.pages) db.pages = [];
    const p = db.pages.find(x => (x.slug || '').toLowerCase() === slug);
    if (!p) return sendJSON(res, 404, { success: false, message: 'Page not found' });
    return sendJSON(res, 200, {
      success: true,
      page: { id: p.id, title: p.title, slug: p.slug, content: p.content || '', order: p.order || 0, createdAt: p.createdAt }
    });
  }

  // GET /api/admin/pages
  if (pathname === '/api/admin/pages' && method === 'GET') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const db = loadDB();
    if (!db.pages) db.pages = [];
    const list = db.pages.slice().sort((a, b) => (a.order || 0) - (b.order || 0));
    return sendJSON(res, 200, { success: true, pages: list });
  }


  // ---------- Admin: website updater (zip upload; data is never touched) ----------
  if (pathname.startsWith('/api/admin/update/')) {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const updater = require('./updater');
    try {
      if (pathname === '/api/admin/update/info' && method === 'GET') {
        return sendJSON(res, 200, Object.assign({ success: true }, updater.info()));
      }
      if (pathname === '/api/admin/update/check' && method === 'POST') {
        const buf = await readBodyLimited(req, updater.MAX_ZIP);
        return sendJSON(res, 200, { success: true, result: updater.check(buf) });
      }
      if (pathname === '/api/admin/update/apply' && method === 'POST') {
        const body = JSON.parse((await readBody(req)).toString() || '{}');
        const r = updater.apply(String(body.token || ''), user.email);
        sendJSON(res, 200, Object.assign({ success: true }, r, { restart: 'pending' }));
        return updater.scheduleRestart(() => server.close());
      }
      if (pathname === '/api/admin/update/rollback' && method === 'POST') {
        const body = JSON.parse((await readBody(req)).toString() || '{}');
        updater.rollback(String(body.id || ''), user.email);
        sendJSON(res, 200, { success: true });
        return updater.scheduleRestart(() => server.close());
      }
    } catch (err) {
      return sendJSON(res, 400, { success: false, message: err.message || 'Update error' });
    }
    return sendJSON(res, 404, { success: false, message: 'Not found' });
  }

  // POST /api/admin/pages  { title, content, order? }
  if (pathname === '/api/admin/pages' && method === 'POST') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    try {
      const body = JSON.parse((await readBody(req)).toString());
      const title = (body.title || '').trim();
      if (!title) return sendJSON(res, 400, { success: false, message: 'Title required' });
      let slug = (body.slug || title).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60) || 'page';
      const db = loadDB();
      if (!db.pages) db.pages = [];
      let base = slug, n = 2;
      while (db.pages.some(p => p.slug === slug)) { slug = base + '-' + n; n++; }
      const item = {
        id: crypto.randomUUID(),
        title,
        slug,
        content: String(body.content || ''),
        order: typeof body.order === 'number' ? body.order : db.pages.length,
        createdAt: new Date().toISOString()
      };
      db.pages.push(item);
      saveDB(db);
      return sendJSON(res, 200, { success: true, page: item });
    } catch (e) {
      return sendJSON(res, 500, { success: false, message: 'Server error' });
    }
  }

  // PUT /api/admin/pages/:id
  if (pathname.startsWith('/api/admin/pages/') && method === 'PUT') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    try {
      const id = pathname.split('/').pop();
      const body = JSON.parse((await readBody(req)).toString());
      const db = loadDB();
      if (!db.pages) db.pages = [];
      const p = db.pages.find(x => x.id === id);
      if (!p) return sendJSON(res, 404, { success: false, message: 'Not found' });
      if (body.title != null) p.title = String(body.title).trim() || p.title;
      if (body.content != null) p.content = String(body.content);
      if (typeof body.order === 'number') p.order = body.order;
      if (body.slug) {
        let slug = String(body.slug).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60);
        if (slug && !db.pages.some(x => x.slug === slug && x.id !== id)) p.slug = slug;
      }
      saveDB(db);
      return sendJSON(res, 200, { success: true, page: p });
    } catch (e) {
      return sendJSON(res, 500, { success: false, message: 'Server error' });
    }
  }

  // DELETE /api/admin/pages/:id
  if (pathname.startsWith('/api/admin/pages/') && method === 'DELETE') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const id = pathname.split('/').pop();
    const db = loadDB();
    if (!db.pages) db.pages = [];
    const before = db.pages.length;
    db.pages = db.pages.filter(p => p.id !== id);
    if (db.pages.length === before) return sendJSON(res, 404, { success: false, message: 'Not found' });
    saveDB(db);
    return sendJSON(res, 200, { success: true, message: 'Deleted' });
  }


  // ---------- Categories ----------
  // GET /api/categories  (public list, optional ?pageId=)
  if (pathname === '/api/categories' && method === 'GET') {
    const db = loadDB();
    if (!db.categories) db.categories = [];
    const url = new URL(req.url, 'http://localhost');
    const pageId = url.searchParams.get('pageId') || '';
    let list = db.categories.slice().sort((a, b) => (a.order || 0) - (b.order || 0));
    list = list.filter(c => c.enabled !== false);
    if (pageId) {
      list = list.filter(c => !c.pageId || c.pageId === pageId);
    }
    const out = list.map(c => ({
      id: c.id,
      name: c.name,
      description: c.description || '',
      logo: c.logo || '',
      pageId: c.pageId || null,
      order: c.order || 0,
      enabled: c.enabled !== false,
      createdAt: c.createdAt
    }));
    return sendJSON(res, 200, { success: true, categories: out });
  }

  // GET /api/admin/categories
  if (pathname === '/api/admin/categories' && method === 'GET') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const db = loadDB();
    if (!db.categories) db.categories = [];
    const list = db.categories.slice().sort((a, b) => (a.order || 0) - (b.order || 0));
    return sendJSON(res, 200, { success: true, categories: list });
  }

  // POST /api/admin/categories  (multipart or JSON: name, description, pageId, logo file)
  if (pathname === '/api/admin/categories' && method === 'POST') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    try {
      const contentType = req.headers['content-type'] || '';
      let fields = {};
      let files = {};
      if (contentType.includes('multipart/form-data')) {
        const boundary = contentType.split('boundary=')[1];
        const buffer = await readBody(req);
        const parsed = parseMultipart(buffer, boundary);
        fields = parsed.fields;
        files = parsed.files;
        if (!files.logo && files.image) files.logo = files.image; // admin form sends 'image'
      } else {
        fields = JSON.parse((await readBody(req)).toString());
      }
      const name = (fields.name || '').trim();
      if (!name) return sendJSON(res, 400, { success: false, message: 'Name required' });
      const description = String(fields.description || '').trim();
      const pageId = (fields.pageId || '').trim() || null;
      const db = loadDB();
      if (!db.categories) db.categories = [];
      if (pageId && !(db.pages || []).some(pg => pg.id === pageId)) {
        return sendJSON(res, 400, { success: false, message: 'Invalid page selected' });
      }
      let logoPath = '';
      if (files.logo && files.logo.data && files.logo.data.length > 0) {
        const ext = path.extname(files.logo.filename).toLowerCase() || '.png';
        const allowed = ['.png', '.jpg', '.jpeg', '.jfif', '.gif', '.webp', '.avif', '.bmp', '.svg'];
        if (!allowed.includes(ext)) {
          return sendJSON(res, 400, { success: false, message: 'Logo must be image (png/jpg/gif/webp/svg)' });
        }
        if (files.logo.data.length > 20 * 1024 * 1024) {
          return sendJSON(res, 400, { success: false, message: 'Logo max 20MB' });
        }
        const filename = 'cat-' + crypto.randomUUID().slice(0, 8) + ext;
        fs.writeFileSync(path.join(UPLOADS_DIR, filename), files.logo.data);
        logoPath = '/uploads/' + filename;
      }
      const item = {
        id: crypto.randomUUID(),
        name,
        description,
        logo: logoPath,
        pageId,
        enabled: true,
        order: typeof fields.order === 'number' ? fields.order : (parseInt(fields.order, 10) || db.categories.length),
        createdAt: new Date().toISOString()
      };
      db.categories.push(item);
      saveDB(db);
      return sendJSON(res, 200, { success: true, category: item });
    } catch (e) {
      console.error(e);
      return sendJSON(res, 500, { success: false, message: 'Failed to create category' });
    }
  }

  // PUT /api/admin/categories/:id
  if (pathname.startsWith('/api/admin/categories/') && method === 'PUT') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    try {
      const id = pathname.split('/').pop();
      const contentType = req.headers['content-type'] || '';
      let fields = {};
      let files = {};
      if (contentType.includes('multipart/form-data')) {
        const boundary = contentType.split('boundary=')[1];
        const buffer = await readBody(req);
        const parsed = parseMultipart(buffer, boundary);
        fields = parsed.fields;
        files = parsed.files;
        if (!files.logo && files.image) files.logo = files.image; // admin form sends 'image'
      } else {
        fields = JSON.parse((await readBody(req)).toString());
      }
      const db = loadDB();
      if (!db.categories) db.categories = [];
      const c = db.categories.find(x => x.id === id);
      if (!c) return sendJSON(res, 404, { success: false, message: 'Not found' });
      if (fields.name !== undefined) {
        const n = String(fields.name).trim();
        if (!n) return sendJSON(res, 400, { success: false, message: 'Name required' });
        c.name = n;
      }
      if (fields.description !== undefined) c.description = String(fields.description).trim();
      if (fields.pageId !== undefined) {
        const pid = String(fields.pageId || '').trim() || null;
        if (pid && !(db.pages || []).some(pg => pg.id === pid)) {
          return sendJSON(res, 400, { success: false, message: 'Invalid page' });
        }
        c.pageId = pid;
      }
      if (fields.order !== undefined) c.order = parseInt(fields.order, 10) || 0;
      if (fields.enabled !== undefined) {
        c.enabled = (fields.enabled === true || fields.enabled === 'true' || fields.enabled === '1');
      }
      if (files.logo && files.logo.data && files.logo.data.length > 0) {
        const ext = path.extname(files.logo.filename).toLowerCase() || '.png';
        const allowed = ['.png', '.jpg', '.jpeg', '.jfif', '.gif', '.webp', '.avif', '.bmp', '.svg'];
        if (!allowed.includes(ext)) {
          return sendJSON(res, 400, { success: false, message: 'Invalid image type' });
        }
        if (files.logo.data.length > 20 * 1024 * 1024) {
          return sendJSON(res, 400, { success: false, message: 'Logo max 20MB' });
        }
        const filename = 'cat-' + crypto.randomUUID().slice(0, 8) + ext;
        fs.writeFileSync(path.join(UPLOADS_DIR, filename), files.logo.data);
        c.logo = '/uploads/' + filename;
      }
      saveDB(db);
      return sendJSON(res, 200, { success: true, category: c });
    } catch (e) {
      console.error(e);
      return sendJSON(res, 500, { success: false, message: 'Failed to update' });
    }
  }

  // DELETE /api/admin/categories/:id
  if (pathname.startsWith('/api/admin/categories/') && method === 'DELETE') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const id = pathname.split('/').pop();
    const db = loadDB();
    if (!db.categories) db.categories = [];
    const before = db.categories.length;
    db.categories = db.categories.filter(c => c.id !== id);
    if (db.categories.length === before) return sendJSON(res, 404, { success: false, message: 'Not found' });
    saveDB(db);
    return sendJSON(res, 200, { success: true, message: 'Deleted' });
  }


  // ---------- Products ----------
  // GET /api/products  public list (?categoryId=)
  if (pathname === '/api/products' && method === 'GET') {
    const db = loadDB();
    if (!db.products) db.products = [];
    const url = new URL(req.url, 'http://localhost');
    const categoryId = url.searchParams.get('categoryId') || '';
    let list = db.products.slice().sort((a, b) => (a.order || 0) - (b.order || 0));
    list = list.filter(x => x.enabled !== false);
    const now = Date.now();
    list = list.filter(x => {
      if (x.publishAt) { const t = new Date(x.publishAt).getTime(); if (!isNaN(t) && now < t) return false; }
      if (x.unpublishAt) { const t = new Date(x.unpublishAt).getTime(); if (!isNaN(t) && now > t) return false; }
      return true;
    });
    if (categoryId) list = list.filter(x => x.categoryId === categoryId);
    // popular flag: top by salesCount among returned
    const maxSales = list.reduce((m, x) => Math.max(m, x.salesCount || 0), 0);
    const out = list.map(pr => ({
      id: pr.id,
      name: pr.name,
      shortDescription: pr.shortDescription || pr.description || '',
      price: pr.price || 0,
      image: pr.image || '',
      descriptionImage: pr.descriptionImage || '',
      categoryId: pr.categoryId || null,
      salesCount: pr.salesCount || 0,
      popular: maxSales > 0 && (pr.salesCount || 0) === maxSales && maxSales >= 1,
      featured: !!pr.featured,
      tags: pr.tags || [],
      stock: pr.stock != null ? pr.stock : null,
      variants: pr.variants || [],
      order: pr.order || 0,
      createdAt: pr.createdAt
    }));
    return sendJSON(res, 200, { success: true, products: out });
  }

  // GET /api/products/:id  public detail
  if (pathname.startsWith('/api/products/') && method === 'GET' && !pathname.startsWith('/api/admin/')) {
    const id = decodeURIComponent(pathname.split('/').pop());
    const db = loadDB();
    if (!db.products) db.products = [];
    const pr = db.products.find(x => x.id === id);
    if (!pr || pr.enabled === false) return sendJSON(res, 404, { success: false, message: 'Product not found' });
    let catName = '';
    if (pr.categoryId && db.categories) {
      const cat = db.categories.find(c => c.id === pr.categoryId);
      if (cat) catName = cat.name;
    }
    const maxSales = (db.products || []).reduce((m, x) => Math.max(m, x.salesCount || 0), 0);
    return sendJSON(res, 200, {
      success: true,
      product: {
        id: pr.id,
        name: pr.name,
        shortDescription: pr.shortDescription || '',
        fullDescription: pr.fullDescription || '',
        price: pr.price || 0,
        image: pr.image || '',
        descriptionImage: pr.descriptionImage || '',
        categoryId: pr.categoryId || null,
        categoryName: catName,
        salesCount: pr.salesCount || 0,
        popular: maxSales > 0 && (pr.salesCount || 0) === maxSales && maxSales >= 1,
        createdAt: pr.createdAt
      }
    });
  }

  // GET /api/admin/products
  if (pathname === '/api/admin/products' && method === 'GET') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const db = loadDB();
    if (!db.products) db.products = [];
    const list = db.products.slice().sort((a, b) => (a.order || 0) - (b.order || 0));
    return sendJSON(res, 200, { success: true, products: list });
  }

  // POST /api/admin/products  multipart: name, shortDescription, fullDescription, price, categoryId, commands (JSON string), image
  if (pathname === '/api/admin/products' && method === 'POST') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    try {
      const contentType = req.headers['content-type'] || '';
      let fields = {};
      let files = {};
      if (contentType.includes('multipart/form-data')) {
        const boundary = contentType.split('boundary=')[1];
        const buffer = await readBody(req);
        const parsed = parseMultipart(buffer, boundary);
        fields = parsed.fields;
        files = parsed.files;
      } else {
        fields = JSON.parse((await readBody(req)).toString());
      }
      const name = (fields.name || '').trim();
      if (!name) return sendJSON(res, 400, { success: false, message: 'Name required' });
      const categoryId = (fields.categoryId || '').trim();
      if (!categoryId) return sendJSON(res, 400, { success: false, message: 'Category required' });
      const db = loadDB();
      if (!db.products) db.products = [];
      if (!(db.categories || []).some(c => c.id === categoryId)) {
        return sendJSON(res, 400, { success: false, message: 'Invalid category' });
      }
      const price = parseFloat(fields.price);
      if (isNaN(price) || price < 0) return sendJSON(res, 400, { success: false, message: 'Valid price required' });
      let commands = [];
      try {
        const raw = fields.commands;
        if (typeof raw === 'string' && raw.trim()) commands = JSON.parse(raw);
        else if (Array.isArray(raw)) commands = raw;
      } catch (_) {}
      commands = (commands || []).map(c => normalizeCommand(c)).filter(Boolean).slice(0, 50);

      function saveProdImage(fileObj, prefix) {
        if (!fileObj || !fileObj.data || fileObj.data.length === 0) return '';
        const ext = path.extname(fileObj.filename).toLowerCase() || '.png';
        const allowed = ['.png', '.jpg', '.jpeg', '.jfif', '.gif', '.webp', '.avif', '.bmp'];
        if (!allowed.includes(ext)) return null;
        if (fileObj.data.length > 20 * 1024 * 1024) return null;
        const filename = prefix + '-' + crypto.randomUUID().slice(0, 8) + ext;
        fs.writeFileSync(path.join(UPLOADS_DIR, filename), fileObj.data);
        return '/uploads/' + filename;
      }
      const imagePath = saveProdImage(files.image, 'prod') || '';
      const descImagePath = saveProdImage(files.descriptionImage, 'proddesc') || '';
      if (files.image && files.image.data && files.image.data.length > 0 && imagePath === '') {
        return sendJSON(res, 400, { success: false, message: 'Product image invalid (png/jpg/gif/webp, max 20MB)' });
      }
      if (files.descriptionImage && files.descriptionImage.data && files.descriptionImage.data.length > 0 && descImagePath === '') {
        return sendJSON(res, 400, { success: false, message: 'Description image invalid (png/jpg/gif/webp, max 20MB)' });
      }

      let connectorId = (fields.connectorId || '').trim() || null;
      if (connectorId && !(db.connectors || []).some(c => c.id === connectorId)) {
        return sendJSON(res, 400, { success: false, message: 'Invalid server connector' });
      }

      // Advanced product fields (all optional / off by default)
      let stock = null;
      if (fields.stock !== undefined && fields.stock !== '' && fields.stock !== null) {
        const n = parseInt(fields.stock, 10);
        if (!isNaN(n) && n >= 0) stock = n;
      }
      let lowStockAlert = null;
      if (fields.lowStockAlert !== undefined && fields.lowStockAlert !== '' && fields.lowStockAlert !== null) {
        const n = parseInt(fields.lowStockAlert, 10);
        if (!isNaN(n) && n >= 0) lowStockAlert = n;
      }
      let tags = [];
      try {
        if (typeof fields.tags === 'string' && fields.tags.trim()) tags = JSON.parse(fields.tags);
        else if (Array.isArray(fields.tags)) tags = fields.tags;
      } catch (_) {}
      tags = (tags || []).map(t => String(t).trim()).filter(Boolean).slice(0, 20);
      let variants = [];
      try {
        if (typeof fields.variants === 'string' && fields.variants.trim()) variants = JSON.parse(fields.variants);
        else if (Array.isArray(fields.variants)) variants = fields.variants;
      } catch (_) {}
      variants = (variants || []).slice(0, 30).map(v => ({
        name: String(v.name || '').trim(),
        price: parseFloat(v.price) || price,
        commands: Array.isArray(v.commands) ? v.commands.slice(0, 20) : [],
        stock: (v.stock !== undefined && v.stock !== '' && v.stock !== null) ? parseInt(v.stock, 10) : null
      })).filter(v => v.name);

      const item = {
        id: crypto.randomUUID(),
        name,
        shortDescription: String(fields.shortDescription || fields.description || ''),
        fullDescription: String(fields.fullDescription || ''),
        description: String(fields.description || fields.shortDescription || ''),
        price,
        image: imagePath,
        descriptionImage: descImagePath,
        categoryId,
        connectorId,
        commands,
        enabled: true,
        salesCount: 0,
        order: parseInt(fields.order, 10) || db.products.length,
        // Advanced
        stock,
        lowStockAlert,
        featured: (fields.featured === true || fields.featured === 'true' || fields.featured === '1'),
        tags,
        variants,
        publishAt: (fields.publishAt || '').trim() || null,
        unpublishAt: (fields.unpublishAt || '').trim() || null,
        createdAt: new Date().toISOString()
      };
      db.products.push(item);
      saveDB(db);
      return sendJSON(res, 200, { success: true, product: item });
    } catch (e) {
      console.error(e);
      return sendJSON(res, 500, { success: false, message: 'Failed to create product' });
    }
  }

  // PUT /api/admin/products/:id
  if (pathname.startsWith('/api/admin/products/') && method === 'PUT') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    try {
      const id = pathname.split('/').pop();
      const contentType = req.headers['content-type'] || '';
      let fields = {};
      let files = {};
      if (contentType.includes('multipart/form-data')) {
        const boundary = contentType.split('boundary=')[1];
        const buffer = await readBody(req);
        const parsed = parseMultipart(buffer, boundary);
        fields = parsed.fields;
        files = parsed.files;
      } else {
        fields = JSON.parse((await readBody(req)).toString());
      }
      const db = loadDB();
      if (!db.products) db.products = [];
      const pr = db.products.find(x => x.id === id);
      if (!pr) return sendJSON(res, 404, { success: false, message: 'Not found' });
      if (fields.name !== undefined) {
        const n = String(fields.name).trim();
        if (!n) return sendJSON(res, 400, { success: false, message: 'Name required' });
        pr.name = n;
      }
      if (fields.shortDescription !== undefined) pr.shortDescription = String(fields.shortDescription);
      if (fields.fullDescription !== undefined) pr.fullDescription = String(fields.fullDescription);
      if (fields.price !== undefined) {
        const price = parseFloat(fields.price);
        if (isNaN(price) || price < 0) return sendJSON(res, 400, { success: false, message: 'Invalid price' });
        pr.price = price;
      }
      if (fields.categoryId !== undefined) {
        const cid = String(fields.categoryId).trim();
        if (!(db.categories || []).some(c => c.id === cid)) return sendJSON(res, 400, { success: false, message: 'Invalid category' });
        pr.categoryId = cid;
      }
      if (fields.commands !== undefined) {
        let commands = [];
        try {
          const raw = fields.commands;
          if (typeof raw === 'string' && raw.trim()) commands = JSON.parse(raw);
          else if (Array.isArray(raw)) commands = raw;
        } catch (_) {}
        pr.commands = (commands || []).map(c => normalizeCommand(c)).filter(Boolean).slice(0, 50);
      }
      if (fields.enabled !== undefined) {
        pr.enabled = (fields.enabled === true || fields.enabled === 'true' || fields.enabled === '1');
      }
      if (fields.connectorId !== undefined) {
        const cid = String(fields.connectorId || '').trim() || null;
        if (cid && !(db.connectors || []).some(c => c.id === cid)) {
          return sendJSON(res, 400, { success: false, message: 'Invalid server connector' });
        }
        pr.connectorId = cid;
      }
      if (files.image && files.image.data && files.image.data.length > 0) {
        const ext = path.extname(files.image.filename).toLowerCase() || '.png';
        const allowed = ['.png', '.jpg', '.jpeg', '.jfif', '.gif', '.webp', '.avif', '.bmp'];
        if (!allowed.includes(ext)) return sendJSON(res, 400, { success: false, message: 'Invalid image' });
        if (files.image.data.length > 20 * 1024 * 1024) return sendJSON(res, 400, { success: false, message: 'Image max 20MB' });
        const filename = 'prod-' + crypto.randomUUID().slice(0, 8) + ext;
        fs.writeFileSync(path.join(UPLOADS_DIR, filename), files.image.data);
        pr.image = '/uploads/' + filename;
      }
      if (files.descriptionImage && files.descriptionImage.data && files.descriptionImage.data.length > 0) {
        const ext = path.extname(files.descriptionImage.filename).toLowerCase() || '.png';
        const allowed = ['.png', '.jpg', '.jpeg', '.jfif', '.gif', '.webp', '.avif', '.bmp'];
        if (!allowed.includes(ext)) return sendJSON(res, 400, { success: false, message: 'Invalid description image' });
        if (files.descriptionImage.data.length > 20 * 1024 * 1024) return sendJSON(res, 400, { success: false, message: 'Image max 20MB' });
        const filename = 'proddesc-' + crypto.randomUUID().slice(0, 8) + ext;
        fs.writeFileSync(path.join(UPLOADS_DIR, filename), files.descriptionImage.data);
        pr.descriptionImage = '/uploads/' + filename;
      }
      // Advanced fields
      if (fields.stock !== undefined) {
        if (fields.stock === '' || fields.stock === null) pr.stock = null;
        else {
          const n = parseInt(fields.stock, 10);
          pr.stock = (!isNaN(n) && n >= 0) ? n : pr.stock;
        }
      }
      if (fields.lowStockAlert !== undefined) {
        if (fields.lowStockAlert === '' || fields.lowStockAlert === null) pr.lowStockAlert = null;
        else {
          const n = parseInt(fields.lowStockAlert, 10);
          pr.lowStockAlert = (!isNaN(n) && n >= 0) ? n : pr.lowStockAlert;
        }
      }
      if (fields.featured !== undefined) {
        pr.featured = (fields.featured === true || fields.featured === 'true' || fields.featured === '1');
      }
      if (fields.tags !== undefined) {
        let tags = [];
        try {
          if (typeof fields.tags === 'string' && fields.tags.trim()) tags = JSON.parse(fields.tags);
          else if (Array.isArray(fields.tags)) tags = fields.tags;
        } catch (_) {}
        pr.tags = (tags || []).map(t => String(t).trim()).filter(Boolean).slice(0, 20);
      }
      if (fields.variants !== undefined) {
        let variants = [];
        try {
          if (typeof fields.variants === 'string' && fields.variants.trim()) variants = JSON.parse(fields.variants);
          else if (Array.isArray(fields.variants)) variants = fields.variants;
        } catch (_) {}
        pr.variants = (variants || []).slice(0, 30).map(v => ({
          name: String(v.name || '').trim(),
          price: parseFloat(v.price) || pr.price,
          commands: Array.isArray(v.commands) ? v.commands.slice(0, 20) : [],
          stock: (v.stock !== undefined && v.stock !== '' && v.stock !== null) ? parseInt(v.stock, 10) : null
        })).filter(v => v.name);
      }
      if (fields.publishAt !== undefined) pr.publishAt = (fields.publishAt || '').trim() || null;
      if (fields.unpublishAt !== undefined) pr.unpublishAt = (fields.unpublishAt || '').trim() || null;
      if (fields.order !== undefined) {
        const o = parseInt(fields.order, 10);
        if (!isNaN(o)) pr.order = o;
      }
      if (fields.description !== undefined) pr.description = String(fields.description || '');
      saveDB(db);
      return sendJSON(res, 200, { success: true, product: pr });
    } catch (e) {
      console.error(e);
      return sendJSON(res, 500, { success: false, message: 'Failed to update' });
    }
  }

  // DELETE /api/admin/products/:id
  if (pathname.startsWith('/api/admin/products/') && method === 'DELETE') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const id = pathname.split('/').pop();
    const db = loadDB();
    if (!db.products) db.products = [];
    const before = db.products.length;
    db.products = db.products.filter(x => x.id !== id);
    if (db.products.length === before) return sendJSON(res, 404, { success: false, message: 'Not found' });
    saveDB(db);
    return sendJSON(res, 200, { success: true, message: 'Deleted' });
  }

  // GET /api/categories/:id  public single category
  if (pathname.startsWith('/api/categories/') && method === 'GET' && !pathname.startsWith('/api/admin/')) {
    const id = decodeURIComponent(pathname.split('/').pop());
    const db = loadDB();
    if (!db.categories) db.categories = [];
    const c = db.categories.find(x => x.id === id);
    if (!c || c.enabled === false) return sendJSON(res, 404, { success: false, message: 'Category not found' });
    return sendJSON(res, 200, {
      success: true,
      category: { id: c.id, name: c.name, description: c.description || '', logo: c.logo || '', pageId: c.pageId || null, enabled: c.enabled !== false }
    });
  }


  // ---------- Coupons ----------
  // GET /api/admin/coupons
  if (pathname === '/api/admin/coupons' && method === 'GET') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const db = loadDB();
    if (!db.coupons) db.coupons = [];
    return sendJSON(res, 200, { success: true, coupons: db.coupons.slice().sort((a,b) => String(b.createdAt||'').localeCompare(String(a.createdAt||''))) });
  }

  // POST /api/admin/coupons
  if (pathname === '/api/admin/coupons' && method === 'POST') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    try {
      const body = JSON.parse((await readBody(req)).toString());
      const code = String(body.code || '').trim().toUpperCase().replace(/\s+/g, '');
      if (!code || code.length < 2) return sendJSON(res, 400, { success: false, message: 'Coupon code required' });
      const db = loadDB();
      if (!db.coupons) db.coupons = [];
      if (db.coupons.some(c => c.code === code)) return sendJSON(res, 400, { success: false, message: 'Code already exists' });
      const type = body.type === 'fixed' ? 'fixed' : 'percent';
      const value = parseFloat(body.value);
      if (isNaN(value) || value <= 0) return sendJSON(res, 400, { success: false, message: 'Valid discount value required' });
      if (type === 'percent' && value > 100) return sendJSON(res, 400, { success: false, message: 'Percent max 100' });
      let productIds = [];
      if (Array.isArray(body.productIds)) productIds = body.productIds.map(String);
      else if (typeof body.productIds === 'string' && body.productIds.trim()) {
        try { productIds = JSON.parse(body.productIds); } catch { productIds = body.productIds.split(',').map(s => s.trim()).filter(Boolean); }
      }
      const scope = body.scope === 'products' ? 'products' : 'all';
      if (scope === 'products' && !productIds.length) return sendJSON(res, 400, { success: false, message: 'Select at least one product' });
      const item = {
        id: crypto.randomUUID(),
        code,
        type,
        value,
        scope,
        productIds: scope === 'products' ? productIds : [],
        minOrder: parseFloat(body.minOrder) || 0,
        maxUses: body.maxUses === '' || body.maxUses == null ? null : parseInt(body.maxUses, 10),
        usedCount: 0,
        enabled: body.enabled !== false && body.enabled !== 'false',
        expiresAt: body.expiresAt ? String(body.expiresAt) : null,
        note: String(body.note || '').trim(),
        kind: body.kind === 'referral' ? 'referral' : 'coupon',
        createdAt: new Date().toISOString()
      };
      db.coupons.push(item);
      saveDB(db);
      return sendJSON(res, 200, { success: true, coupon: item });
    } catch (e) {
      console.error(e);
      return sendJSON(res, 500, { success: false, message: 'Failed' });
    }
  }

  // PUT /api/admin/coupons/:id
  if (pathname.startsWith('/api/admin/coupons/') && method === 'PUT') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    try {
      const id = pathname.split('/').pop();
      const body = JSON.parse((await readBody(req)).toString());
      const db = loadDB();
      if (!db.coupons) db.coupons = [];
      const c = db.coupons.find(x => x.id === id);
      if (!c) return sendJSON(res, 404, { success: false, message: 'Not found' });
      if (body.code !== undefined) {
        const code = String(body.code).trim().toUpperCase().replace(/\s+/g, '');
        if (code && db.coupons.some(x => x.code === code && x.id !== id)) return sendJSON(res, 400, { success: false, message: 'Code exists' });
        if (code) c.code = code;
      }
      if (body.type !== undefined) c.type = body.type === 'fixed' ? 'fixed' : 'percent';
      if (body.value !== undefined) c.value = parseFloat(body.value) || c.value;
      if (body.scope !== undefined) c.scope = body.scope === 'products' ? 'products' : 'all';
      if (body.productIds !== undefined) {
        let productIds = body.productIds;
        if (typeof productIds === 'string') {
          try { productIds = JSON.parse(productIds); } catch { productIds = productIds.split(',').map(s => s.trim()).filter(Boolean); }
        }
        c.productIds = Array.isArray(productIds) ? productIds.map(String) : [];
      }
      if (body.minOrder !== undefined) c.minOrder = parseFloat(body.minOrder) || 0;
      if (body.maxUses !== undefined) c.maxUses = body.maxUses === '' || body.maxUses == null ? null : parseInt(body.maxUses, 10);
      if (body.enabled !== undefined) c.enabled = body.enabled === true || body.enabled === 'true';
      if (body.expiresAt !== undefined) c.expiresAt = body.expiresAt ? String(body.expiresAt) : null;
      if (body.note !== undefined) c.note = String(body.note || '').trim();
      saveDB(db);
      return sendJSON(res, 200, { success: true, coupon: c });
    } catch (e) {
      return sendJSON(res, 500, { success: false, message: 'Failed' });
    }
  }

  // DELETE /api/admin/coupons/:id
  if (pathname.startsWith('/api/admin/coupons/') && method === 'DELETE') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const id = pathname.split('/').pop();
    const db = loadDB();
    if (!db.coupons) db.coupons = [];
    const before = db.coupons.length;
    db.coupons = db.coupons.filter(c => c.id !== id);
    if (db.coupons.length === before) return sendJSON(res, 404, { success: false, message: 'Not found' });
    saveDB(db);
    return sendJSON(res, 200, { success: true });
  }

  // POST /api/validate-coupon  { code, items: [{productId, qty}] }
  if (pathname === '/api/validate-coupon' && method === 'POST') {
    try {
      const body = JSON.parse((await readBody(req)).toString());
      const code = String(body.code || '').trim().toUpperCase();
      if (!code) return sendJSON(res, 400, { success: false, message: 'Code required' });
      const db = loadDB();
      if (!db.coupons) db.coupons = [];
      if (!db.products) db.products = [];
      let coupon = db.coupons.find(c => c.code === code && c.enabled !== false);
      // Referral link code: user referralCode works as percent from settings
      let isReferral = false;
      let referrer = null;
      if (!coupon) {
        referrer = db.users.find(u => (u.referralCode || '').toUpperCase() === code || (u.mcUsername || '').toUpperCase() === code);
        if (referrer) {
          const pct = parseFloat(db.settings.referralDiscountPercent) || 5;
          if (db.settings.referralEnabled === false) {
            return sendJSON(res, 400, { success: false, message: 'Referral discounts disabled' });
          }
          coupon = {
            id: 'ref-' + referrer.id,
            code,
            type: 'percent',
            value: pct,
            scope: 'all',
            productIds: [],
            minOrder: parseFloat(db.settings.referralMinOrder) || 0,
            maxUses: null,
            usedCount: 0,
            enabled: true,
            kind: 'referral'
          };
          isReferral = true;
        }
      }
      if (!coupon) return sendJSON(res, 404, { success: false, message: 'Invalid coupon / referral code' });
      const items = Array.isArray(body.items) ? body.items : [];
      const cartLines = [];
      let subtotal = 0;
      for (const it of items) {
        const pr = db.products.find(x => x.id === it.productId);
        if (!pr || pr.enabled === false) continue;
        const qty = Math.max(1, Math.min(99, parseInt(it.qty, 10) || 1));
        const lineTotal = (pr.price || 0) * qty;
        subtotal += lineTotal;
        cartLines.push({ productId: pr.id, lineTotal });
      }
      const result = calcCouponDiscount(coupon, cartLines);
      if (result.reason) return sendJSON(res, 400, { success: false, message: result.reason });
      return sendJSON(res, 200, {
        success: true,
        discount: result.discount,
        subtotal,
        total: Math.max(0, Math.round((subtotal - result.discount) * 100) / 100),
        code: coupon.code,
        type: coupon.type,
        value: coupon.value,
        kind: coupon.kind || 'coupon',
        message: isReferral ? ('Referral applied: ' + coupon.value + '% off') : ('Coupon applied: ' + (coupon.type === 'percent' ? coupon.value + '%' : '₹' + coupon.value) + ' off')
      });
    } catch (e) {
      console.error(e);
      return sendJSON(res, 500, { success: false, message: 'Failed' });
    }
  }

  // POST /api/checkout  multipart or JSON: items, payerUpi, proof (file)
  // Creates pending payment — commands run only after admin approve
  if (pathname === '/api/checkout' && method === 'POST') {
    if (!user) return sendJSON(res, 401, { success: false, message: 'Login required' });
    try {
      const contentType = req.headers['content-type'] || '';
      let fields = {};
      let files = {};
      if (contentType.includes('multipart/form-data')) {
        const boundary = contentType.split('boundary=')[1];
        const buffer = await readBody(req);
        const parsed = parseMultipart(buffer, boundary);
        fields = parsed.fields;
        files = parsed.files;
      } else {
        fields = JSON.parse((await readBody(req)).toString());
      }
      let items = [];
      try {
        items = typeof fields.items === 'string' ? JSON.parse(fields.items) : (fields.items || []);
      } catch (_) { items = []; }
      if (!Array.isArray(items) || !items.length) return sendJSON(res, 400, { success: false, message: 'Cart is empty' });
      const payerUpi = String(fields.payerUpi || '').trim();
      if (!payerUpi) return sendJSON(res, 400, { success: false, message: 'UPI ID used for payment is required' });

      let proofPath = '';
      if (files.proof && files.proof.data && files.proof.data.length > 0) {
        const ext = path.extname(files.proof.filename).toLowerCase() || '.png';
        const allowed = ['.png', '.jpg', '.jpeg', '.jfif', '.gif', '.webp', '.avif', '.bmp'];
        if (!allowed.includes(ext)) return sendJSON(res, 400, { success: false, message: 'Proof must be image' });
        if (files.proof.data.length > 20 * 1024 * 1024) return sendJSON(res, 400, { success: false, message: 'Proof max 20MB' });
        const filename = 'proof-' + crypto.randomUUID().slice(0, 8) + ext;
        fs.writeFileSync(path.join(UPLOADS_DIR, filename), files.proof.data);
        proofPath = '/uploads/' + filename;
      } else {
        return sendJSON(res, 400, { success: false, message: 'Payment proof screenshot required' });
      }

      const db = loadDB();
      if (!db.products) db.products = [];
      if (!db.payments) db.payments = [];

      const playerName = user.mcUsername || user.email || 'Player';
      const purchased = [];
      let subtotal = 0;
      const cartLines = [];
      for (const it of items) {
        const productId = it.productId;
        const qty = Math.max(1, Math.min(99, parseInt(it.qty, 10) || 1));
        const pr = db.products.find(x => x.id === productId);
        if (!pr) return sendJSON(res, 400, { success: false, message: 'Product not found' });
        const line = (pr.price || 0) * qty;
        subtotal += line;
        cartLines.push({ productId: pr.id, lineTotal: line });
        purchased.push({
          productId: pr.id,
          name: pr.name,
          price: pr.price,
          qty,
          image: pr.image || '',
          commands: pr.commands || [],
          connectorId: pr.connectorId || null
        });
      }

      let discount = 0;
      let couponCode = String(fields.couponCode || '').trim().toUpperCase();
      let couponMeta = null;
      if (couponCode) {
        if (!db.coupons) db.coupons = [];
        let coupon = db.coupons.find(c => c.code === couponCode && c.enabled !== false);
        let isReferral = false;
        if (!coupon) {
          const referrer = db.users.find(u => (u.referralCode || '').toUpperCase() === couponCode || (u.mcUsername || '').toUpperCase() === couponCode);
          if (referrer && referrer.id !== user.id) {
            if (db.settings.referralEnabled !== false) {
              coupon = {
                id: 'ref-' + referrer.id,
                code: couponCode,
                type: 'percent',
                value: parseFloat(db.settings.referralDiscountPercent) || 5,
                scope: 'all',
                productIds: [],
                minOrder: parseFloat(db.settings.referralMinOrder) || 0,
                maxUses: null,
                usedCount: 0,
                enabled: true,
                kind: 'referral'
              };
              isReferral = true;
            }
          }
        }
        if (!coupon) return sendJSON(res, 400, { success: false, message: 'Invalid coupon / referral code' });
        if (coupon.kind !== 'referral' && coupon.maxUses != null && coupon.maxUses > 0 && (coupon.usedCount || 0) >= coupon.maxUses) {
          return sendJSON(res, 400, { success: false, message: 'Coupon usage limit reached' });
        }
        const result = calcCouponDiscount(coupon, cartLines);
        if (result.reason) return sendJSON(res, 400, { success: false, message: result.reason });
        discount = result.discount;
        couponMeta = { code: coupon.code, type: coupon.type, value: coupon.value, kind: coupon.kind || 'coupon', discount };
        if (!isReferral && coupon.id && !String(coupon.id).startsWith('ref-')) {
          const real = db.coupons.find(c => c.id === coupon.id);
          if (real) real.usedCount = (real.usedCount || 0) + 1;
        }
      }

      // Site-wide sale discount
      let saleMeta = null;
      if (db.settings.saleEnabled && (parseFloat(db.settings.saleDiscountPercent) || 0) > 0) {
        const sp = parseFloat(db.settings.saleDiscountPercent) || 0;
        const afterCoupon = Math.max(0, subtotal - discount);
        const saleDisc = Math.round(afterCoupon * sp / 100 * 100) / 100;
        if (saleDisc > 0) {
          discount += saleDisc;
          saleMeta = { percent: sp, discount: saleDisc, title: db.settings.saleTitle || 'Sale' };
        }
      }
      // New-user first-order discount
      let newUserMeta = null;
      const uFull = db.users.find(x => x.id === user.id);
      const orderCount = (uFull && uFull.orderCount) || 0;
      if (db.settings.newUserEnabled && (parseFloat(db.settings.newUserPercent) || 0) > 0 && orderCount === 0) {
        const np = parseFloat(db.settings.newUserPercent) || 0;
        const after = Math.max(0, subtotal - discount);
        const nuDisc = Math.round(after * np / 100 * 100) / 100;
        if (nuDisc > 0) {
          discount += nuDisc;
          newUserMeta = { percent: np, discount: nuDisc };
        }
      }

      const total = Math.max(0, Math.round((subtotal - discount) * 100) / 100);

      const payment = {
        id: crypto.randomUUID(),
        userId: user.id,
        mcUsername: playerName,
        email: user.email,
        items: purchased,
        subtotal,
        discount,
        coupon: couponMeta,
        sale: saleMeta,
        newUserDiscount: newUserMeta,
        total,
        payerUpi,
        proof: proofPath,
        status: 'pending',
        createdAt: new Date().toISOString(),
        reviewedAt: null,
        reviewedBy: null
      };
      db.payments.push(payment);
      saveDB(db);
      return sendJSON(res, 200, {
        success: true,
        message: 'Payment submitted. Waiting for admin approval.',
        payment: { id: payment.id, status: payment.status, total: payment.total }
      });
    } catch (e) {
      console.error(e);
      return sendJSON(res, 500, { success: false, message: 'Checkout failed' });
    }
  }

  // GET /api/my-payments  — member orders/status
  if (pathname === '/api/my-payments' && method === 'GET') {
    if (!user) return sendJSON(res, 401, { success: false, message: 'Login required' });
    const db = loadDB();
    if (!db.payments) db.payments = [];
    const list = db.payments
      .filter(p => p.userId === user.id)
      .slice()
      .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
      .map(p => ({
        id: p.id,
        items: p.items,
        total: p.total,
        status: p.status,
        payerUpi: p.payerUpi,
        proof: p.proof,
        createdAt: p.createdAt,
        reviewedAt: p.reviewedAt
      }));
    return sendJSON(res, 200, { success: true, payments: list });
  }

  // GET /api/admin/payments
  if (pathname === '/api/admin/payments' && method === 'GET') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const db = loadDB();
    if (!db.payments) db.payments = [];
    const list = db.payments.slice().sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
    return sendJSON(res, 200, { success: true, payments: list });
  }

  // POST /api/admin/payments/:id/approve
  if (pathname.match(/^\/api\/admin\/payments\/[^/]+\/approve$/) && method === 'POST') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    try {
      const id = pathname.split('/')[4];
      const db = loadDB();
      if (!db.payments) db.payments = [];
      if (!db.products) db.products = [];
      if (!db.sales) db.sales = [];
      if (!db.connectors) db.connectors = [];
      const pay = db.payments.find(x => x.id === id);
      if (!pay) return sendJSON(res, 404, { success: false, message: 'Not found' });
      if (pay.status === 'approved') return sendJSON(res, 400, { success: false, message: 'Already approved' });
      pay.status = 'approved';
      pay.reviewedAt = new Date().toISOString();
      pay.reviewedBy = user.id;
      const buyer = db.users.find(x => x.id === pay.userId);
      if (buyer) buyer.orderCount = (buyer.orderCount || 0) + 1;

      const playerName = pay.mcUsername || 'Player';
      let commandsQueued = 0;
      const now = Date.now();
      const isOnline = (c) => c.lastSeen && (now - new Date(c.lastSeen).getTime()) < 120000;

      if (!db.globalPendingCommands) db.globalPendingCommands = [];
      (pay.items || []).forEach(it => {
        const qty = it.qty || 1;
        const pr = db.products.find(x => x.id === it.productId);
        if (pr) pr.salesCount = (pr.salesCount || 0) + qty;
        const cmds = [];
        for (let i = 0; i < qty; i++) {
          (it.commands || (pr && pr.commands) || []).forEach(cmd => {
            cmds.push(normalizeCommand(replacePlayerPlaceholders(cmd, playerName)));
          });
        }
        const preferredId = it.connectorId || (pr && pr.connectorId) || null;
        let target = preferredId ? db.connectors.find(x => x.id === preferredId) : null;
        // Prefer online, else any connector, else global queue (delivered when ANY server connects)
        if (!target) {
          const online = db.connectors.filter(isOnline);
          target = online[0] || db.connectors[0] || null;
        }
        if (cmds.length) {
          if (target) {
            if (!Array.isArray(target.pendingCommands)) target.pendingCommands = [];
            cmds.forEach(command => {
              if (!command) return;
              target.pendingCommands.push({
                id: crypto.randomUUID(),
                command,
                paymentId: pay.id,
                player: playerName,
                createdAt: new Date().toISOString()
              });
            });
            commandsQueued += cmds.length;
          } else {
            // No connector yet — store globally; delivered on first heartbeat from any future connector
            cmds.forEach(command => {
              if (!command) return;
              db.globalPendingCommands.push({
                id: crypto.randomUUID(),
                command,
                paymentId: pay.id,
                player: playerName,
                createdAt: new Date().toISOString()
              });
            });
            commandsQueued += cmds.length;
          }
        }
        db.sales.push({
          id: crypto.randomUUID(),
          product: it.name,
          productId: it.productId,
          amount: (it.price || 0) * qty,
          qty,
          userId: pay.userId,
          mcUsername: playerName,
          paymentId: pay.id,
          connectorId: target ? target.id : null,
          createdAt: new Date().toISOString()
        });
      });
      pay.commandsQueued = commandsQueued;
      pay.deliveredAt = null;

      saveDB(db);
      return sendJSON(res, 200, { success: true, message: 'Approved. Commands queued.', commandsQueued });
    } catch (e) {
      console.error(e);
      return sendJSON(res, 500, { success: false, message: 'Approve failed' });
    }
  }

  // POST /api/admin/payments/:id/reject
  if (pathname.match(/^\/api\/admin\/payments\/[^/]+\/reject$/) && method === 'POST') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const id = pathname.split('/')[4];
    const db = loadDB();
    if (!db.payments) db.payments = [];
    const pay = db.payments.find(x => x.id === id);
    if (!pay) return sendJSON(res, 404, { success: false, message: 'Not found' });
    pay.status = 'rejected';
    pay.reviewedAt = new Date().toISOString();
    pay.reviewedBy = user.id;
    saveDB(db);
    return sendJSON(res, 200, { success: true, message: 'Rejected' });
  }

  // DELETE /api/admin/payments/:id
  if (pathname.startsWith('/api/admin/payments/') && method === 'DELETE') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const id = pathname.split('/').pop();
    const db = loadDB();
    if (!db.payments) db.payments = [];
    const before = db.payments.length;
    db.payments = db.payments.filter(x => x.id !== id);
    if (db.payments.length === before) return sendJSON(res, 404, { success: false, message: 'Not found' });
    saveDB(db);
    return sendJSON(res, 200, { success: true, message: 'Deleted' });
  }

  // GET /api/admin/plugin-download — SimpleConnectorStore.jar with api-url auto-filled
  if (pathname === '/api/admin/plugin-download' && method === 'GET') {
    if (!user || user.role !== 'admin') return sendJSON(res, 403, { success: false, message: 'Admin only' });
    const pluginJar = path.join(__dirname, 'plugin', 'SimpleConnectorStore.jar');
    if (!fs.existsSync(pluginJar)) {
      return sendJSON(res, 404, { success: false, message: 'Plugin package not found' });
    }
    // Build public base URL from request (so user never types website URL)
    const proto = (req.headers['x-forwarded-proto'] || 'http').split(',')[0].trim();
    const host = (req.headers['x-forwarded-host'] || req.headers.host || 'localhost:3000').split(',')[0].trim();
    const baseUrl = proto + '://' + host;
    const configYml = [
      '# Simple Connector Store — api-url auto-filled from your website',
      'api-url: "' + baseUrl + '"',
      'connect-code: "SC-XXXX-XXXX-XXXX"',
      'heartbeat-seconds: 15',
      ''
    ].join('\n');
    try {
      const AdmZip = null; // pure node: use zlib + manual zip is hard; rewrite via child process unzip/zip
    } catch (_) {}
    // Use system zip tools to inject config.yml
    const os = require('os');
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scs-'));
    const tmpJar = path.join(tmpDir, 'SimpleConnectorStore.jar');
    fs.copyFileSync(pluginJar, tmpJar);
    const cfgPath = path.join(tmpDir, 'config.yml');
    fs.writeFileSync(cfgPath, configYml);
    const { execSync } = require('child_process');
    try {
      // jar is zip — update config.yml inside
      execSync('cd "' + tmpDir + '" && jar uf SimpleConnectorStore.jar config.yml', { stdio: 'ignore' });
    } catch (e1) {
      try {
        execSync('cd "' + tmpDir + '" && zip -q SimpleConnectorStore.jar config.yml', { stdio: 'ignore' });
      } catch (e2) {
        // fallback: serve original
        const data = fs.readFileSync(pluginJar);
        res.writeHead(200, {
          'Content-Type': 'application/java-archive',
          'Content-Disposition': 'attachment; filename="SimpleConnectorStore.jar"',
          'Content-Length': data.length
        });
        return res.end(data);
      }
    }
    const data = fs.readFileSync(tmpJar);
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
    res.writeHead(200, {
      'Content-Type': 'application/java-archive',
      'Content-Disposition': 'attachment; filename="SimpleConnectorStore.jar"',
      'Content-Length': data.length
    });
    return res.end(data);
  }


  return sendJSON(res, 404, { success: false, message: 'API not found' });
}

// ---------- Static files + routing ----------
function serveStatic(req, res, pathname) {
  let filePath = pathname;
  if (filePath === '/' || filePath.endsWith('/')) {
    filePath = filePath + 'index.html';
  }
  // security
  filePath = path.normalize(filePath).replace(/^(\.\.[\/\\])+/, '');
  let fullPath = path.join(PUBLIC_DIR, filePath);

  if (!fullPath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  // If path is a directory without trailing slash, try index.html
  if (fs.existsSync(fullPath) && fs.statSync(fullPath).isDirectory()) {
    fullPath = path.join(fullPath, 'index.html');
  }

  fs.readFile(fullPath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/html' });
      return res.end('<h1>404 - Page not found</h1><a href="/">Home</a>');
    }
    const ext = path.extname(fullPath).toLowerCase();
    const headers = { 'Content-Type': getMime(ext) };
    if (['.png','.jpg','.jpeg','.jfif','.gif','.webp','.avif','.bmp','.svg','.ico','.css','.js','.woff','.woff2'].includes(ext)) {
      headers['Cache-Control'] = 'public, max-age=86400';
    }
    res.writeHead(200, headers);
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const parsed = new URL(req.url, `http://${req.headers.host}`);
    const pathname = parsed.pathname;

    if (pathname === '/favicon.ico') {
      const db = loadDB();
      const fav = (db.settings.favicon || db.settings.logo || '').split('?')[0];
      if (fav) {
        const full = path.join(PUBLIC_DIR, fav);
        if (fs.existsSync(full)) {
          res.writeHead(200, { 'Content-Type': getMime(path.extname(full).toLowerCase()), 'Cache-Control': 'no-cache' });
          return res.end(fs.readFileSync(full));
        }
      }
      res.writeHead(204);
      return res.end();
    }
    if (pathname.startsWith('/api/')) {
      return await handleAPI(req, res, pathname);
    }
    return serveStatic(req, res, pathname);
  } catch (e) {
    console.error(e);
    res.writeHead(500);
    res.end('Internal Server Error');
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅ Minecraft Server Website running at http://localhost:${PORT}`);
  console.log(`   Home:     http://localhost:${PORT}/`);
  console.log(`   Register: http://localhost:${PORT}/register.html`);
  console.log(`   Login:    http://localhost:${PORT}/login.html`);
  console.log(`   Admin:    http://localhost:${PORT}/admin/\n`);
});
