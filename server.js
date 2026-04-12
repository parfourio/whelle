require('dotenv').config();
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const auth = require('./auth-routes');

const PORT = process.env.PORT || 3000;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';
const ADMIN_PASSWORD_PLAIN = process.env.ADMIN_PASSWORD || '';
function checkAdminPassword(input) {
  if (ADMIN_PASSWORD_HASH) return auth.verifyPassword(input, ADMIN_PASSWORD_HASH);
  return input === ADMIN_PASSWORD_PLAIN;
}

// ── Session store ─────────────────────────────────────────────
const sessions = new Map();

function createSession(data) {
  const id = crypto.randomBytes(32).toString('hex');
  sessions.set(id, { ...data, expires: Date.now() + 1000 * 60 * 60 * 8 });
  return id;
}

function getSession(req) {
  const m = (req.headers.cookie || '').match(/whelle_session=([a-f0-9]+)/);
  if (!m) return null;
  const s = sessions.get(m[1]);
  if (!s) return null;
  if (Date.now() > s.expires) { sessions.delete(m[1]); return null; }
  return s;
}

function getAdminSession(req) {
  const m = (req.headers.cookie || '').match(/whelle_admin=([a-f0-9]+)/);
  if (!m) return null;
  const s = sessions.get(m[1]);
  if (!s || s.role !== 'admin') return null;
  if (Date.now() > s.expires) { sessions.delete(m[1]); return null; }
  return s;
}

function getSessionId(req) {
  const m = (req.headers.cookie || '').match(/whelle_session=([a-f0-9]+)/);
  return m ? m[1] : null;
}

// ── Body parser (JSON + form) ─────────────────────────────────
function parseBody(req) {
  return new Promise(r => {
    let b = '';
    req.on('data', c => b += c);
    req.on('end', () => {
      const ct = req.headers['content-type'] || '';
      if (ct.includes('application/json')) {
        try { r(JSON.parse(b)); } catch(e) { r({}); }
        return;
      }
      const p = {};
      b.split('&').forEach(pair => {
        const [k, v] = pair.split('=');
        if (k) p[decodeURIComponent(k)] = decodeURIComponent((v || '').replace(/\+/g, ' '));
      });
      r(p);
    });
  });
}

// ── Serve static HTML file ────────────────────────────────────
function serveFile(res, filePath) {
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    const ext = path.extname(filePath);
    const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.jpg': 'image/jpeg' };
    res.writeHead(200, { 'Content-Type': types[ext] || 'text/plain' });
    res.end(data);
  });
}

// ── Server ────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  const session = getSession(req);
  const adminSession = getAdminSession(req);

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // ── Admin login ────────────────────────────────────────────
  if (url === '/admin/login' && req.method === 'POST') {
    const body = await parseBody(req);
    if (body.username === ADMIN_USERNAME && checkAdminPassword(body.password)) {
      const id = createSession({ role: 'admin' });
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': `whelle_admin=${id}; HttpOnly; Path=/; Max-Age=28800`
      });
      res.end(JSON.stringify({ success: true }));
    } else {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid credentials' }));
    }
    return;
  }

  // ── Logout ─────────────────────────────────────────────────
  if (url === '/logout') {
    const sid = getSessionId(req);
    if (sid) sessions.delete(sid);
    res.writeHead(302, {
      'Set-Cookie': 'whelle_session=; HttpOnly; Path=/; Max-Age=0',
      'Location': '/'
    });
    res.end();
    return;
  }

  if (url === '/admin/logout') {
    const m = (req.headers.cookie || '').match(/whelle_admin=([a-f0-9]+)/);
    if (m) sessions.delete(m[1]);
    res.writeHead(302, {
      'Set-Cookie': 'whelle_admin=; HttpOnly; Path=/; Max-Age=0',
      'Location': '/admin'
    });
    res.end();
    return;
  }

  // ── Public pages ───────────────────────────────────────────
  if (url === '/' || url === '/index.html') { serveFile(res, path.join(__dirname, 'index.html')); return; }
  if (url === '/provider-login' || url === '/provider-login.html') { serveFile(res, path.join(__dirname, 'provider-login.html')); return; }
  if (url === '/member-login' || url === '/member-login.html') { serveFile(res, path.join(__dirname, 'member-login.html')); return; }

  // ── Protected: provider dashboard ─────────────────────────
  if (url === '/provider-dashboard' || url === '/provider-dashboard.html') {
    if (!session || session.role !== 'provider') {
      res.writeHead(302, { 'Location': '/provider-login' }); res.end(); return;
    }
    serveFile(res, path.join(__dirname, 'provider-dashboard.html'));
    return;
  }

  // ── Protected: member dashboard ───────────────────────────
  if (url === '/member-dashboard' || url === '/member-dashboard.html') {
    if (!session || session.role !== 'member') {
      res.writeHead(302, { 'Location': '/member-login' }); res.end(); return;
    }
    serveFile(res, path.join(__dirname, 'member-dashboard.html'));
    return;
  }

  // ── Protected: admin panel ────────────────────────────────
  if (url === '/admin' || url === '/admin.html') {
    serveFile(res, path.join(__dirname, 'admin.html'));
    return;
  }

  // ── Public provider profile page ──────────────────────────
  if (url.startsWith('/provider/')) {
    serveFile(res, path.join(__dirname, 'provider-profile.html'));
    return;
  }

  // ── PROVIDER API ───────────────────────────────────────────
  if (url === '/api/provider/signup' && req.method === 'POST') {
    await auth.handleProviderSignup(req, res, parseBody); return;
  }
  if (url === '/api/provider/login' && req.method === 'POST') {
    await auth.handleProviderLogin(req, res, parseBody, createSession); return;
  }
  if (url === '/api/provider/me' && req.method === 'GET') {
    if (!session || session.role !== 'provider') { res.writeHead(401, {'Content-Type':'application/json'}); res.end(JSON.stringify({error:'Unauthorized'})); return; }
    await auth.handleGetProvider(req, res, session); return;
  }
  if (url === '/api/provider/me' && req.method === 'PUT') {
    if (!session || session.role !== 'provider') { res.writeHead(401, {'Content-Type':'application/json'}); res.end(JSON.stringify({error:'Unauthorized'})); return; }
    await auth.handleUpdateProvider(req, res, session, parseBody); return;
  }
  if (url === '/api/provider/password' && req.method === 'PUT') {
    if (!session || session.role !== 'provider') { res.writeHead(401, {'Content-Type':'application/json'}); res.end(JSON.stringify({error:'Unauthorized'})); return; }
    await auth.handleProviderChangePassword(req, res, session, parseBody); return;
  }

  // ── MEMBER API ─────────────────────────────────────────────
  if (url === '/api/member/signup' && req.method === 'POST') {
    await auth.handleMemberSignup(req, res, parseBody); return;
  }
  if (url === '/api/member/login' && req.method === 'POST') {
    await auth.handleMemberLogin(req, res, parseBody, createSession); return;
  }
  if (url === '/api/member/me' && req.method === 'GET') {
    if (!session || session.role !== 'member') { res.writeHead(401, {'Content-Type':'application/json'}); res.end(JSON.stringify({error:'Unauthorized'})); return; }
    await auth.handleGetMember(req, res, session); return;
  }
  if (url === '/api/member/me' && req.method === 'PUT') {
    if (!session || session.role !== 'member') { res.writeHead(401, {'Content-Type':'application/json'}); res.end(JSON.stringify({error:'Unauthorized'})); return; }
    await auth.handleUpdateMember(req, res, session, parseBody); return;
  }

  // ── ADMIN API ──────────────────────────────────────────────
  if (url === '/api/admin/login' && req.method === 'POST') {
    const body = await parseBody(req);
    if (body.username === ADMIN_USERNAME && checkAdminPassword(body.password)) {
      const id = createSession({ role: 'admin' });
      res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': `whelle_admin=${id}; HttpOnly; Path=/; Max-Age=28800` });
      res.end(JSON.stringify({ success: true }));
    } else {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid credentials' }));
    }
    return;
  }
  if (url === '/api/admin/providers' && req.method === 'GET') {
    if (!adminSession) { res.writeHead(401, {'Content-Type':'application/json'}); res.end(JSON.stringify({error:'Unauthorized'})); return; }
    await auth.handleAdminGetProviders(req, res); return;
  }
  if (url === '/api/admin/members' && req.method === 'GET') {
    if (!adminSession) { res.writeHead(401, {'Content-Type':'application/json'}); res.end(JSON.stringify({error:'Unauthorized'})); return; }
    await auth.handleAdminGetMembers(req, res); return;
  }
  if (url.startsWith('/api/admin/providers/') && req.method === 'PUT') {
    if (!adminSession) { res.writeHead(401, {'Content-Type':'application/json'}); res.end(JSON.stringify({error:'Unauthorized'})); return; }
    const id = url.split('/')[4];
    await auth.handleAdminUpdateProvider(req, res, id, parseBody); return;
  }
  if (url.startsWith('/api/admin/members/') && req.method === 'PUT') {
    if (!adminSession) { res.writeHead(401, {'Content-Type':'application/json'}); res.end(JSON.stringify({error:'Unauthorized'})); return; }
    const id = url.split('/')[4];
    await auth.handleAdminUpdateMember(req, res, id, parseBody); return;
  }

  // ── Public provider profile API ────────────────────────────
  if (url.startsWith('/api/provider/profile/') && req.method === 'GET') {
    const slug = url.split('/')[4];
    await auth.handlePublicProvider(req, res, slug); return;
  }

  // ── Static fallback ────────────────────────────────────────
  const filePath = path.join(__dirname, url === '/' ? 'index.html' : url);
  serveFile(res, filePath);
});

server.listen(PORT, () => {
  console.log(`\nWhelle live on http://localhost:${PORT}`);
  console.log(`Admin: /admin (${ADMIN_USERNAME})`);
});
