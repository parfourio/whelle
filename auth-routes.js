/**
 * auth-routes.js - Whelle auth + profile API handlers
 * Providers, Members, Admin
 */

const https = require('https');
const crypto = require('crypto');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;

// ── Password helpers ──────────────────────────────────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  try {
    const [salt, hash] = stored.split(':');
    const v = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return hash === v;
  } catch(e) { return false; }
}
function slugify(str) {
  return str.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

// ── Supabase REST helper ──────────────────────────────────────
function supabase(method, path, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(`${SUPABASE_URL}/rest/v1/${path}`);
    const data = body ? JSON.stringify(body) : null;
    const options = {
      hostname: url.hostname,
      path: url.pathname + url.search,
      method,
      headers: {
        'apikey': SUPABASE_KEY,
        'Authorization': `Bearer ${SUPABASE_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=representation',
      }
    };
    if (data) options.headers['Content-Length'] = Buffer.byteLength(data);
    const req = https.request(options, res => {
      let b = '';
      res.on('data', c => b += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(b) }); }
        catch(e) { resolve({ status: res.statusCode, data: b }); }
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// ── PROVIDER SIGNUP ───────────────────────────────────────────
async function handleProviderSignup(req, res, parseBody) {
  try {
    const body = await parseBody(req);
    const { name, email, password, modality, location } = body;
    if (!name || !email || !password || password.length < 8) {
      res.writeHead(400, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'Name, email, and password (8+ chars) required'}));
      return;
    }
    // Check if email exists
    const existing = await supabase('GET', `providers?email=eq.${encodeURIComponent(email)}&select=id`);
    if (Array.isArray(existing.data) && existing.data.length > 0) {
      res.writeHead(400, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'Email already registered'}));
      return;
    }
    const baseSlug = slugify(name);
    const slug = `${baseSlug}-${crypto.randomBytes(3).toString('hex')}`;
    const result = await supabase('POST', 'providers', {
      name, email,
      password_hash: hashPassword(password),
      modality: modality || '',
      location: location || '',
      bio: '',
      photo_url: '',
      services: [],
      active: true,
      approved: false,
      slug,
    });
    if (result.status === 201 || (Array.isArray(result.data) && result.data.length > 0)) {
      const provider = Array.isArray(result.data) ? result.data[0] : result.data;
      res.writeHead(200, {'Content-Type':'application/json'});
      res.end(JSON.stringify({success:true, id: provider.id, slug: provider.slug}));
    } else {
      const msg = result.data?.message || result.data?.hint || 'Signup failed';
      res.writeHead(400, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error: msg}));
    }
  } catch(e) {
    console.error('providerSignup error:', e);
    res.writeHead(500, {'Content-Type':'application/json'});
    res.end(JSON.stringify({error: e.message}));
  }
}

// ── PROVIDER LOGIN ────────────────────────────────────────────
async function handleProviderLogin(req, res, parseBody, createSession) {
  try {
    const body = await parseBody(req);
    const { email, password } = body;
    if (!email || !password) {
      res.writeHead(400, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'Email and password required'}));
      return;
    }
    const result = await supabase('GET', `providers?email=eq.${encodeURIComponent(email)}&select=id,email,name,password_hash,slug,approved,active`);
    if (!Array.isArray(result.data) || result.data.length === 0) {
      res.writeHead(401, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'Invalid email or password'}));
      return;
    }
    const provider = result.data[0];
    if (!provider.active) {
      res.writeHead(403, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'Account is deactivated'}));
      return;
    }
    if (!verifyPassword(password, provider.password_hash)) {
      res.writeHead(401, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'Invalid email or password'}));
      return;
    }
    const sessionId = createSession({ id: provider.id, role: 'provider', slug: provider.slug });
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': `whelle_session=${sessionId}; HttpOnly; Path=/; Max-Age=28800`
    });
    res.end(JSON.stringify({success:true, name: provider.name, slug: provider.slug, approved: provider.approved}));
  } catch(e) {
    console.error('providerLogin error:', e);
    res.writeHead(500, {'Content-Type':'application/json'});
    res.end(JSON.stringify({error: e.message}));
  }
}

// ── GET PROVIDER PROFILE ──────────────────────────────────────
async function handleGetProvider(req, res, session) {
  try {
    const result = await supabase('GET', `providers?id=eq.${session.id}&select=id,email,name,bio,photo_url,modality,location,services,slug,approved,active,created_at`);
    if (!Array.isArray(result.data) || result.data.length === 0) {
      res.writeHead(404, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'Provider not found'}));
      return;
    }
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify(result.data[0]));
  } catch(e) {
    res.writeHead(500, {'Content-Type':'application/json'});
    res.end(JSON.stringify({error: e.message}));
  }
}

// ── UPDATE PROVIDER PROFILE ───────────────────────────────────
async function handleUpdateProvider(req, res, session, parseBody) {
  try {
    const body = await parseBody(req);
    const updates = {};
    const allowed = ['name','bio','photo_url','modality','location','services'];
    for (const key of allowed) {
      if (body[key] !== undefined) updates[key] = body[key];
    }
    await supabase('PATCH', `providers?id=eq.${session.id}`, updates);
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify({success:true}));
  } catch(e) {
    res.writeHead(500, {'Content-Type':'application/json'});
    res.end(JSON.stringify({error: e.message}));
  }
}

// ── PROVIDER CHANGE PASSWORD ──────────────────────────────────
async function handleProviderChangePassword(req, res, session, parseBody) {
  try {
    const body = await parseBody(req);
    const { current_password, new_password } = body;
    if (!current_password || !new_password || new_password.length < 8) {
      res.writeHead(400, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'Invalid password data'}));
      return;
    }
    const result = await supabase('GET', `providers?id=eq.${session.id}&select=password_hash`);
    if (!Array.isArray(result.data) || !result.data[0]) {
      res.writeHead(404, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'Provider not found'}));
      return;
    }
    if (!verifyPassword(current_password, result.data[0].password_hash)) {
      res.writeHead(401, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'Current password is incorrect'}));
      return;
    }
    await supabase('PATCH', `providers?id=eq.${session.id}`, {password_hash: hashPassword(new_password)});
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify({success:true}));
  } catch(e) {
    res.writeHead(500, {'Content-Type':'application/json'});
    res.end(JSON.stringify({error: e.message}));
  }
}

// ── MEMBER SIGNUP ─────────────────────────────────────────────
async function handleMemberSignup(req, res, parseBody) {
  try {
    const body = await parseBody(req);
    const { name, email, password, location } = body;
    if (!name || !email || !password || password.length < 8) {
      res.writeHead(400, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'Name, email, and password (8+ chars) required'}));
      return;
    }
    const existing = await supabase('GET', `members?email=eq.${encodeURIComponent(email)}&select=id`);
    if (Array.isArray(existing.data) && existing.data.length > 0) {
      res.writeHead(400, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'Email already registered'}));
      return;
    }
    const result = await supabase('POST', 'members', {
      name, email,
      password_hash: hashPassword(password),
      location: location || '',
      photo_url: '',
      active: true,
    });
    if (result.status === 201 || (Array.isArray(result.data) && result.data.length > 0)) {
      const member = Array.isArray(result.data) ? result.data[0] : result.data;
      res.writeHead(200, {'Content-Type':'application/json'});
      res.end(JSON.stringify({success:true, id: member.id}));
    } else {
      res.writeHead(400, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error: result.data?.message || 'Signup failed'}));
    }
  } catch(e) {
    res.writeHead(500, {'Content-Type':'application/json'});
    res.end(JSON.stringify({error: e.message}));
  }
}

// ── MEMBER LOGIN ──────────────────────────────────────────────
async function handleMemberLogin(req, res, parseBody, createSession) {
  try {
    const body = await parseBody(req);
    const { email, password } = body;
    if (!email || !password) {
      res.writeHead(400, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'Email and password required'}));
      return;
    }
    const result = await supabase('GET', `members?email=eq.${encodeURIComponent(email)}&select=id,email,name,password_hash,active`);
    if (!Array.isArray(result.data) || result.data.length === 0) {
      res.writeHead(401, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'Invalid email or password'}));
      return;
    }
    const member = result.data[0];
    if (!member.active) {
      res.writeHead(403, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'Account is deactivated'}));
      return;
    }
    if (!verifyPassword(password, member.password_hash)) {
      res.writeHead(401, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'Invalid email or password'}));
      return;
    }
    const sessionId = createSession({ id: member.id, role: 'member' });
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': `whelle_session=${sessionId}; HttpOnly; Path=/; Max-Age=28800`
    });
    res.end(JSON.stringify({success:true, name: member.name}));
  } catch(e) {
    res.writeHead(500, {'Content-Type':'application/json'});
    res.end(JSON.stringify({error: e.message}));
  }
}

// ── GET MEMBER PROFILE ────────────────────────────────────────
async function handleGetMember(req, res, session) {
  try {
    const result = await supabase('GET', `members?id=eq.${session.id}&select=id,email,name,photo_url,location,active,created_at`);
    if (!Array.isArray(result.data) || result.data.length === 0) {
      res.writeHead(404, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'Member not found'}));
      return;
    }
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify(result.data[0]));
  } catch(e) {
    res.writeHead(500, {'Content-Type':'application/json'});
    res.end(JSON.stringify({error: e.message}));
  }
}

// ── UPDATE MEMBER PROFILE ─────────────────────────────────────
async function handleUpdateMember(req, res, session, parseBody) {
  try {
    const body = await parseBody(req);
    const updates = {};
    const allowed = ['name','photo_url','location'];
    for (const key of allowed) {
      if (body[key] !== undefined) updates[key] = body[key];
    }
    await supabase('PATCH', `members?id=eq.${session.id}`, updates);
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify({success:true}));
  } catch(e) {
    res.writeHead(500, {'Content-Type':'application/json'});
    res.end(JSON.stringify({error: e.message}));
  }
}

// ── ADMIN: GET ALL PROVIDERS ──────────────────────────────────
async function handleAdminGetProviders(req, res) {
  try {
    const result = await supabase('GET', 'providers?select=id,email,name,modality,location,approved,active,created_at&order=created_at.desc');
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify({providers: Array.isArray(result.data) ? result.data : []}));
  } catch(e) {
    res.writeHead(500, {'Content-Type':'application/json'});
    res.end(JSON.stringify({error: e.message}));
  }
}

// ── ADMIN: GET ALL MEMBERS ────────────────────────────────────
async function handleAdminGetMembers(req, res) {
  try {
    const result = await supabase('GET', 'members?select=id,email,name,location,active,created_at&order=created_at.desc');
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify({members: Array.isArray(result.data) ? result.data : []}));
  } catch(e) {
    res.writeHead(500, {'Content-Type':'application/json'});
    res.end(JSON.stringify({error: e.message}));
  }
}

// ── ADMIN: UPDATE PROVIDER ────────────────────────────────────
async function handleAdminUpdateProvider(req, res, id, parseBody) {
  try {
    const body = await parseBody(req);
    const updates = {};
    if (body.approved !== undefined) updates.approved = body.approved;
    if (body.active !== undefined) updates.active = body.active;
    if (body.name !== undefined) updates.name = body.name;
    if (body.modality !== undefined) updates.modality = body.modality;
    await supabase('PATCH', `providers?id=eq.${id}`, updates);
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify({success:true}));
  } catch(e) {
    res.writeHead(500, {'Content-Type':'application/json'});
    res.end(JSON.stringify({error: e.message}));
  }
}

// ── ADMIN: UPDATE MEMBER ──────────────────────────────────────
async function handleAdminUpdateMember(req, res, id, parseBody) {
  try {
    const body = await parseBody(req);
    const updates = {};
    if (body.active !== undefined) updates.active = body.active;
    if (body.name !== undefined) updates.name = body.name;
    await supabase('PATCH', `members?id=eq.${id}`, updates);
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify({success:true}));
  } catch(e) {
    res.writeHead(500, {'Content-Type':'application/json'});
    res.end(JSON.stringify({error: e.message}));
  }
}

// ── PUBLIC: GET PROVIDER PROFILE ──────────────────────────────
async function handlePublicProvider(req, res, slug) {
  try {
    const result = await supabase('GET', `providers?slug=eq.${slug}&select=id,name,bio,photo_url,modality,location,services,slug&active=eq.true`);
    if (!Array.isArray(result.data) || result.data.length === 0) {
      res.writeHead(404, {'Content-Type':'application/json'});
      res.end(JSON.stringify({error:'Provider not found'}));
      return;
    }
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify(result.data[0]));
  } catch(e) {
    res.writeHead(500, {'Content-Type':'application/json'});
    res.end(JSON.stringify({error: e.message}));
  }
}

module.exports = {
  handleProviderSignup,
  handleProviderLogin,
  handleGetProvider,
  handleUpdateProvider,
  handleProviderChangePassword,
  handleMemberSignup,
  handleMemberLogin,
  handleGetMember,
  handleUpdateMember,
  handleAdminGetProviders,
  handleAdminGetMembers,
  handleAdminUpdateProvider,
  handleAdminUpdateMember,
  handlePublicProvider,
  hashPassword,
  verifyPassword,
};
