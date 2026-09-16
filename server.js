// ============================================
// GateFlow DJ — Serveur principal
// Coordination PSD x Securise Departement
// ============================================
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

// ---------- CONFIGURATION ----------
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || 'gateflow2026').trim();


const TOKEN_TTL = '12h';

// Roles
const ROLE_ADMIN = 'admin';
const PSD_ROLES = ['agent_psd', 'chef_equipe', 'superieur_psd', 'inspecteur_psd', 'operateur_central'];
const SD_ROLES = ['superieur_terrain', 'superviseur_sd', 'coordinateur_sd', 'head_manager'];
const SD_DECIDERS = ['superieur_terrain', 'superviseur_sd', 'coordinateur_sd', 'head_manager'];
const DIRECTIVE_WRITERS = ['inspecteur_psd', 'superieur_psd', 'superieur_terrain', 'superviseur_sd', 'coordinateur_sd', 'head_manager'];

function companyOf(role) {
  if (role === ROLE_ADMIN) return 'SYSTEM';
  return PSD_ROLES.indexOf(role) >= 0 ? 'PSD' : 'SD';
}

// ---------- BASE DE DONNEES ----------
const db = new Database(path.join(__dirname, 'gateflow.db'));
db.pragma('journal_mode = WAL');

db.exec(
  "CREATE TABLE IF NOT EXISTS users (" +
  "id INTEGER PRIMARY KEY AUTOINCREMENT," +
  "full_name TEXT NOT NULL," +
  "phone TEXT NOT NULL UNIQUE," +
  "role TEXT NOT NULL," +
  "company TEXT NOT NULL," +
  "badge_number TEXT DEFAULT ''," +
  "password_hash TEXT NOT NULL," +
  "active INTEGER DEFAULT 1," +
  "created_at TEXT DEFAULT (datetime('now'))" +
  ")"
);
db.exec(
  "CREATE TABLE IF NOT EXISTS requests (" +
  "id INTEGER PRIMARY KEY AUTOINCREMENT," +
  "type TEXT NOT NULL," +
  "subject_name TEXT NOT NULL," +
  "badge_number TEXT DEFAULT ''," +
  "note TEXT DEFAULT ''," +
  "status TEXT DEFAULT 'en_attente'," +
  "created_by INTEGER NOT NULL," +
  "created_by_name TEXT DEFAULT ''," +
  "created_by_role TEXT DEFAULT ''," +
  "created_at TEXT DEFAULT (datetime('now'))," +
  "decided_by INTEGER," +
  "decided_by_name TEXT DEFAULT ''," +
  "decided_by_role TEXT DEFAULT ''," +
  "decision_note TEXT DEFAULT ''," +
  "decided_at TEXT" +
  ")"
);
db.exec(
  "CREATE TABLE IF NOT EXISTS directives (" +
  "id INTEGER PRIMARY KEY AUTOINCREMENT," +
  "title TEXT NOT NULL," +
  "body TEXT NOT NULL," +
  "author_id INTEGER NOT NULL," +
  "author_name TEXT DEFAULT ''," +
  "author_role TEXT DEFAULT ''," +
  "created_at TEXT DEFAULT (datetime('now'))" +
  ")"
);
db.exec(
  "CREATE TABLE IF NOT EXISTS audit_log (" +
  "id INTEGER PRIMARY KEY AUTOINCREMENT," +
  "actor_id INTEGER," +
  "actor_name TEXT DEFAULT ''," +
  "action TEXT NOT NULL," +
  "details TEXT DEFAULT ''," +
  "created_at TEXT DEFAULT (datetime('now'))" +
  ")"
);

/// Compte admin : synchronise le mot de passe a chaque demarrage
const adminHash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
const adminExists = db.prepare("SELECT id FROM users WHERE role = 'admin'").get();
if (!adminExists) {
  db.prepare(
    "INSERT INTO users (full_name, phone, role, company, badge_number, password_hash) VALUES (?,?,?,?,?,?)"
  ).run('Administrateur', '0000000000', ROLE_ADMIN, 'SYSTEM', 'ADMIN', adminHash);
  console.log('Compte admin cree');
} else {
  db.prepare("UPDATE users SET password_hash = ? WHERE role = 'admin'").run(adminHash);
}


// ---------- APPLI EXPRESS ----------
const app = express();
app.use(cors());
app.use(express.json({ limit: '200kb' }));

// En-tetes de securite
app.use(function (req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});

// Limiteur anti force brute sur la connexion
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Trop de tentatives. Reessayez dans 15 minutes.' }
});

// ---------- OUTILS ----------
function logAudit(actor, action, details) {
  db.prepare(
    "INSERT INTO audit_log (actor_id, actor_name, action, details) VALUES (?,?,?,?)"
  ).run(actor ? actor.id : null, actor ? actor.full_name : 'SYSTEM', action, details || '');
}

function signToken(user) {
  return jwt.sign({ id: user.id, role: user.role, company: user.company }, JWT_SECRET, { expiresIn: TOKEN_TTL });
}

function publicUser(u) {
  return {
    id: u.id, full_name: u.full_name, phone: u.phone, role: u.role,
    company: u.company, badge_number: u.badge_number, active: u.active
  };
}

// Middleware d'authentification
function authenticate(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.indexOf('Bearer ') === 0 ? h.slice(7) : null;
  if (!token) return res.status(401).json({ success: false, error: 'Non connecte' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.id);
    if (!user || !user.active) return res.status(401).json({ success: false, error: 'Compte invalide ou suspendu' });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ success: false, error: 'Session expiree' });
  }
}

function requireRoles(roles) {
  return function (req, res, next) {
    if (roles.indexOf(req.user.role) === -1) {
      return res.status(403).json({ success: false, error: 'Acces refuse pour votre fonction' });
    }
    next();
  };
}

// ---------- ROUTES ----------
app.get('/healthz', function (req, res) { res.json({ ok: true, service: 'gateflow-dj' }); });// SONDE DE DIAGNOSTIC (temporaire)
app.get('/api/debug', function (req, res) {
  const admin = db.prepare("SELECT phone, length(password_hash) AS hl FROM users WHERE role='admin'").get();
  res.json({
    adminExiste: !!admin,
    telephoneAdmin: admin ? admin.phone : null,
    variableAdminPresente: !!process.env.ADMIN_PASSWORD,
    longueurVariable: process.env.ADMIN_PASSWORD ? process.env.ADMIN_PASSWORD.length : 0,
    node: process.version
  });
});


// Connexion
1app.post('/api/login', loginLimiter, function (req, res) {
const phone = String(req.body.phone || '').trim();
const password = String(req.body.password || '').trim();


  if (!phone || !password) return res.status(400).json({ success: false, error: 'Numero et mot de passe requis' });
  const user = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ success: false, error: 'Identifiants incorrects' });
  }
  if (!user.active) return res.status(403).json({ success: false, error: 'Compte suspendu. Contactez un Inspecteur.' });
  logAudit(user, 'CONNEXION', 'Connexion reussie');
  res.json({ success: true, token: signToken(user), user: publicUser(user) });
});

// Profil
app.get('/api/me', authenticate, function (req, res) {
  res.json({ success: true, user: publicUser(req.user) });
});

// --- GESTION DES COMPTES (admin) ---
app.post('/api/users', authenticate, requireRoles([ROLE_ADMIN]), function (req, res) {
  const full_name = String(req.body.full_name || '').trim();
  const phone = String(req.body.phone || '').trim();
  const role = String(req.body.role || '').trim();
  const badge_number = String(req.body.badge_number || '').trim();
  const password = String(req.body.password || '');
  const allRoles = [ROLE_ADMIN].concat(PSD_ROLES, SD_ROLES);
  if (!full_name || !phone || !role || !password) {
    return res.status(400).json({ success: false, error: 'Nom, numero, fonction et mot de passe requis' });
  }
  if (allRoles.indexOf(role) === -1) return res.status(400).json({ success: false, error: 'Fonction inconnue' });
  try {
    const info = db.prepare(
      "INSERT INTO users (full_name, phone, role, company, badge_number, password_hash) VALUES (?,?,?,?,?,?)"
    ).run(full_name, phone, role, companyOf(role), badge_number, bcrypt.hashSync(password, 10));
    logAudit(req.user, 'CREATION_COMPTE', full_name + ' / ' + role);
    res.json({ success: true, id: info.lastInsertRowid });
  } catch (e) {
    res.status(409).json({ success: false, error: 'Ce numero WhatsApp est deja enregistre' });
  }
});

app.get('/api/users', authenticate, requireRoles([ROLE_ADMIN, 'inspecteur_psd', 'head_manager']), function (req, res) {
  const users = db.prepare('SELECT * FROM users ORDER BY id DESC').all();
  res.json({ success: true, users: users.map(publicUser) });
});

app.patch('/api/users/:id', authenticate, requireRoles([ROLE_ADMIN]), function (req, res) {
  const id = parseInt(req.params.id, 10);
  const active = req.body.active ? 1 : 0;
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!target) return res.status(404).json({ success: false, error: 'Compte introuvable' });
  if (target.role === ROLE_ADMIN) return res.status(403).json({ success: false, error: 'Impossible de suspendre le compte admin' });
  db.prepare('UPDATE users SET active = ? WHERE id = ?').run(active, id);
  logAudit(req.user, active ? 'REACTIVATION_COMPTE' : 'SUSPENSION_COMPTE', target.full_name);
  res.json({ success: true });
});

// --- DEMANDES ---
app.post('/api/requests', authenticate, function (req, res) {
  const type = String(req.body.type || '').trim();
  const subject_name = String(req.body.subject_name || '').trim();
  const badge_number = String(req.body.badge_number || '').trim();
  const note = String(req.body.note || '').trim();
  const allowedTypes = ['badge_oublie', 'panne_camion', 'document_expire', 'autre'];
  if (allowedTypes.indexOf(type) === -1 || !subject_name) {
    return res.status(400).json({ success: false, error: 'Type de demande et nom requis' });
  }
  const info = db.prepare(
    "INSERT INTO requests (type, subject_name, badge_number, note, created_by, created_by_name, created_by_role) VALUES (?,?,?,?,?,?,?)"
  ).run(type, subject_name, badge_number, note, req.user.id, req.user.full_name, req.user.role);
  logAudit(req.user, 'NOUVELLE_DEMANDE', '#' + info.lastInsertRowid + ' ' + type + ' — ' + subject_name);
  res.json({ success: true, id: info.lastInsertRowid });
});

app.get('/api/requests', authenticate, function (req, res) {
  let rows;
  if (req.user.role === ROLE_ADMIN || SD_DECIDERS.indexOf(req.user.role) >= 0) {
    rows = db.prepare('SELECT * FROM requests ORDER BY id DESC LIMIT 200').all();
  } else {
    rows = db.prepare('SELECT * FROM requests WHERE created_by = ? ORDER BY id DESC LIMIT 200').all(req.user.id);
  }
  res.json({ success: true, requests: rows });
});

// Decision du Securise Departement
app.post('/api/requests/:id/decide', authenticate, requireRoles(SD_DECIDERS), function (req, res) {
  const id = parseInt(req.params.id, 10);
  const approve = req.body.approve === true;
  const note = String(req.body.note || '').trim();
  const r = db.prepare('SELECT * FROM requests WHERE id = ?').get(id);
  if (!r) return res.status(404).json({ success: false, error: 'Demande introuvable' });
  if (r.status !== 'en_attente') return res.status(409).json({ success: false, error: 'Demande deja traitee' });
  const status = approve ? 'approuvee' : 'refusee';
  db.prepare(
    "UPDATE requests SET status = ?, decided_by = ?, decided_by_name = ?, decided_by_role = ?, decision_note = ?, decided_at = datetime('now') WHERE id = ?"
  ).run(status, req.user.id, req.user.full_name, req.user.role, note, id);
  logAudit(req.user, approve ? 'APPROBATION' : 'REFUS', 'Demande #' + id + ' (' + r.subject_name + ')' + (note ? ' — note: ' + note : ''));
  res.json({ success: true, status: status });
});

// --- CONSIGNES DE SERVICE ---
app.post('/api/directives', authenticate, requireRoles(DIRECTIVE_WRITERS), function (req, res) {
  const title = String(req.body.title || '').trim();
  const body = String(req.body.body || '').trim();
  if (!title || !body) return res.status(400).json({ success: false, error: 'Titre et contenu requis' });
  const info = db.prepare(
    "INSERT INTO directives (title, body, author_id, author_name, author_role) VALUES (?,?,?,?,?)"
  ).run(title, body, req.user.id, req.user.full_name, req.user.role);
  logAudit(req.user, 'CONSIGNE_PUBLIEE', title);
  res.json({ success: true, id: info.lastInsertRowid });
});

app.get('/api/directives', authenticate, function (req, res) {
  const rows = db.prepare('SELECT * FROM directives ORDER BY id DESC LIMIT 50').all();
  res.json({ success: true, directives: rows });
});

// --- JOURNAL D'AUDIT ---
app.get('/api/audit', authenticate, requireRoles([ROLE_ADMIN, 'inspecteur_psd', 'head_manager']), function (req, res) {
  const rows = db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 300').all();
  res.json({ success: true, audit: rows });
});

// --- PAGES STATIQUES ---
app.get('/', function (req, res) { res.sendFile(path.join(__dirname, 'index.html')); });
app.get('/app', function (req, res) { res.sendFile(path.join(__dirname, 'app.html')); });

// Gestion des erreurs
app.use(function (err, req, res, next) {
  console.error('Erreur serveur:', err.message);
  res.status(500).json({ success: false, error: 'Erreur interne du serveur' });
});

// ---------- DEMARRAGE ----------
app.listen(PORT, function () {
  console.log('GateFlow DJ demarre sur le port ' + PORT);
});
