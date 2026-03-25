/**
 * KazyPanel - Serveur Node.js
 * Gestion des domaines/sous-domaines Apache + PHP 8.4
 * Port: 8080
 * Node.js 24 LTS — Dernière modification : 21/03/2026
 */

'use strict';

const express    = require('express');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcryptjs');
const { exec, spawn } = require('child_process');
const { promisify }   = require('util');
const fs         = require('fs');
const fsp        = require('fs').promises;
const path       = require('path');
const cors       = require('cors');
const helmet     = require('helmet');
const crypto     = require('crypto');

// util.promisify(exec) — plus propre que le callback, tiré des améliorations Node 24
const execAsync  = promisify(exec);

const app  = express();
const PORT = process.env.PORT || 8080;


// ─── VERSION ──────────────────────────────────────────────────────────────────
const KAZYPANEL_VERSION = '1.3.0';
const KAZYPANEL_UPDATE_URL = 'https://raw.githubusercontent.com/kazypanel/kazypanel/main/version.json';

// ─── CONFIGURATION ────────────────────────────────────────────────────────────
const CONFIG = {
  JWT_SECRET: process.env.JWT_SECRET || (() => {
    // Node 24 : Web Crypto API stable — crypto.getRandomValues
    const bytes = new Uint8Array(64);
    crypto.getRandomValues(bytes);
    const fallback = Buffer.from(bytes).toString('hex');
    console.warn('\n⚠️  JWT_SECRET non défini dans .env — clé temporaire générée.');
    console.warn('   Les sessions seront perdues au prochain redémarrage.\n');
    return fallback;
  })(),
  APACHE_SITES_PATH: '/etc/apache2/sites-available',
  APACHE_ENABLED_PATH: '/etc/apache2/sites-enabled',
  WEB_ROOT: '/var/www/admin',
  FTP_ROOT: '/var/www',
  PHP_VERSION: '8.4',
  PHP_POOL_DIR: (v => `/etc/php/${v}/fpm/pool.d`)(process.env.PHP_VERSION || '8.4'),
  LOG_FILE: '/var/log/kazypanel.log',
  DB_ROOT_PASS: process.env.DB_ROOT_PASS || '',
  DB_DEFAULT_LIMIT: 5,
  FTP_DEFAULT_LIMIT: 1,
  PMA_URL: process.env.PMA_URL || ''  // ex: http://monserveur/phpmyadmin ou https://pma.monserveur.fr
};

// ─── HELPERS MARIADB ──────────────────────────────────────────────────────────
function mysqlCmd(sql) {
  return new Promise((resolve, reject) => {
    const args = ['-uroot', '--batch', '--skip-column-names'];
    if (CONFIG.DB_ROOT_PASS) args.push(`-p${CONFIG.DB_ROOT_PASS}`);

    const proc = spawn('mysql', args, { timeout: 15000 });
    let stdout = '', stderr = '';
    proc.stdout.on('data', d => { stdout += d; });
    proc.stderr.on('data', d => { stderr += d; });
    proc.on('close', code => {
      if (code !== 0) reject(new Error(stderr.trim() || `MySQL exit ${code}`));
      else resolve(stdout.trim());
    });
    proc.on('error', reject);
    proc.stdin.write(sql + '\n');
    proc.stdin.end();
  });
}

async function getUserDatabases(username) {
  try {
    const prefix = `${username}_`;
    const out = await mysqlCmd(`SHOW DATABASES LIKE '${prefix}%';`);
    return out.split('\n').filter(l => l.trim().startsWith(prefix));
  } catch { return []; }
}

// ─── VALIDATION DU MOT DE PASSE ───────────────────────────────────────────────
function validatePassword(password) {
  const errors = [];
  if (!password || password.length < 5) errors.push('Au moins 5 caractères');
  if (!/[A-Z]/.test(password)) errors.push('Au moins une majuscule (A-Z)');
  if (!/[a-z]/.test(password)) errors.push('Au moins une minuscule (a-z)');
  if (!/[0-9]/.test(password)) errors.push('Au moins un chiffre (0-9)');
  if (!/[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]/.test(password))
    errors.push('Au moins un caractère spécial (!@#$%^&*...)');
  return { valid: errors.length === 0, errors };
}

// ─── UTILISATEURS ─────────────────────────────────────────────────────────────
let USERS = [];
const USERS_FILE = path.join(__dirname, 'users.json');

function saveUsers() {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(USERS, null, 2), 'utf8');
  } catch (err) {
    console.error('⚠️  Impossible de sauvegarder users.json :', err.message);
  }
}

// ─── TEMPLATES ────────────────────────────────────────────────────────────────
let TEMPLATES = [];
const TEMPLATES_FILE = path.join(__dirname, 'templates.json');

function saveTemplates() {
  try {
    fs.writeFileSync(TEMPLATES_FILE, JSON.stringify(TEMPLATES, null, 2), 'utf8');
  } catch (err) {
    console.error('⚠️  Impossible de sauvegarder templates.json :', err.message);
  }
}

function loadTemplates() {
  try {
    if (fs.existsSync(TEMPLATES_FILE)) {
      const data = JSON.parse(fs.readFileSync(TEMPLATES_FILE, 'utf8'));
      if (Array.isArray(data)) { TEMPLATES = data; return; }
    }
  } catch {}
  // Templates par défaut
  TEMPLATES = [
    { id: 1, name: 'Starter',  description: 'Hébergement basique',     ftpLimit: 1, dbLimit: 1,  domainLimit: 1,  subdomainLimit: 2,  diskLimit: 500,   dbStorageLimit: 100,  cronLimit: 3,  createdAt: new Date().toISOString() },
    { id: 2, name: 'Standard', description: 'Usage courant',            ftpLimit: 2, dbLimit: 3,  domainLimit: 3,  subdomainLimit: 5,  diskLimit: 2048,  dbStorageLimit: 500,  cronLimit: 10, createdAt: new Date().toISOString() },
    { id: 3, name: 'Pro',      description: 'Sites multiples',          ftpLimit: 5, dbLimit: 10, domainLimit: 10, subdomainLimit: 20, diskLimit: 10240, dbStorageLimit: 2048, cronLimit: 30, createdAt: new Date().toISOString() },
    { id: 4, name: 'Illimité', description: 'Aucune restriction (0=∞)', ftpLimit: 0, dbLimit: 0,  domainLimit: 0,  subdomainLimit: 0,  diskLimit: 0,     dbStorageLimit: 0,    cronLimit: 0,  createdAt: new Date().toISOString() },
  ];
  saveTemplates();
}

// Charge les templates au démarrage
loadTemplates();

function loadUsersFromFile() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      const data = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
      if (Array.isArray(data) && data.length > 0) return data;
    }
  } catch (err) {
    console.error('⚠️  Impossible de lire users.json :', err.message);
  }
  return null;
}

async function initUsers() {
  const adminPassword = process.env.ADMIN_PASSWORD || 'Admin@1234!';
  const check = validatePassword(adminPassword);
  if (!check.valid) {
    console.warn('\n⚠️  ADMIN_PASSWORD trop faible :');
    check.errors.forEach(e => console.warn(`   ✗ ${e}`));
    console.warn('   → Définissez un mot de passe plus fort dans votre .env\n');
  }

  // Charger les utilisateurs sauvegardés
  const saved = loadUsersFromFile();
  if (saved) {
    USERS = saved;

    // ── Migration : corriger les anciens chemins FTP qui pointent dans WEB_ROOT ──
    let migrated = false;
    USERS.forEach(u => {
      // Migration chemin WEB_ROOT → FTP_ROOT
      if (u.ftp && u.ftp.dir && u.ftp.dir.startsWith(CONFIG.WEB_ROOT + '/')) {
        const newDir = `${CONFIG.FTP_ROOT}/${u.username}`;
        console.warn(`🔧  Migration FTP chemin : ${u.ftp.dir} → ${newDir}`);
        u.ftp.dir = newDir;
        migrated = true;
      }
      // Migration user.ftp (objet unique) → user.ftpAccounts (tableau)
      if (u.ftp && !u.ftpAccounts) {
        u.ftpAccounts = [{
          ftpUsername: u.username,
          label: 'Compte principal',
          dir: u.ftp.dir,
          createdAt: u.ftp.createdAt || new Date().toISOString()
        }];
        delete u.ftp;
        migrated = true;
        console.warn(`🔧  Migration FTP accounts : ${u.username} → ftpAccounts[]`);
      }
      // Initialiser ftpAccounts si absent
      if (!u.ftpAccounts) {
        u.ftpAccounts = [];
      }
    });
    if (migrated) saveUsers();

    // Réhydrater templateName depuis templateId (si redémarrage serveur)
    let rehydrated = false;
    USERS.forEach(u => {
      if (u.templateId && !u.templateName) {
        const tpl = TEMPLATES.find(t => t.id === u.templateId);
        if (tpl) { u.templateName = tpl.name; rehydrated = true; }
      }
    });
    if (rehydrated) saveUsers();
    // Mettre à jour le mot de passe admin depuis .env si changé
    const adminUser = USERS.find(u => u.username === 'admin');
    if (adminUser) {
      const changed = !(await bcrypt.compare(adminPassword, adminUser.password));
      if (changed) {
        adminUser.password = await bcrypt.hash(adminPassword, 12);
        saveUsers();
        console.log('🔑  Mot de passe admin mis à jour depuis .env\n');
      }
    }
    console.log(`\n✅  Panel démarré → http://0.0.0.0:${PORT}`);
    console.log(`👥  ${USERS.length} utilisateur(s) chargé(s) depuis users.json`);
    console.log(`🔐  Authentification bcrypt x12 active\n`);
    return;
  }

  // Première fois : créer le compte admin
  const hash = await bcrypt.hash(adminPassword, 12);
  USERS = [{ id: 1, username: 'admin', password: hash, role: 'admin' }];
  saveUsers();
  console.log(`\n✅  Panel démarré → http://0.0.0.0:${PORT}`);
  console.log(`🔐  Authentification bcrypt x12 active\n`);
}

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false,
  permissionsPolicy: false  // on le gère manuellement ci-dessous
}));

// Permissions-Policy — restreindre les API navigateur inutiles
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    cb(null, true);
  },
  credentials: true
}));

// Compression gzip des réponses JSON — réduit la bande passante jusqu'à 70%
app.use((req, res, next) => {
  const origJson = res.json.bind(res);
  res.json = function(body) {
    const accept = req.headers['accept-encoding'] || '';
    if (!accept.includes('gzip')) return origJson(body);
    const str = JSON.stringify(body);
    if (str.length < 1024) return origJson(body); // pas la peine pour les petites réponses
    require('zlib').gzip(str, (err, compressed) => {
      if (err) return origJson(body);
      res.setHeader('Content-Encoding', 'gzip');
      res.setHeader('Content-Type', 'application/json');
      res.end(compressed);
    });
    return res;
  };
  next();
});

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1h',         // Cache navigateur 1h pour les assets statiques
  etag: true,
  lastModified: true
}));

// ─── LOG ─────────────────────────────────────────────────────────────────────
function log(action, detail, status = 'OK') {
  const entry = `[${new Date().toISOString()}] [${status}] ${action}: ${detail}`;
  console.log(entry);
  // Écriture asynchrone non-bloquante — Node 24 fs.promises optimisé
  fsp.stat(CONFIG.LOG_FILE)
    .then(stat => {
      if (stat.size > 10 * 1024 * 1024) return fsp.rename(CONFIG.LOG_FILE, CONFIG.LOG_FILE + '.bak');
    })
    .catch(() => {})
    .finally(() => fsp.appendFile(CONFIG.LOG_FILE, entry + '\n').catch(() => {}));
}

// ─── LISTE DES PRÉFIXES DE COMMANDES NÉCESSITANT SUDO ────────────────────────
// Ces commandes requièrent des droits root lorsque le serveur tourne en tant que
// utilisateur non-privilégié (ex: debian). Assurez-vous que /etc/sudoers.d/kazypanel
// autorise ces commandes en NOPASSWD pour l'utilisateur qui lance KazyPanel.
const SUDO_PREFIXES = [
  'a2ensite', 'a2dissite', 'a2enmod',
  'systemctl',
  'useradd', 'userdel', 'usermod',
  'chpasswd',
  'chown', 'chmod',
  'mkdir',
  'cp ',
  'rm -rf', 'rm -f',
  'rndc',
  'named-checkzone', 'named-checkconf',
  'certbot',
  'ufw',
  'fail2ban-client',
  'sshd -t', 'hostnamectl', 'timedatectl',
  'du -sm', 'du -sk',
  'crontab -u',
  'tar ',
  'apache2ctl', 'apachectl',
  'bash -c "source',
  'passwd ',
];

// Commandes de lecture qui ne nécessitent PAS sudo
const NO_SUDO_PREFIXES = [
  'systemctl is-active',
  'systemctl status',
  'du -sm "/proc',
  'du -sk "/proc',
  'cat ',
  'ls ',
  'grep ',
  'hostname',
  'which ',
  'id ',
  'free ',
  'df ',
  'lsb_release',
  'uname',
  'uptime',
  'ss -',
  'netstat',
  'tail ',
  'head ',
  'find ',
];

function needsSudo(cmd) {
  const trimmed = cmd.trim();
  if (trimmed.startsWith('sudo ')) return false;
  // Vérifier d'abord si c'est une commande de lecture (pas de sudo)
  if (NO_SUDO_PREFIXES.some(prefix => trimmed.startsWith(prefix))) return false;
  return SUDO_PREFIXES.some(prefix => trimmed.startsWith(prefix));
}

function runCmd(cmd, opts = {}) {
  const finalCmd = needsSudo(cmd) ? `sudo ${cmd}` : cmd;
  return execAsync(finalCmd, { timeout: opts.timeout || 30000, maxBuffer: opts.maxBuffer || 1024 * 1024 })
    .then(({ stdout }) => stdout.trim())
    .catch(err => { throw new Error(err.stderr?.trim() || err.message, { cause: err }); });
}

// Utilise spawn + stdin pour éviter les problèmes d'échappement avec chpasswd
function setSystemPassword(username, password) {
  return new Promise((resolve, reject) => {
    const proc = spawn('sudo', ['chpasswd'], { timeout: 10000 });
    let stderr = '';
    proc.stderr.on('data', d => { stderr += d; });
    proc.on('close', code => {
      if (code !== 0) reject(new Error(stderr.trim() || `chpasswd exit ${code}`));
      else resolve();
    });
    proc.on('error', reject);
    proc.stdin.write(`${username}:${password}\n`);
    proc.stdin.end();
  });
}

// ─── ANTI BRUTE-FORCE ────────────────────────────────────────────────────────
const loginAttempts = new Map();

function checkBruteForce(ip) {
  const entry = loginAttempts.get(ip) || { count: 0, blockedUntil: 0 };
  if (entry.blockedUntil > Date.now())
    return { blocked: true, remaining: Math.ceil((entry.blockedUntil - Date.now()) / 60000) };
  return { blocked: false };
}

function recordFailedAttempt(ip) {
  const entry = loginAttempts.get(ip) || { count: 0, blockedUntil: 0 };
  entry.count += 1;
  if (entry.count >= 5) { entry.blockedUntil = Date.now() + 15 * 60 * 1000; entry.count = 0; }
  loginAttempts.set(ip, entry);
}

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token manquant' });
  try { req.user = jwt.verify(token, CONFIG.JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Token invalide ou expiré' }); }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin')
    return res.status(403).json({ error: 'Accès réservé à l\'administrateur' });
  next();
}

// ─── ROUTE: LOGIN ─────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress || '';
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ error: 'Identifiants requis' });

  const bf = checkBruteForce(ip);
  if (bf.blocked)
    return res.status(429).json({ error: `Trop de tentatives. Réessayez dans ${bf.remaining} minute(s).` });

  const user = USERS.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    recordFailedAttempt(ip);
    log('LOGIN', `${username} depuis ${ip}`, 'FAIL');
    return res.status(401).json({ error: 'Identifiants incorrects' });
  }

  loginAttempts.delete(ip);
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    CONFIG.JWT_SECRET,
    { expiresIn: '8h' }
  );
  log('LOGIN', `${username} depuis ${ip}`, 'OK');
  res.json({ token, username: user.username, role: user.role });
});

// ─── ROUTE: CHANGER LE MOT DE PASSE ──────────────────────────────────────────
app.post('/api/change-password', authMiddleware, async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  if (!currentPassword || !newPassword || !confirmPassword)
    return res.status(400).json({ error: 'Tous les champs sont requis' });
  if (!(await bcrypt.compare(currentPassword, user.password)))
    return res.status(401).json({ error: 'Mot de passe actuel incorrect' });
  if (newPassword !== confirmPassword)
    return res.status(400).json({ error: 'Les nouveaux mots de passe ne correspondent pas' });
  const check = validatePassword(newPassword);
  if (!check.valid) return res.status(400).json({ error: 'Mot de passe trop faible', rules: check.errors });
  if (await bcrypt.compare(newPassword, user.password))
    return res.status(400).json({ error: 'Le nouveau mot de passe doit être différent de l\'ancien' });
  user.password = await bcrypt.hash(newPassword, 12);
  saveUsers();
  log('CHANGE_PASSWORD', user.username, 'OK');
  res.json({ success: true, message: 'Mot de passe mis à jour avec succès' });
});

app.get('/api/password-rules', authMiddleware, (req, res) => {
  res.json({
    minLength: 5,
    rules: [
      'Minimum 5 caractères',
      'Au moins une majuscule (A-Z)',
      'Au moins une minuscule (a-z)',
      'Au moins un chiffre (0-9)',
      'Au moins un caractère spécial (!@#$%^&*...)'
    ]
  });
});

// ─── ROUTES: CONFIGURATION SERVEUR (admin) ───────────────────────────────────

// GET /api/server-config — lire l'état courant
app.get('/api/server-config', authMiddleware, adminOnly, async (req, res) => {
  try {
    // Port SSH
    let sshPort = '22';
    try {
      const sshConf = fs.readFileSync('/etc/ssh/sshd_config', 'utf8');
      const m = sshConf.match(/^\s*Port\s+(\d+)/m);
      if (m) sshPort = m[1];
    } catch {}

    // MOTD
    let motd = '';
    try { motd = fs.readFileSync('/etc/motd', 'utf8').trim(); } catch {}

    // Fail2ban jail.local
    let jailLocal = '';
    try { jailLocal = fs.readFileSync('/etc/fail2ban/jail.local', 'utf8'); } catch {}

    // Fuseau horaire
    let timezone = 'UTC';
    try {
      const { stdout } = await runCmdOut('timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo UTC');
      timezone = stdout.trim();
    } catch {}

    // Message de maintenance dans panel_config
    const maintenanceMsg = PANEL_CONFIG.maintenanceMsg || '';
    const maintenanceEnabled = !!PANEL_CONFIG.maintenanceEnabled;

    // Hostname actuel
    let hostname = 'N/A';
    try { hostname = (await runCmd('hostname')).trim(); } catch {}

    res.json({ sshPort, motd, jailLocal, timezone, maintenanceMsg, maintenanceEnabled, hostname });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/server-config/ssh-port — changer le port SSH
app.post('/api/server-config/ssh-port', authMiddleware, adminOnly, async (req, res) => {
  const { port } = req.body;
  const p = parseInt(port);
  if (!p || p < 1024 || p > 65535)
    return res.status(400).json({ error: 'Port invalide (1024–65535)' });
  try {
    const conf = fs.readFileSync('/etc/ssh/sshd_config', 'utf8');
    let updated;
    if (/^\s*Port\s+\d+/m.test(conf)) {
      updated = conf.replace(/^\s*Port\s+\d+/m, `Port ${p}`);
    } else if (/^#\s*Port\s+\d+/m.test(conf)) {
      updated = conf.replace(/^#\s*Port\s+\d+/m, `Port ${p}`);
    } else {
      updated = `Port ${p}\n` + conf;
    }
    // Valider la config avant d'appliquer
    const tmpFile = '/tmp/sshd_config_test';
    fs.writeFileSync(tmpFile, updated);
    try { await runCmd(`sshd -t -f ${tmpFile}`); } finally { try { fs.unlinkSync(tmpFile); } catch {} }
    const tmpApply = `/tmp/sshd_config_apply_${Date.now()}`;
    fs.writeFileSync(tmpApply, updated);
    await runCmd(`sudo cp "${tmpApply}" /etc/ssh/sshd_config && sudo chmod 644 /etc/ssh/sshd_config`);
    fs.unlinkSync(tmpApply);
    await runCmd('systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true');
    log('SSH_PORT', `Port SSH changé vers ${p}`, 'OK');
    res.json({ success: true, message: `Port SSH changé vers ${p} — reconnectez-vous sur le port ${p}` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/server-config/ssh-allowusers
app.get('/api/server-config/ssh-allowusers', authMiddleware, adminOnly, (req, res) => {
  try {
    const conf = fs.readFileSync('/etc/ssh/sshd_config', 'utf8');
    const m = conf.match(/^\s*AllowUsers\s+(.+)/m);
    const allowUsers = m ? m[1].trim().split(/\s+/).filter(Boolean) : [];
    res.json({ allowUsers });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/server-config/ssh-allowusers
app.post('/api/server-config/ssh-allowusers', authMiddleware, adminOnly, async (req, res) => {
  const { users } = req.body;
  if (!Array.isArray(users)) return res.status(400).json({ error: 'users doit être un tableau' });
  const safe = users.map(u => String(u).replace(/[^a-zA-Z0-9_-]/g, '')).filter(Boolean);
  try {
    let conf = fs.readFileSync('/etc/ssh/sshd_config', 'utf8');
    if (safe.length === 0) {
      conf = conf.replace(/^\s*#?\s*# Restriction SSH.*\n?/m, '').replace(/^\s*AllowUsers\s+.+\n?/m, '');
    } else {
      const line = `AllowUsers ${safe.join(' ')}`;
      if (/^\s*AllowUsers\s+/m.test(conf)) {
        conf = conf.replace(/^\s*AllowUsers\s+.+/m, line);
      } else {
        conf = conf.trimEnd() + `\n\n# Restriction SSH — KazyPanel\n${line}\n`;
      }
    }
    const tmpFile = '/tmp/sshd_config_allowusers_test';
    fs.writeFileSync(tmpFile, conf);
    try { await runCmd(`sshd -t -f ${tmpFile}`); } finally { try { fs.unlinkSync(tmpFile); } catch {} }
    const tmpApply = `/tmp/sshd_config_allowusers_apply_${Date.now()}`;
    fs.writeFileSync(tmpApply, conf);
    await runCmd(`sudo cp "${tmpApply}" /etc/ssh/sshd_config && sudo chmod 644 /etc/ssh/sshd_config`);
    fs.unlinkSync(tmpApply);
    await runCmd('systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true');
    const msg = safe.length ? `SSH restreint à : ${safe.join(', ')}` : 'Restriction SSH supprimée';
    log('SSH_ALLOWUSERS', msg, 'OK');
    res.json({ success: true, message: msg, allowUsers: safe });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/server-config/motd — mettre à jour /etc/motd
app.post('/api/server-config/motd', authMiddleware, adminOnly, async (req, res) => {
  const { motd } = req.body;
  if (motd === undefined) return res.status(400).json({ error: 'Contenu requis' });
  try {
    const tmpMotd = `/tmp/kp_motd_${Date.now()}`;
    fs.writeFileSync(tmpMotd, motd + '\n', 'utf8');
    await runCmd(`sudo cp "${tmpMotd}" /etc/motd && sudo chmod 644 /etc/motd`);
    fs.unlinkSync(tmpMotd);
    log('MOTD', 'Mis à jour', 'OK');
    res.json({ success: true, message: 'MOTD mis à jour' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/server-config/fail2ban — écrire jail.local + créer le filtre kazypanel + redémarrer
const KAZYPANEL_FILTER = `[Definition]
# Filtre Fail2ban pour KazyPanel
# Détecte les échecs de connexion dans /var/log/kazypanel.log
# Format de log : [2026-03-13T10:30:00.000Z] [FAIL] LOGIN: admin depuis ::ffff:192.168.1.100
failregex = ^\\[.+\\] \\[FAIL\\] LOGIN: \\S+ depuis (::ffff:)?<HOST>$
ignoreregex =
datepattern = ^\\[{DATE}\\]
`;

app.post('/api/server-config/fail2ban', authMiddleware, adminOnly, async (req, res) => {
  const { content } = req.body;
  if (!content || !content.trim()) return res.status(400).json({ error: 'Contenu requis' });

  // Créer /etc/fail2ban/filter.d/ si nécessaire
  try { await runCmd('sudo mkdir -p /etc/fail2ban/filter.d'); } catch {}

  // Créer automatiquement le filtre kazypanel s'il est référencé et manquant
  const filterPath = '/etc/fail2ban/filter.d/kazypanel.conf';
  if (content.includes('filter   = kazypanel') || content.includes('filter=kazypanel')) {
    if (!fs.existsSync(filterPath)) {
      try {
        const tmpFilter = `/tmp/kp_f2b_filter_${Date.now()}.conf`;
        fs.writeFileSync(tmpFilter, KAZYPANEL_FILTER, 'utf8');
        await runCmd(`sudo cp "${tmpFilter}" "${filterPath}" && sudo chmod 644 "${filterPath}"`);
        fs.unlinkSync(tmpFilter);
        log('FAIL2BAN_FILTER', 'Filtre kazypanel.conf créé automatiquement', 'OK');
      } catch (e) {
        return res.status(500).json({ error: `Impossible de créer le filtre kazypanel : ${e.message}` });
      }
    }
  }

  // Sauvegarde de l'ancien jail.local
  const bak = '/etc/fail2ban/jail.local.bak.' + Date.now();
  try { await runCmd(`sudo cp /etc/fail2ban/jail.local "${bak}"`); } catch {}

  try {
    const tmpJail = `/tmp/kp_jail_${Date.now()}`;
    fs.writeFileSync(tmpJail, content, 'utf8');
    await runCmd(`sudo cp "${tmpJail}" /etc/fail2ban/jail.local && sudo chmod 644 /etc/fail2ban/jail.local`);
    fs.unlinkSync(tmpJail);
    await runCmd('systemctl restart fail2ban');
    log('FAIL2BAN_CONFIG', 'jail.local mis à jour et redémarré', 'OK');
    const filterCreated = content.includes('filter   = kazypanel') && !fs.existsSync(filterPath + '.exists');
    res.json({ success: true, message: 'Fail2ban reconfiguré et redémarré' + (filterCreated ? ' — filtre kazypanel.conf créé' : '') });
  } catch (err) {
    // Restaurer la sauvegarde en cas d'erreur
    try { await runCmd(`sudo cp "${bak}" /etc/fail2ban/jail.local`); await runCmd('systemctl restart fail2ban'); } catch {}
    res.status(500).json({ error: err.message });
  }
});

// POST /api/server-config/timezone — changer le fuseau horaire
app.post('/api/server-config/timezone', authMiddleware, adminOnly, async (req, res) => {
  const { timezone } = req.body;
  if (!timezone || !/^[A-Za-z_/]+$/.test(timezone))
    return res.status(400).json({ error: 'Fuseau horaire invalide' });
  try {
    await runCmd(`timedatectl set-timezone ${timezone}`);
    log('TIMEZONE', `Fuseau changé vers ${timezone}`, 'OK');
    res.json({ success: true, message: `Fuseau horaire défini sur ${timezone}` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/server-config/hostname — lire le hostname actuel
app.get('/api/server-config/hostname', authMiddleware, adminOnly, async (req, res) => {
  try {
    const hostname = await runCmd('hostname');
    res.json({ hostname: hostname.trim() });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/server-config/hostname — changer le hostname
app.post('/api/server-config/hostname', authMiddleware, adminOnly, async (req, res) => {
  const { hostname } = req.body;
  if (!hostname || !/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$/.test(hostname))
    return res.status(400).json({ error: 'Hostname invalide (lettres, chiffres, tirets — 63 car. max)' });
  try {
    await runCmd(`hostnamectl set-hostname "${hostname}"`);
    // Mettre à jour /etc/hosts si l'ancien hostname y figure
    try {
      const oldHostname = (await runCmd('hostname')).trim();
      const hosts = require('fs').readFileSync('/etc/hosts', 'utf8');
      if (hosts.includes(oldHostname)) {
        const tmpHosts = `/tmp/kp_hosts_${Date.now()}`;
        require('fs').writeFileSync(tmpHosts, hosts.replace(new RegExp(oldHostname, 'g'), hostname));
        await runCmd(`sudo cp "${tmpHosts}" /etc/hosts && sudo chmod 644 /etc/hosts`);
        require('fs').unlinkSync(tmpHosts);
      }
    } catch {}
    log('HOSTNAME', `Hostname changé vers ${hostname}`, 'OK');
    res.json({ success: true, message: `Hostname défini sur "${hostname}" — redémarrage recommandé pour prise en compte complète` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Helper : retourne les .bashrc disponibles (root + utilisateurs du panel) ──
function getBashrcPaths() {
  const paths = [];

  // Toujours root en premier
  paths.push({ label: 'root', path: '/root/.bashrc' });

  // Lire /etc/passwd une seule fois
  let passwdLines = [];
  try { passwdLines = fs.readFileSync('/etc/passwd', 'utf8').split('\n'); } catch {}

  // Fonction pour trouver le home d'un username dans /etc/passwd
  function getHomeDir(username) {
    const line = passwdLines.find(l => l.startsWith(username + ':'));
    if (!line) return null;
    return line.split(':')[5] || null;
  }

  // Ajouter EN PREMIER l'utilisateur qui lance le process (ex: debian)
  try {
    const procUsername = require('os').userInfo().username || process.env.USER || '';
    const procHome     = process.env.HOME || require('os').homedir();
    if (procUsername && procUsername !== 'root' && procHome && procHome !== '/root') {
      const bashrcPath = path.join(procHome, '.bashrc');
      if (!fs.existsSync(bashrcPath)) {
        try { fs.writeFileSync(bashrcPath, `# .bashrc — ${procUsername}\n`); } catch {}
      }
      paths.push({ label: procUsername, path: bashrcPath });
    }
  } catch {}

  // Utilisateurs du panel KazyPanel
  for (const u of USERS) {
    if (u.username === 'admin') continue;
    const homeDir = getHomeDir(u.username);
    if (!homeDir) continue;
    const bashrcPath = path.join(homeDir, '.bashrc');
    // Créer un .bashrc vide si inexistant
    if (!fs.existsSync(bashrcPath)) {
      try {
        fs.mkdirSync(homeDir, { recursive: true });
        fs.writeFileSync(bashrcPath, `# .bashrc — ${u.username}\n`);
      } catch {}
    }
    // Éviter les doublons
    if (!paths.find(p => p.label === u.username)) {
      paths.push({ label: u.username, path: bashrcPath });
    }
  }

  return paths;
}

function getBashrcPath(target) {
  if (!target || target === 'root') return '/root/.bashrc';
  const all = getBashrcPaths();
  const found = all.find(p => p.label === target);
  return found ? found.path : '/root/.bashrc';
}

app.get('/api/server-config/bashrc', authMiddleware, adminOnly, (req, res) => {
  try {
    const target     = req.query.target || 'root';
    const bashrcPath = getBashrcPath(target);
    const content    = fs.existsSync(bashrcPath) ? fs.readFileSync(bashrcPath, 'utf8') : '';
    const templates  = PANEL_CONFIG.bashrcTemplates || [];
    const available  = getBashrcPaths();
    res.json({ content, templates, bashrcPath, target, available });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/server-config/bashrc/templates — créer un template personnalisé
app.post('/api/server-config/bashrc/templates', authMiddleware, adminOnly, (req, res) => {
  const { name, content } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Nom requis' });
  if (!content)              return res.status(400).json({ error: 'Contenu requis' });
  if (!PANEL_CONFIG.bashrcTemplates) PANEL_CONFIG.bashrcTemplates = [];
  const id = 'tpl_' + Date.now();
  PANEL_CONFIG.bashrcTemplates.push({ id, name: name.trim(), content, createdAt: new Date().toISOString() });
  savePanelConfig();
  log('BASHRC_TPL', `Template "${name}" créé`, 'OK');
  res.json({ success: true, message: `Template "${name}" sauvegardé`, templates: PANEL_CONFIG.bashrcTemplates });
});

// DELETE /api/server-config/bashrc/templates/:id — supprimer un template
app.delete('/api/server-config/bashrc/templates/:id', authMiddleware, adminOnly, (req, res) => {
  if (!PANEL_CONFIG.bashrcTemplates) PANEL_CONFIG.bashrcTemplates = [];
  const idx = PANEL_CONFIG.bashrcTemplates.findIndex(t => t.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Template introuvable' });
  const [tpl] = PANEL_CONFIG.bashrcTemplates.splice(idx, 1);
  savePanelConfig();
  log('BASHRC_TPL', `Template "${tpl.name}" supprimé`, 'OK');
  res.json({ success: true, message: `Template "${tpl.name}" supprimé`, templates: PANEL_CONFIG.bashrcTemplates });
});

// POST /api/server-config/bashrc — sauvegarder le .bashrc
app.post('/api/server-config/bashrc', authMiddleware, adminOnly, async (req, res) => {
  const { content, target } = req.body;
  if (content === undefined) return res.status(400).json({ error: 'Contenu requis' });
  try {
    const bashrcPath = getBashrcPath(target || 'root');
    // Sauvegarde de l'ancien fichier
    if (fs.existsSync(bashrcPath))
      await runCmd(`sudo cp "${bashrcPath}" "${bashrcPath}.bak.${Date.now()}"`);
    const tmpBashrc = `/tmp/kp_bashrc_${Date.now()}`;
    fs.writeFileSync(tmpBashrc, content, 'utf8');
    await runCmd(`sudo cp "${tmpBashrc}" "${bashrcPath}" && sudo chmod 644 "${bashrcPath}"`);
    fs.unlinkSync(tmpBashrc);
    log('BASHRC', `Mis à jour (${bashrcPath})`, 'OK');
    res.json({ success: true, message: `${bashrcPath} sauvegardé avec succès`, bashrcPath });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/server-config/bashrc/apply — source le .bashrc
app.post('/api/server-config/bashrc/apply', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { target } = req.body;
    const bashrcPath = getBashrcPath(target || 'root');
    await runCmd(`sudo bash -c "source ${bashrcPath}"`);
    log('BASHRC', `Appliqué via source (${bashrcPath})`, 'OK');
    res.json({ success: true, message: `${bashrcPath} appliqué (source) avec succès`, bashrcPath });
  } catch (err) {
    res.status(500).json({ error: `Erreur lors de l'application : ${err.message}` });
  }
});

// GET /api/server-config/bashrc/backups — lister les fichiers .bashrc.bak.*
app.get('/api/server-config/bashrc/backups', authMiddleware, adminOnly, async (req, res) => {
  try {
    const all = getBashrcPaths();
    const backups = [];
    for (const { label, path: bashrcPath } of all) {
      const dir  = require('path').dirname(bashrcPath);
      const base = require('path').basename(bashrcPath);
      try {
        const files = fs.readdirSync(dir)
          .filter(f => f.startsWith(base + '.bak.'))
          .map(f => {
            const full = require('path').join(dir, f);
            const stat = fs.statSync(full);
            return { file: full, name: f, user: label, size: stat.size, mtime: stat.mtime.toISOString() };
          })
          .sort((a, b) => new Date(b.mtime) - new Date(a.mtime));
        backups.push(...files);
      } catch {}
    }
    res.json({ backups, count: backups.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// DELETE /api/server-config/bashrc/backups — supprimer tous les .bashrc.bak.*
app.delete('/api/server-config/bashrc/backups', authMiddleware, adminOnly, async (req, res) => {
  try {
    const all = getBashrcPaths();
    let deleted = 0;
    for (const { path: bashrcPath } of all) {
      const dir  = require('path').dirname(bashrcPath);
      const base = require('path').basename(bashrcPath);
      try {
        const files = fs.readdirSync(dir).filter(f => f.startsWith(base + '.bak.'));
        for (const f of files) {
          await runCmd(`sudo rm -f "${require('path').join(dir, f)}"`);
          deleted++;
        }
      } catch {}
    }
    log('BASHRC_BACKUPS', `${deleted} fichier(s) supprimé(s)`, 'OK');
    res.json({ success: true, message: `${deleted} fichier(s) de sauvegarde supprimé(s)` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/server-config/maintenance — bannière de maintenance
app.post('/api/server-config/maintenance', authMiddleware, adminOnly, (req, res) => {
  const { enabled, message } = req.body;
  PANEL_CONFIG.maintenanceEnabled = !!enabled;
  PANEL_CONFIG.maintenanceMsg = (message || '').slice(0, 300);
  savePanelConfig();
  log('MAINTENANCE', `${enabled ? 'activée' : 'désactivée'}: ${message}`, 'OK');
  res.json({ success: true, message: `Bannière de maintenance ${enabled ? 'activée' : 'désactivée'}` });
});

// GET /api/server-config/usage — consommation du process KazyPanel
app.get('/api/server-config/usage', authMiddleware, adminOnly, async (req, res) => {
  try {
    const pid = process.pid;

    // Mémoire Node.js (interne)
    const mem = process.memoryUsage();

    // CPU + RSS via /proc (Linux)
    let cpuPercent = null;
    let rssKb = null;
    let vsizeKb = null;
    let threads = null;
    try {
      const stat   = fs.readFileSync(`/proc/${pid}/stat`, 'utf8').split(' ');
      const status = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
      const uptime = parseFloat(fs.readFileSync('/proc/uptime', 'utf8').split(' ')[0]);
      const clkTck = 100; // USER_HZ standard Linux
      const utime  = parseInt(stat[13]);
      const stime  = parseInt(stat[14]);
      const starttime = parseInt(stat[21]);
      const totalCpu  = (utime + stime) / clkTck;
      const elapsed   = uptime - starttime / clkTck;
      cpuPercent = elapsed > 0 ? ((totalCpu / elapsed) * 100).toFixed(2) : '0.00';

      const rssMatch   = status.match(/VmRSS:\s+(\d+)/);
      const vsizeMatch = status.match(/VmSize:\s+(\d+)/);
      const threadsMatch = status.match(/Threads:\s+(\d+)/);
      if (rssMatch)    rssKb   = parseInt(rssMatch[1]);
      if (vsizeMatch)  vsizeKb = parseInt(vsizeMatch[1]);
      if (threadsMatch) threads = parseInt(threadsMatch[1]);
    } catch {}

    // Taille du dossier KazyPanel
    let dirSizeKb = null;
    try {
      const out = await runCmdOut(`du -sk /opt/kazypanel 2>/dev/null | awk '{print $1}'`);
      dirSizeKb = parseInt(out.stdout.trim()) || null;
    } catch {}

    // Taille du fichier log
    let logSizeBytes = null;
    try {
      const stat = fs.statSync(CONFIG.LOG_FILE);
      logSizeBytes = stat.size;
    } catch {}

    // Uptime du process
    const uptimeSec = Math.floor(process.uptime());

    res.json({
      pid,
      uptimeSec,
      cpu: cpuPercent,
      threads,
      memory: {
        rssKb,
        vsizeKb,
        heapUsedMb: (mem.heapUsed / 1024 / 1024).toFixed(1),
        heapTotalMb: (mem.heapTotal / 1024 / 1024).toFixed(1),
        externalMb: (mem.external / 1024 / 1024).toFixed(1),
      },
      disk: {
        dirSizeKb,
        logSizeBytes,
      }
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── ROUTE: VÉRIFICATION DE MISE À JOUR ──────────────────────────────────────
app.get('/api/update/check', authMiddleware, adminOnly, async (req, res) => {
  // Lire le version.json local pour avoir la version et la date d'installation réelles
  let current = KAZYPANEL_VERSION;
  let installedDate = null;
  try {
    const localVersion = JSON.parse(fs.readFileSync(path.join(__dirname, 'version.json'), 'utf8'));
    if (localVersion.version) current = localVersion.version;
    installedDate = localVersion.releaseDate || null;
  } catch {}

  try {
    // Node 24 — fetch natif stable
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    let remoteData;
    try {
      const response = await fetch(KAZYPANEL_UPDATE_URL, { signal: controller.signal });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      remoteData = await response.json();
    } finally { clearTimeout(timeout); }

    const latest = remoteData.version || '0.0.0';

    // Comparaison semver simple
    const toNum = v => v.split('.').map(Number).reduce((a, n, i) => a + n * Math.pow(1000, 2 - i), 0);
    const hasUpdate = toNum(latest) > toNum(current);

    res.json({
      current, latest, hasUpdate, installedDate,
      changelog:    remoteData.changelog    || [],
      releaseDate:  remoteData.releaseDate  || null,
      downloadUrl:  remoteData.downloadUrl  || null,
      releaseNotes: remoteData.releaseNotes || '',
    });
  } catch (err) {
    res.json({ current, latest: null, hasUpdate: false, installedDate, error: err.message });
  }
});

// ─── ROUTE: APPLIQUER LA MISE À JOUR ─────────────────────────────────────────
// Exécute git pull + npm install + systemctl restart en séquentiel
// Retourne les logs de chaque étape
app.post('/api/update/apply', authMiddleware, adminOnly, async (req, res) => {
  const installDir = path.resolve(__dirname);
  const steps = [
    { label: 'Récupération des fichiers (git pull)',   cmd: `git -C "${installDir}" pull origin main` },
    { label: 'Mise à jour des dépendances (npm install)', cmd: `npm install --production --prefix "${installDir}"` },
    { label: 'Redémarrage du service',                cmd: 'systemctl restart kazypanel' },
  ];

  const results = [];
  for (const step of steps) {
    try {
      const { stdout, stderr } = await execAsync(
        needsSudo(step.cmd) ? `sudo ${step.cmd}` : step.cmd,
        { timeout: 120000, maxBuffer: 2 * 1024 * 1024 }
      );
      results.push({ label: step.label, success: true, output: (stdout + stderr).trim() });
    } catch (err) {
      results.push({ label: step.label, success: false, output: (err.stderr || err.message || '').trim() });
      log('UPDATE_APPLY', `Échec : ${step.label}`, 'FAIL');
      return res.json({ success: false, results });
    }
  }

  // Invalider le cache de version côté serveur (sera relu au prochain check)
  log('UPDATE_APPLY', 'Mise à jour appliquée avec succès', 'OK');
  res.json({ success: true, results });
});

// ─── ROUTE: HISTORIQUE DES CONNEXIONS ───────────────────────────────────────
app.get('/api/logins', authMiddleware, async (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const filter  = req.query.filter || 'all'; // all | ok | fail
  const limit   = Math.min(parseInt(req.query.limit) || 100, 500);

  let logContent = '';
  try { logContent = fs.readFileSync(CONFIG.LOG_FILE, 'utf8'); } catch { logContent = ''; }

  const lines = logContent.split('\n').filter(l => l.includes('] LOGIN:'));

  // Parser chaque ligne de log LOGIN
  const allEntries = [];
  for (const line of lines) {
    const m = line.match(/^\[([^\]]+)\] \[(OK|FAIL)\] LOGIN: (\S+) depuis (\S+)$/);
    if (!m) continue;
    const [, dateRaw, status, username, ip] = m;
    // Filtrer par utilisateur si non admin
    if (!isAdmin && username !== req.user.username) continue;
    allEntries.push({
      date:     new Date(dateRaw).toLocaleString('fr-FR', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit', second:'2-digit' }),
      dateRaw,
      status,
      username,
      ip:       ip.replace('::ffff:', ''),
      detail:   status === 'FAIL' ? 'Identifiants incorrects' : null
    });
  }

  // Appliquer le filtre
  const filtered = allEntries
    .filter(e => filter === 'all' || e.status === filter.toUpperCase())
    .reverse()
    .slice(0, limit);

  // Stats admin
  let stats = null;
  if (isAdmin) {
    const today    = new Date().toISOString().slice(0, 10);
    const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    stats = {
      successToday: allEntries.filter(e => e.status === 'OK'   && e.dateRaw.startsWith(today)).length,
      failToday:    allEntries.filter(e => e.status === 'FAIL' && e.dateRaw.startsWith(today)).length,
      uniqueIps:    new Set(allEntries.filter(e => new Date(e.dateRaw).getTime() > sevenDaysAgo).map(e => e.ip)).size,
      totalLogins:  allEntries.length
    };
  }

  res.json({ entries: filtered, stats, total: allEntries.length });
});

// ─── ROUTE: EFFACER LES LOGS DE CONNEXION ────────────────────────────────────
app.delete('/api/logins', authMiddleware, adminOnly, async (req, res) => {
  try {
    // Lire le fichier log actuel
    let logContent = '';
    try { logContent = fs.readFileSync(CONFIG.LOG_FILE, 'utf8'); } catch {}

    // Garder toutes les lignes sauf les LOGIN
    const filtered = logContent
      .split('\n')
      .filter(l => !l.includes('] LOGIN:'))
      .join('\n');

    // Réécrire le fichier sans les lignes LOGIN
    const tmpLog = `/tmp/kp_log_clean_${Date.now()}`;
    fs.writeFileSync(tmpLog, filtered);
    await runCmd(`sudo cp "${tmpLog}" "${CONFIG.LOG_FILE}" && sudo chmod 644 "${CONFIG.LOG_FILE}"`);
    fs.unlinkSync(tmpLog);

    log('LOGINS_CLEAR', `Logs de connexion effacés par ${req.user.username}`, 'OK');
    res.json({ success: true, message: 'Logs de connexion effacés avec succès' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/version', (req, res) => {
  res.json({ version: KAZYPANEL_VERSION });
});

// ─── ROUTES: TEMPLATES ──────────────────────────────────────────────────────

// Lister tous les templates
app.get('/api/templates', authMiddleware, adminOnly, (req, res) => {
  res.json({ templates: TEMPLATES });
});

// Créer un template
app.post('/api/templates', authMiddleware, adminOnly, (req, res) => {
  try {
  const { name, description = '', ftpLimit = 1, dbLimit = 5, domainLimit = 3, subdomainLimit = 5, diskLimit = 1024, dbStorageLimit = 500, cronLimit = 10 } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Nom du template requis' });
  if (TEMPLATES.find(t => t.name.toLowerCase() === name.trim().toLowerCase()))
    return res.status(409).json({ error: 'Un template avec ce nom existe déjà' });

  const tpl = {
    id: Date.now(),
    name: name.trim(),
    description: description.trim(),
    ftpLimit:        Math.max(0, parseInt(ftpLimit)        || 0),
    dbLimit:         Math.max(0, parseInt(dbLimit)         || 0),
    domainLimit:     Math.max(0, parseInt(domainLimit)     || 0),
    subdomainLimit:  Math.max(0, parseInt(subdomainLimit)  || 0),
    diskLimit:       Math.max(0, parseInt(diskLimit)       || 0),
    dbStorageLimit:  Math.max(0, parseInt(dbStorageLimit)  || 0),
    cronLimit:       Math.max(0, parseInt(cronLimit)       || 0),
    createdAt: new Date().toISOString()
  };
  TEMPLATES.push(tpl);
  saveTemplates();
  log('TPL_CREATE', `${name} par ${req.user.username}`, 'OK');
  res.status(201).json({ success: true, message: `Template "${name}" créé`, template: tpl });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Modifier un template
app.put('/api/templates/:id', authMiddleware, adminOnly, (req, res) => {
  try {
  const tpl = TEMPLATES.find(t => t.id === parseInt(req.params.id));
  if (!tpl) return res.status(404).json({ error: 'Template introuvable' });

  const { name, description, ftpLimit, dbLimit, domainLimit, subdomainLimit, diskLimit, dbStorageLimit, cronLimit } = req.body || {};
  if (name) tpl.name = name.trim();
  if (description !== undefined) tpl.description = description.trim();
  if (ftpLimit       !== undefined) tpl.ftpLimit       = Math.max(0, parseInt(ftpLimit)       || 0);
  if (dbLimit        !== undefined) tpl.dbLimit        = Math.max(0, parseInt(dbLimit)        || 0);
  if (domainLimit    !== undefined) tpl.domainLimit    = Math.max(0, parseInt(domainLimit)    || 0);
  if (subdomainLimit !== undefined) tpl.subdomainLimit = Math.max(0, parseInt(subdomainLimit) || 0);
  if (diskLimit      !== undefined) tpl.diskLimit      = Math.max(0, parseInt(diskLimit)      || 0);
  if (dbStorageLimit !== undefined) tpl.dbStorageLimit = Math.max(0, parseInt(dbStorageLimit) || 0);
  if (cronLimit      !== undefined) tpl.cronLimit      = Math.max(0, parseInt(cronLimit)      || 0);

  saveTemplates();
  log('TPL_UPDATE', `${tpl.name} par ${req.user.username}`, 'OK');
  res.json({ success: true, message: `Template "${tpl.name}" mis à jour`, template: tpl });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Supprimer un template
app.delete('/api/templates/:id', authMiddleware, adminOnly, (req, res) => {
  const idx = TEMPLATES.findIndex(t => t.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Template introuvable' });
  const [tpl] = TEMPLATES.splice(idx, 1);
  saveTemplates();
  log('TPL_DELETE', `${tpl.name} par ${req.user.username}`, 'OK');
  res.json({ success: true, message: `Template "${tpl.name}" supprimé` });
});

// Appliquer un template à un utilisateur
app.post('/api/users/:id/template', authMiddleware, adminOnly, (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const tpl = TEMPLATES.find(t => t.id === parseInt(req.body.templateId));
  if (!tpl) return res.status(404).json({ error: 'Template introuvable' });

  user.ftpLimit       = tpl.ftpLimit;
  user.dbLimit        = tpl.dbLimit;
  user.domainLimit    = tpl.domainLimit;
  user.subdomainLimit = tpl.subdomainLimit;
  user.diskLimit      = tpl.diskLimit ?? 0;
  user.dbStorageLimit = tpl.dbStorageLimit ?? 0;
  user.cronLimit      = tpl.cronLimit ?? 10;
  user.templateId     = tpl.id;
  user.templateName   = tpl.name;
  saveUsers();
  log('TPL_APPLY', `${tpl.name} → ${user.username} par ${req.user.username}`, 'OK');
  res.json({ success: true, message: `Template "${tpl.name}" appliqué à ${user.username}` });
});

// ─── ROUTES: GESTION DES UTILISATEURS (admin seulement) ──────────────────────

// Lister tous les utilisateurs
app.get('/api/users', authMiddleware, adminOnly, async (req, res) => {
  const users = await Promise.all(USERS.map(async u => {
    // Compter les domaines/sous-domaines
    let domainCount = 0, subdomainCount = 0;
    try {
      if (fs.existsSync(CONFIG.APACHE_SITES_PATH)) {
        const files = fs.readdirSync(CONFIG.APACHE_SITES_PATH)
          .filter(f => f.endsWith('.conf') && !['000-default.conf','default-ssl.conf'].includes(f) && !f.includes('-le-ssl.conf') && !f.includes('phpmyadmin'));
        for (const file of files) {
          const conf    = fs.readFileSync(path.join(CONFIG.APACHE_SITES_PATH, file), 'utf8');
          const docRoot = (conf.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim() || '';
          if (!userOwnsDocRoot(u, docRoot)) continue;
          file.replace('.conf','').split('.').length > 2 ? subdomainCount++ : domainCount++;
        }
      }
    } catch {}

    // Compter les bases de données
    let dbCount = 0;
    try { dbCount = (await getUserDatabases(u.username)).length; } catch {}

    // Taille disque utilisée
    let diskUsedMb = 0;
    try {
      const homeDir = `${CONFIG.FTP_ROOT}/${u.username}`;
      if (fs.existsSync(homeDir)) {
        const out = await runCmd(`du -sm "${homeDir}" 2>/dev/null || echo 0`);
        diskUsedMb = parseInt(out.split('\t')[0]) || 0;
      }
    } catch {}

    // Tâches cron actives
    let cronCount = 0;
    try {
      const raw = await runCmd(`crontab -u ${u.username} -l 2>/dev/null || echo ""`);
      cronCount = raw.split('\n').filter(l => l.trim() && !l.trim().startsWith('#')).length;
    } catch {}

    return {
      id: u.id,
      username: u.username,
      role: u.role,
      createdAt: u.createdAt || null,
      ftpAccounts: u.ftpAccounts || [],
      ftpLimit:       u.ftpLimit       ?? CONFIG.FTP_DEFAULT_LIMIT,
      dbLimit:        u.dbLimit        ?? CONFIG.DB_DEFAULT_LIMIT,
      domainLimit:    u.domainLimit    ?? 0,
      subdomainLimit: u.subdomainLimit ?? 0,
      diskLimit:      u.diskLimit      ?? 0,
      dbStorageLimit: u.dbStorageLimit ?? 0,
      cronLimit:      u.cronLimit      ?? 10,
      templateId:     u.templateId     || null,
      templateName:   u.templateName   || null,
      // Données d'utilisation réelle
      ftpCount:       (u.ftpAccounts || []).length,
      dbCount,
      domainCount,
      subdomainCount,
      diskUsedMb,
      cronCount
    };
  }));
  res.json({ users });
});

// Créer un utilisateur
app.post('/api/users', authMiddleware, adminOnly, async (req, res) => {
  const { username, password, role = 'user' } = req.body;

  if (!username || !password)
    return res.status(400).json({ error: 'Nom d\'utilisateur et mot de passe requis' });

  if (!/^[a-zA-Z0-9_-]{3,32}$/.test(username))
    return res.status(400).json({ error: 'Nom d\'utilisateur invalide (3-32 caractères, lettres/chiffres/_/-)' });

  if (USERS.find(u => u.username === username))
    return res.status(409).json({ error: 'Ce nom d\'utilisateur existe déjà' });

  if (!['admin', 'user'].includes(role))
    return res.status(400).json({ error: 'Rôle invalide (admin ou user)' });

  const check = validatePassword(password);
  if (!check.valid)
    return res.status(400).json({ error: 'Mot de passe trop faible', rules: check.errors });

  const hash = await bcrypt.hash(password, 12);
  const homeDir = `${CONFIG.FTP_ROOT}/${username}`;

  // Créer le compte FTP système automatiquement
  let ftpInfo = null;
  try {
    let userExists = false;
    try { await runCmd(`id ${username}`); userExists = true; } catch {}

    if (!userExists) {
      await runCmd(`sudo mkdir -p "${homeDir}"`);
      await runCmd(`useradd -d "${homeDir}" -s /bin/bash -M ${username}`);
      await setSystemPassword(username, password);
      await runCmd(`chown ${username}:${username} "${homeDir}"`);
      await runCmd(`chmod 755 "${homeDir}"`);
    } else {
      await setSystemPassword(username, password);
    }

    // Ajouter à la liste vsftpd si elle existe
    const vsftpdUserList = '/etc/vsftpd.userlist';
    if (fs.existsSync(vsftpdUserList)) {
      const list = fs.readFileSync(vsftpdUserList, 'utf8');
      if (!list.split('\n').includes(username)) {
        const tmpVsftpd = `/tmp/kp_userlist_${Date.now()}`;
        fs.writeFileSync(tmpVsftpd, list.trimEnd() + `\n${username}\n`);
        await runCmd(`sudo cp "${tmpVsftpd}" "${vsftpdUserList}" && sudo chmod 644 "${vsftpdUserList}"; rm -f "${tmpVsftpd}"`);
      }
    }

    ftpInfo = { ftpUsername: username, label: 'Compte principal', dir: homeDir, createdAt: new Date().toISOString() };
    log('FTP_AUTO_CREATE', `${username} → ${homeDir}`, 'OK');
  } catch (ftpErr) {
    // Le compte FTP a échoué mais on crée quand même l'utilisateur panel
    log('FTP_AUTO_CREATE', username, 'ERROR: ' + ftpErr.message);
  }

  const newUser = {
    id: Date.now(),
    username,
    password: hash,
    role,
    createdAt: new Date().toISOString(),
    ftpAccounts: ftpInfo ? [ftpInfo] : [],
    ftpLimit: CONFIG.FTP_DEFAULT_LIMIT
  };
  USERS.push(newUser);
  saveUsers();
  log('CREATE_USER', `${username} (rôle: ${role}) par ${req.user.username}`, 'OK');

  const ftpStatus = ftpInfo ? ` — Compte FTP créé dans ${homeDir}` : ' — ⚠️ Compte FTP non créé (vérifiez les logs)';
  res.status(201).json({
    success: true,
    id: newUser.id,
    message: `Utilisateur ${username} créé avec succès${ftpStatus}`,
    ftp: ftpInfo
  });
});

// Modifier le rôle d'un utilisateur
app.put('/api/users/:id', authMiddleware, adminOnly, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  if (user.username === 'admin') return res.status(403).json({ error: 'Le compte admin ne peut pas être modifié' });

  const { role, newPassword } = req.body;

  if (role) {
    if (!['admin', 'user'].includes(role))
      return res.status(400).json({ error: 'Rôle invalide' });
    user.role = role;
  }

  if (newPassword) {
    const check = validatePassword(newPassword);
    if (!check.valid) return res.status(400).json({ error: 'Mot de passe trop faible', rules: check.errors });
    user.password = await bcrypt.hash(newPassword, 12);

    // Synchroniser le mot de passe FTP système si le compte existe
    try { await setSystemPassword(user.username, newPassword); } catch {}
  }

  saveUsers();
  log('UPDATE_USER', `${user.username} par ${req.user.username}`, 'OK');
  res.json({ success: true, message: `Utilisateur ${user.username} mis à jour` });
});

// Supprimer un utilisateur
app.delete('/api/users/:id', authMiddleware, adminOnly, async (req, res) => {
  const idx = USERS.findIndex(u => u.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Utilisateur introuvable' });
  if (USERS[idx].username === 'admin')
    return res.status(403).json({ error: 'Le compte admin ne peut pas être supprimé' });

  const deleted = USERS.splice(idx, 1)[0];
  const errors = [];

  // 1. Supprimer tous les comptes FTP système (principaux + secondaires)
  const ftpAccounts = deleted.ftpAccounts || [];
  for (const acc of ftpAccounts) {
    try { await deleteFtpSystemAccount(acc.ftpUsername); } catch (e) { errors.push(`FTP ${acc.ftpUsername}: ${e.message}`); }
  }
  // Supprimer aussi le compte système linux principal si pas dans ftpAccounts
  try {
    await runCmd(`id ${deleted.username} 2>/dev/null && userdel ${deleted.username} 2>/dev/null || true`);
  } catch {}

  // 2. Supprimer toutes les bases MariaDB de l'utilisateur
  try {
    const dbs = await getUserDatabases(deleted.username);
    for (const dbName of dbs) {
      try {
        await mysqlCmd(`DROP DATABASE IF EXISTS \`${dbName}\`; DROP USER IF EXISTS '${dbName}'@'localhost';`);
      } catch (e) { errors.push(`BDD ${dbName}: ${e.message}`); }
    }
  } catch (e) { errors.push(`Lecture BDD: ${e.message}`); }

  // 3. Supprimer les VirtualHosts Apache appartenant à l'utilisateur
  try {
    if (fs.existsSync(CONFIG.APACHE_SITES_PATH)) {
      const ftpDirs = (deleted.ftpAccounts || []).map(a => a.dir);
      const primaryDir = `${CONFIG.FTP_ROOT}/${deleted.username}`;
      const allDirs = ftpDirs.length ? ftpDirs : [primaryDir];

      const files = fs.readdirSync(CONFIG.APACHE_SITES_PATH)
        .filter(f => f.endsWith('.conf') && !['000-default.conf','default-ssl.conf'].includes(f) && !f.includes('-le-ssl.conf') && !f.includes('phpmyadmin'));

      for (const file of files) {
        try {
          const conf = fs.readFileSync(path.join(CONFIG.APACHE_SITES_PATH, file), 'utf8');
          const docRoot = (conf.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim() || '';
          if (allDirs.some(dir => docRoot.startsWith(dir))) {
            const name = file.replace('.conf', '');
            const enabledLink = path.join(CONFIG.APACHE_ENABLED_PATH, file);
            try { await runCmd(`sudo rm -f "${enabledLink}"`); } catch {}
            await runCmd(`sudo rm -f "${path.join(CONFIG.APACHE_SITES_PATH, file)}"`);
            log('VHOST_DELETE', `${name} (suppression user ${deleted.username})`, 'OK');
          }
        } catch (e) { errors.push(`VHost ${file}: ${e.message}`); }
      }
      await runCmd('systemctl reload apache2').catch(() => {});
    }
  } catch (e) { errors.push(`VHosts: ${e.message}`); }

  // 4. Supprimer le dossier de l'utilisateur dans FTP_ROOT
  const userDir = `${CONFIG.FTP_ROOT}/${deleted.username}`;
  try {
    if (fs.existsSync(userDir)) {
      fs.rmSync(userDir, { recursive: true, force: true });
      log('DIR_DELETE', userDir, 'OK');
    }
// Supprimer un de mes comptes FTP
  } catch (e) { errors.push(`Dossier ${userDir}: ${e.message}`); }

  saveUsers();
  log('DELETE_USER', `${deleted.username} par ${req.user.username}`, 'OK');

  const msg = errors.length
    ? `Utilisateur ${deleted.username} supprimé (${errors.length} avertissement(s) : ${errors.join(', ')})`
    : `Utilisateur ${deleted.username} supprimé avec toutes ses ressources`;

  res.json({ success: true, message: msg });
});

// ─── ROUTE: IMPERSONATION (admin → token utilisateur) ────────────────────────
app.post('/api/users/:id/impersonate', authMiddleware, adminOnly, (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  if (user.username === 'admin') return res.status(403).json({ error: 'Impossible d\'impersonner le compte admin' });

  // Token de courte durée (1h) avec flag impersonated pour traçabilité
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role, impersonatedBy: req.user.username },
    CONFIG.JWT_SECRET,
    { expiresIn: '1h' }
  );
  log('IMPERSONATE', `admin ${req.user.username} → ${user.username}`, 'OK');
  res.json({ token, username: user.username, role: user.role });
});

// ─── HELPERS FTP ──────────────────────────────────────────────────────────────
async function createFtpSystemAccount(ftpUsername, homeDir, password) {
  // 1. /bin/false doit être dans /etc/shells pour que vsftpd accepte le login
  const shellsPath = '/etc/shells';
  if (fs.existsSync(shellsPath)) {
    const shells = fs.readFileSync(shellsPath, 'utf8').split('\n').map(l => l.trim());
    if (!shells.includes('/bin/false')) {
      const tmpShells = `/tmp/kp_shells_${Date.now()}`;
      fs.writeFileSync(tmpShells, fs.readFileSync(shellsPath, 'utf8') + '/bin/false\n');
      await runCmd(`sudo cp "${tmpShells}" "${shellsPath}" && sudo chmod 644 "${shellsPath}"`);
      fs.unlinkSync(tmpShells);
    }
  }

  // 2. Créer ou mettre à jour le compte système
  let exists = false;
  try { await runCmd(`id "${ftpUsername}"`); exists = true; } catch {}
  if (!exists) {
    await runCmd(`sudo mkdir -p "${homeDir}"`);
    await runCmd(`useradd -d "${homeDir}" -s /bin/false -M "${ftpUsername}"`);
  } else {
    await runCmd(`sudo mkdir -p "${homeDir}"`);
    await runCmd(`usermod -d "${homeDir}" -s /bin/false "${ftpUsername}"`);
  }

  // 3. Permissions du dossier racine (chroot vsftpd)
  // Si allow_writeable_chroot=YES dans vsftpd.conf → le dossier peut appartenir à l'utilisateur
  // Sinon → doit appartenir à root
  let writeableChroot = false;
  try {
    const vsftpdConf = fs.readFileSync('/etc/vsftpd.conf', 'utf8');
    writeableChroot = /^allow_writeable_chroot=YES/m.test(vsftpdConf);
  } catch {}

  if (writeableChroot) {
    // Dossier appartient à l'utilisateur FTP — accès en écriture direct
    await runCmd(`chown "${ftpUsername}":"${ftpUsername}" "${homeDir}"`);
    await runCmd(`chmod 755 "${homeDir}"`);
  } else {
    // Dossier appartient à root — seul le sous-dossier files est writable
    await runCmd(`chown root:root "${homeDir}"`);
    await runCmd(`chmod 755 "${homeDir}"`);
    const uploadDir = `${homeDir}/files`;
    await runCmd(`sudo mkdir -p "${uploadDir}"`);
    await runCmd(`chown "${ftpUsername}":"${ftpUsername}" "${uploadDir}"`);
    await runCmd(`chmod 755 "${uploadDir}"`);
  }

  // 4. Mot de passe
  await setSystemPassword(ftpUsername, password);

  // 6. vsftpd.userlist — un user par ligne, sans espaces
  const list = '/etc/vsftpd.userlist';
  if (fs.existsSync(list)) {
    const lines = fs.readFileSync(list, 'utf8').split('\n').map(l => l.trim()).filter(Boolean);
    if (!lines.includes(ftpUsername)) {
      lines.push(ftpUsername);
      const tmpList = `/tmp/kp_userlist_${Date.now()}`;
      fs.writeFileSync(tmpList, lines.join('\n') + '\n');
      await runCmd(`sudo cp "${tmpList}" "${list}" && sudo chmod 644 "${list}"; rm -f "${tmpList}"`);
    }
  }

  // 7. Appliquer vsftpd.conf + restart
  await ensureVsftpdChroot();
}

async function ensureVsftpdChroot() {
  const confPath = '/etc/vsftpd.conf';
  if (!fs.existsSync(confPath)) {
    log('FTP_CONFIG', 'vsftpd.conf introuvable — vsftpd non installé ?', 'WARN');
    return;
  }

  let conf = fs.readFileSync(confPath, 'utf8');
  let changed = false;

  const required = [
    ['local_enable',           'YES'],
    ['write_enable',           'YES'],
    ['chroot_local_user',      'YES'],
    ['allow_writeable_chroot', 'YES'],
    ['local_umask',            '022'],
    ['pam_service_name',       'vsftpd'],
  ];

  if (fs.existsSync('/etc/vsftpd.userlist')) {
    required.push(['userlist_enable', 'YES']);
    required.push(['userlist_deny',   'NO']);
    required.push(['userlist_file',   '/etc/vsftpd.userlist']);
  }

  for (const [key, val] of required) {
    const re = new RegExp(`^#?\\s*${key}\\s*=.*`, 'm');
    const expected = `${key}=${val}`;
    if (re.test(conf)) {
      const current = (conf.match(re) || [''])[0].trim();
      if (current !== expected) { conf = conf.replace(re, expected); changed = true; }
    } else {
      conf += `\n${expected}`;
      changed = true;
    }
  }

  if (changed) {
    const tmpConf = `/tmp/kp_vsftpd_${Date.now()}`;
    fs.writeFileSync(tmpConf, conf);
    await runCmd(`sudo cp "${tmpConf}" "${confPath}" && sudo chmod 644 "${confPath}"; rm -f "${tmpConf}"`);
    log('FTP_CONFIG', 'vsftpd.conf mis à jour', 'OK');
  }

  // Restart uniquement si vsftpd est installé
  try {
    await runCmd('which vsftpd || test -f /usr/sbin/vsftpd');
    await runCmd('systemctl restart vsftpd 2>&1 || true');
    log('FTP_CONFIG', 'vsftpd redémarré', 'OK');
  } catch {
    log('FTP_CONFIG', 'vsftpd non disponible', 'WARN');
  }
}

async function deleteFtpSystemAccount(ftpUsername) {
  try { await runCmd(`userdel ${ftpUsername} 2>/dev/null || true`); } catch {}
  const list = '/etc/vsftpd.userlist';
  if (fs.existsSync(list)) {
    const lines = fs.readFileSync(list, 'utf8').split('\n')
      .filter(l => l.trim() !== ftpUsername);
    const tmpList = `/tmp/kp_userlist_${Date.now()}`;
    fs.writeFileSync(tmpList, lines.join('\n'));
    await runCmd(`sudo cp "${tmpList}" "${list}" && sudo chmod 644 "${list}"; rm -f "${tmpList}"`);
  }
}

// ─── ROUTES: GESTION FTP (admin) ──────────────────────────────────────────────

// Lister les comptes FTP d'un utilisateur
app.get('/api/users/:id/ftp', authMiddleware, adminOnly, (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  res.json({
    ftpAccounts: user.ftpAccounts || [],
    ftpLimit: user.ftpLimit ?? CONFIG.FTP_DEFAULT_LIMIT
  });
});

// Créer un compte FTP (admin — contourne la limite)
app.post('/api/users/:id/ftp', authMiddleware, adminOnly, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  const { ftpPassword, ftpSuffix, ftpDir } = req.body;
  if (!ftpPassword) return res.status(400).json({ error: 'Mot de passe FTP requis' });

  const check = validatePassword(ftpPassword);
  if (!check.valid) return res.status(400).json({ error: 'Mot de passe trop faible', rules: check.errors });

  // ftpSuffix vide = compte principal (username), sinon username_suffix
  const suffix = ftpSuffix ? ftpSuffix.replace(/[^a-zA-Z0-9]/g, '').toLowerCase() : '';
  const ftpUsername = suffix ? `${user.username}_${suffix}` : user.username;
  const homeDir = ftpDir || `${CONFIG.FTP_ROOT}/${user.username}`;
  const label = suffix ? suffix : 'Compte principal';

  if (!user.ftpAccounts) user.ftpAccounts = [];
  if (user.ftpAccounts.find(a => a.ftpUsername === ftpUsername))
    return res.status(409).json({ error: `Le compte FTP "${ftpUsername}" existe déjà` });

  try {
    await createFtpSystemAccount(ftpUsername, homeDir, ftpPassword);
    user.ftpAccounts.push({ ftpUsername, label, dir: homeDir, createdAt: new Date().toISOString() });
    saveUsers();
    log('FTP_CREATE_ADMIN', `${ftpUsername} → ${homeDir}`, 'OK');
    res.json({ success: true, message: `Compte FTP "${ftpUsername}" créé`, ftpUsername, dir: homeDir });
  } catch (err) {
    log('FTP_CREATE_ADMIN', ftpUsername, 'ERROR');
    res.status(500).json({ error: err.message });
  }
});

// Changer le mot de passe d'un compte FTP (admin)
app.put('/api/users/:id/ftp/:ftpUser', authMiddleware, adminOnly, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const ftpUser = req.params.ftpUser;
  if (!user.ftpAccounts || !user.ftpAccounts.find(a => a.ftpUsername === ftpUser))
    return res.status(404).json({ error: 'Compte FTP introuvable' });
  const { ftpPassword } = req.body;
  if (!ftpPassword) return res.status(400).json({ error: 'Mot de passe requis' });
  const check = validatePassword(ftpPassword);
  if (!check.valid) return res.status(400).json({ error: 'Mot de passe trop faible', rules: check.errors });
  try {
    await setSystemPassword(ftpUser, ftpPassword);
    log('FTP_PASSWD_ADMIN', `${ftpUser} par ${req.user.username}`, 'OK');
    res.json({ success: true, message: `Mot de passe de "${ftpUser}" mis à jour` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Supprimer un compte FTP (admin)
app.delete('/api/users/:id/ftp/:ftpUser', authMiddleware, adminOnly, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const ftpUser = req.params.ftpUser;
  if (!user.ftpAccounts || !user.ftpAccounts.find(a => a.ftpUsername === ftpUser))
    return res.status(404).json({ error: 'Compte FTP introuvable' });
  try {
    await deleteFtpSystemAccount(ftpUser);
    user.ftpAccounts = user.ftpAccounts.filter(a => a.ftpUsername !== ftpUser);
    saveUsers();
    log('FTP_DELETE_ADMIN', `${ftpUser} par ${req.user.username}`, 'OK');
    res.json({ success: true, message: `Compte FTP "${ftpUser}" supprimé` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Définir la limite de comptes FTP (admin)
app.put('/api/users/:id/ftplimit', authMiddleware, adminOnly, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const { limit } = req.body;
  if (typeof limit !== 'number' || limit < 0 || limit > 20)
    return res.status(400).json({ error: 'Limite invalide (0-20)' });
  user.ftpLimit = limit;
  saveUsers();
  log('FTP_LIMIT', `${user.username} → ${limit} par ${req.user.username}`, 'OK');
  res.json({ success: true, message: `Limite FTP fixée à ${limit} pour ${user.username}` });
});

// ─── ROUTES: GESTION FTP (utilisateur — self-service) ─────────────────────────

// Lister mes comptes FTP
app.get('/api/me/ftp', authMiddleware, (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  res.json({
    ftpAccounts: user.ftpAccounts || [],
    ftpLimit: user.ftpLimit ?? CONFIG.FTP_DEFAULT_LIMIT,
    count: (user.ftpAccounts || []).length
  });
});

// Créer un de mes comptes FTP
app.post('/api/me/ftp', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  const limit = user.ftpLimit ?? CONFIG.FTP_DEFAULT_LIMIT;
  if (!user.ftpAccounts) user.ftpAccounts = [];
  if (limit > 0 && user.ftpAccounts.length >= limit)
    return res.status(403).json({ error: `Limite atteinte (${limit} compte${limit > 1 ? 's' : ''} FTP maximum)` });

  const { ftpPassword, ftpSuffix, ftpHomeDir } = req.body;
  if (!ftpPassword) return res.status(400).json({ error: 'Mot de passe FTP requis' });

  const check = validatePassword(ftpPassword);
  if (!check.valid) return res.status(400).json({ error: 'Mot de passe trop faible', rules: check.errors });

  const suffix = ftpSuffix ? ftpSuffix.replace(/[^a-zA-Z0-9]/g, '').toLowerCase() : '';
  if (!suffix && user.ftpAccounts.find(a => a.ftpUsername === user.username))
    return res.status(409).json({ error: 'Le compte FTP principal existe déjà. Choisissez un suffixe.' });
  if (suffix && !/^[a-z0-9]{1,12}$/.test(suffix))
    return res.status(400).json({ error: 'Suffixe invalide (lettres/chiffres, 12 car. max)' });

  const ftpUsername = suffix ? `${user.username}_${suffix}` : user.username;

  // Validation du dossier choisi — doit être le DocumentRoot d'un sous-domaine appartenant à l'utilisateur
  const baseDir = `${CONFIG.FTP_ROOT}/${user.username}`;
  let homeDir = baseDir;
  if (ftpHomeDir && ftpHomeDir.trim()) {
    const cleanDir = path.resolve(ftpHomeDir.trim());

    // Vérifier que le dossier correspond au DocumentRoot d'un sous-domaine de l'utilisateur
    let isAllowed = false;
    try {
      if (fs.existsSync(CONFIG.APACHE_SITES_PATH)) {
        const files = fs.readdirSync(CONFIG.APACHE_SITES_PATH)
          .filter(f => f.endsWith('.conf') && !['000-default.conf','default-ssl.conf'].includes(f) && !f.includes('-le-ssl.conf') && !f.includes('phpmyadmin'));
        for (const file of files) {
          const parts = file.replace('.conf','').split('.');
          if (parts.length <= 2) continue; // pas un sous-domaine
          const conf    = fs.readFileSync(path.join(CONFIG.APACHE_SITES_PATH, file), 'utf8');
          const docRoot = (conf.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim() || '';
          if (userOwnsDocRoot(user, docRoot) && path.resolve(docRoot) === cleanDir) {
            isAllowed = true;
            break;
          }
        }
      }
    } catch {}

    if (!isAllowed)
      return res.status(400).json({ error: 'Dossier non autorisé — doit être le DocumentRoot d\'un de vos sous-domaines' });

    homeDir = cleanDir;
  }

  const label = suffix ? suffix : 'Compte principal';

  if (user.ftpAccounts.find(a => a.ftpUsername === ftpUsername))
    return res.status(409).json({ error: `Le compte FTP "${ftpUsername}" existe déjà` });

  try {
    await createFtpSystemAccount(ftpUsername, homeDir, ftpPassword);
    user.ftpAccounts.push({ ftpUsername, label, dir: homeDir, createdAt: new Date().toISOString() });
    saveUsers();
    log('FTP_CREATE_USER', `${user.username} → ${ftpUsername} (${homeDir})`, 'OK');
    res.status(201).json({ success: true, message: `Compte FTP "${ftpUsername}" créé`, ftpUsername, dir: homeDir });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Changer le mot de passe d'un de mes comptes FTP
app.put('/api/me/ftp/:ftpUser', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const ftpUser = req.params.ftpUser;
  // Vérifier que le compte appartient bien à cet utilisateur
  if (!user.ftpAccounts || !user.ftpAccounts.find(a => a.ftpUsername === ftpUser))
    return res.status(403).json({ error: 'Ce compte FTP ne vous appartient pas' });
  const { ftpPassword } = req.body;
  if (!ftpPassword) return res.status(400).json({ error: 'Nouveau mot de passe requis' });
  const check = validatePassword(ftpPassword);
  if (!check.valid) return res.status(400).json({ error: 'Mot de passe trop faible', rules: check.errors });
  try {
    await setSystemPassword(ftpUser, ftpPassword);
    log('FTP_PASSWD_USER', `${user.username} → ${ftpUser}`, 'OK');
    res.json({ success: true, message: `Mot de passe de "${ftpUser}" mis à jour` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/me/ftp/:ftpUser', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const ftpUser = req.params.ftpUser;
  if (!user.ftpAccounts || !user.ftpAccounts.find(a => a.ftpUsername === ftpUser))
    return res.status(403).json({ error: 'Ce compte FTP ne vous appartient pas' });
  try {
    await deleteFtpSystemAccount(ftpUser);
    user.ftpAccounts = user.ftpAccounts.filter(a => a.ftpUsername !== ftpUser);
    saveUsers();
    log('FTP_DELETE_USER', `${user.username} → ${ftpUser}`, 'OK');
    res.json({ success: true, message: `Compte FTP "${ftpUser}" supprimé` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── ROUTE: DIAGNOSTIC FTP (admin) ───────────────────────────────────────────
app.get('/api/ftp/diagnostic', authMiddleware, adminOnly, async (req, res) => {
  const checks = { ok: true, issues: [] };

  // vsftpd installé ?
  try {
    await runCmd('which vsftpd || test -f /usr/sbin/vsftpd');
    checks.vsftpd_installed = true;
  } catch {
    checks.vsftpd_installed = false;
    checks.ok = false;
    checks.issues.push('vsftpd non installé — apt install vsftpd');
  }

  // vsftpd actif ? — on utilise || echo pour éviter exit code 1 si inactif
  try {
    const out = await runCmd('systemctl is-active vsftpd 2>/dev/null || echo inactive');
    checks.vsftpd_running = out.trim() === 'active';
    if (!checks.vsftpd_running) {
      checks.ok = false;
      checks.issues.push('vsftpd non actif — systemctl start vsftpd && systemctl enable vsftpd');
    }
  } catch {
    checks.vsftpd_running = false;
  }

  // /etc/shells contient /bin/false ?
  try {
    const shells = fs.readFileSync('/etc/shells', 'utf8').split('\n').map(l => l.trim());
    checks.binfalse_in_shells = shells.includes('/bin/false');
    if (!checks.binfalse_in_shells) {
      checks.ok = false;
      checks.issues.push('/bin/false absent de /etc/shells — echo "/bin/false" >> /etc/shells');
    }
  } catch { checks.binfalse_in_shells = null; }

  // vsftpd.conf — uniquement les directives actives (non commentées)
  checks.vsftpd_conf = {};
  const CONF_KEYS = ['local_enable','write_enable','chroot_local_user','allow_writeable_chroot','userlist_enable','userlist_deny','userlist_file','pam_service_name'];
  const CONF_EXPECTED = { local_enable:'YES', write_enable:'YES', chroot_local_user:'YES', allow_writeable_chroot:'YES', userlist_enable:'YES', userlist_deny:'NO' };
  try {
    const conf = fs.readFileSync('/etc/vsftpd.conf', 'utf8');
    for (const key of CONF_KEYS) {
      const m = conf.match(new RegExp(`^${key}=(.*)`, 'm')); // ^ = début de ligne, sans #
      const val = m ? m[1].trim() : null;
      checks.vsftpd_conf[key] = val ?? 'absent';
      if (CONF_EXPECTED[key] && val !== CONF_EXPECTED[key]) {
        checks.ok = false;
        checks.issues.push(`vsftpd.conf : ${key}=${CONF_EXPECTED[key]} requis (actuel: ${val ?? 'absent/commenté'})`);
      }
    }
  } catch {
    checks.vsftpd_conf.error = '/etc/vsftpd.conf introuvable';
    checks.ok = false;
    checks.issues.push('/etc/vsftpd.conf introuvable');
  }

  // vsftpd.userlist
  try {
    checks.userlist_exists = true;
    checks.userlist = fs.readFileSync('/etc/vsftpd.userlist', 'utf8')
      .split('\n').map(l => l.trim()).filter(Boolean);
  } catch {
    checks.userlist_exists = false;
    checks.userlist = null;
  }

  // Port 21 en écoute — grep retourne exit 1 si rien, on force || echo ""
  try {
    const out = await runCmd('ss -tlnp 2>/dev/null | grep ":21" || netstat -tlnp 2>/dev/null | grep ":21" || echo ""');
    checks.port21_open = out.trim().length > 0;
    if (!checks.port21_open) checks.issues.push('Port 21 non détecté en écoute');
  } catch { checks.port21_open = null; }

  // UFW — port 21 autorisé ?
  try {
    const ufw = await runCmd('ufw status 2>/dev/null | grep -i "21\\|ftp" || echo "no_rule"');
    checks.ufw_port21 = ufw.trim();
    if (!ufw.includes('ALLOW')) {
      checks.ok = false;
      checks.issues.push('Port 21 bloqué par UFW — ufw allow 21/tcp && ufw allow 20/tcp');
    }
  } catch { checks.ufw_port21 = null; }

  res.json(checks);
});

// ─── ROUTE: MON PROFIL (utilisateur connecté) ────────────────────────────────
app.get('/api/me', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  // Uptime serveur en secondes (via /proc/uptime, plus fiable que la commande uptime)
  let uptimeSeconds = null;
  try {
    const raw = await runCmd('cat /proc/uptime');
    uptimeSeconds = Math.floor(parseFloat(raw.split(' ')[0]));
  } catch {}

  // Nombre de bases actuelles
  let dbCount = 0;
  try { dbCount = (await getUserDatabases(user.username)).length; } catch {}

  // Comptage réel des domaines et sous-domaines appartenant à l'utilisateur
  let domainCount = 0, subdomainCount = 0;
  try {
    if (fs.existsSync(CONFIG.APACHE_SITES_PATH)) {
      const files = fs.readdirSync(CONFIG.APACHE_SITES_PATH)
        .filter(f => f.endsWith('.conf') && !['000-default.conf','default-ssl.conf'].includes(f) && !f.includes('-le-ssl.conf') && !f.includes('phpmyadmin'));
      for (const file of files) {
        const conf    = fs.readFileSync(path.join(CONFIG.APACHE_SITES_PATH, file), 'utf8');
        const docRoot = (conf.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim() || '';
        if (!userOwnsDocRoot(user, docRoot)) continue;
        file.replace('.conf','').split('.').length > 2 ? subdomainCount++ : domainCount++;
      }
    }
  } catch {}

  res.json({
    id:             user.id,
    username:       user.username,
    role:           user.role,
    createdAt:      user.createdAt || null,
    templateName:   user.templateName   || null,
    // FTP
    ftpAccounts:    user.ftpAccounts || [],
    ftpLimit:       user.ftpLimit       ?? CONFIG.FTP_DEFAULT_LIMIT,
    // Bases de données
    dbLimit:        user.dbLimit        ?? CONFIG.DB_DEFAULT_LIMIT,
    dbCount,
    dbStorageLimit: user.dbStorageLimit ?? 0,
    // Domaines
    domainLimit:    user.domainLimit    ?? 0,
    subdomainLimit: user.subdomainLimit ?? 0,
    domainCount,
    subdomainCount,
    // Disque
    diskLimit:      user.diskLimit      ?? 0,
    // Crontab
    cronLimit:      user.cronLimit      ?? 10,
    // Serveur
    uptimeSeconds
  });
});

// ─── ROUTES: BASES DE DONNÉES PERSONNELLES ────────────────────────────────────

// Lister les bases de l'utilisateur connecté
app.get('/api/me/databases', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const databases = await getUserDatabases(user.username);
  const limit = user.dbLimit ?? CONFIG.DB_DEFAULT_LIMIT;
  res.json({ databases, count: databases.length, limit });
});

// Créer une base de données
app.post('/api/me/databases', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  const { dbName, dbPassword } = req.body;
  if (!dbName || !dbPassword)
    return res.status(400).json({ error: 'Nom de base et mot de passe requis' });

  if (!/^[a-zA-Z0-9_]{1,32}$/.test(dbName))
    return res.status(400).json({ error: 'Nom invalide (lettres, chiffres, _ — 32 car. max)' });

  const limit = user.dbLimit ?? CONFIG.DB_DEFAULT_LIMIT;
  const current = await getUserDatabases(user.username);
  if (limit > 0 && current.length >= limit)
    return res.status(403).json({ error: `Limite atteinte (${limit} base${limit > 1 ? 's' : ''} maximum)` });

  // Vérifier le quota de stockage par base
  const storageLimit = user.dbStorageLimit ?? 0;
  if (storageLimit > 0 && current.length > 0) {
    let totalUsed = 0;
    for (const db of current) totalUsed += await getDbSizeMb(db);
    const avgUsed = totalUsed / current.length;
    if (avgUsed >= storageLimit)
      return res.status(403).json({ error: `Quota de stockage BDD atteint (${storageLimit} Mo par base)` });
  }

  const fullName = `${user.username}_${dbName}`;
  // Échapper le mot de passe pour SQL (simple quotes)
  const safePass = dbPassword.replace(/\\/g, '\\\\').replace(/'/g, "\\'");

  try {
    // Tout en une seule requête pour éviter les problèmes de connexion multiples
    const sql = [
      `CREATE DATABASE IF NOT EXISTS \`${fullName}\`;`,
      `CREATE USER IF NOT EXISTS '${user.username}'@'localhost' IDENTIFIED BY '${safePass}';`,
      `GRANT ALL PRIVILEGES ON \`${fullName}\`.* TO '${user.username}'@'localhost';`,
      `FLUSH PRIVILEGES;`
    ].join('\n');

    await mysqlCmd(sql);
    log('DB_CREATE', `${user.username} → ${fullName}`, 'OK');
    res.status(201).json({ success: true, message: `Base ${fullName} créée`, database: fullName });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Supprimer une base de données
app.delete('/api/me/databases/:name', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  const safeName = req.params.name.replace(/[^a-zA-Z0-9_]/g, '');
  // Sécurité : le nom doit commencer par le préfixe de l'utilisateur
  if (!safeName.startsWith(`${user.username}_`))
    return res.status(403).json({ error: 'Cette base ne vous appartient pas' });

  try {
    await mysqlCmd(`DROP DATABASE IF EXISTS \`${safeName}\`;`);
    log('DB_DELETE', `${user.username} → ${safeName}`, 'OK');
    res.json({ success: true, message: `Base ${safeName} supprimée` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── ROUTE ADMIN : définir la limite de BDD d'un utilisateur ─────────────────
app.put('/api/users/:id/dblimit', authMiddleware, adminOnly, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  const { limit } = req.body;
  if (typeof limit !== 'number' || limit < 0 || limit > 100)
    return res.status(400).json({ error: 'Limite invalide (0-100)' });

  user.dbLimit = limit;
  saveUsers();
  log('DB_LIMIT', `${user.username} → ${limit} par ${req.user.username}`, 'OK');
  res.json({ success: true, message: `Limite fixée à ${limit} base${limit > 1 ? 's' : ''} pour ${user.username}` });
});

app.put('/api/users/:id/dbstoragelimit', authMiddleware, adminOnly, (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const mb = parseInt(req.body.limit);
  if (isNaN(mb) || mb < 0) return res.status(400).json({ error: 'Quota invalide (Mo, 0 = illimité)' });
  user.dbStorageLimit = mb;
  saveUsers();
  log('DB_STORAGE_LIMIT', `${user.username} → ${mb} Mo par ${req.user.username}`, 'OK');
  const label = mb === 0 ? 'illimité' : `${mb} Mo`;
  res.json({ success: true, message: `Quota stockage BDD fixé à ${label} pour ${user.username}` });
});

// ─── ROUTE ADMIN : quota disque utilisateur ──────────────────────────────────
app.put('/api/users/:id/disklimit', authMiddleware, adminOnly, (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const { limit } = req.body;
  const mb = parseInt(limit);
  if (isNaN(mb) || mb < 0) return res.status(400).json({ error: 'Quota invalide (Mo, 0 = illimité)' });
  user.diskLimit = mb;
  saveUsers();
  log('DISK_LIMIT', `${user.username} → ${mb} Mo par ${req.user.username}`, 'OK');
  const label = mb === 0 ? 'illimité' : `${mb} Mo`;
  res.json({ success: true, message: `Quota disque fixé à ${label} pour ${user.username}` });
});

// Usage disque réel d'un utilisateur
app.get('/api/users/:id/diskusage', authMiddleware, adminOnly, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const userDir = `${CONFIG.FTP_ROOT}/${user.username}`;
  let usedMb = 0;
  try {
    if (fs.existsSync(userDir)) {
      const out = await runCmd(`du -sm "${userDir}" 2>/dev/null | cut -f1`);
      usedMb = parseInt(out.trim()) || 0;
    }
  } catch {}
  const limitMb = user.diskLimit ?? 0;
  const pct = limitMb > 0 ? Math.min(100, Math.round(usedMb / limitMb * 100)) : null;
  res.json({ usedMb, limitMb, percent: pct, dir: userDir });
});

// Usage disque — route utilisateur (profil)
app.get('/api/me/diskusage', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const userDir = `${CONFIG.FTP_ROOT}/${user.username}`;
  let usedMb = 0;
  try {
    if (fs.existsSync(userDir)) {
      const out = await runCmd(`du -sm "${userDir}" 2>/dev/null | cut -f1`);
      usedMb = parseInt(out.trim()) || 0;
    }
  } catch {}
  const limitMb = user.diskLimit ?? 0;
  const pct = limitMb > 0 ? Math.min(100, Math.round(usedMb / limitMb * 100)) : null;
  res.json({ usedMb, limitMb, percent: pct });
});

// ─── ROUTES: CRONTAB UTILISATEUR ─────────────────────────────────────────────

// Helpers cron
function parseUserCrontab(raw) {
  const lines = raw.split('\n');
  const entries = [];
  let idx = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#!')) continue;
    // Commentaire de label juste avant
    let label = '';
    if (i > 0 && lines[i - 1].trim().startsWith('# KP:')) {
      label = lines[i - 1].trim().replace(/^# KP:\s*/, '');
    }
    if (line.startsWith('#')) continue;
    // Parser les 5 champs + commande
    const m = line.match(/^(@\S+|\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(.+)$/);
    if (!m) continue;
    entries.push({ id: ++idx, schedule: m[1].trim(), command: m[2].trim(), label });
  }
  return entries;
}

function buildCrontabLine(label, schedule, command) {
  return (label ? `# KP: ${label}\n` : '') + `${schedule} ${command}`;
}

// Helpers crontab — lecture/écriture via shell (droits root)
const CRONTAB_DIR = '/var/spool/cron/crontabs';

function readUserCrontabFile(username) {
  const p = `${CRONTAB_DIR}/${username}`;
  try { return fs.readFileSync(p, 'utf8'); } catch { return ''; }
}

async function writeUserCrontabFile(username, content) {
  await runCmd(`sudo mkdir -p ${CRONTAB_DIR}`);
  const filePath = `${CRONTAB_DIR}/${username}`;
  // Écrire via un fichier tmp pour éviter les problèmes d'échappement shell
  const tmpPath = `/tmp/kp_cron_${username}_${Date.now()}`;
  fs.writeFileSync(tmpPath, content, 'utf8');
  await runCmd(`sudo cp "${tmpPath}" "${filePath}" && sudo chmod 600 "${filePath}" && sudo chown ${username}: "${filePath}" 2>/dev/null; rm -f "${tmpPath}"`);
}

// GET /api/me/crontab
app.get('/api/me/crontab', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  try {
    const raw = readUserCrontabFile(user.username);
    res.json({ entries: parseUserCrontab(raw), raw });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/me/crontab — ajouter une entrée
app.post('/api/me/crontab', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const { label = '', schedule, command } = req.body;
  if (!schedule || !command) return res.status(400).json({ error: 'schedule et command requis' });
  const cronField = '(\\*|\\*/\\d+|\\d+(-\\d+)?(,\\d+(-\\d+)?)*(\/\\d+)?)';
  const validSchedule = new RegExp(
    `^(@(reboot|hourly|daily|weekly|monthly|yearly|annually)|(${cronField}\\s+){4}${cronField})$`
  ).test(schedule.trim());
  if (!validSchedule) return res.status(400).json({ error: 'Expression cron invalide' });
  const forbidden = ['rm -rf /', 'mkfs', ':(){ :|:& };:', 'dd if=/dev/zero'];
  if (forbidden.some(f => command.includes(f)))
    return res.status(400).json({ error: 'Commande non autorisée' });
  try {
    const raw      = readUserCrontabFile(user.username);
    const existing = parseUserCrontab(raw);
    const cronLimit = user.cronLimit ?? 10;
    if (cronLimit > 0 && existing.length >= cronLimit)
      return res.status(403).json({ error: `Limite atteinte : ${cronLimit} tâche${cronLimit > 1 ? 's' : ''} maximum` });
    const newLine    = buildCrontabLine(label.slice(0, 80), schedule.trim(), command.trim());
    const newContent = (raw.trim() ? raw.trim() + '\n' : '') + newLine + '\n';
    await writeUserCrontabFile(user.username, newContent);
    log('CRONTAB_ADD', `${user.username}: ${schedule} ${command}`, 'OK');
    res.json({ success: true, message: 'Tâche planifiée ajoutée' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// DELETE /api/me/crontab/:id — supprimer une entrée par index
app.delete('/api/me/crontab/:id', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const targetId = parseInt(req.params.id);
  if (isNaN(targetId)) return res.status(400).json({ error: 'ID invalide' });
  try {
    const raw   = readUserCrontabFile(user.username);
    const lines = raw.split('\n');

    // Reconstruire les entrées avec leurs numéros de ligne réels
    const entries = [];
    let idx = 0;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('#!')) continue;
      if (line.startsWith('#')) continue;
      const m = line.match(/^(@\S+|\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(.+)$/);
      if (!m) continue;
      let labelLine = -1;
      if (i > 0 && lines[i - 1].trim().startsWith('# KP:')) labelLine = i - 1;
      entries.push({ id: ++idx, lineIndex: i, labelLineIndex: labelLine });
    }

    const entry = entries.find(e => e.id === targetId);
    if (!entry) return res.status(404).json({ error: 'Entrée introuvable' });

    // Supprimer les lignes concernées (label + commande)
    const toRemove = new Set([entry.lineIndex]);
    if (entry.labelLineIndex >= 0) toRemove.add(entry.labelLineIndex);
    const filtered = lines.filter((_, i) => !toRemove.has(i));

    // Nettoyer les lignes vides consécutives
    const cleaned = filtered.join('\n').replace(/\n{3,}/g, '\n\n').trim();
    await writeUserCrontabFile(user.username, cleaned ? cleaned + '\n' : '');
    log('CRONTAB_DEL', `${user.username}: entrée #${targetId}`, 'OK');
    res.json({ success: true, message: 'Tâche supprimée' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── ROUTE: EXPLORATEUR DE FICHIERS UTILISATEUR ──────────────────────────────

// Helper : résoudre et sécuriser un chemin dans le répertoire FTP de l'utilisateur
function safeUserPath(user, reqPath) {
  const baseDir = path.resolve(getPrimaryFtpDir(user));
  const target  = reqPath ? path.resolve(baseDir, reqPath.replace(/^\/+/, '')) : baseDir;
  if (!target.startsWith(baseDir + path.sep) && target !== baseDir)
    throw new Error('Accès refusé — chemin hors de votre répertoire');
  return target;
}

// Extensions éditables en texte
const TEXT_EXTS = new Set([
  '.php','.html','.htm','.css','.js','.ts','.json','.xml','.txt','.md',
  '.env','.htaccess','.htpasswd','.ini','.conf','.yaml','.yml','.sh',
  '.sql','.csv','.log','.twig','.blade','.vue','.jsx','.tsx','.svg'
]);

// GET /api/me/files — lister un dossier
app.get('/api/me/files', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  try {
    const dir = safeUserPath(user, req.query.path || '');
    if (!fs.existsSync(dir)) return res.status(404).json({ error: 'Dossier introuvable' });
    const stat = fs.statSync(dir);
    if (!stat.isDirectory()) return res.status(400).json({ error: 'Ce chemin n\'est pas un dossier' });

    const entries = fs.readdirSync(dir).map(name => {
      try {
        const full = path.join(dir, name);
        const s    = fs.statSync(full);
        const ext  = path.extname(name).toLowerCase();
        return {
          name,
          type:     s.isDirectory() ? 'dir' : 'file',
          size:     s.isFile() ? s.size : null,
          mtime:    s.mtime.toISOString(),
          ext:      s.isFile() ? ext : null,
          editable: s.isFile() && TEXT_EXTS.has(ext),
          perms:    (s.mode & 0o777).toString(8)
        };
      } catch { return null; }
    }).filter(Boolean);

    // Dossiers en premier, puis fichiers, tri alphabétique
    entries.sort((a, b) => {
      if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
      return a.name.localeCompare(b.name);
    });

    const baseDir = path.resolve(getPrimaryFtpDir(user));
    const relPath = path.relative(baseDir, dir);
    res.json({ path: relPath || '', entries, base: baseDir });
  } catch (err) { res.status(err.message.startsWith('Accès') ? 403 : 500).json({ error: err.message }); }
});

// GET /api/me/files/content — lire un fichier
app.get('/api/me/files/content', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  try {
    const file = safeUserPath(user, req.query.path || '');
    if (!fs.existsSync(file)) return res.status(404).json({ error: 'Fichier introuvable' });
    const s = fs.statSync(file);
    if (!s.isFile()) return res.status(400).json({ error: 'Ce chemin n\'est pas un fichier' });
    if (s.size > 2 * 1024 * 1024) return res.status(400).json({ error: 'Fichier trop grand pour l\'éditeur (2 Mo max)' });
    const ext = path.extname(file).toLowerCase();
    if (!TEXT_EXTS.has(ext)) return res.status(400).json({ error: 'Type de fichier non éditable' });
    const content = fs.readFileSync(file, 'utf8');
    res.json({ content, path: req.query.path, size: s.size, mtime: s.mtime.toISOString() });
  } catch (err) { res.status(err.message.startsWith('Accès') ? 403 : 500).json({ error: err.message }); }
});

// PUT /api/me/files/content — sauvegarder un fichier édité
app.put('/api/me/files/content', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const { path: reqPath, content } = req.body;
  if (content === undefined) return res.status(400).json({ error: 'Contenu requis' });
  try {
    const file = safeUserPath(user, reqPath);
    const ext  = path.extname(file).toLowerCase();
    if (!TEXT_EXTS.has(ext)) return res.status(400).json({ error: 'Type de fichier non éditable' });
    fs.writeFileSync(file, content, 'utf8');
    log('FILE_EDIT', `${user.username}: ${reqPath}`, 'OK');
    res.json({ success: true, message: 'Fichier sauvegardé' });
  } catch (err) { res.status(err.message.startsWith('Accès') ? 403 : 500).json({ error: err.message }); }
});

// POST /api/me/files/mkdir — créer un dossier
app.post('/api/me/files/mkdir', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const { path: reqPath } = req.body;
  if (!reqPath) return res.status(400).json({ error: 'Chemin requis' });
  try {
    const dir = safeUserPath(user, reqPath);
    if (fs.existsSync(dir)) return res.status(409).json({ error: 'Ce dossier existe déjà' });
    fs.mkdirSync(dir, { recursive: true });
    log('FILE_MKDIR', `${user.username}: ${reqPath}`, 'OK');
    res.json({ success: true, message: 'Dossier créé' });
  } catch (err) { res.status(err.message.startsWith('Accès') ? 403 : 500).json({ error: err.message }); }
});

// POST /api/me/files/touch — créer un fichier vide
app.post('/api/me/files/touch', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const { path: reqPath } = req.body;
  if (!reqPath) return res.status(400).json({ error: 'Chemin requis' });
  try {
    const file = safeUserPath(user, reqPath);
    if (fs.existsSync(file)) return res.status(409).json({ error: 'Ce fichier existe déjà' });
    fs.writeFileSync(file, '', 'utf8');
    log('FILE_TOUCH', `${user.username}: ${reqPath}`, 'OK');
    res.json({ success: true, message: 'Fichier créé' });
  } catch (err) { res.status(err.message.startsWith('Accès') ? 403 : 500).json({ error: err.message }); }
});

// POST /api/me/files/rename — renommer
app.post('/api/me/files/rename', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const { path: reqPath, newName } = req.body;
  if (!reqPath || !newName) return res.status(400).json({ error: 'Chemin et nouveau nom requis' });
  if (newName.includes('/') || newName.includes('\\')) return res.status(400).json({ error: 'Nom invalide' });
  try {
    const src  = safeUserPath(user, reqPath);
    const dest = path.join(path.dirname(src), newName);
    safeUserPath(user, path.relative(path.resolve(getPrimaryFtpDir(user)), dest));
    if (!fs.existsSync(src)) return res.status(404).json({ error: 'Source introuvable' });
    if (fs.existsSync(dest)) return res.status(409).json({ error: 'Un fichier avec ce nom existe déjà' });
    fs.renameSync(src, dest);
    log('FILE_RENAME', `${user.username}: ${reqPath} → ${newName}`, 'OK');
    res.json({ success: true, message: 'Renommé avec succès' });
  } catch (err) { res.status(err.message.startsWith('Accès') ? 403 : 500).json({ error: err.message }); }
});

// DELETE /api/me/files — supprimer un fichier ou dossier
app.delete('/api/me/files', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const reqPath = req.body.path || req.query.path;
  if (!reqPath) return res.status(400).json({ error: 'Chemin requis' });
  try {
    const target = safeUserPath(user, reqPath);
    const base   = path.resolve(getPrimaryFtpDir(user));
    if (target === base) return res.status(403).json({ error: 'Impossible de supprimer le répertoire racine' });
    if (!fs.existsSync(target)) return res.status(404).json({ error: 'Fichier introuvable' });
    fs.rmSync(target, { recursive: true, force: true });
    log('FILE_DELETE', `${user.username}: ${reqPath}`, 'OK');
    res.json({ success: true, message: 'Supprimé avec succès' });
  } catch (err) { res.status(err.message.startsWith('Accès') ? 403 : 500).json({ error: err.message }); }
});

// GET /api/me/files/download — télécharger un fichier
app.get('/api/me/files/download', async (req, res) => {
  // Accepter le token en query string pour les téléchargements directs
  let userId;
  try {
    const t = req.query.token || (req.headers.authorization || '').replace('Bearer ', '');
    const decoded = require('jsonwebtoken').verify(t, CONFIG.JWT_SECRET);
    userId = decoded.id;
  } catch { return res.status(401).json({ error: 'Token invalide' }); }
  const user = USERS.find(u => u.id === parseInt(userId));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  try {
    const file = safeUserPath(user, req.query.path || '');
    if (!fs.existsSync(file) || !fs.statSync(file).isFile())
      return res.status(404).json({ error: 'Fichier introuvable' });
    res.download(file);
  } catch (err) { res.status(err.message.startsWith('Accès') ? 403 : 500).json({ error: err.message }); }
});

// POST /api/me/files/upload — uploader un ou plusieurs fichiers
app.post('/api/me/files/upload', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  // Récupérer les données multipart manuellement avec busboy
  let busboy;
  try { busboy = require('busboy')({ headers: req.headers, limits: { fileSize: 100 * 1024 * 1024 } }); }
  catch { return res.status(500).json({ error: 'Module busboy non disponible — npm install busboy' }); }

  const targetDir = safeUserPath(user, req.query.path || '');
  if (!fs.existsSync(targetDir)) return res.status(404).json({ error: 'Dossier cible introuvable' });

  const uploaded = [];
  const errors   = [];

  busboy.on('file', (fieldname, file, info) => {
    const { filename } = info;
    if (!filename) { file.resume(); return; }
    const safeName = path.basename(filename);
    let destPath;
    try { destPath = safeUserPath(user, path.join(req.query.path || '', safeName)); }
    catch { file.resume(); errors.push(`${safeName}: accès refusé`); return; }

    const ws = fs.createWriteStream(destPath);
    file.pipe(ws);
    ws.on('finish', () => uploaded.push(safeName));
    ws.on('error', e => errors.push(`${safeName}: ${e.message}`));
  });

  busboy.on('finish', () => {
    log('FILE_UPLOAD', `${user.username}: ${uploaded.length} fichier(s) → ${req.query.path || '/'}`, 'OK');
    res.json({ success: true, uploaded, errors });
  });

  busboy.on('error', err => res.status(500).json({ error: err.message }));
  req.pipe(busboy);
});

// POST /api/me/files/chmod — changer les permissions
app.post('/api/me/files/chmod', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const { path: reqPath, mode } = req.body;
  if (!reqPath || !mode) return res.status(400).json({ error: 'Chemin et mode requis' });
  const modeNum = parseInt(mode, 8);
  if (isNaN(modeNum) || modeNum < 0 || modeNum > 0o777)
    return res.status(400).json({ error: 'Mode invalide (ex: 644, 755)' });
  try {
    const target = safeUserPath(user, reqPath);
    if (!fs.existsSync(target)) return res.status(404).json({ error: 'Fichier introuvable' });
    fs.chmodSync(target, modeNum);
    log('FILE_CHMOD', `${user.username}: ${reqPath} → ${mode}`, 'OK');
    res.json({ success: true, message: `Permissions modifiées : ${mode}` });
  } catch (err) { res.status(err.message.startsWith('Accès') ? 403 : 500).json({ error: err.message }); }
});

// ─── ROUTE ADMIN : lister les bases d'un utilisateur ────────────────────────
app.get('/api/users/:id/databases', authMiddleware, adminOnly, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const databases = await getUserDatabases(user.username);
  const limit = user.dbLimit ?? CONFIG.DB_DEFAULT_LIMIT;
  res.json({ databases, count: databases.length, limit });
});

// ─── ROUTE ADMIN : supprimer une base d'un utilisateur ──────────────────────
app.delete('/api/users/:id/databases/:dbname', authMiddleware, adminOnly, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const safeName = req.params.dbname.replace(/[^a-zA-Z0-9_]/g, '');
  if (!safeName.startsWith(`${user.username}_`))
    return res.status(403).json({ error: 'Base invalide' });
  try {
    await mysqlCmd(`DROP DATABASE IF EXISTS \`${safeName}\`;`);
    log('DB_DELETE_ADMIN', `${user.username} → ${safeName} par ${req.user.username}`, 'OK');
    res.json({ success: true, message: `Base ${safeName} supprimée` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── HELPER : taille réelle d'une base MariaDB ───────────────────────────────
async function getDbSizeMb(dbName) {
  try {
    const out = await mysqlCmd(
      `SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) FROM information_schema.TABLES WHERE table_schema = '${dbName}';`
    );
    return parseFloat(out.trim()) || 0;
  } catch { return 0; }
}

// Usage stockage d'une base (utilisateur ou admin)
app.get('/api/databases/:dbname/usage', authMiddleware, async (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const dbname  = req.params.dbname.replace(/[^a-zA-Z0-9_]/g, '');
  const user    = USERS.find(u => u.id === parseInt(req.user.id));
  if (!isAdmin) {
    const dbs = await getUserDatabases(user.username).catch(() => []);
    if (!dbs.includes(dbname)) return res.status(403).json({ error: 'Cette base ne vous appartient pas' });
  }
  const usedMb    = await getDbSizeMb(dbname);
  const limitMb   = user?.dbStorageLimit ?? 0;
  const percent   = limitMb > 0 ? Math.min(100, Math.round(usedMb / limitMb * 100)) : null;
  res.json({ usedMb, limitMb, percent, dbname });
});

// ─── HELPER : dirs FTP d'un utilisateur ──────────────────────────────────────
function getUserFtpDirs(user) {
  return (user.ftpAccounts || []).map(a => a.dir);
}

function userOwnsDocRoot(user, docRoot) {
  return getUserFtpDirs(user).some(dir => docRoot.startsWith(dir));
}

function getPrimaryFtpDir(user) {
  const accounts = user.ftpAccounts || [];
  const main = accounts.find(a => a.ftpUsername === user.username) || accounts[0];
  return main ? main.dir : `${CONFIG.FTP_ROOT}/${user.username}`;
}

// Lister les domaines de l'utilisateur connecté
app.get('/api/me/domains', authMiddleware, (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  if (!user.ftpAccounts || !user.ftpAccounts.length)
    return res.status(403).json({ error: 'Aucun compte FTP configuré. Contactez l\'administrateur.' });

  try {
    if (!fs.existsSync(CONFIG.APACHE_SITES_PATH)) return res.json({ domains: [] });
    const files = fs.readdirSync(CONFIG.APACHE_SITES_PATH)
      .filter(f => f.endsWith('.conf') && !['000-default.conf','default-ssl.conf'].includes(f) && !f.includes('-le-ssl.conf') && !f.includes('phpmyadmin'));

    const domains = files
      .map(file => {
        const name = file.replace('.conf', '');
        const conf = fs.readFileSync(path.join(CONFIG.APACHE_SITES_PATH, file), 'utf8');
        const docRoot = (conf.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim() || '';
        const isEnabled = fs.existsSync(path.join(CONFIG.APACHE_ENABLED_PATH, file));
        const ports = [...conf.matchAll(/<VirtualHost\s+[^:>]+:(\d+)/gi)].map(m => parseInt(m[1]));
        const hasSsl = ports.includes(443);

        // Jours SSL restants
        let sslDaysLeft = null;
        if (hasSsl) {
          const sslCertPath = `/etc/letsencrypt/live/${name}/fullchain.pem`;
          if (fs.existsSync(sslCertPath)) {
            try {
              const { execSync } = require('child_process');
              const out = execSync(`openssl x509 -enddate -noout -in "${sslCertPath}" 2>/dev/null`, { timeout: 5000 }).toString().trim();
              const match = out.match(/notAfter=(.+)/);
              if (match) sslDaysLeft = Math.max(0, Math.ceil((new Date(match[1]).getTime() - Date.now()) / (1000 * 60 * 60 * 24)));
            } catch {}
          }
        }

        return {
          name,
          domain: (conf.match(/ServerName\s+(.+)/) || [])[1]?.trim() || name,
          docRoot,
          phpVersion: (conf.match(/php(\d+\.\d+)-fpm/) || [])[1] || CONFIG.PHP_VERSION,
          enabled: isEnabled,
          isSubdomain: name.split('.').length > 2,
          hasSsl,
          sslDaysLeft,
          ports
        };
      })
      .filter(d => userOwnsDocRoot(user, d.docRoot));

    res.json({
      domains,
      ftpDir: getPrimaryFtpDir(user),
      domainLimit:    user.domainLimit    ?? 0,
      subdomainLimit: user.subdomainLimit ?? 0,
      domainCount:    domains.filter(d => !d.isSubdomain).length,
      subdomainCount: domains.filter(d =>  d.isSubdomain).length,
      templateName:   user.templateName   || null
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Créer un domaine/sous-domaine dans le répertoire FTP de l'utilisateur
app.post('/api/me/domains', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  if (!user.ftpAccounts || !user.ftpAccounts.length)
    return res.status(403).json({ error: 'Aucun compte FTP configuré. Contactez l\'administrateur.' });

  const { domain, phpVersion = CONFIG.PHP_VERSION } = req.body;
  if (!domain || !/^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$/.test(domain))
    return res.status(400).json({ error: 'Nom de domaine invalide' });

  const ftpDir = getPrimaryFtpDir(user);
  const safeDomain = domain.replace(/[^a-zA-Z0-9._-]/g, '').toLowerCase();
  const parts = safeDomain.split('.');
  const isSubdomain = parts.length > 2;

  // ── Vérification des limites ──
  if (fs.existsSync(CONFIG.APACHE_SITES_PATH)) {
    const allFiles = fs.readdirSync(CONFIG.APACHE_SITES_PATH)
      .filter(f => f.endsWith('.conf') && !['000-default.conf','default-ssl.conf'].includes(f) && !f.includes('-le-ssl.conf') && !f.includes('phpmyadmin'));
    const userDomains = allFiles.filter(f => {
      try {
        const c = fs.readFileSync(path.join(CONFIG.APACHE_SITES_PATH, f), 'utf8');
        const dr = (c.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim() || '';
        return userOwnsDocRoot(user, dr);
      } catch { return false; }
    }).map(f => f.replace('.conf', ''));

    if (isSubdomain) {
      const limit = user.subdomainLimit ?? 0;
      const count = userDomains.filter(n => n.split('.').length > 2).length;
      if (limit > 0 && count >= limit)
        return res.status(403).json({ error: `Limite de sous-domaines atteinte (${limit} maximum)` });
    } else {
      const limit = user.domainLimit ?? 0;
      const count = userDomains.filter(n => n.split('.').length <= 2).length;
      if (limit > 0 && count >= limit)
        return res.status(403).json({ error: `Limite de domaines atteinte (${limit} maximum)` });
    }
  }

  let webRoot;
  if (isSubdomain) {
    const parentDomain = parts.slice(1).join('.');
    const subName = parts[0];
    webRoot = `${ftpDir}/${parentDomain}/${subName}/public_html`;
  } else {
    webRoot = `${ftpDir}/${safeDomain}/public_html`;
  }

  const confFile = path.join(CONFIG.APACHE_SITES_PATH, `${safeDomain}.conf`);

  if (!fs.existsSync(CONFIG.APACHE_SITES_PATH))
    return res.json({ success: true, message: `Domaine ${safeDomain} créé (mode démo)`, webRoot });
  if (fs.existsSync(confFile))
    return res.status(409).json({ error: 'Ce domaine existe déjà' });

  try {
    await runCmd(`sudo mkdir -p "${webRoot}"`);
    const domainRoot = isSubdomain
      ? `${ftpDir}/${parts.slice(1).join('.')}`
      : `${ftpDir}/${safeDomain}`;
    await runCmd(`chown -R ${user.username}:${user.username} "${domainRoot}"`);

    const vhostConfig = isSubdomain
      ? generateVhostConfigSub(safeDomain, webRoot, phpVersion)
      : generateVhostConfig(safeDomain, webRoot, phpVersion, false);

    const tmpIdx  = `/tmp/kp_index_${Date.now()}.html`;
    const tmpConf = `/tmp/kp_vhost_${Date.now()}.conf`;
    fs.writeFileSync(tmpIdx,  defaultIndexPage(safeDomain, isSubdomain));
    fs.writeFileSync(tmpConf, vhostConfig);
    await runCmd(`sudo cp "${tmpIdx}"  "${webRoot}/index.html" && sudo chmod 644 "${webRoot}/index.html"`);
    await runCmd(`sudo cp "${tmpConf}" "${confFile}" && sudo chmod 644 "${confFile}"`);
    try { fs.unlinkSync(tmpIdx);  } catch {}
    try { fs.unlinkSync(tmpConf); } catch {}
    await runCmd(`a2ensite ${safeDomain}.conf`);
    await runCmd('systemctl reload apache2');
    log('USER_CREATE_DOMAIN', `${user.username} → ${safeDomain} (${webRoot})`, 'OK');

    // ── SSL automatique Let's Encrypt ────────────────────────────────────────
    // L'email est pris depuis la config DNS admin (champ "email SOA", ex: admin.kazylax.fr → admin@kazylax.fr)
    const dnsEmail = (dnsConf().email || '').replace(/^([^.]+)\./, '$1@');
    const sslResult = await tryIssueSsl(safeDomain, dnsEmail);

    const sslMsg = sslResult.success
      ? `🔒 SSL Let's Encrypt activé`
      : `⚠️ SSL non activé — ${sslResult.message}`;

    res.status(201).json({
      success: true,
      message: `${isSubdomain ? 'Sous-domaine' : 'Domaine'} ${safeDomain} créé — dossier : ${webRoot}`,
      ssl: sslResult,
      sslMessage: sslMsg,
      webRoot
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Voir la configuration Apache d'un domaine (utilisateur)
app.get('/api/me/domains/:name/config', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user || !user.ftpAccounts || !user.ftpAccounts.length) return res.status(403).json({ error: 'Accès refusé' });
  const safeName = req.params.name.replace(/[^a-zA-Z0-9._-]/g, '');
  const confFile = path.join(CONFIG.APACHE_SITES_PATH, `${safeName}.conf`);
  if (!fs.existsSync(confFile)) return res.status(404).json({ error: 'Configuration introuvable' });
  const conf = fs.readFileSync(confFile, 'utf8');
  const docRoot = (conf.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim() || '';
  if (!userOwnsDocRoot(user, docRoot)) return res.status(403).json({ error: 'Ce domaine ne vous appartient pas' });
  res.json({ name: safeName, config: conf });
});

// Modifier la configuration Apache d'un domaine (utilisateur)
app.put('/api/me/domains/:name/config', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user || !user.ftpAccounts || !user.ftpAccounts.length)
    return res.status(403).json({ error: 'Accès refusé' });

  const safeName = req.params.name.replace(/[^a-zA-Z0-9._-]/g, '');
  const confFile = path.join(CONFIG.APACHE_SITES_PATH, `${safeName}.conf`);
  if (!fs.existsSync(confFile)) return res.status(404).json({ error: 'Domaine introuvable' });

  const existing = fs.readFileSync(confFile, 'utf8');
  const docRoot  = (existing.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim() || '';
  if (!userOwnsDocRoot(user, docRoot))
    return res.status(403).json({ error: 'Ce domaine ne vous appartient pas' });

  const { config } = req.body;
  if (!config || !config.trim())
    return res.status(400).json({ error: 'Configuration vide' });

  // Vérifications de sécurité basiques
  const forbidden = ['exec', 'system(', 'passthru', 'shell_exec', 'popen', 'proc_open'];
  if (forbidden.some(f => config.toLowerCase().includes(f)))
    return res.status(400).json({ error: 'Configuration non autorisée' });

  // Le DocumentRoot ne doit pas changer
  const newDocRoot = (config.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim() || '';
  if (newDocRoot && !userOwnsDocRoot(user, newDocRoot))
    return res.status(400).json({ error: 'DocumentRoot non autorisé' });

  // Valider la config avec apache2ctl
  const tmpFile = `/tmp/vhost_check_${Date.now()}.conf`;
  try {
    fs.writeFileSync(tmpFile, config);
    await runCmd(`apache2ctl -t 2>&1 || apachectl -t 2>&1`).catch(() => {});
  } finally { try { fs.unlinkSync(tmpFile); } catch {} }

  try {
    const tmpConf = `/tmp/kp_vhost_${Date.now()}.conf`;
    fs.writeFileSync(tmpConf, config);
    await runCmd(`sudo cp "${tmpConf}" "${confFile}" && sudo chmod 644 "${confFile}"`);
    try { fs.unlinkSync(tmpConf); } catch {}
    await runCmd('systemctl reload apache2');
    log('USER_UPDATE_VHOST', `${user.username} → ${safeName}`, 'OK');
    res.json({ success: true, message: `Configuration de ${safeName} mise à jour et Apache rechargé` });
  } catch (err) {
    // Restaurer l'ancienne config en cas d'erreur
    const tmpRestore = `/tmp/kp_vhost_restore_${Date.now()}.conf`;
    fs.writeFileSync(tmpRestore, existing);
    await runCmd(`sudo cp "${tmpRestore}" "${confFile}"`).catch(() => {});
    try { fs.unlinkSync(tmpRestore); } catch {}
    res.status(500).json({ error: err.message });
  }
});

// Supprimer un domaine de l'utilisateur
app.delete('/api/me/domains/:name', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user || !user.ftpAccounts || !user.ftpAccounts.length)
    return res.status(403).json({ error: 'Aucun compte FTP configuré.' });

  const safeName = req.params.name.replace(/[^a-zA-Z0-9._-]/g, '');
  const confFile = path.join(CONFIG.APACHE_SITES_PATH, `${safeName}.conf`);

  if (!fs.existsSync(confFile))
    return res.status(404).json({ error: 'Domaine introuvable' });

  const conf = fs.readFileSync(confFile, 'utf8');
  const docRoot = (conf.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim() || '';
  if (!userOwnsDocRoot(user, docRoot))
    return res.status(403).json({ error: 'Ce domaine ne vous appartient pas' });

  try {
    await runCmd(`a2dissite ${safeName}.conf`);
    await runCmd(`sudo rm -f "${confFile}"`);
    const ftpDir = getPrimaryFtpDir(user);
    const domainDir = `${ftpDir}/${safeName}`;
    try { await runCmd(`rm -rf "${domainDir}"`); } catch {}
    await runCmd(`systemctl reload apache2`);
    log('USER_DELETE_DOMAIN', `${user.username} → ${safeName}`, 'OK');
    res.json({ success: true, message: `Domaine ${safeName} et ses fichiers supprimés` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── ROUTE: JOURNAUX APACHE D'UN DOMAINE UTILISATEUR ─────────────────────────
// GET /api/me/domains/:name/logs?type=error|access&lines=100
app.get('/api/me/domains/:name/logs', authMiddleware, (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user || !user.ftpAccounts || !user.ftpAccounts.length)
    return res.status(403).json({ error: 'Accès refusé' });

  const safeName = req.params.name.replace(/[^a-zA-Z0-9._-]/g, '');
  const confFile  = path.join(CONFIG.APACHE_SITES_PATH, `${safeName}.conf`);
  if (!fs.existsSync(confFile)) return res.status(404).json({ error: 'Domaine introuvable' });

  const conf = fs.readFileSync(confFile, 'utf8');
  const docRoot = (conf.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim() || '';
  if (!userOwnsDocRoot(user, docRoot))
    return res.status(403).json({ error: 'Ce domaine ne vous appartient pas' });

  const type  = (req.query.type  === 'access') ? 'access' : 'error';
  const lines = Math.min(Math.max(parseInt(req.query.lines) || 100, 10), 1000);

  // Résoudre le chemin réel du log depuis la directive ErrorLog / CustomLog du .conf
  // Apache résout ${APACHE_LOG_DIR} → /var/log/apache2
  const APACHE_LOG_DIR = '/var/log/apache2';
  let logFile;
  if (type === 'error') {
    const m = conf.match(/ErrorLog\s+(\S+)/);
    logFile  = m ? m[1].replace('${APACHE_LOG_DIR}', APACHE_LOG_DIR) : null;
  } else {
    const m = conf.match(/CustomLog\s+(\S+)/);
    logFile  = m ? m[1].replace('${APACHE_LOG_DIR}', APACHE_LOG_DIR) : null;
  }

  if (!logFile) return res.status(404).json({ error: `Directive ${type === 'error' ? 'ErrorLog' : 'CustomLog'} introuvable dans la configuration` });

  // Sécurité : le chemin doit rester dans /var/log/apache2
  const resolved = path.resolve(logFile);
  if (!resolved.startsWith('/var/log/apache2/'))
    return res.status(403).json({ error: 'Chemin de log non autorisé' });

  if (!fs.existsSync(resolved))
    return res.json({ file: resolved, lines: [], empty: true, message: 'Fichier journal vide ou inexistant — aucune entrée pour ce domaine.' });

  try {
    const raw = require('child_process').execSync(`tail -n ${lines} "${resolved}" 2>/dev/null`, { timeout: 5000 }).toString();
    const logLines = raw.split('\n').filter(l => l.trim());
    log('USER_VIEW_LOG', `${user.username} → ${resolved} (${lines} lignes)`, 'OK');
    res.json({ file: resolved, lines: logLines, total: logLines.length, type });
  } catch (err) {
    res.status(500).json({ error: `Impossible de lire le journal : ${err.message}` });
  }
});

// ─── ROUTE: LISTER LES DOMAINES (admin seulement) ────────────────────────────
app.get('/api/domains', authMiddleware, adminOnly, (req, res) => {
  try {
    if (!fs.existsSync(CONFIG.APACHE_SITES_PATH)) return res.json({ domains: getDemoDomains() });
    const files = fs.readdirSync(CONFIG.APACHE_SITES_PATH)
      .filter(f => f.endsWith('.conf') && !['000-default.conf','default-ssl.conf'].includes(f) && !f.includes('-le-ssl.conf') && !f.includes('phpmyadmin'));
    const domains = files.map(file => {
      const name = file.replace('.conf', '');
      const conf = fs.readFileSync(path.join(CONFIG.APACHE_SITES_PATH, file), 'utf8');
      const isEnabled = fs.existsSync(path.join(CONFIG.APACHE_ENABLED_PATH, file));
      const sslCertPath = `/etc/letsencrypt/live/${name}/fullchain.pem`;
      const hasSsl = conf.includes('VirtualHost *:443') || fs.existsSync(sslCertPath);

      // Calcul des jours restants avant expiration SSL (via openssl x509)
      let sslDaysLeft = null;
      if (hasSsl && fs.existsSync(sslCertPath)) {
        try {
          const { execSync } = require('child_process');
          const out = execSync(
            `openssl x509 -enddate -noout -in "${sslCertPath}" 2>/dev/null`,
            { timeout: 5000 }
          ).toString().trim();
          // Format: notAfter=Mar 22 12:00:00 2026 GMT
          const match = out.match(/notAfter=(.+)/);
          if (match) {
            const expDate = new Date(match[1]);
            sslDaysLeft = Math.max(0, Math.ceil((expDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24)));
          }
        } catch {}
      }

      return {
        name,
        domain: (conf.match(/ServerName\s+(.+)/) || [])[1]?.trim() || name,
        docRoot: (conf.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim() || `${CONFIG.WEB_ROOT}/${name}/public_html`,
        phpVersion: (conf.match(/php(\d+\.\d+)-fpm/) || [])[1] || CONFIG.PHP_VERSION,
        enabled: isEnabled,
        isSubdomain: name.split('.').length > 2,
        ssl: hasSsl,
        sslDaysLeft
      };
    });
    res.json({ domains });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── ROUTE: CRÉER UN DOMAINE (admin seulement) ───────────────────────────────
app.post('/api/domains', authMiddleware, adminOnly, async (req, res) => {
  const { domain, phpVersion = CONFIG.PHP_VERSION, enableSsl = false, docRoot } = req.body;
  if (!domain || !/^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$/.test(domain))
    return res.status(400).json({ error: 'Nom de domaine invalide' });
  const safeDomain = domain.replace(/[^a-zA-Z0-9._-]/g, '');
  const webRoot = docRoot || `${CONFIG.WEB_ROOT}/${safeDomain}/public_html`;
  const confFile = path.join(CONFIG.APACHE_SITES_PATH, `${safeDomain}.conf`);
  if (!fs.existsSync(CONFIG.APACHE_SITES_PATH))
    return res.json({ success: true, message: `Domaine ${safeDomain} créé (mode démo)`, domain: safeDomain });
  if (fs.existsSync(confFile)) return res.status(409).json({ error: 'Ce domaine existe déjà' });
  try {
    await runCmd(`sudo mkdir -p "${webRoot}"`);
    await runCmd(`chown -R www-data:www-data "${webRoot}"`);
    const tmpIdx  = `/tmp/kp_index_${Date.now()}.html`;
    const tmpConf = `/tmp/kp_vhost_${Date.now()}.conf`;
    fs.writeFileSync(tmpIdx,  defaultIndexPage(safeDomain, false));
    fs.writeFileSync(tmpConf, generateVhostConfig(safeDomain, webRoot, phpVersion, enableSsl));
    await runCmd(`sudo cp "${tmpIdx}"  "${webRoot}/index.html" && sudo chmod 644 "${webRoot}/index.html"`);
    await runCmd(`sudo cp "${tmpConf}" "${confFile}" && sudo chmod 644 "${confFile}"`);
    try { fs.unlinkSync(tmpIdx);  } catch {}
    try { fs.unlinkSync(tmpConf); } catch {}
    await runCmd(`a2ensite ${safeDomain}.conf`);
    await runCmd('systemctl reload apache2');
    log('CREATE_DOMAIN', safeDomain, 'OK');
    res.json({ success: true, message: `Domaine ${safeDomain} créé avec succès`, domain: safeDomain });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── PAGE D'ACCUEIL PAR DÉFAUT (créée avec chaque nouveau domaine) ────────────
function defaultIndexPage(domain, isSubdomain) {
  const type = isSubdomain ? 'sous-domaine' : 'domaine';
  const year = new Date().getFullYear();
  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${domain} — Hébergement actif</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #0f1117;
      --surface: #171c2a;
      --surface2: #1e2438;
      --border: rgba(255,255,255,.07);
      --accent: #4f6ef7;
      --accent2: #7c8fff;
      --text: #e8ecf4;
      --muted: #6b7280;
      --green: #22c55e;
    }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    /* ── Header ── */
    header {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 0 40px;
      height: 60px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .header-brand {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 14px;
      font-weight: 600;
      color: var(--text);
      text-decoration: none;
    }
    .header-brand .logo {
      width: 30px;
      height: 30px;
      background: linear-gradient(135deg, var(--accent), #6d5acd);
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 15px;
    }
    .header-tag {
      font-size: 11px;
      color: var(--muted);
      font-weight: 400;
    }
    .header-domain {
      font-family: 'Courier New', monospace;
      font-size: 12px;
      color: var(--accent2);
      background: rgba(79,110,247,.1);
      border: 1px solid rgba(79,110,247,.2);
      border-radius: 20px;
      padding: 4px 14px;
    }

    /* ── Main ── */
    main {
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 60px 24px;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 48px 48px 40px;
      max-width: 600px;
      width: 100%;
      text-align: center;
      box-shadow: 0 20px 60px rgba(0,0,0,.4);
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      background: rgba(34,197,94,.1);
      border: 1px solid rgba(34,197,94,.25);
      color: var(--green);
      border-radius: 100px;
      font-size: 12px;
      font-weight: 600;
      padding: 5px 14px;
      margin-bottom: 28px;
      letter-spacing: .3px;
    }
    .status-badge::before {
      content: '';
      display: block;
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--green);
      box-shadow: 0 0 0 2px rgba(34,197,94,.3);
    }
    .card h1 {
      font-size: 28px;
      font-weight: 700;
      color: var(--text);
      margin-bottom: 10px;
      letter-spacing: -.3px;
    }
    .card h1 span { color: var(--accent2); }
    .card .subtitle {
      font-size: 15px;
      color: var(--muted);
      line-height: 1.6;
      margin-bottom: 32px;
    }
    .divider {
      border: none;
      border-top: 1px solid var(--border);
      margin: 28px 0;
    }
    .info-box {
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 18px 20px;
      text-align: left;
    }
    .info-box .info-title {
      font-size: 11px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 1.2px;
      margin-bottom: 10px;
      font-weight: 600;
    }
    .info-box code {
      font-family: 'Courier New', monospace;
      font-size: 13px;
      color: var(--accent2);
      background: rgba(79,110,247,.08);
      border: 1px solid rgba(79,110,247,.15);
      border-radius: 5px;
      padding: 2px 7px;
    }
    .info-box p {
      font-size: 13px;
      color: #9ca3af;
      line-height: 1.6;
    }
    .info-box p + p { margin-top: 6px; }

    /* ── Footer ── */
    footer {
      background: var(--surface);
      border-top: 1px solid var(--border);
      text-align: center;
      padding: 16px 24px;
      font-size: 11px;
      color: var(--muted);
    }
    footer a { color: var(--accent2); text-decoration: none; }
    footer a:hover { text-decoration: underline; }
  </style>
</head>
<body>

  <header>
    <a class="header-brand" href="https://www.kazylax.fr" target="_blank" rel="noopener">
      <div class="logo">🛡️</div>
      <div>
        <div>KazyPanel</div>
        <div class="header-tag">pour hébergeur de site</div>
      </div>
    </a>
    <div class="header-domain">${domain}</div>
  </header>

  <main>
    <div class="card">
      <div class="status-badge">Hébergement actif</div>
      <h1>Votre ${type} est <span>en ligne</span> ✦</h1>
      <p class="subtitle">
        ${domain} a été configuré avec succès et est maintenant accessible.<br>
        Cette page d'accueil provisoire est prête à être remplacée par votre contenu.
      </p>

      <hr class="divider">

      <div class="info-box">
        <div class="info-title">📁 Comment mettre en ligne votre site</div>
        <p>Connectez-vous en <code>FTP</code> avec vos identifiants d'accès, puis déposez vos fichiers dans le répertoire associé à ce ${type}.</p>
        <p>Remplacez ce fichier <code>index.html</code> par votre propre page d'accueil — votre site sera immédiatement visible.</p>
      </div>
    </div>
  </main>

  <footer>
    &copy; ${year} <a href="https://www.kazylax.fr" target="_blank" rel="noopener">kazylax.fr</a>
    &nbsp;·&nbsp; KazyPanel pour hébergeur de site &nbsp;·&nbsp;
    By <a href="https://www.kazylax.fr" target="_blank" rel="noopener">www.kazylax.fr</a>
  </footer>

</body>
</html>`;
}


app.put('/api/domains/:name', authMiddleware, adminOnly, async (req, res) => {
  const safeName = req.params.name.replace(/[^a-zA-Z0-9._-]/g, '');
  const { phpVersion, docRoot } = req.body;
  const confFile = path.join(CONFIG.APACHE_SITES_PATH, `${safeName}.conf`);
  if (!fs.existsSync(CONFIG.APACHE_SITES_PATH))
    return res.json({ success: true, message: `Domaine ${safeName} modifié (mode démo)` });
  if (!fs.existsSync(confFile)) return res.status(404).json({ error: 'Domaine introuvable' });
  try {
    const webRoot = docRoot || `${CONFIG.WEB_ROOT}/${safeName}/public_html`;
    const tmpConf = `/tmp/kp_vhost_${Date.now()}.conf`;
    fs.writeFileSync(tmpConf, generateVhostConfig(safeName, webRoot, phpVersion || CONFIG.PHP_VERSION, false));
    await runCmd(`sudo cp "${tmpConf}" "${confFile}" && sudo chmod 644 "${confFile}"`);
    try { fs.unlinkSync(tmpConf); } catch {}
    await runCmd(`systemctl reload apache2`);
    log('UPDATE_DOMAIN', safeName, 'OK');
    res.json({ success: true, message: `Domaine ${safeName} mis à jour` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── ROUTE: SUPPRIMER UN DOMAINE (admin seulement) ───────────────────────────
app.delete('/api/domains/:name', authMiddleware, adminOnly, async (req, res) => {
  const safeName = req.params.name.replace(/[^a-zA-Z0-9._-]/g, '');
  const { deleteFiles = false } = req.body;
  const confFile = path.join(CONFIG.APACHE_SITES_PATH, `${safeName}.conf`);
  if (!fs.existsSync(CONFIG.APACHE_SITES_PATH))
    return res.json({ success: true, message: `Domaine ${safeName} supprimé (mode démo)` });
  if (!fs.existsSync(confFile)) return res.status(404).json({ error: 'Domaine introuvable' });
  try {
    await runCmd(`a2dissite ${safeName}.conf`);
    await runCmd(`sudo rm -f "${confFile}"`);
    if (deleteFiles) await runCmd(`rm -rf "${CONFIG.WEB_ROOT}/${safeName}"`);
    await runCmd(`systemctl reload apache2`);
    log('DELETE_DOMAIN', safeName, 'OK');
    res.json({ success: true, message: `Domaine ${safeName} supprimé` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── ROUTE: TOGGLE DOMAINE (admin seulement) ─────────────────────────────────
app.post('/api/domains/:name/toggle', authMiddleware, adminOnly, async (req, res) => {
  const safeName = req.params.name.replace(/[^a-zA-Z0-9._-]/g, '');
  const { enable } = req.body;
  if (!fs.existsSync(CONFIG.APACHE_SITES_PATH)) return res.json({ success: true });
  try {
    await runCmd(`${enable ? 'a2ensite' : 'a2dissite'} ${safeName}.conf`);
    await runCmd('systemctl reload apache2');
    log('TOGGLE_DOMAIN', `${safeName} → ${enable ? 'activé' : 'désactivé'}`, 'OK');
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── ROUTE: STATUT SERVEUR (admin seulement) ─────────────────────────────────
app.get('/api/status', authMiddleware, adminOnly, async (req, res) => {
  const s = {};
  try { await runCmd('systemctl is-active apache2'); s.apache = 'running'; } catch { s.apache = 'stopped'; }
  try { await runCmd(`systemctl is-active php${CONFIG.PHP_VERSION}-fpm`); s.php = 'running'; } catch { s.php = 'stopped'; }
  try { await runCmd('systemctl is-active vsftpd'); s.vsftpd = 'running'; } catch { s.vsftpd = 'stopped'; }
  try { await runCmd('systemctl is-active mariadb'); s.mariadb = 'running'; } catch { s.mariadb = 'stopped'; }
  try { const ufwOut = await runCmd('ufw status 2>/dev/null | head -1'); s.ufw = ufwOut.includes('active') ? 'active' : 'inactive'; } catch { s.ufw = 'unknown'; }
  try { await runCmd('systemctl is-active fail2ban'); s.fail2ban = 'running'; } catch { s.fail2ban = 'stopped'; }
  try { await runCmd('systemctl is-active kazypanel'); s.kazypanel = 'running'; } catch { s.kazypanel = 'stopped'; }
  try { await runCmd('systemctl is-active named 2>/dev/null || systemctl is-active bind9'); s.bind9 = 'running'; } catch { s.bind9 = 'stopped'; }

  // Uptime par service via systemctl show
  const svcList = ['apache2', `php${CONFIG.PHP_VERSION}-fpm`, 'vsftpd', 'mariadb', 'fail2ban', 'kazypanel', 'named'];
  s.uptimes = {};
  for (const svc of svcList) {
    try {
      const out = await runCmd(`systemctl show ${svc} --property=ActiveEnterTimestamp --value 2>/dev/null`);
      if (out && out.trim()) {
        // Format : "Sat 2026-03-21 07:11:47 CET" → extraire la partie date/heure
        const match = out.trim().match(/(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})/);
        if (match) {
          const startTime = new Date(`${match[1]}T${match[2]}`);
          if (!isNaN(startTime)) {
            const diffSec = Math.floor((Date.now() - startTime.getTime()) / 1000);
            if (diffSec > 0) {
              const days  = Math.floor(diffSec / 86400);
              const hours = Math.floor((diffSec % 86400) / 3600);
              const mins  = Math.floor((diffSec % 3600) / 60);
              const parts = [];
              if (days)  parts.push(`${days}j`);
              if (hours) parts.push(`${hours}h`);
              parts.push(`${mins}min`);
              s.uptimes[svc] = parts.join(' ');
            }
          }
        }
      }
    } catch {}
  }
  try {
    let sec = Math.floor(parseFloat(fs.readFileSync('/proc/uptime', 'utf8').split(' ')[0]));
    const months  = Math.floor(sec / 2592000); sec %= 2592000;
    const days    = Math.floor(sec / 86400);   sec %= 86400;
    const hours   = Math.floor(sec / 3600);    sec %= 3600;
    const minutes = Math.floor(sec / 60);
    const parts = [];
    if (months)  parts.push(`${months} mois`);
    if (days)    parts.push(`${days} j`);
    if (hours)   parts.push(`${hours} h`);
    parts.push(`${minutes} min`);
    s.uptime = parts.join(' ');
    s.uptimeSeconds = Math.floor(parseFloat(fs.readFileSync('/proc/uptime', 'utf8').split(' ')[0]));
  } catch { s.uptime = 'N/A'; }
  try {
    s.memory = await runCmd("free -m | awk 'NR==2{printf \"%d/%d Mo\", $3,$2}'");
    s.ramPercent = await runCmd("free | awk 'NR==2{printf \"%.0f\", $3*100/$2}'");
  } catch { s.memory = 'N/A'; s.ramPercent = 0; }
  try {
    s.disk = await runCmd("df -h / | awk 'NR==2{printf \"%s/%s\", $3,$2}'");
    s.diskPercent = await runCmd("df / | awk 'NR==2{gsub(/%/,\"\",$5); print $5}'");
  } catch { s.disk = 'N/A'; s.diskPercent = 0; }
  try {
    s.load = await runCmd("cat /proc/loadavg | awk '{print $1, $2, $3}'");
    s.cpuPercent = await runCmd("cat /proc/stat | awk 'NR==1{idle=$5;total=0;for(i=2;i<=NF;i++)total+=$i;print int((1-idle/total)*100)}'");
  } catch { s.load = 'N/A'; s.cpuPercent = 0; }
  try { s.hostname = await runCmd('hostname'); } catch { s.hostname = 'N/A'; }
  try { s.os = await runCmd('lsb_release -d -s 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d \'"\''); } catch { s.os = 'N/A'; }
  try { s.nodeVersion = process.version; } catch {}
  try { s.domains = fs.existsSync(CONFIG.APACHE_SITES_PATH) ? fs.readdirSync(CONFIG.APACHE_SITES_PATH).filter(f => f.endsWith('.conf') && !['000-default.conf','default-ssl.conf'].includes(f) && !f.includes('-le-ssl.conf') && !f.includes('phpmyadmin')).length : 0; } catch { s.domains = 0; }
  s.users = USERS.length;
  res.json(s);
});

// ─── ROUTE: CONTRÔLE DES SERVICES ────────────────────────────────────────────
const ALLOWED_SERVICES = {
  apache2:  'Apache',
  vsftpd:   'vsftpd',
  mariadb:  'MariaDB',
  fail2ban: 'Fail2ban',
  ufw:      'UFW',
  bind9:    'BIND9',
  kazypanel:'KazyPanel'
};
const ALLOWED_ACTIONS = ['start', 'stop', 'restart', 'reload'];

app.post('/api/services/:service/:action', authMiddleware, adminOnly, async (req, res) => {
  let { service, action } = req.params;

  const phpFpm = `php${CONFIG.PHP_VERSION}-fpm`;
  const allowed = { ...ALLOWED_SERVICES, [phpFpm]: `PHP ${CONFIG.PHP_VERSION}-FPM` };

  if (!allowed[service]) return res.status(400).json({ error: 'Service non autorisé' });
  if (!ALLOWED_ACTIONS.includes(action)) return res.status(400).json({ error: 'Action non autorisée' });

  // KazyPanel restart — répondre avant de redémarrer
  if (service === 'kazypanel') {
    if (action !== 'restart') return res.status(403).json({ error: 'KazyPanel : seul "restart" est autorisé depuis le panel' });
    res.json({ success: true, message: 'KazyPanel redémarre — reconnexion dans 5 secondes', status: 'running' });
    log('SERVICE_CTRL', `restart kazypanel par ${req.user.username}`, 'OK');
    setTimeout(() => { runCmd('systemctl restart kazypanel').catch(() => {}); }, 500);
    return;
  }

  // Empêcher de stopper Apache — le panel passerait hors ligne
  if (service === 'apache2' && action === 'stop')
    return res.status(403).json({ error: '⚠️ Impossible d\'arrêter Apache — le panel est accessible via le reverse proxy Apache. Utilisez "reload" ou "restart" uniquement.' });

  try {
    // UFW utilise ses propres commandes
    if (service === 'ufw') {
      if (action === 'start')  await runCmd('ufw --force enable');
      else if (action === 'stop') await runCmd('ufw disable');
      else return res.status(400).json({ error: 'UFW : seules les actions start/stop sont supportées' });
      const ufwOut = await runCmd('ufw status 2>/dev/null | head -1');
      const newStatus = ufwOut.includes('active') ? 'active' : 'inactive';
      log('SERVICE_CTRL', `${action} ufw par ${req.user.username}`, 'OK');
      return res.json({ success: true, message: `UFW : ${action} effectué`, status: newStatus });
    }

    // Pour apache2 restart, on répond avant de redémarrer pour que le client reçoive la réponse
    if (service === 'apache2' && action === 'restart') {
      res.json({ success: true, message: 'Apache : restart en cours — reconnexion dans 3 secondes', status: 'running' });
      log('SERVICE_CTRL', `restart apache2 par ${req.user.username}`, 'OK');
      setTimeout(() => { runCmd('systemctl restart apache2').catch(() => {}); }, 500);
      return;
    }

    await runCmd(`systemctl ${action} ${service}`);
    let newStatus = 'stopped';
    try { await runCmd(`systemctl is-active ${service}`); newStatus = 'running'; } catch {}
    log('SERVICE_CTRL', `${action} ${service} par ${req.user.username}`, 'OK');
    res.json({ success: true, message: `${allowed[service]} : ${action} effectué`, status: newStatus });
  } catch (err) {
    res.status(500).json({ error: `Erreur lors de ${action} sur ${service} : ${err.message}` });
  }
});

// ─── ROUTE: SSL LET'S ENCRYPT ────────────────────────────────────────────────
app.post('/api/domains/:name/ssl', authMiddleware, adminOnly, async (req, res) => {
  const safeName = req.params.name.replace(/[^a-zA-Z0-9._-]/g, '');
  const confFile = path.join(CONFIG.APACHE_SITES_PATH, `${safeName}.conf`);
  if (!fs.existsSync(confFile)) return res.status(404).json({ error: 'Domaine introuvable' });

  const conf   = fs.readFileSync(confFile, 'utf8');
  const domain = (conf.match(/ServerName\s+(.+)/) || [])[1]?.trim();
  if (!domain) return res.status(400).json({ error: 'ServerName introuvable dans le VirtualHost' });

  if (!fs.existsSync(path.join(CONFIG.APACHE_ENABLED_PATH, `${safeName}.conf`)))
    return res.status(400).json({ error: 'Le domaine doit être activé avant de générer un certificat SSL' });

  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: "Email valide requis pour Let's Encrypt" });

  if (!findCertbot()) {
    return res.status(400).json({
      error: 'Certbot non installé',
      install: 'sudo apt install -y certbot python3-certbot-apache\n# ou via snap :\nsudo snap install --classic certbot\nsudo ln -s /snap/bin/certbot /usr/bin/certbot'
    });
  }

  const result = await tryIssueSsl(domain, email);
  if (result.success) return res.json({ success: true, message: result.message });
  res.status(500).json({ error: result.message });
});

// Renouveler tous les certificats
// ─── ROUTE: SSL UTILISATEUR ───────────────────────────────────────────────────
app.post('/api/me/domains/:name/ssl', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  const safeName = req.params.name.replace(/[^a-zA-Z0-9._-]/g, '');
  const confFile = path.join(CONFIG.APACHE_SITES_PATH, `${safeName}.conf`);
  if (!fs.existsSync(confFile)) return res.status(404).json({ error: 'Domaine introuvable' });

  // Vérifier que le domaine appartient à l'utilisateur
  const conf    = fs.readFileSync(confFile, 'utf8');
  const docRoot = (conf.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim() || '';
  if (!userOwnsDocRoot(user, docRoot))
    return res.status(403).json({ error: 'Ce domaine ne vous appartient pas' });

  const domain = (conf.match(/ServerName\s+(.+)/) || [])[1]?.trim();
  if (!domain) return res.status(400).json({ error: 'ServerName introuvable dans le VirtualHost' });

  if (!fs.existsSync(path.join(CONFIG.APACHE_ENABLED_PATH, `${safeName}.conf`)))
    return res.status(400).json({ error: 'Le domaine doit être activé avant de générer un certificat SSL' });

  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: "Email valide requis pour Let's Encrypt" });

  if (!findCertbot())
    return res.status(400).json({ error: 'Certbot non installé sur ce serveur' });

  const result = await tryIssueSsl(domain, email);
  log('SSL_USER', `${user.username} → ${domain}`, result.success ? 'OK' : 'FAIL');
  if (result.success) return res.json({ success: true, message: result.message });
  res.status(500).json({ error: result.message });
});

// ─── ROUTE: CONFIG PHPMYADMIN URL ────────────────────────────────────────────
const PANEL_CONFIG_FILE = path.join(__dirname, 'panel_config.json');
let PANEL_CONFIG = { pmaUrl: CONFIG.PMA_URL };
if (fs.existsSync(PANEL_CONFIG_FILE)) {
  try { Object.assign(PANEL_CONFIG, JSON.parse(fs.readFileSync(PANEL_CONFIG_FILE, 'utf8'))); } catch {}
}
function savePanelConfig() {
  fs.writeFileSync(PANEL_CONFIG_FILE, JSON.stringify(PANEL_CONFIG, null, 2));
}

app.get('/api/config/pma', authMiddleware, (req, res) => {
  res.json({ pmaUrl: PANEL_CONFIG.pmaUrl || '' });
});

app.put('/api/config/pma', authMiddleware, adminOnly, (req, res) => {
  const { pmaUrl } = req.body;
  PANEL_CONFIG.pmaUrl = (pmaUrl || '').trim().replace(/\/$/, '');
  savePanelConfig();
  log('CONFIG_PMA', PANEL_CONFIG.pmaUrl || '(vide)', 'OK');
  res.json({ success: true, pmaUrl: PANEL_CONFIG.pmaUrl });
});

app.post('/api/ssl/renew', authMiddleware, adminOnly, async (req, res) => {
  try {
    const output = await runCmd('certbot renew --quiet');
    log('SSL_RENEW', 'all', 'OK');
    res.json({ success: true, message: 'Renouvellement des certificats effectué', output });
  } catch (err) {
    res.status(500).json({ error: `Erreur renouvellement : ${err.message}` });
  }
});

// ─── PHP CONFIG PAR DOMAINE ───────────────────────────────────────────────────
// Valeurs PHP autorisées (whitelist sécurité)
const PHP_ALLOWED_KEYS = [
  'memory_limit', 'upload_max_filesize', 'post_max_size', 'max_execution_time',
  'max_input_time', 'max_input_vars', 'max_input_nesting_level', 'max_file_uploads',
  'default_socket_timeout', 'display_errors', 'display_startup_errors', 'log_errors',
  'error_reporting', 'error_log', 'session.gc_maxlifetime', 'session.cookie_lifetime',
  'session.cookie_secure', 'session.cookie_httponly', 'session.use_strict_mode', 'session.save_path',
  'date.timezone', 'default_charset', 'output_buffering', 'short_open_tag',
  'allow_url_fopen', 'allow_url_include', 'expose_php', 'file_uploads', 'disable_functions'
];

const PHP_DEFAULTS = {
  memory_limit: '256M', upload_max_filesize: '64M', post_max_size: '64M',
  max_execution_time: '60', max_input_time: '60', max_input_vars: '3000',
  display_errors: 'Off', error_reporting: 'E_ALL & ~E_DEPRECATED & ~E_STRICT',
  'session.gc_maxlifetime': '1440', 'date.timezone': 'Europe/Paris',
  default_charset: 'UTF-8', output_buffering: 'Off',
  short_open_tag: 'Off', allow_url_fopen: 'On', file_uploads: 'On',
  disable_functions: ''
};

function getUserIniPath(docRoot) {
  return path.join(docRoot, '.user.ini');
}

function parseUserIni(content) {
  const cfg = {};
  for (const line of content.split('\n')) {
    const m = line.match(/^\s*([^;#=\s][^=]*?)\s*=\s*(.+?)\s*$/);
    if (m) cfg[m[1].trim()] = m[2].trim();
  }
  return cfg;
}

async function writeUserIni(docRoot, values) {
  const lines = ['; KazyPanel PHP config — ne pas modifier manuellement', ''];
  for (const [k, v] of Object.entries(values)) {
    if (PHP_ALLOWED_KEYS.includes(k) && v !== '' && v !== null) {
      lines.push(`${k} = ${v}`);
    }
  }
  await runCmd(`sudo mkdir -p "${docRoot}"`);
  const tmpIni = `/tmp/kp_userini_${Date.now()}.ini`;
  fs.writeFileSync(tmpIni, lines.join('\n') + '\n', 'utf8');
  await runCmd(`sudo cp "${tmpIni}" "${path.join(docRoot, '.user.ini')}" && sudo chmod 644 "${path.join(docRoot, '.user.ini')}"`);
  fs.unlinkSync(tmpIni);
}

// GET config PHP d'un domaine (admin ou propriétaire)
app.get('/api/domains/:name/phpconfig', authMiddleware, async (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const safeName = req.params.name.replace(/[^a-zA-Z0-9._-]/g, '');
  const confFile = path.join(CONFIG.APACHE_SITES_PATH, `${safeName}.conf`);
  if (!fs.existsSync(confFile)) return res.status(404).json({ error: 'Domaine introuvable' });

  const conf    = fs.readFileSync(confFile, 'utf8');
  const docRoot = (conf.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim();
  if (!docRoot) return res.status(400).json({ error: 'DocumentRoot introuvable' });

  // Vérifier propriété si non admin
  if (!isAdmin) {
    const user = USERS.find(u => u.id === parseInt(req.user.id));
    if (!userOwnsDocRoot(user, docRoot))
      return res.status(403).json({ error: 'Ce domaine ne vous appartient pas' });
  }

  const iniPath = getUserIniPath(docRoot);
  let current = { ...PHP_DEFAULTS };
  if (fs.existsSync(iniPath)) {
    Object.assign(current, parseUserIni(fs.readFileSync(iniPath, 'utf8')));
  }
  res.json({ config: current, defaults: PHP_DEFAULTS, docRoot });
});

// PUT config PHP d'un domaine
app.put('/api/domains/:name/phpconfig', authMiddleware, async (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const safeName = req.params.name.replace(/[^a-zA-Z0-9._-]/g, '');
  const confFile = path.join(CONFIG.APACHE_SITES_PATH, `${safeName}.conf`);
  if (!fs.existsSync(confFile)) return res.status(404).json({ error: 'Domaine introuvable' });

  const conf    = fs.readFileSync(confFile, 'utf8');
  const docRoot = (conf.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim();
  if (!docRoot) return res.status(400).json({ error: 'DocumentRoot introuvable' });

  if (!isAdmin) {
    const user = USERS.find(u => u.id === parseInt(req.user.id));
    if (!userOwnsDocRoot(user, docRoot))
      return res.status(403).json({ error: 'Ce domaine ne vous appartient pas' });
  }

  const values = req.body || {};
  // Filtrer les clés non autorisées
  const safe = {};
  for (const k of PHP_ALLOWED_KEYS) {
    if (values[k] !== undefined) safe[k] = String(values[k]);
  }

  try {
    await writeUserIni(docRoot, safe);
    // Forcer rechargement PHP-FPM pour prise en compte
    await runCmd(`systemctl reload php${CONFIG.PHP_VERSION}-fpm`).catch(() => {});
    log('PHP_CONFIG', safeName, 'OK');
    res.json({ success: true, message: `Configuration PHP mise à jour pour ${safeName}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE config PHP (reset aux défauts)
app.delete('/api/domains/:name/phpconfig', authMiddleware, async (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const safeName = req.params.name.replace(/[^a-zA-Z0-9._-]/g, '');
  const confFile = path.join(CONFIG.APACHE_SITES_PATH, `${safeName}.conf`);
  if (!fs.existsSync(confFile)) return res.status(404).json({ error: 'Domaine introuvable' });
  const conf    = fs.readFileSync(confFile, 'utf8');
  const docRoot = (conf.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim();
  if (!isAdmin) {
    const user = USERS.find(u => u.id === parseInt(req.user.id));
    if (!userOwnsDocRoot(user, docRoot))
      return res.status(403).json({ error: 'Ce domaine ne vous appartient pas' });
  }
  const iniPath = getUserIniPath(docRoot);
  if (fs.existsSync(iniPath)) await runCmd(`sudo rm -f "${iniPath}"`).catch(() => {});
  await runCmd(`systemctl reload php${CONFIG.PHP_VERSION}-fpm`).catch(() => {});
  log('PHP_CONFIG_RESET', safeName, 'OK');
  res.json({ success: true, message: `Configuration PHP réinitialisée pour ${safeName}` });
});

// ─── DB CONFIG PAR BASE ───────────────────────────────────────────────────────
// Paramètres MariaDB autorisés par base (via session variables + métadonnées stockées)
const DB_CONFIG_FILE = path.join(__dirname, 'db_configs.json');
let DB_CONFIGS = {};
if (fs.existsSync(DB_CONFIG_FILE)) {
  try { DB_CONFIGS = JSON.parse(fs.readFileSync(DB_CONFIG_FILE, 'utf8')); } catch {}
}
function saveDbConfigs() {
  fs.writeFileSync(DB_CONFIG_FILE, JSON.stringify(DB_CONFIGS, null, 2));
}

const DB_ALLOWED_VARS = {
  'max_allowed_packet': { default: '16M', desc: 'Taille max des paquets', type: 'text' },
  'wait_timeout':       { default: '28800', desc: 'Timeout connexion inactive (sec)', type: 'number' },
  'interactive_timeout':{ default: '28800', desc: 'Timeout connexion interactive (sec)', type: 'number' },
  'innodb_lock_wait_timeout': { default: '50', desc: 'Timeout verrou InnoDB (sec)', type: 'number' },
  'charset':            { default: 'utf8mb4', desc: 'Charset par défaut', type: 'select', options: ['utf8mb4','utf8','latin1','ascii'] },
  'collation':          { default: 'utf8mb4_unicode_ci', desc: 'Collation par défaut', type: 'select',
    options: ['utf8mb4_unicode_ci','utf8mb4_general_ci','utf8_general_ci','latin1_swedish_ci'] },
  'notes':              { default: '', desc: 'Notes / description', type: 'textarea' }
};

app.get('/api/databases/:dbname/config', authMiddleware, async (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const dbname  = req.params.dbname.replace(/[^a-zA-Z0-9_]/g, '');
  // Vérifier propriété
  if (!isAdmin) {
    const dbs = await getUserDatabases(req.user.username).catch(() => []);
    if (!dbs.includes(dbname))
      return res.status(403).json({ error: 'Cette base ne vous appartient pas' });
  }
  const saved = DB_CONFIGS[dbname] || {};
  const config = {};
  for (const [k, meta] of Object.entries(DB_ALLOWED_VARS)) {
    config[k] = { value: saved[k] ?? meta.default, ...meta };
  }
  res.json({ config, dbname });
});

app.put('/api/databases/:dbname/config', authMiddleware, async (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const dbname  = req.params.dbname.replace(/[^a-zA-Z0-9_]/g, '');
  if (!isAdmin) {
    const dbs = await getUserDatabases(req.user.username).catch(() => []);
    if (!dbs.includes(dbname))
      return res.status(403).json({ error: 'Cette base ne vous appartient pas' });
  }
  const values = req.body || {};
  const safe = {};
  for (const k of Object.keys(DB_ALLOWED_VARS)) {
    if (values[k] !== undefined) safe[k] = String(values[k]);
  }

  // Appliquer charset/collation via ALTER DATABASE
  try {
    if (safe.charset && safe.collation) {
      await mysqlCmd(`ALTER DATABASE \`${dbname}\` CHARACTER SET ${safe.charset} COLLATE ${safe.collation};`);
    } else if (safe.charset) {
      await mysqlCmd(`ALTER DATABASE \`${dbname}\` CHARACTER SET ${safe.charset};`);
    }
  } catch (err) {
    return res.status(500).json({ error: `ALTER DATABASE : ${err.message}` });
  }

  DB_CONFIGS[dbname] = { ...(DB_CONFIGS[dbname] || {}), ...safe };
  saveDbConfigs();
  log('DB_CONFIG', dbname, 'OK');
  res.json({ success: true, message: `Configuration mise à jour pour ${dbname}` });
});

// ─── GÉNÉRATEUR DE CONFIG VHOST ───────────────────────────────────────────────
// Voir la configuration Apache d'un domaine (admin)
app.get('/api/domains/:name/config', authMiddleware, adminOnly, async (req, res) => {
  const safeName = req.params.name.replace(/[^a-zA-Z0-9._-]/g, '');
  const confFile = path.join(CONFIG.APACHE_SITES_PATH, `${safeName}.conf`);
  if (!fs.existsSync(CONFIG.APACHE_SITES_PATH))
    return res.json({ name: safeName, config: `# Mode démo — configuration non disponible\n# Domaine : ${safeName}` });
  if (!fs.existsSync(confFile)) return res.status(404).json({ error: 'Configuration introuvable' });
  const config = fs.readFileSync(confFile, 'utf8');
  res.json({ name: safeName, config });
});

// ── Helpers SSL Let's Encrypt ─────────────────────────────────────────────────

function findCertbot() {
  for (const p of ['/usr/bin/certbot', '/usr/local/bin/certbot', '/snap/bin/certbot']) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

// Lance certbot --apache et retourne { success, message, hasSsl }
// Non-bloquant sur les erreurs : un échec SSL n'empêche pas la création du domaine
async function tryIssueSsl(domain, email) {
  const certbot = findCertbot();
  if (!certbot) return { success: false, message: 'Certbot non installé — SSL ignoré' };
  if (!email)   return { success: false, message: 'Email admin non configuré — SSL ignoré' };

  const isSubdomain = domain.split('.').length > 2;
  const domainsArg  = isSubdomain ? `-d ${domain}` : `-d ${domain} -d www.${domain}`;
  const cmd = `${certbot} --apache ${domainsArg} --non-interactive --agree-tos -m ${email} --redirect`;

  try {
    await runCmd(cmd);
    log('SSL_AUTO', domain, 'OK');
    return { success: true, message: `Certificat SSL Let's Encrypt émis pour ${domain}`, hasSsl: true };
  } catch (err) {
    // Certbot peut retourner un code non-nul même si le certificat existe (ex: --redirect déjà en place)
    const certExists = fs.existsSync(`/etc/letsencrypt/live/${domain}/fullchain.pem`);
    if (certExists) {
      log('SSL_AUTO', domain, 'OK (cert exists)');
      return { success: true, message: `Certificat SSL Let's Encrypt actif pour ${domain}`, hasSsl: true };
    }
    log('SSL_AUTO', domain, `FAIL: ${err.message}`);
    return { success: false, message: `SSL échoué (DNS non propagé ?) : ${err.message.split('\n')[0]}` };
  }
}

function generateVhostConfigSub(domain, docRoot, phpVersion) {
  return `<VirtualHost *:80>
    ServerName ${domain}
    DocumentRoot ${docRoot}
    ErrorLog \${APACHE_LOG_DIR}/${domain}-error.log
    CustomLog \${APACHE_LOG_DIR}/${domain}-access.log combined

    <Directory ${docRoot}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    <FilesMatch \\.php$>
        SetHandler "proxy:unix:/run/php/php${phpVersion}-fpm.sock|fcgi://localhost"
    </FilesMatch>

    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
</VirtualHost>
`;
}

function generateVhostConfig(domain, docRoot, phpVersion, ssl) {
  return `<VirtualHost *:80>
    ServerName ${domain}
    ServerAlias www.${domain}
    DocumentRoot ${docRoot}
    ErrorLog \${APACHE_LOG_DIR}/${domain}-error.log
    CustomLog \${APACHE_LOG_DIR}/${domain}-access.log combined

    <Directory ${docRoot}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    <FilesMatch \\.php$>
        SetHandler "proxy:unix:/run/php/php${phpVersion}-fpm.sock|fcgi://localhost"
    </FilesMatch>

    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
</VirtualHost>
`;
}

// ─── DONNÉES DÉMO ────────────────────────────────────────────────────────────
function getDemoDomains() {
  return [
    { name: 'kazylax.fr', domain: 'kazylax.fr', docRoot: '/var/www/admin/public_html', phpVersion: '8.4', enabled: true, isSubdomain: false },
    { name: 'blog.kazylax.fr', domain: 'blog.kazylax.fr', docRoot: '/var/www/admin/blog/public_html', phpVersion: '8.4', enabled: true, isSubdomain: true }
  ];
}

// ─── DÉMARRAGE ────────────────────────────────────────────────────────────────
// ─── ROUTE: SAUVEGARDE KAZYPANEL ────────────────────────────────────────────
// ─── ROUTE: SAUVEGARDE KAZYPANEL ────────────────────────────────────────────
const BACKUP_DIR = path.join(__dirname, 'backups');

// Lister les sauvegardes existantes
app.get('/api/backup', authMiddleware, adminOnly, (req, res) => {
  try {
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const files = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.endsWith('.tar.gz'))
      .map(f => {
        const stat = fs.statSync(path.join(BACKUP_DIR, f));
        return { name: f, size: stat.size, createdAt: stat.mtime.toISOString() };
      })
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json({ backups: files });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Créer une sauvegarde
app.post('/api/backup', authMiddleware, adminOnly, async (req, res) => {
  if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

  const timestamp  = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const backupName = `kazypanel-backup-${timestamp}.tar.gz`;
  const backupPath = path.join(BACKUP_DIR, backupName);
  const srcDir     = path.dirname(__dirname);
  const panelDir   = path.basename(__dirname);

  const excludes = [
    'node_modules',
    '.env',
    'backups',
    'users.json',
    'db_configs.json',
    'panel_config.json',
    '*.log',
    '*.bak',
    '*.tmp',
    '.git',
    '.gitignore',
    'npm-debug.log*',
    '.npm',
  ].map(e => `--exclude='${panelDir}/${e}'`).join(' ');

  try {
    await runCmd(`tar ${excludes} -czvf '${backupPath}' -C '${srcDir}' '${panelDir}'`);
  } catch (err) {
    return res.status(500).json({ error: `Erreur tar : ${err.message}` });
  }

  if (!fs.existsSync(backupPath))
    return res.status(500).json({ error: 'Archive introuvable après création' });

  const stat = fs.statSync(backupPath);
  log('BACKUP', backupName, 'OK');
  res.json({ success: true, backup: { name: backupName, size: stat.size, createdAt: stat.mtime.toISOString() } });
});

// Télécharger une sauvegarde
app.get('/api/backup/:name', authMiddleware, adminOnly, (req, res) => {
  const safeName = req.params.name.replace(/[^a-zA-Z0-9._-]/g, '');
  const filePath = path.join(BACKUP_DIR, safeName);
  if (!filePath.startsWith(BACKUP_DIR) || !fs.existsSync(filePath))
    return res.status(404).json({ error: 'Fichier introuvable' });
  res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);
  res.download(filePath);
});

// Supprimer une sauvegarde
app.delete('/api/backup/:name', authMiddleware, adminOnly, (req, res) => {
  const safeName = req.params.name.replace(/[^a-zA-Z0-9._-]/g, '');
  const filePath = path.join(BACKUP_DIR, safeName);
  if (!filePath.startsWith(BACKUP_DIR) || !fs.existsSync(filePath))
    return res.status(404).json({ error: 'Fichier introuvable' });
  fs.unlinkSync(filePath);
  log('BACKUP_DELETE', safeName, 'OK');
  res.json({ success: true, message: `${safeName} supprimé` });
});

// ─── ROUTES: UFW (PARE-FEU) ──────────────────────────────────────────────────

// Vérifier si UFW est installé
async function ufwAvailable() {
  try { await runCmd('which ufw'); return true; } catch { return false; }
}

// Statut UFW + liste des règles
app.get('/api/ufw/status', authMiddleware, adminOnly, async (req, res) => {
  if (!await ufwAvailable()) return res.status(404).json({ error: 'UFW n\'est pas installé sur ce serveur', notInstalled: true });
  try {
    const raw     = await runCmd('ufw status numbered 2>/dev/null');
    const enabled = raw.toLowerCase().includes('status: active');

    // UFW marque les règles IPv6 avec le suffixe " (v6)" dans le champ "To".
    // Format d'une ligne : [ 1] 22/tcp (v6)       ALLOW IN    Anywhere (v6)
    // On parse ligne par ligne pour garder le contrôle complet sur chaque champ.
    const rules = [];
    for (const line of raw.split('\n')) {
      const m = line.match(/^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|LIMIT|REJECT)\s*(IN|OUT|FWD)?\s*(.*)/i);
      if (!m) continue;

      const toRaw   = m[2].trim();
      const fromRaw = (m[5] || '').trim() || 'Anywhere';

      // UFW appose systématiquement " (v6)" sur le champ "To" des règles IPv6.
      // On s'appuie uniquement sur ce marqueur officiel — jamais sur les adresses.
      const isV6 = /\(v6\)\s*$/i.test(toRaw);

      rules.push({
        num:       parseInt(m[1]),
        to:        toRaw.replace(/\s*\(v6\)\s*$/i, '').trim(),
        action:    m[3].toUpperCase(),
        direction: (m[4] || 'IN').toUpperCase(),
        from:      fromRaw.replace(/\s*\(v6\)\s*$/i, '').trim() || 'Anywhere',
        isV6
      });
    }

    res.json({ enabled, rules, raw: raw.trim() });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Activer / désactiver UFW
app.post('/api/ufw/toggle', authMiddleware, adminOnly, async (req, res) => {
  if (!await ufwAvailable()) return res.status(404).json({ error: 'UFW non installé' });
  const { enable } = req.body;
  try {
    if (enable) {
      await runCmd('ufw --force enable');
    } else {
      await runCmd('ufw --force disable');
    }
    log('UFW_TOGGLE', `${enable ? 'activé' : 'désactivé'} par ${req.user.username}`, 'OK');
    res.json({ success: true, message: `UFW ${enable ? 'activé' : 'désactivé'}` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Ajouter une règle UFW
app.post('/api/ufw/rules', authMiddleware, adminOnly, async (req, res) => {
  if (!await ufwAvailable()) return res.status(404).json({ error: 'UFW non installé' });

  let { action, port, proto, direction, from, ipver } = req.body;
  // Validation
  if (!['allow', 'deny', 'limit', 'reject'].includes((action || '').toLowerCase()))
    return res.status(400).json({ error: 'Action invalide (allow|deny|limit|reject)' });
  if (!port && port !== 0)
    return res.status(400).json({ error: 'Port ou service requis' });

  // Nettoyer le port : accepte "80", "80/tcp", "8080:8090", nom de service
  const safePort  = String(port).replace(/[^a-zA-Z0-9/:_-]/g, '');
  const safeProto = proto && ['tcp','udp'].includes(proto.toLowerCase()) ? proto.toLowerCase() : null;
  const safeFrom  = from && from !== 'Anywhere' ? String(from).replace(/[^a-zA-Z0-9.:/]/g, '') : null;
  const dir       = direction === 'out' ? 'out' : 'in';

  // Version IP (any | v4 | v6)
  const safeIPVer = ['v4','v6'].includes(ipver) ? ipver : null;

  // Construction de la commande
  let cmd = `ufw ${action.toLowerCase()} ${dir}`;
  if (safeIPVer === 'v4') cmd = `ufw ${action.toLowerCase()} proto tcp from any${safeFrom ? ` from ${safeFrom}` : ''} to any port ${safePort}`.replace('proto tcp ', safeProto ? `proto ${safeProto} ` : '');
  // Rebuild properly
  cmd = `ufw ${action.toLowerCase()} ${dir}`;
  if (safeFrom) cmd += ` from ${safeFrom}`;
  cmd += ` to any port ${safePort}`;
  if (safeProto && !safePort.includes('/')) cmd += ` proto ${safeProto}`;

  // Pour forcer IPv4 ou IPv6 uniquement, on utilise ufw route ou on insère l'adresse family
  if (safeIPVer === 'v4') {
    cmd = `ufw ${action.toLowerCase()} ${dir} from ${safeFrom || 'any'} to any port ${safePort}`;
    if (safeProto) cmd += ` proto ${safeProto}`;
    // Désactiver temporairement ipv6 dans /etc/default/ufw n'est pas viable ;
    // on passe par ip6tables=no uniquement si l'IP source est v4 explicite
  } else if (safeIPVer === 'v6') {
    // On spécifie une source IPv6 générique si aucune IP fournie
    const v6from = safeFrom || '::/0';
    cmd = `ufw ${action.toLowerCase()} ${dir} from ${v6from} to any port ${safePort}`;
    if (safeProto) cmd += ` proto ${safeProto}`;
  } else {
    cmd = `ufw ${action.toLowerCase()} ${dir}`;
    if (safeFrom) cmd += ` from ${safeFrom}`;
    cmd += ` to any port ${safePort}`;
    if (safeProto && !safePort.includes('/')) cmd += ` proto ${safeProto}`;
  }

  try {
    await runCmd(cmd);
    log('UFW_ADD', `${cmd} par ${req.user.username}`, 'OK');
    res.json({ success: true, message: `Règle ajoutée : ${cmd.replace('ufw ', '')}` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Supprimer une règle UFW par numéro
app.delete('/api/ufw/rules/:num', authMiddleware, adminOnly, async (req, res) => {
  if (!await ufwAvailable()) return res.status(404).json({ error: 'UFW non installé' });
  const num = parseInt(req.params.num);
  if (!num || num < 1) return res.status(400).json({ error: 'Numéro de règle invalide' });
  try {
    await runCmd(`ufw --force delete ${num}`);
    log('UFW_DELETE', `règle #${num} par ${req.user.username}`, 'OK');
    res.json({ success: true, message: `Règle #${num} supprimée` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── ROUTES: FAIL2BAN ─────────────────────────────────────────────────────────

function fail2banAvailable() {
  return new Promise(resolve => {
    exec('which fail2ban-client', (err) => resolve(!err));
  });
}

async function f2bCmd(args) {
  const { stdout } = await runCmdOut(`fail2ban-client ${args}`);
  return stdout.trim();
}

async function runCmdOut(cmd, opts = {}) {
  const finalCmd = needsSudo(cmd) ? `sudo ${cmd}` : cmd;
  try {
    const { stdout, stderr } = await execAsync(finalCmd, { timeout: opts.timeout || 30000, maxBuffer: opts.maxBuffer || 1024 * 1024 });
    return { stdout, stderr };
  } catch (err) {
    throw new Error(err.stderr?.trim() || err.message, { cause: err });
  }
}

// GET /api/fail2ban/status — état global + liste des jails avec stats
app.get('/api/fail2ban/status', authMiddleware, adminOnly, async (req, res) => {
  if (!await fail2banAvailable()) return res.json({ installed: false });

  try {
    // État du service
    const { stdout: svcOut } = await runCmdOut('systemctl is-active fail2ban 2>/dev/null || echo inactive');
    const running = svcOut.trim() === 'active';

    if (!running) return res.json({ installed: true, running: false, jails: [] });

    // Liste des jails
    const listOut = await f2bCmd('status');
    const jailMatch = listOut.match(/Jail list:\s*(.+)/i);
    const jailNames = jailMatch
      ? jailMatch[1].split(',').map(j => j.trim()).filter(Boolean)
      : [];

    // Stats par jail (en parallèle)
    const jails = await Promise.all(jailNames.map(async name => {
      try {
        const out = await f2bCmd(`status ${name}`);
        const get = (label) => {
          const m = out.match(new RegExp(`${label}[^:]*:\\s*(.+)`, 'i'));
          return m ? m[1].trim() : '—';
        };
        const bannedRaw = get('Banned IP list');
        const bannedIps = bannedRaw && bannedRaw !== '—' && bannedRaw !== ''
          ? bannedRaw.split(/\s+/).filter(Boolean) : [];
        return {
          name,
          filter:        get('Filter'),
          totalFailed:   get('Total failed'),
          currentFailed: get('Currently failed'),
          totalBanned:   get('Total banned'),
          currentBanned: bannedIps.length,
          bannedIps,
        };
      } catch { return { name, error: true, bannedIps: [] }; }
    }));

    res.json({ installed: true, running: true, jails });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/fail2ban/unban — débannir une IP d'un jail
app.post('/api/fail2ban/unban', authMiddleware, adminOnly, async (req, res) => {
  if (!await fail2banAvailable()) return res.status(404).json({ error: 'fail2ban non installé' });
  const { jail, ip } = req.body;
  if (!jail || !ip) return res.status(400).json({ error: 'jail et ip requis' });
  // Validation IP basique
  if (!/^[\d.:a-fA-F/]+$/.test(ip)) return res.status(400).json({ error: 'IP invalide' });
  try {
    await runCmd(`fail2ban-client set ${jail} unbanip ${ip}`);
    log('FAIL2BAN_UNBAN', `IP ${ip} débannie du jail ${jail} par ${req.user.username}`, 'OK');
    res.json({ success: true, message: `${ip} débannie de ${jail}` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/fail2ban/jail/:name/toggle — activer / désactiver un jail à chaud
app.post('/api/fail2ban/jail/:name/toggle', authMiddleware, adminOnly, async (req, res) => {
  if (!await fail2banAvailable()) return res.status(404).json({ error: 'fail2ban non installé' });
  const { name }   = req.params;
  const { enable } = req.body; // boolean
  if (!/^[\w-]+$/.test(name)) return res.status(400).json({ error: 'Nom de jail invalide' });
  try {
    const action = enable ? 'start' : 'stop';
    await runCmd(`fail2ban-client ${action} ${name}`);
    log('FAIL2BAN_TOGGLE', `jail ${name} ${action} par ${req.user.username}`, 'OK');
    res.json({ success: true, message: `Jail ${name} ${enable ? 'démarré' : 'arrêté'}` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/fail2ban/banall — bannir toutes les IP d'un jail (flush)
app.post('/api/fail2ban/banall', authMiddleware, adminOnly, async (req, res) => {
  if (!await fail2banAvailable()) return res.status(404).json({ error: 'fail2ban non installé' });
  const { jail } = req.body;
  if (!jail || !/^[\w-]+$/.test(jail)) return res.status(400).json({ error: 'jail invalide' });
  try {
    await runCmd(`fail2ban-client set ${jail} unbanip --all`);
    log('FAIL2BAN_FLUSH', `jail ${jail} vidé par ${req.user.username}`, 'OK');
    res.json({ success: true, message: `Toutes les IP débanies de ${jail}` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── BIND9 DNS MANAGEMENT ─────────────────────────────────────────────────────

const BIND_ZONES_DIR   = '/etc/bind/zones';
const BIND_CONF_LOCAL  = '/etc/bind/named.conf.local';

// Valeurs DNS par défaut dans PANEL_CONFIG
// PANEL_CONFIG.dns = { ns1, ns2, ttl, email, refresh, retry, expire, minimum, serverIp }

function dnsConf() {
  return PANEL_CONFIG.dns || {
    ns1:      'ns1.example.com',
    ns2:      '',
    ttl:      604800,
    email:    'admin.example.com',
    refresh:  604800,
    retry:    86400,
    expire:   2419200,
    minimum:  604800,
    serverIp: ''
  };
}

// Vérifie si BIND9 est disponible
async function bindAvailable() {
  try { await runCmd('which named'); return true; } catch { return false; }
}

// Génère un serial basé sur la date + index (format YYYYMMDDnn)
function generateSerial() {
  const now  = new Date();
  const date = `${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}`;
  return parseInt(date + '01');
}

// Incrémente le serial existant (ou génère un nouveau)
function bumpSerial(existing) {
  const today   = generateSerial();
  const current = parseInt(existing) || 0;
  if (current >= today) return current + 1;
  return today;
}

// Parse un fichier de zone en liste de records avec IDs
function parseZoneRecords(content) {
  const records = [];
  for (const line of content.split('\n')) {
    const m = line.match(/;kp-id:([a-z0-9]+)/);
    if (!m) continue;
    const id   = m[1];
    const clean = line.replace(/;kp-id:[a-z0-9]+/, '').replace(/\s*;\s*$/, '').trim();
    const parts = clean.split(/\s+/);
    if (parts.length >= 4) {
      // name [ttl] IN type value...
      let name, ttl, type, value;
      let i = 0;
      name = parts[i++];
      if (/^\d+$/.test(parts[i])) { ttl = parts[i++]; } else { ttl = null; }
      if (parts[i] === 'IN') i++;
      type  = parts[i++];
      value = parts.slice(i).join(' ');
      records.push({ id, name, ttl, type, value, raw: clean });
    }
  }
  return records;
}

// Générer un ID court aléatoire
function shortId() {
  return Math.random().toString(36).slice(2, 9);
}

// Crée ou recrée un fichier de zone complet depuis les records
function buildZoneFile(domain, records, serial) {
  const c   = dnsConf();
  const ttl = parseInt(c.ttl) || 3600;

  // Garantit un trailing dot (FQDN obligatoire dans une zone)
  const fqdn = s => {
    const t = (s || '').trim();
    return t ? (t.endsWith('.') ? t : t + '.') : '';
  };

  const ns1   = fqdn(c.ns1);
  const ns2   = fqdn(c.ns2);
  const email = fqdn((c.email || `hostmaster.${domain}`).replace('@', '.'));
  const serverIp = (c.serverIp || '').trim();

  const refresh = parseInt(c.refresh) || 3600;
  const retry   = parseInt(c.retry)   || 900;
  const expire  = parseInt(c.expire)  || 604800;
  const minimum = parseInt(c.minimum) || 300;

  // Détermine si un FQDN de NS est un sous-domaine de la zone (nécessite un glue record)
  // Ex : ns1.kazylax.fr. est dans la zone kazylax.fr → glue requis
  // Ex : ns1.otherwhere.com. → hors zone → pas de glue
  const zoneSuffix = `.${domain}.`;
  const isInZone   = fqdn => fqdn.endsWith(zoneSuffix) || fqdn === `${domain}.`;
  const glueLabel  = fqdn => fqdn.slice(0, -(zoneSuffix.length)); // retire ".domain." de la fin

  let out = `; Zone: ${domain}
; Générée par KazyPanel — ne pas éditer manuellement
$TTL ${ttl}
@ IN SOA ${ns1} ${email} (
  ${serial}  ; serial
  ${refresh} ; refresh
  ${retry}   ; retry
  ${expire}  ; expire
  ${minimum} ; minimum TTL
)
; -- Serveurs de noms --
@ IN NS ${ns1}
`;

  if (ns2) out += `@ IN NS ${ns2}\n`;

  // Glue records automatiques : si ns1/ns2 sont dans cette zone, qu'une IP est configurée,
  // ET que le label correspondant n'est pas déjà présent dans les records utilisateur
  if (serverIp) {
    const existingNames = new Set(records.map(r => r.name.toLowerCase()));
    if (isInZone(ns1)) {
      const label = glueLabel(ns1);
      if (!existingNames.has(label.toLowerCase())) {
        out += `${label} IN A ${serverIp} ; glue record auto\n`;
      }
    }
    if (ns2 && isInZone(ns2)) {
      const label = glueLabel(ns2);
      if (!existingNames.has(label.toLowerCase())) {
        out += `${label} IN A ${serverIp} ; glue record auto\n`;
      }
    }
  }

  out += '\n; -- Enregistrements utilisateur --\n';

  for (const r of records) {
    const name    = (r.name || '@').trim();
    const type    = (r.type || 'A').toUpperCase();
    const value   = (r.value || '').trim();
    const ttlPart = r.ttl ? `${parseInt(r.ttl)} ` : '';
    out += `${name} ${ttlPart}IN ${type} ${value} ;kp-id:${r.id}\n`;
  }
  return out;
}

// Lire les records d'une zone (sans les NS par défaut)
function readZoneRecords(domain) {
  const file = path.join(BIND_ZONES_DIR, `db.${domain}`);
  if (!fs.existsSync(file)) return [];
  return parseZoneRecords(fs.readFileSync(file, 'utf8'));
}

// Écrire une zone et recharger BIND
async function writeAndReload(domain, records, existingSerial) {
  const serial  = bumpSerial(existingSerial);
  const c       = dnsConf();

  // Garder l'IP du serveur si définie, pas de config ns1 vide
  if (!c.ns1) throw new Error('NS primaire non configuré — Admin → Config DNS (BIND9)');

  const content = buildZoneFile(domain, records, serial);

  if (!fs.existsSync(BIND_ZONES_DIR)) {
    await runCmd(`mkdir -p "${BIND_ZONES_DIR}" && chown root:bind "${BIND_ZONES_DIR}" && chmod 775 "${BIND_ZONES_DIR}"`);
  }

  const file    = path.join(BIND_ZONES_DIR, `db.${domain}`);
  const tmpFile = `/tmp/kp_zone_${domain}_${Date.now()}.tmp`;

  // Écrire dans /tmp (accessible sans droits root)
  fs.writeFileSync(tmpFile, content);

  // Valider avec named-checkzone si disponible
  const checkzonePath = await new Promise(r => exec(
    'which named-checkzone 2>/dev/null || find /usr /sbin /bin -name named-checkzone 2>/dev/null | head -1',
    (e, out) => r(out.trim() || null)
  ));
  if (checkzonePath) {
    await new Promise((resolve, reject) => {
      exec(`"${checkzonePath}" "${domain}" "${tmpFile}"`, (error, stdout, stderr) => {
        if (error) {
          try { fs.unlinkSync(tmpFile); } catch {}
          const detail = (stdout || stderr || error.message).trim().split('\n').slice(-3).join(' | ');
          reject(new Error(`Zone invalide : ${detail}`));
        } else {
          resolve();
        }
      });
    });
  }

  // Validation OK → copier vers le dossier bind avec sudo
  await runCmd(`sudo cp "${tmpFile}" "${file}" && sudo chown root:bind "${file}" && sudo chmod 644 "${file}"`);
  try { fs.unlinkSync(tmpFile); } catch {}

  // Recharger BIND9 — rndc reload si disponible, sinon systemctl
  try { await runCmd(`rndc reload "${domain}"`); }
  catch {
    try { await runCmd('rndc reload'); }
    catch { await runCmd('systemctl reload bind9 2>/dev/null || systemctl reload named 2>/dev/null || true'); }
  }

  return serial;
}

// Récupérer le serial actuel d'une zone
function getCurrentSerial(domain) {
  const file = path.join(BIND_ZONES_DIR, `db.${domain}`);
  if (!fs.existsSync(file)) return generateSerial();
  const m = fs.readFileSync(file, 'utf8').match(/(\d{8,10})\s*;\s*serial/);
  return m ? parseInt(m[1]) : generateSerial();
}

// S'assure que le domaine est déclaré dans named.conf.local
async function ensureZoneInConf(domain) {
  const file  = path.join(BIND_ZONES_DIR, `db.${domain}`);
  const entry = `\nzone "${domain}" {\n\ttype master;\n\tfile "${file}";\n\tallow-update { none; };\n};\n`;
  if (!fs.existsSync(BIND_CONF_LOCAL)) return;
  const content = fs.readFileSync(BIND_CONF_LOCAL, 'utf8');
  if (content.includes(`zone "${domain}"`)) return;
  const tmpNamed = `/tmp/kp_named_${Date.now()}`;
  fs.writeFileSync(tmpNamed, content + entry);
  await runCmd(`sudo cp "${tmpNamed}" "${BIND_CONF_LOCAL}" && sudo chmod 644 "${BIND_CONF_LOCAL}"`);
  fs.unlinkSync(tmpNamed);
  const checkconfPath = await new Promise(r => exec(
    'which named-checkconf 2>/dev/null || find /usr /sbin /bin -name named-checkconf 2>/dev/null | head -1',
    (e, out) => r(out.trim() || null)
  ));
  if (checkconfPath) {
    let tmpCreated = false;
    if (!fs.existsSync(file)) {
      try {
        await runCmd(`sudo mkdir -p "${BIND_ZONES_DIR}" && sudo chown root:bind "${BIND_ZONES_DIR}" && sudo chmod 775 "${BIND_ZONES_DIR}"`);
        const tmpPlaceholder = `/tmp/kp_zone_placeholder_${Date.now()}`;
        fs.writeFileSync(tmpPlaceholder, '; placeholder\n');
        await runCmd(`sudo cp "${tmpPlaceholder}" "${file}" && sudo chmod 644 "${file}"`);
        fs.unlinkSync(tmpPlaceholder);
        tmpCreated = true;
      } catch {}
    }
    try {
      await runCmd(`"${checkconfPath}"`);
    } catch (e) {
      const cleaned = fs.readFileSync(BIND_CONF_LOCAL, 'utf8').replace(entry, '');
      const tmpNamedClean = `/tmp/kp_named_clean_${Date.now()}`;
      fs.writeFileSync(tmpNamedClean, cleaned);
      await runCmd(`sudo cp "${tmpNamedClean}" "${BIND_CONF_LOCAL}" && sudo chmod 644 "${BIND_CONF_LOCAL}"`);
      fs.unlinkSync(tmpNamedClean);
      if (tmpCreated) try { await runCmd(`sudo rm -f "${file}"`); } catch {}
      throw new Error(`Erreur named.conf : ${e.message}`);
    }
    if (tmpCreated) try { await runCmd(`sudo rm -f "${file}"`); } catch {}
  }
}

// Retire une zone de named.conf.local
function removeZoneFromConf(domain) {
  if (!fs.existsSync(BIND_CONF_LOCAL)) return;
  let content = fs.readFileSync(BIND_CONF_LOCAL, 'utf8');
  const safe  = domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const regex = new RegExp(`\\nzone\\s+"${safe}"\\s*\\{[^]*?\\};\\s*\\n?`, 'g');
  const cleaned = content.replace(regex, '\n').replace(/\n{3,}/g, '\n\n').trimEnd() + '\n';
  const tmpNamed = `/tmp/kp_named_remove_${Date.now()}`;
  fs.writeFileSync(tmpNamed, cleaned);
  require('child_process').execSync(`sudo cp "${tmpNamed}" "${BIND_CONF_LOCAL}" && sudo chmod 644 "${BIND_CONF_LOCAL}"`);
  fs.unlinkSync(tmpNamed);
}

// Vérifie que l'utilisateur est propriétaire du domaine DNS
function userOwnsDnsZone(user, domain) {
  const safe = domain.replace(/[^a-zA-Z0-9._-]/g, '');
  // Le domaine doit correspondre à un VirtualHost appartenant à l'utilisateur
  if (!fs.existsSync(CONFIG.APACHE_SITES_PATH)) return false;
  const conf = path.join(CONFIG.APACHE_SITES_PATH, `${safe}.conf`);
  if (!fs.existsSync(conf)) return false;
  const text    = fs.readFileSync(conf, 'utf8');
  const docRoot = (text.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim() || '';
  return userOwnsDocRoot(user, docRoot);
}

// ── Config DNS par défaut (admin) ─────────────────────────────────────────────
app.get('/api/config/dns', authMiddleware, adminOnly, (req, res) => {
  res.json(dnsConf());
});

app.put('/api/config/dns', authMiddleware, adminOnly, (req, res) => {
  const allowed = ['ns1','ns2','ttl','email','refresh','retry','expire','minimum','serverIp'];
  const update  = {};
  for (const k of allowed) {
    if (req.body[k] !== undefined) update[k] = req.body[k];
  }
  PANEL_CONFIG.dns = { ...(PANEL_CONFIG.dns || {}), ...update };
  savePanelConfig();
  log('CONFIG_DNS', JSON.stringify(update), 'OK');
  res.json({ success: true, config: dnsConf() });
});

// ── Setup HTTPS sous-domaine panel ────────────────────────────────────────────
app.post('/api/config/setup-https', authMiddleware, adminOnly, async (req, res) => {
  const { fqdn, port, email } = req.body;
  if (!fqdn || !port || !email)
    return res.status(400).json({ error: 'fqdn, port et email requis' });

  if (!/^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/.test(fqdn))
    return res.status(400).json({ error: 'Sous-domaine invalide' });

  const confPath = `/etc/apache2/sites-available/${fqdn}.conf`;
  const logLines = [];
  const out = msg => logLines.push(msg);

  try {
    // 1. Activer les modules Apache nécessaires
    out('→ Activation des modules proxy Apache…');
    await runCmd('a2enmod proxy proxy_http headers ssl rewrite 2>&1 || true');

    // 2. Créer le vhost HTTP (port 80) avec redirection HTTPS + ACME challenge
    out(`→ Création du vhost HTTP pour ${fqdn}…`);
    const vhostHttp = `<VirtualHost *:80>
    ServerName ${fqdn}
    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/.well-known/acme-challenge/
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>`;
    const tmpHttp = `/tmp/kp_vhost_http_${Date.now()}.conf`;
    fs.writeFileSync(tmpHttp, vhostHttp);
    await runCmd(`sudo cp "${tmpHttp}" "${confPath}" && sudo chmod 644 "${confPath}"`);
    fs.unlinkSync(tmpHttp);
    await runCmd(`a2ensite ${fqdn}.conf 2>&1`);
    await runCmd('apache2ctl graceful 2>&1');

    // 3. Obtenir le certificat SSL
    out(`→ Obtention du certificat Let's Encrypt pour ${fqdn}…`);
    const certResult = await runCmd(
      `certbot certonly --apache -d ${fqdn} --email ${email} --agree-tos --non-interactive 2>&1`
    );
    out(certResult.trim());

    // 4. Créer le vhost HTTPS avec reverse proxy
    out('→ Création du vhost HTTPS avec reverse proxy…');
    const vhostHttps = `<VirtualHost *:80>
    ServerName ${fqdn}
    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/.well-known/acme-challenge/
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>

<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName ${fqdn}

    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:${port}/
    ProxyPassReverse / http://127.0.0.1:${port}/

    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"

    SSLCertificateFile    /etc/letsencrypt/live/${fqdn}/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/${fqdn}/privkey.pem
    Include /etc/letsencrypt/options-ssl-apache.conf
</VirtualHost>
</IfModule>`;
    const tmpHttps = `/tmp/kp_vhost_https_${Date.now()}.conf`;
    fs.writeFileSync(tmpHttps, vhostHttps);
    await runCmd(`sudo cp "${tmpHttps}" "${confPath}" && sudo chmod 644 "${confPath}"`);
    fs.unlinkSync(tmpHttps);

    // 5. Recharger Apache
    out('→ Rechargement Apache…');
    await runCmd('apache2ctl configtest 2>&1');
    await runCmd('systemctl reload apache2 2>&1');
    out(`✅ Panel accessible sur https://${fqdn}`);

    // Sauvegarder dans panel_config
    PANEL_CONFIG.panelHttpsUrl = `https://${fqdn}`;
    savePanelConfig();

    res.json({ success: true, url: `https://${fqdn}`, log: logLines.join('\n') });
  } catch(e) {
    out(`❌ ${e.message}`);
    res.status(500).json({ error: e.message, log: logLines.join('\n') });
  }
});

// ── Zones de l'utilisateur ────────────────────────────────────────────────────

// Lister les zones DNS de l'utilisateur
app.get('/api/me/dns', authMiddleware, (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  const zones = [];
  if (fs.existsSync(BIND_ZONES_DIR)) {
    for (const file of fs.readdirSync(BIND_ZONES_DIR).filter(f => f.startsWith('db.'))) {
      const domain  = file.slice(3); // strip "db."
      if (!userOwnsDnsZone(user, domain)) continue;
      const records = readZoneRecords(domain);
      zones.push({ domain, records, serial: getCurrentSerial(domain) });
    }
  }
  res.json({ zones, dnsConfig: dnsConf() });
});

// Créer une zone DNS pour un domaine de l'utilisateur
app.post('/api/me/dns', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domaine requis' });
  const safe = domain.replace(/[^a-zA-Z0-9._-]/g, '').toLowerCase();

  if (!userOwnsDnsZone(user, safe)) {
    return res.status(403).json({ error: 'Ce domaine ne vous appartient pas ou n\'existe pas dans Apache.' });
  }
  const file = path.join(BIND_ZONES_DIR, `db.${safe}`);
  if (fs.existsSync(file)) return res.status(409).json({ error: 'Zone déjà configurée' });

  try {
    const c        = dnsConf();
    const serverIp = c.serverIp || '';

    // Records initiaux conformes au modèle de référence :
    // @ A, www A, ns1 A (glue), ns2 A (glue si ns2 dans la zone), CAA Let's Encrypt
    const initRecords = [];

    if (serverIp) {
      // Enregistrement racine
      initRecords.push({ id: shortId(), name: '@',   ttl: null, type: 'A', value: serverIp });
      // www
      initRecords.push({ id: shortId(), name: 'www', ttl: null, type: 'A', value: serverIp });
      // ns1 / ns2 glue si dans la zone (buildZoneFile les injecte aussi, mais on les met
      // explicitement en records utilisateur pour qu'ils soient éditables)
      const zoneSuffix = `.${safe}.`;
      const fqdn = s => s && !s.endsWith('.') ? s + '.' : s;
      const ns1fqdn = fqdn(c.ns1 || '');
      const ns2fqdn = fqdn(c.ns2 || '');
      if (ns1fqdn && ns1fqdn.endsWith(zoneSuffix)) {
        const label = ns1fqdn.slice(0, -(zoneSuffix.length));
        initRecords.push({ id: shortId(), name: label, ttl: null, type: 'A', value: serverIp });
      }
      if (ns2fqdn && ns2fqdn.endsWith(zoneSuffix)) {
        const label = ns2fqdn.slice(0, -(zoneSuffix.length));
        initRecords.push({ id: shortId(), name: label, ttl: null, type: 'A', value: serverIp });
      }
      // CAA Let's Encrypt (recommandé pour la sécurité SSL)
      initRecords.push({ id: shortId(), name: `${safe}.`, ttl: null, type: 'CAA', value: '0 issue "letsencrypt.org"' });
      initRecords.push({ id: shortId(), name: `${safe}.`, ttl: null, type: 'CAA', value: '0 issuewild "letsencrypt.org"' });
    }

    // 1. Déclarer la zone dans named.conf.local EN PREMIER
    //    (BIND doit connaître la zone avant le premier reload)
    await ensureZoneInConf(safe);

    // 2. Écrire le fichier de zone et recharger BIND
    const serial = await writeAndReload(safe, initRecords, null);

    log('DNS_CREATE_ZONE', `${user.username} → ${safe}`, 'OK');
    res.status(201).json({ success: true, message: `Zone ${safe} créée avec ${initRecords.length} enregistrement(s) initial/initiaux`, domain: safe, serial });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Lire les records d'une zone utilisateur
app.get('/api/me/dns/:domain', authMiddleware, (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const domain = req.params.domain.replace(/[^a-zA-Z0-9._-]/g, '').toLowerCase();

  if (!userOwnsDnsZone(user, domain)) return res.status(403).json({ error: 'Accès refusé' });
  const file = path.join(BIND_ZONES_DIR, `db.${domain}`);
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'Zone introuvable' });

  const records = readZoneRecords(domain);
  res.json({ domain, records, serial: getCurrentSerial(domain), dnsConfig: dnsConf() });
});

// Ajouter un record dans une zone
app.post('/api/me/dns/:domain/records', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const domain = req.params.domain.replace(/[^a-zA-Z0-9._-]/g, '').toLowerCase();
  if (!userOwnsDnsZone(user, domain)) return res.status(403).json({ error: 'Accès refusé' });

  const { name, type, value, ttl } = req.body;
  if (!name || !type || !value) return res.status(400).json({ error: 'name, type, value requis' });

  const allowedTypes = ['A','AAAA','CNAME','MX','TXT','NS'];
  if (!allowedTypes.includes(type.toUpperCase()))
    return res.status(400).json({ error: `Type non supporté. Autorisés : ${allowedTypes.join(', ')}` });

  const records  = readZoneRecords(domain);
  const newRecord = { id: shortId(), name: name.trim(), ttl: ttl || null, type: type.toUpperCase(), value: value.trim() };
  records.push(newRecord);

  try {
    const serial = await writeAndReload(domain, records, getCurrentSerial(domain));
    log('DNS_ADD_RECORD', `${user.username} → ${domain} | ${type} ${name} ${value}`, 'OK');
    res.json({ success: true, message: 'Enregistrement ajouté et zone rechargée', record: newRecord, serial });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Supprimer un record d'une zone
app.delete('/api/me/dns/:domain/records/:id', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const domain = req.params.domain.replace(/[^a-zA-Z0-9._-]/g, '').toLowerCase();
  if (!userOwnsDnsZone(user, domain)) return res.status(403).json({ error: 'Accès refusé' });

  const records = readZoneRecords(domain).filter(r => r.id !== req.params.id);
  try {
    const serial = await writeAndReload(domain, records, getCurrentSerial(domain));
    log('DNS_DEL_RECORD', `${user.username} → ${domain} | id:${req.params.id}`, 'OK');
    res.json({ success: true, message: 'Enregistrement supprimé et zone rechargée', serial });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Appliquer les NS par défaut (remplace les NS dans le fichier de zone et recharge)
app.post('/api/me/dns/:domain/apply-ns', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const domain = req.params.domain.replace(/[^a-zA-Z0-9._-]/g, '').toLowerCase();
  if (!userOwnsDnsZone(user, domain)) return res.status(403).json({ error: 'Accès refusé' });

  // Les NS par défaut sont écrits dans l'en-tête par buildZoneFile — pas de record spécifique NS admin
  // On se contente de réécrire la zone (ce qui remet les NS admin en place)
  const records = readZoneRecords(domain).filter(r => r.type !== 'NS'); // retire NS custom si existants
  try {
    const serial = await writeAndReload(domain, records, getCurrentSerial(domain));
    log('DNS_APPLY_NS', `${user.username} → ${domain}`, 'OK');
    res.json({ success: true, message: 'NS par défaut appliqués et zone rechargée', serial });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Supprimer une zone entière
app.delete('/api/me/dns/:domain', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === parseInt(req.user.id));
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const domain = req.params.domain.replace(/[^a-zA-Z0-9._-]/g, '').toLowerCase();
  if (!userOwnsDnsZone(user, domain)) return res.status(403).json({ error: 'Accès refusé' });

  const file = path.join(BIND_ZONES_DIR, `db.${domain}`);
  try {
    if (fs.existsSync(file)) await runCmd(`sudo rm -f "${file}"`);
    removeZoneFromConf(domain);
    try { await runCmd(`rndc delzone ${domain}`); } catch {}
    try { await runCmd('systemctl reload bind9 || systemctl reload named'); } catch {}
    log('DNS_DELETE_ZONE', `${user.username} → ${domain}`, 'OK');
    res.json({ success: true, message: `Zone ${domain} supprimée` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});



// ─── ROUTE: TERMINAL (admin seulement) ───────────────────────────────────────
// Sessions : Map<sessionId, { cwd, env, lastActivity }>
const termSessions = new Map();

// POST /api/terminal/session — créer une session
app.post('/api/terminal/session', authMiddleware, adminOnly, (req, res) => {
  const sessionId = require('crypto').randomBytes(16).toString('hex');
  termSessions.set(sessionId, {
    cwd: '/home/debian',
    env: { ...process.env, TERM: 'xterm-256color', HOME: '/home/debian', USER: 'debian' },
    lastActivity: Date.now()
  });
  // Nettoyage auto après 30 min
  const cleanup = setInterval(() => {
    const s = termSessions.get(sessionId);
    if (!s || Date.now() - s.lastActivity > 30 * 60 * 1000) {
      termSessions.delete(sessionId);
      clearInterval(cleanup);
    }
  }, 60000);
  log('TERMINAL', `Session ouverte par ${req.user.username}`, 'OK');
  res.json({ sessionId, cwd: '/home/debian' });
});

// POST /api/terminal/:id/exec — exécuter une commande
app.post('/api/terminal/:id/exec', authMiddleware, adminOnly, async (req, res) => {
  const session = termSessions.get(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session introuvable ou expirée' });

  const { cmd } = req.body;
  if (!cmd || typeof cmd !== 'string') return res.status(400).json({ error: 'cmd requis' });

  session.lastActivity = Date.now();

  // Commande cd spéciale — on change le cwd de la session
  const cdMatch = cmd.trim().match(/^cd\s*(.*)?$/);
  if (cdMatch) {
    const target = (cdMatch[1] || '').trim() || '/home/debian';
    const dest = target.startsWith('/') ? target
      : target === '~' ? '/home/debian'
      : require('path').resolve(session.cwd, target);
    if (require('fs').existsSync(dest)) {
      session.cwd = dest;
      return res.json({ output: '', cwd: session.cwd });
    } else {
      return res.json({ output: `-bash: cd: ${target}: Aucun fichier ou dossier de ce type\n`, cwd: session.cwd });
    }
  }

  // Wrapper : source bashrc + exécuter la commande avec sudo si nécessaire
  const wrapped = `bash -c "source /home/debian/.bashrc 2>/dev/null; ${cmd.replace(/"/g, '\\"')}"`;
  const finalCmd = needsSudo(cmd) ? `sudo ${wrapped}` : wrapped;

  try {
    const output = await new Promise((resolve) => {
      require('child_process').exec(finalCmd, {
        cwd: session.cwd,
        env: session.env,
        timeout: 30000,
        maxBuffer: 512 * 1024
      }, (err, stdout, stderr) => {
        resolve((stdout || '') + (stderr || ''));
      });
    });
    res.json({ output: output || '\n', cwd: session.cwd });
  } catch (err) {
    res.json({ output: `Erreur : ${err.message}\n`, cwd: session.cwd });
  }
});

// DELETE /api/terminal/:id — fermer la session
app.delete('/api/terminal/:id', authMiddleware, adminOnly, (req, res) => {
  termSessions.delete(req.params.id);
  res.json({ ok: true });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('⚠️  Erreur non capturée :', err.stack || err.message);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ error: err.message || 'Erreur interne du serveur' });
});

initUsers().then(() => {
  app.listen(PORT, '0.0.0.0', () => {});
});
