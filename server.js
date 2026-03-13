/**
 * KazyPanel - Serveur Node.js
 * Gestion des domaines/sous-domaines Apache + PHP 8.4
 * Port: 8080
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 8080;

// ─── VERSION ──────────────────────────────────────────────────────────────────
const KAZYPANEL_VERSION = '1.0.0';
const KAZYPANEL_UPDATE_URL = 'https://raw.githubusercontent.com/kazypanel/kazypanel/main/version.json';

// ─── CONFIGURATION ────────────────────────────────────────────────────────────
const CONFIG = {
  JWT_SECRET: process.env.JWT_SECRET || 'CHANGEZ_CE_SECRET_EN_PRODUCTION_' + Math.random(),
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
const { spawn } = require('child_process');

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
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function log(action, detail, status = 'OK') {
  const entry = `[${new Date().toISOString()}] [${status}] ${action}: ${detail}`;
  console.log(entry);
  try { fs.appendFileSync(CONFIG.LOG_FILE, entry + '\n'); } catch {}
}

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

function runCmd(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd, { timeout: 30000 }, (error, stdout, stderr) => {
      if (error) reject(new Error(stderr || error.message));
      else resolve(stdout.trim());
    });
  });
}

// Utilise spawn + stdin pour éviter les problèmes d'échappement avec chpasswd
function setSystemPassword(username, password) {
  return new Promise((resolve, reject) => {
    const proc = spawn('chpasswd', [], { timeout: 10000 });
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
  const user = USERS.find(u => u.id == req.user.id);
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

    res.json({ sshPort, motd, jailLocal, timezone, maintenanceMsg, maintenanceEnabled });
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
    fs.writeFileSync('/etc/ssh/sshd_config', updated);
    await runCmd('systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true');
    log('SSH_PORT', `Port SSH changé vers ${p}`, 'OK');
    res.json({ success: true, message: `Port SSH changé vers ${p} — reconnectez-vous sur le port ${p}` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/server-config/motd — mettre à jour /etc/motd
app.post('/api/server-config/motd', authMiddleware, adminOnly, (req, res) => {
  const { motd } = req.body;
  if (motd === undefined) return res.status(400).json({ error: 'Contenu requis' });
  try {
    fs.writeFileSync('/etc/motd', motd + '\n', 'utf8');
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
  try { fs.mkdirSync('/etc/fail2ban/filter.d', { recursive: true }); } catch {}

  // Créer automatiquement le filtre kazypanel s'il est référencé et manquant
  const filterPath = '/etc/fail2ban/filter.d/kazypanel.conf';
  if (content.includes('filter   = kazypanel') || content.includes('filter=kazypanel')) {
    if (!fs.existsSync(filterPath)) {
      try {
        fs.writeFileSync(filterPath, KAZYPANEL_FILTER, 'utf8');
        log('FAIL2BAN_FILTER', 'Filtre kazypanel.conf créé automatiquement', 'OK');
      } catch (e) {
        return res.status(500).json({ error: `Impossible de créer le filtre kazypanel : ${e.message}` });
      }
    }
  }

  // Sauvegarde de l'ancien jail.local
  const bak = '/etc/fail2ban/jail.local.bak.' + Date.now();
  try { fs.copyFileSync('/etc/fail2ban/jail.local', bak); } catch {}

  try {
    fs.writeFileSync('/etc/fail2ban/jail.local', content, 'utf8');
    await runCmd('systemctl restart fail2ban');
    log('FAIL2BAN_CONFIG', 'jail.local mis à jour et redémarré', 'OK');
    const filterCreated = content.includes('filter   = kazypanel') && !fs.existsSync(filterPath + '.exists');
    res.json({ success: true, message: 'Fail2ban reconfiguré et redémarré' + (filterCreated ? ' — filtre kazypanel.conf créé' : '') });
  } catch (err) {
    // Restaurer la sauvegarde en cas d'erreur
    try { fs.copyFileSync(bak, '/etc/fail2ban/jail.local'); await runCmd('systemctl restart fail2ban'); } catch {}
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
  try {
    // Fetch du fichier version.json distant via https natif
    const remoteData = await new Promise((resolve, reject) => {
      const req = https.get(KAZYPANEL_UPDATE_URL, { timeout: 8000 }, (r) => {
        let body = '';
        r.on('data', d => { body += d; });
        r.on('end', () => {
          try { resolve(JSON.parse(body)); }
          catch { reject(new Error('Réponse invalide du serveur de mises à jour')); }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout serveur de mises à jour')); });
    });

    const latest   = remoteData.version || '0.0.0';
    const current  = KAZYPANEL_VERSION;

    // Comparaison semver simple
    const toNum = v => v.split('.').map(Number).reduce((a, n, i) => a + n * Math.pow(1000, 2 - i), 0);
    const hasUpdate = toNum(latest) > toNum(current);

    res.json({
      current,
      latest,
      hasUpdate,
      changelog:    remoteData.changelog    || [],
      releaseDate:  remoteData.releaseDate  || null,
      downloadUrl:  remoteData.downloadUrl  || null,
      releaseNotes: remoteData.releaseNotes || '',
    });
  } catch (err) {
    // En cas d'échec réseau, on renvoie quand même la version locale
    res.json({
      current:   KAZYPANEL_VERSION,
      latest:    null,
      hasUpdate: false,
      error:     err.message,
    });
  }
});

// ─── ROUTE: VERSION LOCALE ────────────────────────────────────────────────────
app.get('/api/version', authMiddleware, (req, res) => {
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
app.get('/api/users', authMiddleware, adminOnly, (req, res) => {
  const users = USERS.map(u => ({
    id: u.id,
    username: u.username,
    role: u.role,
    createdAt: u.createdAt || null,
    ftpAccounts: u.ftpAccounts || [],
    ftpLimit: u.ftpLimit ?? CONFIG.FTP_DEFAULT_LIMIT,
    dbLimit: u.dbLimit ?? CONFIG.DB_DEFAULT_LIMIT,
    domainLimit:    u.domainLimit    ?? 0,
    subdomainLimit: u.subdomainLimit ?? 0,
    diskLimit:      u.diskLimit      ?? 0,
    dbStorageLimit: u.dbStorageLimit ?? 0,
    cronLimit:      u.cronLimit      ?? 10,
    templateId:   u.templateId   || null,
    templateName: u.templateName || null
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
      await runCmd(`mkdir -p "${homeDir}"`);
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
      if (!list.split('\n').includes(username))
        fs.appendFileSync(vsftpdUserList, `\n${username}`);
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
        .filter(f => f.endsWith('.conf') && !['000-default.conf', 'default-ssl.conf'].includes(f));

      for (const file of files) {
        try {
          const conf = fs.readFileSync(path.join(CONFIG.APACHE_SITES_PATH, file), 'utf8');
          const docRoot = (conf.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim() || '';
          if (allDirs.some(dir => docRoot.startsWith(dir))) {
            const name = file.replace('.conf', '');
            const enabledLink = path.join(CONFIG.APACHE_ENABLED_PATH, file);
            if (fs.existsSync(enabledLink)) fs.unlinkSync(enabledLink);
            fs.unlinkSync(path.join(CONFIG.APACHE_SITES_PATH, file));
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
  } catch (e) { errors.push(`Dossier ${userDir}: ${e.message}`); }

  saveUsers();
  log('DELETE_USER', `${deleted.username} par ${req.user.username}`, 'OK');

  const msg = errors.length
    ? `Utilisateur ${deleted.username} supprimé (${errors.length} avertissement(s) : ${errors.join(', ')})`
    : `Utilisateur ${deleted.username} supprimé avec toutes ses ressources`;

  res.json({ success: true, message: msg });
});

// ─── HELPERS FTP ──────────────────────────────────────────────────────────────
async function createFtpSystemAccount(ftpUsername, homeDir, password) {
  let exists = false;
  try { await runCmd(`id ${ftpUsername}`); exists = true; } catch {}
  if (!exists) {
    await runCmd(`mkdir -p "${homeDir}"`);
    await runCmd(`useradd -d "${homeDir}" -s /bin/bash -M ${ftpUsername}`);
    await runCmd(`chown ${ftpUsername}:${ftpUsername} "${homeDir}"`);
    await runCmd(`chmod 755 "${homeDir}"`);
  }
  await setSystemPassword(ftpUsername, password);
  const list = '/etc/vsftpd.userlist';
  if (fs.existsSync(list)) {
    const lines = fs.readFileSync(list, 'utf8');
    if (!lines.split('\n').includes(ftpUsername))
      fs.appendFileSync(list, `\n${ftpUsername}`);
  }
}

async function deleteFtpSystemAccount(ftpUsername) {
  try { await runCmd(`userdel ${ftpUsername} 2>/dev/null || true`); } catch {}
  const list = '/etc/vsftpd.userlist';
  if (fs.existsSync(list)) {
    const lines = fs.readFileSync(list, 'utf8').split('\n')
      .filter(l => l.trim() !== ftpUsername);
    fs.writeFileSync(list, lines.join('\n'));
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
  const user = USERS.find(u => u.id == req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  res.json({
    ftpAccounts: user.ftpAccounts || [],
    ftpLimit: user.ftpLimit ?? CONFIG.FTP_DEFAULT_LIMIT,
    count: (user.ftpAccounts || []).length
  });
});

// Créer un de mes comptes FTP
app.post('/api/me/ftp', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id == req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  const limit = user.ftpLimit ?? CONFIG.FTP_DEFAULT_LIMIT;
  if (!user.ftpAccounts) user.ftpAccounts = [];
  if (limit > 0 && user.ftpAccounts.length >= limit)
    return res.status(403).json({ error: `Limite atteinte (${limit} compte${limit > 1 ? 's' : ''} FTP maximum)` });

  const { ftpPassword, ftpSuffix } = req.body;
  if (!ftpPassword) return res.status(400).json({ error: 'Mot de passe FTP requis' });

  const check = validatePassword(ftpPassword);
  if (!check.valid) return res.status(400).json({ error: 'Mot de passe trop faible', rules: check.errors });

  const suffix = ftpSuffix ? ftpSuffix.replace(/[^a-zA-Z0-9]/g, '').toLowerCase() : '';
  if (!suffix && user.ftpAccounts.find(a => a.ftpUsername === user.username))
    return res.status(409).json({ error: 'Le compte FTP principal existe déjà. Choisissez un suffixe.' });
  if (suffix && !/^[a-z0-9]{1,12}$/.test(suffix))
    return res.status(400).json({ error: 'Suffixe invalide (lettres/chiffres, 12 car. max)' });

  const ftpUsername = suffix ? `${user.username}_${suffix}` : user.username;
  const homeDir = `${CONFIG.FTP_ROOT}/${user.username}`;
  const label = suffix ? suffix : 'Compte principal';

  if (user.ftpAccounts.find(a => a.ftpUsername === ftpUsername))
    return res.status(409).json({ error: `Le compte FTP "${ftpUsername}" existe déjà` });

  try {
    await createFtpSystemAccount(ftpUsername, homeDir, ftpPassword);
    user.ftpAccounts.push({ ftpUsername, label, dir: homeDir, createdAt: new Date().toISOString() });
    saveUsers();
    log('FTP_CREATE_USER', `${user.username} → ${ftpUsername}`, 'OK');
    res.status(201).json({ success: true, message: `Compte FTP "${ftpUsername}" créé`, ftpUsername, dir: homeDir });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Changer le mot de passe d'un de mes comptes FTP
app.put('/api/me/ftp/:ftpUser', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id == req.user.id);
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

// Supprimer un de mes comptes FTP
app.delete('/api/me/ftp/:ftpUser', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id == req.user.id);
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

// ─── ROUTE: MON PROFIL (utilisateur connecté) ────────────────────────────────
app.get('/api/me', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id == req.user.id);
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
        .filter(f => f.endsWith('.conf') && !['000-default.conf','default-ssl.conf'].includes(f));
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
  const user = USERS.find(u => u.id == req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const databases = await getUserDatabases(user.username);
  const limit = user.dbLimit ?? CONFIG.DB_DEFAULT_LIMIT;
  res.json({ databases, count: databases.length, limit });
});

// Créer une base de données
app.post('/api/me/databases', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id == req.user.id);
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
  const user = USERS.find(u => u.id == req.user.id);
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
  const user = USERS.find(u => u.id === req.user.id);
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
  await runCmd(`mkdir -p ${CRONTAB_DIR}`);
  const filePath = `${CRONTAB_DIR}/${username}`;
  // Écrire via un fichier tmp pour éviter les problèmes d'échappement shell
  const tmpPath = `/tmp/kp_cron_${username}_${Date.now()}`;
  fs.writeFileSync(tmpPath, content, 'utf8');
  await runCmd(`cp "${tmpPath}" "${filePath}" && chmod 600 "${filePath}" && chown ${username}: "${filePath}" 2>/dev/null; rm -f "${tmpPath}"`);
}

// GET /api/me/crontab
app.get('/api/me/crontab', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  try {
    const raw = readUserCrontabFile(user.username);
    res.json({ entries: parseUserCrontab(raw), raw });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/me/crontab — ajouter une entrée
app.post('/api/me/crontab', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id === req.user.id);
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
  const user = USERS.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const targetId = parseInt(req.params.id);
  if (!targetId) return res.status(400).json({ error: 'ID invalide' });
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
  const user    = USERS.find(u => u.id === req.user.id);
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
  const user = USERS.find(u => u.id == req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  if (!user.ftpAccounts || !user.ftpAccounts.length)
    return res.status(403).json({ error: 'Aucun compte FTP configuré. Contactez l\'administrateur.' });

  try {
    if (!fs.existsSync(CONFIG.APACHE_SITES_PATH)) return res.json({ domains: [] });
    const files = fs.readdirSync(CONFIG.APACHE_SITES_PATH)
      .filter(f => f.endsWith('.conf') && !['000-default.conf', 'default-ssl.conf'].includes(f));

    const domains = files
      .map(file => {
        const name = file.replace('.conf', '');
        const conf = fs.readFileSync(path.join(CONFIG.APACHE_SITES_PATH, file), 'utf8');
        const docRoot = (conf.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim() || '';
        const isEnabled = fs.existsSync(path.join(CONFIG.APACHE_ENABLED_PATH, file));
        const ports = [...conf.matchAll(/<VirtualHost\s+[^:>]+:(\d+)/gi)].map(m => parseInt(m[1]));
        const hasSsl = ports.includes(443);
        return {
          name,
          domain: (conf.match(/ServerName\s+(.+)/) || [])[1]?.trim() || name,
          docRoot,
          phpVersion: (conf.match(/php(\d+\.\d+)-fpm/) || [])[1] || CONFIG.PHP_VERSION,
          enabled: isEnabled,
          isSubdomain: name.split('.').length > 2,
          hasSsl,
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
  const user = USERS.find(u => u.id == req.user.id);
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
      .filter(f => f.endsWith('.conf') && !['000-default.conf','default-ssl.conf'].includes(f));
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
    await runCmd(`mkdir -p "${webRoot}"`);
    const domainRoot = isSubdomain
      ? `${ftpDir}/${parts.slice(1).join('.')}`
      : `${ftpDir}/${safeDomain}`;
    await runCmd(`chown -R ${user.username}:${user.username} "${domainRoot}"`);

    const vhostConfig = isSubdomain
      ? generateVhostConfigSub(safeDomain, webRoot, phpVersion)
      : generateVhostConfig(safeDomain, webRoot, phpVersion, false);

    fs.writeFileSync(`${webRoot}/index.html`, defaultIndexPage(safeDomain, isSubdomain));
    fs.writeFileSync(confFile, vhostConfig);
    await runCmd(`a2ensite ${safeDomain}.conf && systemctl reload apache2`);
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
  const user = USERS.find(u => u.id == req.user.id);
  if (!user || !user.ftpAccounts || !user.ftpAccounts.length) return res.status(403).json({ error: 'Accès refusé' });
  const safeName = req.params.name.replace(/[^a-zA-Z0-9._-]/g, '');
  const confFile = path.join(CONFIG.APACHE_SITES_PATH, `${safeName}.conf`);
  if (!fs.existsSync(confFile)) return res.status(404).json({ error: 'Configuration introuvable' });
  const conf = fs.readFileSync(confFile, 'utf8');
  const docRoot = (conf.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim() || '';
  if (!userOwnsDocRoot(user, docRoot)) return res.status(403).json({ error: 'Ce domaine ne vous appartient pas' });
  res.json({ name: safeName, config: conf });
});

// Supprimer un domaine de l'utilisateur
app.delete('/api/me/domains/:name', authMiddleware, async (req, res) => {
  const user = USERS.find(u => u.id == req.user.id);
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
    fs.unlinkSync(confFile);
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
  const user = USERS.find(u => u.id == req.user.id);
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
    const { execSync } = require('child_process');
    const raw = execSync(`tail -n ${lines} "${resolved}" 2>/dev/null`, { timeout: 5000 }).toString();
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
      .filter(f => f.endsWith('.conf') && !['000-default.conf', 'default-ssl.conf'].includes(f));
    const domains = files.map(file => {
      const name = file.replace('.conf', '');
      const conf = fs.readFileSync(path.join(CONFIG.APACHE_SITES_PATH, file), 'utf8');
      const isEnabled = fs.existsSync(path.join(CONFIG.APACHE_ENABLED_PATH, file));
      const sslCertPath = `/etc/letsencrypt/live/${name}/fullchain.pem`;
      return {
        name,
        domain: (conf.match(/ServerName\s+(.+)/) || [])[1]?.trim() || name,
        docRoot: (conf.match(/DocumentRoot\s+(.+)/) || [])[1]?.trim() || `${CONFIG.WEB_ROOT}/${name}/public_html`,
        phpVersion: (conf.match(/php(\d+\.\d+)-fpm/) || [])[1] || CONFIG.PHP_VERSION,
        enabled: isEnabled,
        isSubdomain: name.split('.').length > 2,
        ssl: conf.includes('VirtualHost *:443') || fs.existsSync(sslCertPath)
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
    await runCmd(`mkdir -p "${webRoot}"`);
    await runCmd(`chown -R www-data:www-data "${webRoot}"`);
    fs.writeFileSync(`${webRoot}/index.html`, defaultIndexPage(safeDomain, false));
    fs.writeFileSync(confFile, generateVhostConfig(safeDomain, webRoot, phpVersion, enableSsl));
    await runCmd(`a2ensite ${safeDomain}.conf && systemctl reload apache2`);
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
    fs.writeFileSync(confFile, generateVhostConfig(safeName, webRoot, phpVersion || CONFIG.PHP_VERSION, false));
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
    fs.unlinkSync(confFile);
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
    await runCmd(`${enable ? 'a2ensite' : 'a2dissite'} ${safeName}.conf && systemctl reload apache2`);
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
  try { s.uptime = await runCmd('uptime -p'); } catch { s.uptime = 'N/A'; }
  try { s.memory = await runCmd("free -m | awk 'NR==2{printf \"%d/%d MB (%.0f%%)\", $3,$2,$3*100/$2}'"); } catch { s.memory = 'N/A'; }
  try { s.disk = await runCmd("df -h / | awk 'NR==2{printf \"%s/%s (%s)\", $3,$2,$5}'"); } catch { s.disk = 'N/A'; }
  try { s.load = await runCmd("cat /proc/loadavg | awk '{print $1, $2, $3}'"); } catch { s.load = 'N/A'; }
  try { s.hostname = await runCmd('hostname'); } catch { s.hostname = 'N/A'; }
  try { s.os = await runCmd('lsb_release -d -s 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d \'"\''); } catch { s.os = 'N/A'; }
  try { s.nodeVersion = process.version; } catch {}
  try { s.domains = fs.existsSync(CONFIG.APACHE_SITES_PATH) ? fs.readdirSync(CONFIG.APACHE_SITES_PATH).filter(f => f.endsWith('.conf') && !['000-default.conf','default-ssl.conf'].includes(f)).length : 0; } catch { s.domains = 0; }
  s.users = USERS.length;
  res.json(s);
});

// ─── ROUTE: CONTRÔLE DES SERVICES ────────────────────────────────────────────
const ALLOWED_SERVICES = {
  apache2:  'Apache',
  vsftpd:   'vsftpd',
  mariadb:  'MariaDB'
};
// PHP-FPM est géré dynamiquement selon CONFIG.PHP_VERSION
const ALLOWED_ACTIONS = ['start', 'stop', 'restart', 'reload'];

app.post('/api/services/:service/:action', authMiddleware, adminOnly, async (req, res) => {
  let { service, action } = req.params;

  // Résoudre le nom du service PHP-FPM
  const phpFpm = `php${CONFIG.PHP_VERSION}-fpm`;
  const allowed = { ...ALLOWED_SERVICES, [phpFpm]: `PHP ${CONFIG.PHP_VERSION}-FPM` };

  if (!allowed[service]) return res.status(400).json({ error: 'Service non autorisé' });
  if (!ALLOWED_ACTIONS.includes(action)) return res.status(400).json({ error: 'Action non autorisée' });

  // Empêcher l'arrêt de KazyPanel lui-même via apache/node
  if (service === 'kazypanel') return res.status(403).json({ error: 'Non autorisé' });

  try {
    await runCmd(`systemctl ${action} ${service}`);
    // Récupérer le nouveau statut
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

function writeUserIni(docRoot, values) {
  const lines = ['; KazyPanel PHP config — ne pas modifier manuellement', ''];
  for (const [k, v] of Object.entries(values)) {
    if (PHP_ALLOWED_KEYS.includes(k) && v !== '' && v !== null) {
      lines.push(`${k} = ${v}`);
    }
  }
  fs.mkdirSync(docRoot, { recursive: true });
  fs.writeFileSync(path.join(docRoot, '.user.ini'), lines.join('\n') + '\n', 'utf8');
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
    const user = USERS.find(u => u.id === req.user.id);
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
    const user = USERS.find(u => u.id === req.user.id);
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
    writeUserIni(docRoot, safe);
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
    const user = USERS.find(u => u.id === req.user.id);
    if (!userOwnsDocRoot(user, docRoot))
      return res.status(403).json({ error: 'Ce domaine ne vous appartient pas' });
  }
  const iniPath = getUserIniPath(docRoot);
  if (fs.existsSync(iniPath)) fs.unlinkSync(iniPath);
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

async function runCmdOut(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd, (err, stdout, stderr) => {
      if (err) reject(new Error(stderr || err.message));
      else resolve({ stdout, stderr });
    });
  });
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
  const tmpFile = `${file}.tmp`;

  // Écrire dans un fichier temporaire d'abord
  fs.writeFileSync(tmpFile, content);

  // Valider avec named-checkzone si disponible (stdout = erreurs, exit code = résultat)
  const checkzoneAvailable = await new Promise(r => exec('which named-checkzone', e => r(!e)));
  if (checkzoneAvailable) {
    await new Promise((resolve, reject) => {
      exec(`named-checkzone "${domain}" "${tmpFile}"`, (error, stdout, stderr) => {
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

  // Validation OK → remplacer le fichier de production
  fs.renameSync(tmpFile, file);

  // S'assurer que bind peut lire le fichier
  try { await runCmd(`chown root:bind "${file}" && chmod 644 "${file}"`); } catch {}

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
  fs.appendFileSync(BIND_CONF_LOCAL, entry);
  // Vérifier la config globale (seulement si named-checkconf est installé)
  const checkconfAvailable = await new Promise(r => exec('which named-checkconf', e => r(!e)));
  if (checkconfAvailable) {
    try { await runCmd('named-checkconf'); } catch (e) {
      // Annuler l'ajout si invalide
      const cleaned = fs.readFileSync(BIND_CONF_LOCAL, 'utf8').replace(entry, '');
      fs.writeFileSync(BIND_CONF_LOCAL, cleaned);
      throw new Error(`Erreur named.conf : ${e.message}`);
    }
  }
}

// Retire une zone de named.conf.local
function removeZoneFromConf(domain) {
  if (!fs.existsSync(BIND_CONF_LOCAL)) return;
  let content = fs.readFileSync(BIND_CONF_LOCAL, 'utf8');
  // Regex robuste : capture tout le bloc zone {...}; même si il contient des } imbriqués
  const safe  = domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const regex = new RegExp(`\\nzone\\s+"${safe}"\\s*\\{[^]*?\\};\\s*\\n?`, 'g');
  const cleaned = content.replace(regex, '\n').replace(/\n{3,}/g, '\n\n').trimEnd() + '\n';
  fs.writeFileSync(BIND_CONF_LOCAL, cleaned);
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

// ── Zones de l'utilisateur ────────────────────────────────────────────────────

// Lister les zones DNS de l'utilisateur
app.get('/api/me/dns', authMiddleware, (req, res) => {
  const user = USERS.find(u => u.id == req.user.id);
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
  const user = USERS.find(u => u.id == req.user.id);
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
  const user = USERS.find(u => u.id == req.user.id);
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
  const user = USERS.find(u => u.id == req.user.id);
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
  const user = USERS.find(u => u.id == req.user.id);
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
  const user = USERS.find(u => u.id == req.user.id);
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
  const user = USERS.find(u => u.id == req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  const domain = req.params.domain.replace(/[^a-zA-Z0-9._-]/g, '').toLowerCase();
  if (!userOwnsDnsZone(user, domain)) return res.status(403).json({ error: 'Accès refusé' });

  const file = path.join(BIND_ZONES_DIR, `db.${domain}`);
  try {
    if (fs.existsSync(file)) fs.unlinkSync(file);
    removeZoneFromConf(domain);
    try { await runCmd(`rndc delzone ${domain}`); } catch {}
    try { await runCmd('systemctl reload bind9 || systemctl reload named'); } catch {}
    log('DNS_DELETE_ZONE', `${user.username} → ${domain}`, 'OK');
    res.json({ success: true, message: `Zone ${domain} supprimée` });
  } catch (err) { res.status(500).json({ error: err.message }); }
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
