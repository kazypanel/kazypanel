# KazyPanel

Panel d'hébergement web auto-hébergé en **Node.js**, conçu pour gérer un serveur Linux (Debian/Ubuntu) avec Apache, PHP 8.4, MariaDB et vsftpd.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Node](https://img.shields.io/badge/node-%3E%3D18.0-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Fonctionnalités

- 🌐 **Domaines & sous-domaines** — VirtualHosts Apache, SSL Let's Encrypt automatique
- 🗄️ **Bases de données** — MariaDB, quotas par utilisateur, lien phpMyAdmin
- 📁 **FTP** — vsftpd, comptes multiples par utilisateur, chroot
- 🔒 **DNS** — Zones BIND9, enregistrements A/AAAA/CNAME/MX/TXT/NS/CAA
- ⏰ **Crontab** — Tâches planifiées par utilisateur
- 🛡️ **Sécurité** — UFW, Fail2ban, restriction SSH AllowUsers
- 👥 **Multi-utilisateurs** — Rôles admin/user, templates de quotas
- 💾 **Sauvegardes** — Archives tar.gz horodatées

---

## Stack technique

| Composant | Détail |
|-----------|--------|
| Runtime | Node.js ≥ 18 |
| Framework | Express 4 |
| Auth | JWT (8h) + bcrypt x12 |
| Anti brute-force | 5 tentatives → blocage 15 min |
| Serveur web | Apache2 |
| PHP | PHP 8.4-FPM |
| BDD | MariaDB |
| FTP | vsftpd |
| DNS | BIND9 |
| SSL | Let's Encrypt (Certbot) |

---

## Installation rapide

### Prérequis

- Debian 12 ou Ubuntu 22.04+
- Accès root
- Node.js ≥ 18

### 1. Installer les dépendances système

```bash
apt update && apt upgrade -y
apt install -y apache2 php8.4 php8.4-fpm mariadb-server vsftpd certbot python3-certbot-apache nodejs curl ufw fail2ban

a2enmod rewrite ssl proxy proxy_http headers proxy_fcgi setenvif
a2enconf php8.4-fpm
```

### 2. Déployer KazyPanel

```bash
mkdir -p /opt/kazypanel/public
cd /opt/kazypanel

# Copier server.js et public/index.html
# Créer package.json puis installer les dépendances
npm install
```

### 3. Configurer l'environnement

```bash
cat > /opt/kazypanel/.env << 'EOF'
JWT_SECRET=changez_cette_cle_par_une_longue_chaine_aleatoire
ADMIN_PASSWORD=MonMotDePasse@2024!
DB_ROOT_PASS=votre_mot_de_passe_mariadb
PORT=8080
EOF
```

### 4. Créer le service systemd

```bash
cat > /etc/systemd/system/kazypanel.service << 'EOF'
[Unit]
Description=KazyPanel - Gestionnaire Apache/PHP
After=network.target mariadb.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/kazypanel
EnvironmentFile=/opt/kazypanel/.env
ExecStart=/usr/bin/node /opt/kazypanel/server.js
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now kazypanel
```

### 5. Ouvrir les ports UFW

```bash
ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp
ufw allow 8080/tcp && ufw allow 21/tcp && ufw allow 20/tcp
ufw allow 40000:50000/tcp
ufw --force enable
```

### 6. Accéder au panel

```
http://IP_SERVEUR:8080
```

Identifiants par défaut : `admin` / valeur de `ADMIN_PASSWORD` dans `.env`

---

## Structure des fichiers

```
/opt/kazypanel/
├── server.js            # Backend API (~3600 lignes)
├── public/
│   └── index.html       # Frontend SPA (~7600 lignes)
├── .env                 # Configuration (secrets) — ne pas versionner
├── users.json           # Comptes (hashés bcrypt) — ne pas versionner
├── templates.json       # Templates de quotas
├── panel_config.json    # Config PMA, DNS, maintenance
└── backups/             # Archives tar.gz
```

> ⚠️ `.env` et `users.json` ne doivent **jamais** être committés.

---

## Configuration avancée

### Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `JWT_SECRET` | aléatoire | Clé de signature des tokens JWT |
| `ADMIN_PASSWORD` | `Admin@1234!` | Mot de passe du compte admin |
| `DB_ROOT_PASS` | _(vide)_ | Mot de passe root MariaDB |
| `PORT` | `8080` | Port d'écoute du panel |
| `PHP_VERSION` | `8.4` | Version PHP-FPM utilisée |
| `PMA_URL` | _(vide)_ | URL phpMyAdmin (ex: `https://pma.domain.fr`) |

### Sécuriser le panel en HTTPS

Dans KazyPanel → **Configuration → HTTPS**, renseignez le sous-domaine souhaité (ex: `panel`) et cliquez sur *Activer HTTPS*. Certbot configurera Apache automatiquement.

### Restriction SSH utilisateurs

Dans KazyPanel → **Configuration → Serveur → Accès SSH**, saisissez les utilisateurs autorisés (ex: `root`) pour bloquer l'accès SSH aux comptes FTP du panel.

---

## Règles de mot de passe

Tous les mots de passe (admin, utilisateurs, FTP) doivent respecter :

- Minimum 5 caractères
- Au moins une majuscule (A-Z)
- Au moins une minuscule (a-z)
- Au moins un chiffre (0-9)
- Au moins un caractère spécial (`!@#$%^&*...`)

---

## Commandes utiles

```bash
# Gestion du service
systemctl restart kazypanel
journalctl -u kazypanel -f

# Réinitialiser le mot de passe admin
node -e 'const b=require("bcryptjs"); b.hash("NouveauMdp@123!", 12).then(h => {
  const fs=require("fs");
  const u=JSON.parse(fs.readFileSync("users.json"));
  u.find(x=>x.username==="admin").password=h;
  fs.writeFileSync("users.json",JSON.stringify(u,null,2));
  console.log("Done");
})'
systemctl restart kazypanel
```

---

## Dépannage

| Problème | Solution |
|----------|----------|
| Port 8080 déjà utilisé (`EADDRINUSE`) | `pkill node && systemctl start kazypanel` |
| Impossible de se connecter | Vérifiez `ADMIN_PASSWORD` dans `.env` et redémarrez |
| CPU élevé | Vérifiez que `top -bn1` n'est pas présent dans `server.js` (remplacer par `/proc/stat`) |
| Erreur `named.conf` | `named-checkconf -p \| head -5` |
| `www.` ne fonctionne pas en SSL | `certbot --apache -d domain.fr -d www.domain.fr --cert-name domain.fr` |
| Login bloqué (brute-force) | Redémarrer le service vide la map en mémoire |

---

## Ports requis

| Port | Protocole | Service |
|------|-----------|---------|
| 22 | TCP | SSH |
| 80 | TCP | HTTP / ACME challenge |
| 443 | TCP | HTTPS |
| 8080 | TCP | KazyPanel |
| 20-21 | TCP | FTP |
| 40000-50000 | TCP | FTP passif |
| 53 | TCP/UDP | DNS (BIND9, optionnel) |

---

## Licence

MIT — Libre d'utilisation, modification et distribution.
