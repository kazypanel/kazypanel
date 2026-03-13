# 🚀 KazyPanel — Guide d'installation

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-4f6ef7?style=for-the-badge)
![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-green?style=for-the-badge&logo=node.js)
![License](https://img.shields.io/badge/license-Proprietary-red?style=for-the-badge)
![OS](https://img.shields.io/badge/OS-Ubuntu%2022.04%2B-orange?style=for-the-badge&logo=ubuntu)
![OS](https://img.shields.io/badge/OS-Debian%2012-red?style=for-the-badge&logo=debian)

**Panel d'hébergement web complet — Domaines · FTP · BDD · DNS · PHP · SSL**

</div>

---

## 📋 Table des matières

- [Prérequis](#-prérequis)
- [Installation manuelle](#-installation-manuelle)
- [Configuration](#-configuration)
- [Démarrage](#-démarrage)
- [Services requis](#-services-requis)
- [Structure des fichiers](#-structure-des-fichiers)
- [Mise à jour](#-mise-à-jour)
- [Désinstallation](#-désinstallation)
- [Dépannage](#-dépannage)

---

## ✅ Prérequis

| Composant | Version minimale | Vérification |
|-----------|-----------------|--------------|
| **OS** | Ubuntu 22.04 LTS / Debian 12 | `lsb_release -a` |
| **Node.js** | 18.x ou supérieur | `node --version` |
| **npm** | 8.x ou supérieur | `npm --version` |
| **Apache2** | 2.4+ | `apache2 -v` |
| **RAM** | 512 Mo minimum | `free -h` |
| **Disque** | 1 Go minimum | `df -h` |

### Services optionnels

| Service | Utilisation |
|---------|------------|
| **BIND9** | Gestion DNS |
| **Fail2ban** | Protection anti-brute-force |
| **Certbot** | Certificats SSL Let's Encrypt |
| **MariaDB / MySQL** | Bases de données |
| **vsftpd / ProFTPd** | Comptes FTP |

---

## 🔧 Installation manuelle

### 1. Installer Node.js 20

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs
node --version   # → v20.x.x
```

### 2. Installer Apache2

```bash
apt install -y apache2
systemctl enable --now apache2
```

### 3. Cloner le dépôt

```bash
git clone https://github.com/kazypanel/kazypanel.git /opt/kazypanel
cd /opt/kazypanel
```

### 4. Installer les dépendances

```bash
npm install
```

### 5. Installer les services optionnels

```bash
# BIND9 (DNS)
apt install -y bind9 bind9utils

# Fail2ban
apt install -y fail2ban

# Certbot (SSL)
apt install -y certbot python3-certbot-apache

# MariaDB
apt install -y mariadb-server

# Cron (requis pour la page Crontab)
apt install -y cron
systemctl enable --now cron
```

---

## ⚙️ Configuration

### Créer le fichier `.env`

```bash
cp .env.example .env   # si disponible
# ou créer manuellement :
nano /opt/kazypanel/.env
```

Contenu du fichier `.env` :

```env
# Port d'écoute du panel (défaut : 8080)
PORT=8080

# Clé secrète JWT — OBLIGATOIRE, changer en production !
JWT_SECRET=CHANGEZ_CE_SECRET_EN_PRODUCTION

# URL phpMyAdmin (optionnel)
PMA_URL=http://localhost/phpmyadmin
```

> 🔐 **Ne jamais commiter le fichier `.env` sur GitHub.**

---

## 🚀 Démarrage

### Avec systemd (recommandé)

Créer le service :

```bash
cat > /etc/systemd/system/kazypanel.service << 'EOF'
[Unit]
Description=KazyPanel - Gestionnaire Apache/PHP
After=network.target apache2.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/kazypanel
EnvironmentFile=/opt/kazypanel/.env
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
```

Démarrer et activer au boot :

```bash
systemctl daemon-reload
systemctl enable --now kazypanel
systemctl status kazypanel
```

### Avec PM2 (alternative)

```bash
npm install -g pm2
cd /opt/kazypanel
pm2 start server.js --name kazypanel
pm2 save
pm2 startup
```

---

## 🌐 Accès au panel

Une fois démarré, accéder au panel via :

```
http://VOTRE_IP:8080
```

### Identifiants par défaut

| Champ | Valeur |
|-------|--------|
| **Utilisateur** | `admin` |
| **Mot de passe** | `admin123` |

> ⚠️ **Changer le mot de passe immédiatement après la première connexion.**

---

## 🔒 Ouvrir les ports dans le pare-feu

> ⚠️ **IMPORTANT — Ouvrir le port SSH avant d'activer UFW, sinon vous perdrez l'accès à votre serveur !**

```bash
# 1. Port SSH — OBLIGATOIRE en premier
ufw allow 22

# 2. Port KazyPanel
ufw allow 8080

# 3. Ports web (optionnel)
ufw allow 80
ufw allow 443

# 4. Activer UFW
ufw enable

# 5. Vérifier
ufw status
```

---

## 📁 Structure des fichiers

```
/opt/kazypanel/
├── server.js              ← Serveur principal (Node.js/Express)
├── package.json           ← Dépendances npm
├── version.json           ← Version du panel
├── .env                   ← Configuration (secrets) — non versionné
├── users.json             ← Utilisateurs — non versionné
├── templates.json         ← Templates de ressources — non versionné
├── db_configs.json        ← Configurations BDD — non versionné
├── panel_config.json      ← Configuration panel — non versionné
├── backups/               ← Sauvegardes générées — non versionné
└── public/
    └── index.html         ← Interface web
```

---

## 🔄 Mise à jour

```bash
cd /opt/kazypanel

# Récupérer les nouveaux fichiers
git pull origin main

# Reinstaller les dépendances si besoin
npm install

# Redémarrer le panel
systemctl restart kazypanel
```

---

## 🗑️ Désinstallation

```bash
# Arrêter et désactiver le service
systemctl stop kazypanel
systemctl disable kazypanel

# Supprimer le service
rm /etc/systemd/system/kazypanel.service
systemctl daemon-reload

# Supprimer les fichiers du panel
rm -rf /opt/kazypanel
```

---

## 🛠️ Dépannage

### Le panel ne démarre pas

```bash
# Voir les logs
journalctl -u kazypanel -n 50 --no-pager

# Tester manuellement
cd /opt/kazypanel
node server.js
```

### Port 8080 déjà utilisé

```bash
# Identifier le processus
lsof -i :8080

# Libérer le port
fuser -k 8080/tcp

# Changer le port dans .env
PORT=3000
```

### Erreur `named-checkconf`

BIND9 n'est pas installé. Installer avec :

```bash
apt install -y bind9 bind9utils
systemctl enable --now named
```

### Erreur `EACCES` sur les crontabs

```bash
# Installer cron
apt install -y cron
systemctl enable --now cron

# Vérifier les permissions
ls -la /var/spool/cron/crontabs/
```

### Réinitialiser le mot de passe admin

```bash
# Editer users.json et supprimer l'entrée admin
# Redémarrer le panel — le compte admin par défaut sera recréé
nano /opt/kazypanel/users.json
systemctl restart kazypanel
```

---

## 📦 Fonctionnalités

| Module | Description |
|--------|-------------|
| 🌐 **Domaines** | Création et gestion de VirtualHosts Apache |
| 📁 **FTP** | Comptes FTP avec répertoires isolés |
| 🗄️ **Bases de données** | Création BDD MariaDB/MySQL + phpMyAdmin |
| 🔒 **SSL** | Certificats Let's Encrypt via Certbot |
| 🌍 **DNS** | Zones DNS avec BIND9 |
| 🐘 **PHP** | Configuration php.ini par domaine |
| ⏰ **Crontab** | Planification de tâches par utilisateur |
| 💾 **Sauvegardes** | Sauvegarde et restauration du panel |
| 🛡️ **Fail2ban** | Gestion des jails et bans IP |
| 🔥 **UFW** | Gestion du pare-feu |
| 📊 **Monitoring** | CPU, RAM, services en temps réel |
| 🔄 **Mises à jour** | Vérification automatique des nouvelles versions |

---

## 📄 Licence

Logiciel propriétaire — © 2026 [kazylax.fr](https://www.kazylax.fr)

Toute reproduction, distribution ou utilisation non autorisée est interdite.

---

<div align="center">
  <sub>Développé avec ❤️ par <a href="https://www.kazylax.fr">kazylax.fr</a></sub>
</div>
