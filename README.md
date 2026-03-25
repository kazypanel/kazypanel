# 🖥️ KazyPanel

![image](https://github.com/kazypanel/kazypanel/blob/main/accueil.png)
![image](https://github.com/kazypanel/kazypanel/blob/main/domaine.png)
![image](https://github.com/kazypanel/kazypanel/blob/main/templates.png)

> Panel d'administration web pour serveurs Apache/PHP — léger, rapide, sans dépendances lourdes.

![Version](https://img.shields.io/badge/version-1.3.0-blue)
![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

---

## 📋 Sommaire

- [Présentation](#-présentation)
- [Fonctionnalités](#-fonctionnalités)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
  - [⚡ Installation automatique (recommandée)](#-installation-automatique-recommandée)
  - [🔧 Installation manuelle](#-installation-manuelle-avancée)
- [Configuration](#-configuration)
- [Démarrage](#-démarrage)
- [Structure des fichiers](#-structure-des-fichiers)
- [API REST](#-api-rest)
- [Thèmes](#-thèmes)
- [Gestion des utilisateurs](#-gestion-des-utilisateurs)
- [Templates de ressources](#-templates-de-ressources)
- [Sécurité](#-sécurité)
- [Mise à jour](#-mise-à-jour)
- [FAQ](#-faq)

---

## 🎯 Présentation

**KazyPanel** est un panel d'hébergement web auto-hébergé, conçu pour administrer facilement des serveurs Linux avec Apache et PHP. Il remplace les solutions lourdes comme cPanel ou Plesk par une interface moderne, légère et entièrement contrôlée par vous.

Il fonctionne sur un serveur **Node.js** et expose une API REST consommée par une interface HTML/CSS/JS sans framework.

---

## ✨ Fonctionnalités

### Administration
- 📊 **Statut serveur** — CPU, RAM, disque, uptime (mois/j/h/min), charge système
- 🌐 **Domaines & sous-domaines** — création, activation/désactivation, configuration Apache
- 🔒 **SSL Let's Encrypt** — génération et renouvellement de certificats en 1 clic
- ⚙️ **Configuration PHP** — par domaine (version, mémoire, upload, etc.)
- 🛡️ **Pare-feu UFW** — gestion des règles depuis l'interface
- 🚫 **Fail2ban** — surveillance, débannissement, activation/désactivation des jails
- 🗄️ **Bases de données MariaDB** — création, suppression, quotas
- 📁 **Comptes FTP** — gestion vsftpd, multi-comptes par utilisateur
- 🔗 **DNS (BIND9)** — zones, enregistrements A/AAAA/CNAME/MX/TXT
- 💾 **Sauvegardes** — création et téléchargement d'archives
- 📋 **Logs Apache** — consultation par domaine
- 🕐 **Crontab** — gestion des tâches planifiées par utilisateur
- 🔑 **Connexions SSH** — historique, gestion des utilisateurs autorisés

### Espace utilisateur
- 📂 **Explorateur de fichiers** — navigation, création, renommage, suppression, upload, téléchargement
- ✏️ **Éditeur de fichiers intégré** — édition en ligne des fichiers texte (PHP, HTML, CSS, JS, JSON, .htaccess, etc.)
- 🔒 **Gestion des permissions** — chmod avec interface visuelle
- 🖱️ **Menu contextuel** — clic droit sur chaque fichier/dossier

### Interface
- 🎨 **4 thèmes** — Dark, Light, Classic (Windows XP), macOS (Ventura)
- 📱 Responsive — adapté desktop et mobile
- 🌙 Préférence de thème sauvegardée localement
- 🔄 Vérification automatique des mises à jour

### Gestion multi-utilisateurs
- 👥 Rôles **Admin** et **Utilisateur**
- 📋 **Templates de ressources** — limites FTP, BDD, domaines, disque
- 🎲 Génération de mot de passe aléatoire sécurisé
- ✉️ Template de message de bienvenue copiable (Gmail, etc.)
- 🔐 Indicateur de force de mot de passe

---

## 🛠️ Prérequis

### Système
- Ubuntu 20.04 / 22.04 / 24.04 (ou Debian équivalent)
- Accès root ou sudo

### Services requis
| Service | Version minimale |
|---------|-----------------|
| Node.js | 18.x ou supérieur |
| Apache2 | 2.4+ |
| PHP-FPM | 8.4 (configurable) |
| MariaDB | 10.6+ |
| vsftpd | 3.x |
| UFW | — |
| Fail2ban | — |
| BIND9 | — (optionnel, pour DNS) |
| Certbot | — (optionnel, pour SSL) |
| phpMyAdmin | 5.2+ (optionnel, pour gérer les BDD) |

---

## 📦 Installation

### ⚡ Installation automatique (recommandée)

La méthode la plus rapide — **tout est installé et configuré en une seule commande**, sans aucune intervention manuelle entre les étapes.

```bash
wget https://raw.githubusercontent.com/kazypanel/kazypanel/main/install.sh
chmod +x install.sh
sudo bash install.sh
```

> ✅ **Durée estimée : 3 à 8 minutes** selon la connexion et le serveur.

#### Ce que fait le script en détail

Le script `install.sh` prend en charge **l'intégralité de l'installation** de zéro à un panel fonctionnel :

**1. Vérifications préliminaires**
Avant de toucher quoi que ce soit, le script vérifie que vous êtes bien en root, que l'OS est compatible (Ubuntu 20/22/24 ou Debian 11/12), que la RAM est suffisante (512 Mo minimum) et que la connexion internet est active. Si une condition n'est pas remplie, il s'arrête avec un message clair.

**2. Questions interactives**
Le script pose quelques questions simples : le port du panel (8080 par défaut), le mot de passe admin (validé en temps réel — il rejette les mots de passe faibles), le mot de passe root MariaDB, la version PHP souhaitée, l'URL phpMyAdmin si vous en avez une, et le répertoire d'installation. Un récapitulatif est affiché avant de commencer.

**3. Mise à jour du système**
`apt-get update && apt-get upgrade` pour partir sur une base propre.

**4. Node.js 20**
Ajout automatique du dépôt officiel NodeSource et installation de Node.js 20 LTS — la version minimale requise pour les API `fetch` natives utilisées par KazyPanel.

**5. Apache2**
Installation et activation des modules nécessaires : `rewrite`, `ssl`, `proxy`, `proxy_http`, `proxy_fcgi`, `headers`, `setenvif`. Un vhost par défaut minimal est créé.

**6. PHP-FPM**
Installation de PHP (version choisie) avec toutes les extensions requises : `mysql`, `curl`, `gd`, `mbstring`, `xml`, `zip`, `intl`, `bcmath`, `opcache`. Le module `proxy_fcgi` Apache est activé pour faire tourner PHP en mode FPM.

**7. MariaDB**
Installation du serveur MariaDB avec sécurisation automatique : suppression des utilisateurs anonymes, désactivation de l'accès root distant, suppression de la base de test, application du mot de passe root si fourni.

**8. vsftpd (FTP)**
Installation et configuration complète : chroot activé, mode passif sur les ports 40000-50000, liste d'utilisateurs autorisés (`/etc/vsftpd.userlist`), écriture dans le chroot autorisée. La configuration est entièrement remplacée par une version optimisée pour KazyPanel.

**9. BIND9 (DNS)**
Installation du serveur DNS avec création du répertoire `/etc/bind/zones` et démarrage du service. Optionnel — KazyPanel fonctionne sans BIND9, mais la gestion DNS depuis l'interface nécessite ce service.

**10. Certbot**
Installation de Certbot avec le plugin Apache pour la génération de certificats SSL Let's Encrypt en 1 clic depuis le panel.

**11. phpMyAdmin**
Téléchargement de la dernière version stable (5.2.1) directement depuis le site officiel. Configuration automatique avec une clé `blowfish_secret` générée aléatoirement. Si une URL personnalisée a été fournie (ex: `pma.mondomaine.fr`), un vhost Apache dédié est créé. Sinon, phpMyAdmin est accessible via `/phpmyadmin` sur l'IP du serveur. L'URL est automatiquement injectée dans le `.env` de KazyPanel pour que le bouton phpMyAdmin dans le panel fonctionne directement.

**11. UFW (pare-feu)**
Configuration et activation d'UFW avec les règles essentielles : SSH, HTTP (80), HTTPS (443), port du panel, FTP (21), plage passif FTP (40000-50000), DNS (53). Toute autre connexion entrante est bloquée par défaut.

**12. Fail2ban**
Configuration d'un `jail.local` avec protection SSH, Apache et vsftpd. Bannissement automatique après 5 tentatives échouées en 10 minutes, pour 1 heure.

**13. KazyPanel**
Clone du dépôt GitHub dans le répertoire choisi, `npm install --production`, création du fichier `.env` avec toutes les variables remplies automatiquement (dont une clé JWT de 128 caractères générée aléatoirement via `openssl rand`).

**14. Service systemd**
Création et activation du service `kazypanel.service` avec redémarrage automatique en cas de crash, logs dans `journald` et chargement automatique du `.env`.

**15. Résumé final**
Le script affiche l'URL d'accès, les identifiants admin, la liste des services installés avec leurs versions et les commandes utiles.

#### Exemple de déroulement

```
▶ Vérifications système
  ✓  OS : Ubuntu 22.04.3 LTS
  ✓  Architecture : x86_64
  ✓  RAM : 2048 Mo
  ✓  Connexion internet : OK

▶ Configuration de l'installation
  Port du panel [8080] :
  Mot de passe admin : ••••••••••••
  Mot de passe root MariaDB :
  Version PHP [8.4] :
  URL phpMyAdmin (optionnel) :
  Répertoire d'installation [/opt/kazypanel] :

▶ Mise à jour du système ...
▶ Installation de Node.js 20 ...
▶ Installation d'Apache2 ...
▶ Installation de PHP 8.4-FPM ...
▶ Installation de MariaDB ...
▶ Installation et configuration de vsftpd ...
▶ Installation de BIND9 (DNS) ...
▶ Installation de Certbot ...
▶ Installation de phpMyAdmin ...
▶ Configuration UFW ...
▶ Configuration Fail2ban ...
▶ Installation de KazyPanel ...
▶ Création du service systemd ...

╔══════════════════════════════════════════════════════╗
║         ✅  Installation terminée avec succès !       ║
╚══════════════════════════════════════════════════════╝

  🔗 URL        : http://1.2.3.4:8080
  👤 Login      : admin
  🔑 Mot passe  : VotreMotDePasse!
```

---

### 🔧 Installation manuelle (avancée)

Si vous préférez installer composant par composant, ou si vous disposez déjà de certains services :

### 1. Cloner le dépôt

```bash
git clone https://github.com/kazypanel/kazypanel.git /opt/kazypanel
cd /opt/kazypanel
```

### 2. Installer les dépendances Node.js

```bash
npm install
```

### 3. Créer le fichier de configuration

```bash
cp .env.example .env
nano .env
```

### 4. Créer le dossier public

```bash
mkdir -p public
cp index.html public/
```

### 5. Configurer le service systemd

```bash
nano /etc/systemd/system/kazypanel.service
```

```ini
[Unit]
Description=KazyPanel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/kazypanel
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=5
EnvironmentFile=/opt/kazypanel/.env

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable kazypanel
systemctl start kazypanel
```

### 6. Accéder au panel

```
http://votre-ip:8080
```

---

## ⚙️ Configuration

Toutes les options se configurent dans le fichier `.env` :

```env
# ── Sécurité ──────────────────────────────────────────────
# Clé secrète JWT (OBLIGATOIRE en production — chaîne aléatoire longue)
JWT_SECRET=changez_cette_valeur_en_production_xxxxxxxxxxxxx

# Mot de passe du compte admin (créé au premier démarrage)
ADMIN_PASSWORD=Admin@1234!

# ── Serveur ───────────────────────────────────────────────
PORT=8080

# ── Base de données ───────────────────────────────────────
# Mot de passe root MariaDB (laisser vide si pas de mot de passe)
DB_ROOT_PASS=

# ── PHP ───────────────────────────────────────────────────
PHP_VERSION=8.4

# ── phpMyAdmin ────────────────────────────────────────────
# URL complète vers votre installation phpMyAdmin (optionnel)
PMA_URL=https://pma.votredomaine.fr
```

### Règles de mot de passe

Le mot de passe admin doit contenir :
- Minimum 5 caractères
- Au moins une majuscule (A-Z)
- Au moins une minuscule (a-z)
- Au moins un chiffre (0-9)
- Au moins un caractère spécial (`!@#$%^&*...`)

---

## 🚀 Démarrage

```bash
# Démarrer
systemctl start kazypanel

# Arrêter
systemctl stop kazypanel

# Redémarrer
systemctl restart kazypanel

# Voir les logs
journalctl -u kazypanel -f

# Statut
systemctl status kazypanel
```

### Démarrage manuel (développement)

```bash
node server.js
# ou avec rechargement automatique
npx nodemon server.js
```

---

## 📁 Structure des fichiers

```
/opt/kazypanel/
├── server.js           # Serveur principal Node.js
├── public/
│   └── index.html      # Interface web
├── users.json          # Base de données utilisateurs
├── templates.json      # Templates de ressources
├── panel_config.json   # Configuration du panel
├── db_configs.json     # Configurations BDD
├── backups/            # Sauvegardes générées
├── .env                # Variables d'environnement
├── .env.example        # Modèle de configuration
└── package.json
```

---

## 🔌 API REST

Toutes les routes (sauf `/api/login` et `/api/version`) requièrent un header d'authentification :

```
Authorization: Bearer <token>
```

### Authentification

| Méthode | Route | Description |
|---------|-------|-------------|
| POST | `/api/login` | Connexion — retourne un JWT |
| POST | `/api/change-password` | Changer son mot de passe |
| GET | `/api/version` | Version du panel |

### Utilisateurs (admin)

| Méthode | Route | Description |
|---------|-------|-------------|
| GET | `/api/users` | Lister tous les utilisateurs |
| POST | `/api/users` | Créer un utilisateur |
| PUT | `/api/users/:id` | Modifier un utilisateur |
| DELETE | `/api/users/:id` | Supprimer un utilisateur |
| POST | `/api/users/:id/template` | Appliquer un template |
| GET | `/api/users/:id/ftp` | Comptes FTP de l'utilisateur |
| POST | `/api/users/:id/ftp` | Créer un compte FTP |
| DELETE | `/api/users/:id/ftp/:ftpUser` | Supprimer un compte FTP |
| PUT | `/api/users/:id/ftplimit` | Modifier la limite FTP |
| PUT | `/api/users/:id/dblimit` | Modifier la limite BDD |
| PUT | `/api/users/:id/disklimit` | Modifier le quota disque |
| GET | `/api/users/:id/diskusage` | Utilisation disque |

### Templates (admin)

| Méthode | Route | Description |
|---------|-------|-------------|
| GET | `/api/templates` | Lister les templates |
| POST | `/api/templates` | Créer un template |
| PUT | `/api/templates/:id` | Modifier un template |
| DELETE | `/api/templates/:id` | Supprimer un template |

### Domaines (admin)

| Méthode | Route | Description |
|---------|-------|-------------|
| GET | `/api/domains` | Lister tous les domaines |
| POST | `/api/domains` | Créer un domaine |
| PUT | `/api/domains/:name` | Modifier un domaine |
| DELETE | `/api/domains/:name` | Supprimer un domaine |
| POST | `/api/domains/:name/toggle` | Activer/désactiver |
| POST | `/api/domains/:name/ssl` | Générer un certificat SSL |
| GET | `/api/domains/:name/phpconfig` | Config PHP du domaine |
| PUT | `/api/domains/:name/phpconfig` | Modifier la config PHP |

### Espace utilisateur

| Méthode | Route | Description |
|---------|-------|-------------|
| GET | `/api/me` | Infos du compte connecté |
| GET | `/api/me/domains` | Mes domaines |
| POST | `/api/me/domains` | Créer un domaine |
| GET | `/api/me/databases` | Mes bases de données |
| POST | `/api/me/databases` | Créer une base |
| DELETE | `/api/me/databases/:name` | Supprimer une base |
| GET | `/api/me/ftp` | Mes comptes FTP |
| POST | `/api/me/ftp` | Créer un compte FTP |
| GET | `/api/me/dns` | Mes zones DNS |
| POST | `/api/me/dns` | Créer une zone DNS |
| POST | `/api/me/dns/:domain/records` | Ajouter un enregistrement |
| DELETE | `/api/me/dns/:domain/records/:id` | Supprimer un enregistrement |
| GET | `/api/me/crontab` | Mes tâches cron |
| POST | `/api/me/crontab` | Ajouter une tâche cron |
| DELETE | `/api/me/crontab/:id` | Supprimer une tâche cron |
| GET | `/api/me/diskusage` | Mon utilisation disque |

### Serveur & sécurité (admin)

| Méthode | Route | Description |
|---------|-------|-------------|
| GET | `/api/status` | Statut du serveur |
| POST | `/api/services/:service/:action` | Contrôle des services |
| GET | `/api/ufw/status` | Statut UFW |
| POST | `/api/ufw/rules` | Ajouter une règle |
| DELETE | `/api/ufw/rules/:num` | Supprimer une règle |
| GET | `/api/fail2ban/status` | Statut Fail2ban |
| POST | `/api/fail2ban/unban` | Débannir une IP |
| GET | `/api/logins` | Historique des connexions |
| GET | `/api/backup` | Lister les sauvegardes |
| POST | `/api/backup` | Créer une sauvegarde |
| DELETE | `/api/backup/:name` | Supprimer une sauvegarde |
| GET | `/api/update/check` | Vérifier les mises à jour |

---

## 🎨 Thèmes

KazyPanel propose 4 thèmes sélectionnables depuis la topbar :

| Thème | Description |
|-------|-------------|
| ☀️ **Light** | Interface claire, sobre et moderne |
| 🌙 **Dark** | Interface sombre, idéale pour un usage prolongé |
| 🖥️ **Classic** | Style Windows XP / OpenPanel, look rétro |
| 🍎 **macOS** | Style Ventura/Sonoma, glassmorphism, icônes emoji |

Le thème choisi est sauvegardé dans le `localStorage` du navigateur.

---

## 👥 Gestion des utilisateurs

### Rôles

| Rôle | Accès |
|------|-------|
| **Admin** | Accès complet — gestion serveur, utilisateurs, configuration |
| **Utilisateur** | Accès limité — ses domaines, BDD, FTP, DNS, crontab |

### Création d'un compte

Lors de la création, l'admin peut :
1. Définir un identifiant et un rôle
2. Choisir un template de ressources
3. Générer un mot de passe aléatoire sécurisé (🎲)
4. Copier un message de bienvenue prêt à envoyer au client
5. Ouvrir Gmail directement avec le message pré-rempli

### Mot de passe aléatoire

Le générateur produit un mot de passe de 12 caractères respectant toutes les règles de sécurité (majuscule, minuscule, chiffre, caractère spécial).

---

## 📋 Templates de ressources

Les templates permettent d'appliquer des limites prédéfinies à un utilisateur en un clic.

### Templates par défaut

| Template | FTP | BDD | Domaines | Sous-domaines | Disque | Cron |
|----------|-----|-----|----------|---------------|--------|------|
| Starter | 1 | 1 | 1 | 2 | 500 Mo | 3 |
| Standard | 2 | 3 | 3 | 5 | 2 Go | 10 |
| Pro | 5 | 10 | 10 | 20 | 10 Go | 30 |
| Illimité | ∞ | ∞ | ∞ | ∞ | ∞ | ∞ |

Les templates sont entièrement personnalisables depuis l'interface.

---

## 🔐 Sécurité

### Recommandations en production

```env
# Utiliser une clé JWT longue et aléatoire
JWT_SECRET=$(openssl rand -hex 64)

# Mot de passe admin fort
ADMIN_PASSWORD=VotreMotDePasseTresSécurisé!123
```

### Bonnes pratiques

- **Ne pas exposer le port 8080 publiquement** — utiliser un reverse proxy Apache/Nginx
- Activer **HTTPS** avec un certificat SSL sur le panel lui-même
- Activer **UFW** et n'autoriser que les ports nécessaires
- Activer **Fail2ban** pour protéger les accès SSH et Apache

### Reverse proxy Apache (exemple)

```apache
<VirtualHost *:443>
    ServerName panel.votredomaine.fr
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/panel.votredomaine.fr/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/panel.votredomaine.fr/privkey.pem

    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"
</VirtualHost>
```

---

## 🔄 Mise à jour

```bash
cd /opt/kazypanel
git pull origin main
npm install
systemctl restart kazypanel
```

Le panel vérifie automatiquement les nouvelles versions au démarrage et affiche une notification dans la topbar.

---

## ❓ FAQ

**Le panel ne démarre pas**
→ Vérifiez les logs : `journalctl -u kazypanel -f`
→ Vérifiez que Node.js ≥ 18 est installé : `node --version`

**Impossible de créer un domaine**
→ Vérifiez qu'Apache est bien installé et que `/etc/apache2/sites-available` existe
→ Le processus doit tourner en root ou avoir les permissions suffisantes

**Les emails ne s'envoient pas**
→ Le port 25 est souvent bloqué par les fournisseurs VPS
→ Utilisez un service externe (Resend, Mailgun, SendGrid) via leur API HTTPS

**L'uptime s'affiche N/A**
→ Vérifiez que `/proc/uptime` est accessible sur votre système

**Erreur `EACCES` sur les ports**
→ Le panel doit tourner en root pour gérer Apache, les utilisateurs système et vsftpd

**Comment réinitialiser le mot de passe admin ?**
→ Arrêtez le panel, supprimez `users.json`, redémarrez — le compte admin sera recréé avec `ADMIN_PASSWORD`

---

## 📄 Licence

MIT — Libre d'utilisation, de modification et de distribution.

---

## 🙏 Crédits

Développé avec ❤️ — Node.js, Express, Apache2, PHP-FPM, MariaDB, vsftpd, BIND9, Let's Encrypt.

---

*KazyPanel v1.3.0 — Dernière mise à jour : Mars 2026*

## Changelog

### v1.3.0 — 2026-03-25
- ✨ **Explorateur de fichiers utilisateur** — navigation arborescence, vue liste/grille, fil d'Ariane
- ✏️ **Éditeur de fichiers intégré** — édition en ligne avec coloration (PHP, HTML, CSS, JS, JSON, .htaccess…)
- 🔒 **Gestion des permissions** (chmod) — interface visuelle avec cases à cocher
- 🖱️ **Menu contextuel clic droit** — ouvrir, éditer, télécharger, renommer, supprimer, chmod
- ⬆️ **Upload de fichiers** — multi-fichiers avec barre de progression
- 🔄 **Mise à jour one-click** depuis le modal — git pull + npm install + restart avec logs en temps réel
- 🗄️ **BIND9** ajouté au dashboard statut, uptime et contrôle des services
- 🐛 Fix : `named-checkconf` / `named-checkzone` — résolution dynamique du chemin (`which` + `find`)
- 🐛 Fix : modal Mise à jour — version lue depuis `version.json` local en priorité
- 🐛 Fix : suppression des fichiers `.bak` inutiles (éditeur .bashrc et config Fail2ban)

### v1.3.0 — 2026-03-23
