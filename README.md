# 🖥️ KazyPanel

![image](https://github.com/kazypanel/kazypanel/blob/main/accueil.png)
![image](https://github.com/kazypanel/kazypanel/blob/main/domaine.png)
![image](https://github.com/kazypanel/kazypanel/blob/main/templates.png)

> Panel d'administration web pour serveurs Apache/PHP — léger, rapide, sans dépendances lourdes.

![Version](https://img.shields.io/badge/version-1.8.0-blue)
![Node](https://img.shields.io/badge/node-%3E%3D24.0.0-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/donate/?token=gi6SgOn_AzcGLU01Q-iFGzhVF7a-CAl-U9tQJpBUzKzy2yL3d-ZBoWgWvlq5ZGe3doaif-XCcGgiATtE&locale.x=fr_FR)

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
- [Explorateur de fichiers](#-explorateur-de-fichiers)
- [Templates de ressources](#-templates-de-ressources)
- [Sécurité](#-sécurité)
- [Multi-PHP par domaine](#multi-php-par-domaine)
- [Mise à jour](#-mise-à-jour)
- [Dépannage](#-dépannage)
- [Logs & Monitoring](#-logs--monitoring)
- [Sécurité avancée](#-sécurité-avancée)
- [Bot Telegram](#-bot-telegram)
- [FAQ](#-faq)

---

## 🎯 Présentation

**KazyPanel** est un panel d'hébergement web auto-hébergé, conçu pour administrer facilement des serveurs Linux avec Apache et PHP. Il remplace les solutions lourdes comme cPanel ou Plesk par une interface moderne, légère et entièrement contrôlée par vous.

Il fonctionne sur un serveur **Node.js** et expose une API REST consommée par une interface HTML/CSS/JS sans framework.

---

## ✨ Fonctionnalités

### Administration
- 📊 **Statut serveur** — 3 jauges circulaires CPU/RAM/Disque, graphique historique Canvas, auto-refresh 30s configurable, détection multi-PHP installés, IP publique, connexions TCP actives, alertes seuils critiques (CPU/RAM/Disque > 85%)
- 🌐 **Domaines & sous-domaines** — création, activation/désactivation, configuration Apache
- 🔒 **SSL Let's Encrypt** — génération et renouvellement de certificats en 1 clic
- ⚙️ **Configuration PHP** — par domaine (mémoire, upload, exécution, erreurs, session)
- 🐘 **Multi-PHP par domaine** — PHP 8.1 / 8.2 / 8.3 / 8.4 sélectionnable indépendamment pour chaque domaine, sans affecter les autres
- 🛡️ **Pare-feu UFW** — gestion des règles depuis l'interface + profils prédéfinis
- 🚫 **Fail2ban** — surveillance, débannissement, activation/désactivation des jails
- 🗄️ **Bases de données MariaDB** — création, suppression, quotas
- 📁 **Comptes FTP** — gestion vsftpd, multi-comptes par utilisateur
- 🔗 **DNS (BIND9)** — zones, enregistrements A/AAAA/CNAME/MX/TXT
- 💾 **Sauvegardes** — création manuelle + planification automatique (cron + rétention configurable)
- 📋 **Logs Apache** — consultation par domaine
- 🕐 **Crontab simplifié** — interface débutant avec 12 presets visuels (boutons avec icônes et descriptions), formulaire guidé en 3 étapes, plus besoin de connaître la syntaxe cron
- 🔑 **Connexions** — historique avec navigateur détecté, graphique 7 jours, alertes brute-force
- 📧 **SMTP** — relay email natif Node.js (STARTTLS), test d'envoi, template configurable
- 🔑 **Clés SSH** — gestion des clés autorisées (`authorized_keys`) par utilisateur
- 🌐 **Réseau FTP** — ports passifs configurables, IP publique
- ⏱️ **NTP** — serveur de temps configurable depuis le panel
- 📜 **Logs du panel** — consultation `kazypanel.log` / `kazypanel-error.log` avec filtres
- 🔒 **Sécurité avancée** — score /100, IPs bloquées, audit SSH professionnel, bannir/débannir en 1 clic
- 🔄 **Mises à jour système** — vérification apt, liste des paquets, installation en streaming avec terminal temps réel
- 📱 **Bot Telegram intégré** — alertes automatiques + 7 commandes de contrôle (`/status`, `/services`, `/restart`, `/users`, `/logs`, `/disk`, `/help`)
- 🛡️ **Sécurité Apache** — configuration `ServerTokens` / `ServerSignature` depuis l'interface, fichier dédié `kazypanel-security.conf`
- 👤 **Gestion utilisateurs** — template email bienvenue personnalisable, envoi automatique à la création
- 🔌 **API REST publique v1** — 22 endpoints, clés API, webhook Stripe, intégration WHMCS/n8n/Zapier
- 🛠️ **KazyDebug** — éditeur `index.html` / `server.js` en direct, CodeMirror, backup auto, activable depuis la config
- 💻 **Terminal SSH professionnel** — thème Catppuccin Macchiato, historique, Ctrl+C/D/L/U, commandes rapides

### Espace utilisateur
- 📂 **Explorateur de fichiers** — navigation, création, renommage, suppression, upload, téléchargement
- ✏️ **Éditeur de fichiers intégré** — édition en ligne des fichiers texte (PHP, HTML, CSS, JS, JSON, .htaccess, etc.)
- 🔒 **Gestion des permissions** — chmod avec interface visuelle
- 🖱️ **Menu contextuel** — clic droit sur chaque fichier/dossier

### Interface
- 🎨 **7 thèmes** — Dark, Light, Classic (Windows XP), macOS, Oceanic, Sunset, Lavender
- 🔐 **Page login améliorée** — fond animé, afficher/masquer MDP, statut serveur, se souvenir de moi, bannière maintenance
- 📱 Responsive — adapté desktop et mobile
- 🌙 Préférence de thème sauvegardée localement
- 🔄 Vérification automatique des mises à jour

### Gestion multi-utilisateurs
- 👥 Rôles **Admin** et **Utilisateur**
- 📋 **Templates de ressources** — limites FTP, BDD, domaines, disque, crontab
- 🎲 Génération de mot de passe aléatoire sécurisé
- ✉️ Template de message de bienvenue copiable (Gmail, etc.)
- 🔐 Indicateur de force de mot de passe

---

## 🛠️ Prérequis

### Système
- Ubuntu 20.04 / 22.04 / 24.04 ou Debian 11 / 12
- Accès root ou sudo

### Services requis
| Service | Version minimale |
|---------|-----------------|
| Node.js | 24.x ou supérieur |
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

**4. Node.js 24**
Ajout automatique du dépôt officiel NodeSource et installation de Node.js 24 LTS — la version minimale requise pour les API `fetch` natives utilisées par KazyPanel.

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
Téléchargement de la dernière version stable directement depuis le site officiel. Configuration automatique avec une clé `blowfish_secret` générée aléatoirement. Si une URL personnalisée a été fournie (ex: `pma.mondomaine.fr`), un vhost Apache dédié est créé. Sinon, phpMyAdmin est accessible via `/phpmyadmin` sur l'IP du serveur.

**12. UFW (pare-feu)**
Configuration et activation d'UFW avec les règles essentielles : SSH, HTTP (80), HTTPS (443), port du panel, FTP (21), plage passif FTP (40000-50000), DNS (53). Toute autre connexion entrante est bloquée par défaut.

**13. Fail2ban**
Configuration d'un `jail.local` avec protection SSH, Apache et vsftpd. Bannissement automatique après 5 tentatives échouées en 10 minutes, pour 1 heure.

**14. KazyPanel**
Clone du dépôt GitHub dans le répertoire choisi, `npm install --production`, création du fichier `.env` avec toutes les variables remplies automatiquement (dont une clé JWT de 128 caractères générée aléatoirement via `openssl rand`).

**15. Service systemd**
Création et activation du service `kazypanel.service` avec redémarrage automatique en cas de crash, logs dans `journald` et chargement automatique du `.env`.

**16. Résumé final**
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
▶ Installation de Node.js 24 ...
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

# ── CORS — origines autorisées (séparées par virgule, optionnel) ──
# PANEL_ALLOWED_ORIGINS=https://panel.votredomaine.fr

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

KazyPanel expose deux types d'API :

### API interne (JWT)

Toutes les routes (sauf `/api/login` et `/api/version`) requièrent un header d'authentification :

```
Authorization: Bearer <token>
```

### API publique v1 (clé API)

Accessible depuis n'importe quel site ou service externe. Authentification par header :

```
X-Api-Key: kp_live_xxxxxxxxxxxxxxxx
```

Les clés se gèrent dans **Configuration → API**. La liste complète des endpoints est accessible depuis le panel via **Configuration → API → Voir les endpoints**.

#### Utilisateurs (10 routes)

| Méthode | Route | Description |
|---------|-------|-------------|
| GET | `/api/v1/users` | Lister les utilisateurs |
| POST | `/api/v1/users` | Créer un utilisateur |
| GET | `/api/v1/users/:username` | Détails d'un utilisateur |
| DELETE | `/api/v1/users/:username` | Supprimer un utilisateur |
| PATCH | `/api/v1/users/:username/suspend` | Suspendre le compte |
| PATCH | `/api/v1/users/:username/unsuspend` | Réactiver le compte |
| GET | `/api/v1/users/:username/databases` | Lister les bases de données |
| POST | `/api/v1/users/:username/databases` | Créer une base de données MariaDB |
| DELETE | `/api/v1/users/:username/databases/:dbname` | Supprimer une base de données |
| GET | `/api/v1/users/:username/diskusage` | Quota disque (utilisé / limite / %) |

#### Domaines (4 routes)

| Méthode | Route | Description |
|---------|-------|-------------|
| GET | `/api/v1/domains` | Lister tous les domaines |
| POST | `/api/v1/domains` | Créer un domaine (SSL optionnel) |
| DELETE | `/api/v1/domains/:domain` | Supprimer un domaine |
| GET | `/api/v1/domains/:domain/ssl` | Statut SSL + jours restants |

#### Monitoring (3 routes)

| Méthode | Route | Description |
|---------|-------|-------------|
| GET | `/api/v1/status` | Statut serveur (CPU, RAM, disque) |
| GET | `/api/v1/status/services` | Statut détaillé de chaque service |
| GET | `/api/v1/status/disk` | Disque global + répartition par utilisateur |

#### Sécurité (3 routes)

| Méthode | Route | Description |
|---------|-------|-------------|
| GET | `/api/v1/security/banned` | IPs bannies par Fail2ban (toutes jails) |
| POST | `/api/v1/security/ban` | Bannir une IP dans une jail |
| DELETE | `/api/v1/security/ban/:ip` | Débannir une IP (`?jail=sshd` optionnel) |

#### Divers (2 routes)

| Méthode | Route | Description |
|---------|-------|-------------|
| GET | `/api/v1/templates` | Templates de ressources disponibles |
| POST | `/api/v1/webhook/stripe` | Webhook Stripe — vérification HMAC SHA256 |

**Exemple — créer un utilisateur :**
```bash
curl -X POST "https://panel.kazylax.fr/api/v1/users" \
  -H "X-Api-Key: kp_live_xxx" \
  -H "Content-Type: application/json" \
  -d '{"username":"client01","password":"pass","email":"client@mail.fr","template":"Starter","sendEmail":true}'
```

**Intégrations compatibles :** WHMCS, WooCommerce, PrestaShop, n8n, Make, Zapier, PHP, Python, Node.js

### Authentification interne

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
| GET | `/api/domains/:name/phpconfig` | Config PHP du domaine (.user.ini) |
| GET | `/api/system/php-versions` | Versions PHP-FPM installées sur le serveur |
| GET | `/api/config/telegram` | Configuration du bot Telegram |
| PUT | `/api/config/telegram` | Sauvegarder la configuration Telegram |
| POST | `/api/config/telegram/test` | Envoyer un message de test Telegram |
| GET | `/api/status` | Statut serveur enrichi : IP publique, TCP actifs, PHP installés, disques extra |
| POST | `/api/domains/:name/php-version` | Changer la version PHP d'un domaine |
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
| GET | `/api/me/files` | Lister un dossier |
| GET | `/api/me/files/content` | Lire un fichier |
| PUT | `/api/me/files/content` | Sauvegarder un fichier |
| POST | `/api/me/files/mkdir` | Créer un dossier |
| POST | `/api/me/files/touch` | Créer un fichier vide |
| POST | `/api/me/files/rename` | Renommer |
| DELETE | `/api/me/files` | Supprimer |
| GET | `/api/me/files/download` | Télécharger un fichier |
| POST | `/api/me/files/upload` | Uploader des fichiers |
| POST | `/api/me/files/chmod` | Changer les permissions |

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
| GET | `/api/security/score` | Score de sécurité /100 |
| GET | `/api/security/banned` | IPs bannies toutes jails |
| POST | `/api/security/ban` | Bannir une IP manuellement |
| GET | `/api/security/ssh-audit` | Audit tentatives SSH (journald + auth.log) |
| GET | `/api/security/logins/stats` | Stats connexions 7 jours |
| GET | `/api/server-config/apache-security` | Lire ServerTokens/ServerSignature |
| POST | `/api/server-config/apache-security` | Appliquer ServerTokens/ServerSignature |
| POST | `/api/server-config/apache-security/repair` | Réparer si erreur de syntaxe Apache |
| GET | `/api/system/updates/check` | Vérifier les mises à jour apt |
| GET | `/api/system/updates/upgradable` | Liste des paquets (cache) |
| GET | `/api/system/updates/upgrade/stream` | Lancer apt-get upgrade (SSE streaming) |
| GET | `/api/system/updates/status` | État mise à jour en cours |
| GET | `/api/update/check` | Vérifier les mises à jour KazyPanel |
| POST | `/api/update/apply` | Appliquer une mise à jour one-click |
| GET | `/api/logs/panel` | Logs du panel (filtres niveau/type) |
| DELETE | `/api/logs/panel` | Vider les logs |
| GET | `/api/config/general` | Paramètres généraux |
| PUT | `/api/config/defaults` | Limites par défaut utilisateurs |
| PUT | `/api/config/jwt` | Expiration des sessions |
| GET/PUT | `/api/config/smtp` | Configuration SMTP |
| POST | `/api/config/smtp/test` | Test d'envoi email |
| GET/PUT | `/api/config/backup-schedule` | Planification sauvegardes |
| GET/PUT | `/api/config/network` | Ports FTP passif + IP publique |
| GET/PUT | `/api/config/ntp` | Serveur NTP |
| GET | `/api/config/ssl-status` | Statut certificats Let's Encrypt (filtrés par vhosts réels) |
| GET/POST/DELETE | `/api/config/ssh-keys` | Gestion clés SSH autorisées |

---

## 🎨 Thèmes

KazyPanel propose 7 thèmes sélectionnables depuis la topbar :

| Thème | Description |
|-------|-------------|
| ☀️ **Light** | Interface claire, sobre et moderne |
| 🌙 **Dark** | Interface sombre, idéale pour un usage prolongé |
| 🖥️ **Classic** | Style Windows XP / OpenPanel, look rétro |
| 🍎 **macOS** | Style Ventura/Sonoma, glassmorphism, icônes emoji |
| 🌊 **Oceanic** | Tons bleu océan, ambiance marine |
| 🌅 **Sunset** | Tons chauds orange et brun, ambiance coucher de soleil |
| 💜 **Lavender** | Tons violet pastel, interface douce |

Le thème choisi est sauvegardé dans le `localStorage` du navigateur.

---

## 👥 Gestion des utilisateurs

### Rôles

| Rôle | Accès |
|------|-------|
| **Admin** | Accès complet — gestion serveur, utilisateurs, configuration |
| **Utilisateur** | Accès limité — ses domaines, BDD, FTP, DNS, crontab, explorateur de fichiers |

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

## 📂 Explorateur de fichiers

Chaque utilisateur dispose d'un explorateur de fichiers accessible depuis la sidebar, limité à son répertoire FTP (`/var/www/username/`).

### Fonctionnalités

- **Navigation** — arborescence latérale, fil d'Ariane cliquable, vue liste ou grille
- **Gestion** — créer, renommer, supprimer fichiers et dossiers
- **Éditeur intégré** — édition en ligne des fichiers texte (`.php`, `.html`, `.css`, `.js`, `.json`, `.env`, `.htaccess`, etc.)
- **Upload** — multi-fichiers depuis le navigateur
- **Téléchargement** — télécharger n'importe quel fichier
- **Permissions** — chmod avec interface visuelle (cases à cocher rwx)
- **Menu contextuel** — clic droit sur chaque élément

### Sécurité

Toutes les opérations passent par `safeUserPath()` qui vérifie que le chemin cible reste dans le répertoire de l'utilisateur. Toute tentative de path traversal (`../`) est rejetée avec une erreur 403.

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

- **Ne pas exposer le port 8080 publiquement** — utiliser un reverse proxy Apache
- Activer **HTTPS** avec un certificat SSL sur le panel lui-même
- Activer **UFW** et n'autoriser que les ports nécessaires
- Activer **Fail2ban** pour protéger les accès SSH et Apache
- Configurer **ServerTokens Prod** et **ServerSignature Off** depuis Configuration > Réseau > Sécurité Apache

### Multi-PHP par domaine

KazyPanel supporte plusieurs versions PHP-FPM en parallèle sur le même serveur. Chaque domaine peut utiliser sa propre version indépendamment.

#### Installer plusieurs versions PHP sur Debian/Ubuntu

Sur **Debian 12**, ajoutez d'abord le dépôt sury.org :

```bash
curl -fsSL https://packages.sury.org/php/apt.gpg | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/php.gpg
echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/php.list
sudo apt-get update
```

Sur **Ubuntu**, le dépôt ondrej/php est utilisé (ajouté automatiquement par l'install) :

```bash
sudo add-apt-repository ppa:ondrej/php
sudo apt-get update
```

Installez ensuite les versions souhaitées :

```bash
# PHP 8.1
sudo apt install -y php8.1-fpm php8.1-mysql php8.1-curl php8.1-gd php8.1-mbstring php8.1-xml php8.1-zip php8.1-intl php8.1-bcmath php8.1-opcache

# PHP 8.2
sudo apt install -y php8.2-fpm php8.2-mysql php8.2-curl php8.2-gd php8.2-mbstring php8.2-xml php8.2-zip php8.2-intl php8.2-bcmath php8.2-opcache

# PHP 8.3
sudo apt install -y php8.3-fpm php8.3-mysql php8.3-curl php8.3-gd php8.3-mbstring php8.3-xml php8.3-zip php8.3-intl php8.3-bcmath php8.3-opcache
```

Vérifier que toutes les versions sont actives :

```bash
systemctl status php8.1-fpm php8.2-fpm php8.3-fpm php8.4-fpm --no-pager
ls /run/php/    # doit lister php8.1-fpm.sock, php8.2-fpm.sock, etc.
```

#### Changer la version PHP d'un domaine depuis le panel

Dans **Domaines** → bouton **🐘 PHP** → onglet **Version** :

- Les versions installées et actives apparaissent automatiquement sous forme de cartes
- Cliquez sur la version souhaitée → bouton **Appliquer cette version**
- KazyPanel modifie le vhost Apache du domaine (HTTP + SSL), vérifie la syntaxe et recharge Apache
- **Les autres domaines ne sont pas affectés**

#### Fonctionnement technique

Chaque version PHP-FPM expose son propre socket Unix :

```
/run/php/php8.1-fpm.sock  → domaine-a.fr
/run/php/php8.2-fpm.sock  → domaine-b.fr
/run/php/php8.4-fpm.sock  → domaine-c.fr  (version par défaut)
```

Apache redirige vers le bon socket grâce à la directive `SetHandler` dans chaque vhost :

```apache
<FilesMatch \.php$>
    SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"
</FilesMatch>
```

#### Vérifier la version active d'un domaine

```bash
grep -r "php.*fpm.sock" /etc/apache2/sites-enabled/mondomaine.fr.conf
```

---

### Reverse proxy Apache (recommandé)

```apache
<VirtualHost *:80>
    ServerName panel.votredomaine.fr
    RewriteEngine On
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>

<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName panel.votredomaine.fr

    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/panel.votredomaine.fr/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/panel.votredomaine.fr/privkey.pem

    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/

    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set Content-Security-Policy "frame-ancestors 'self'"
    Header always unset X-Powered-By

    Include /etc/letsencrypt/options-ssl-apache.conf
</VirtualHost>
</IfModule>
```

### Sécurité Apache — ServerTokens / ServerSignature

KazyPanel permet de configurer ces directives directement depuis l'interface (**Configuration > Réseau > Sécurité Apache**). Les valeurs sont écrites dans un fichier dédié `/etc/apache2/conf-available/kazypanel-security.conf` sans modifier le fichier Debian d'origine.

| Directive | Valeur recommandée | Effet |
|-----------|-------------------|-------|
| `ServerTokens` | `Prod` | Le header HTTP `Server:` n'affiche que `Apache` |
| `ServerSignature` | `Off` | Aucune version affichée dans les pages d'erreur Apache |

---

## 🔄 Mise à jour

### KazyPanel

**Via le panel (recommandé)** — cliquer sur le bouton 🔔 dans la topbar puis "Lancer la mise à jour". Le panel exécute `git pull`, `npm install` et redémarre automatiquement avec les logs en temps réel.

**Via SSH :**

```bash
cd /opt/kazypanel
git pull origin main
npm install
systemctl restart kazypanel
```

Le panel vérifie automatiquement les nouvelles versions au démarrage et affiche une notification dans la topbar.

### Système (paquets Debian/Ubuntu)

Depuis **Sécurité > Mises à jour** :
- Vérification de la liste des paquets (`apt-get update`)
- Affichage de tous les paquets disponibles avec distinction sécurité / standard
- Badge rouge sur l'onglet si des correctifs de sécurité sont en attente
- Installation en streaming avec terminal temps réel
- Deux modes : **Tout mettre à jour** ou **Sécurité uniquement**

---

## 🔧 Dépannage

**Bloqué par le rate limiting ("Trop de tentatives")**
→ Le rate limiting est en mémoire — un redémarrage du service le remet à zéro :
```bash
sudo systemctl restart kazypanel
```

**Le bot Telegram ne reçoit pas les alertes**
→ Vérifiez que le Bot Token et le Chat ID sont corrects dans Configuration → Telegram
→ Cliquez sur "Tester" pour envoyer un message de test
→ Vérifiez que le service KazyPanel tourne : `journalctl -u kazypanel -f`
→ Sur Debian 12, vérifiez que journald retourne les logs SSH : `journalctl _SYSTEMD_UNIT=ssh.service -n 5`

**Changer la version PHP d'un domaine ne fonctionne pas**
→ Vérifiez que la version PHP-FPM cible est installée et active :
```bash
systemctl status php8.1-fpm
ls /run/php/php8.1-fpm.sock
```
→ Si le socket est absent, démarrez le service :
```bash
sudo systemctl start php8.1-fpm
sudo systemctl enable php8.1-fpm
```
→ Sur Debian 12, installez d'abord le dépôt sury.org (voir section [Multi-PHP par domaine](#multi-php-par-domaine))

**BIND9 ne démarre pas**
→ Vérifier la syntaxe du fichier de configuration :
```bash
named-checkconf
journalctl -xeu named.service --no-pager | tail -30
```
→ Port 53 occupé par `systemd-resolved` :
```bash
echo "DNSStubListener=no" | sudo tee -a /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved
sudo systemctl start named
```

**Erreur de syntaxe Apache après configuration ServerTokens**
→ Utiliser le bouton **Réparer** dans Configuration > Réseau > Sécurité Apache, ou manuellement :
```bash
sudo rm -f /etc/apache2/conf-enabled/kazypanel-security.conf
sudo rm -f /etc/apache2/conf-available/kazypanel-security.conf
sudo apache2ctl -t && sudo systemctl reload apache2
```

**Erreur `EACCES` sur `/var/www/`**
→ Corriger les permissions du répertoire :
```bash
sudo chown -R debian:debian /var/www/username
sudo chmod -R 755 /var/www/username
```

**503 sur le reverse proxy**
→ Vérifier que KazyPanel tourne et écoute bien sur le port 8080 :
```bash
systemctl status kazypanel
ss -tlnp | grep 8080
curl -I http://127.0.0.1:8080/
```

**Audit SSH — aucune donnée (Debian 12)**
→ Sur Debian 12, `/var/log/auth.log` n'existe pas par défaut. KazyPanel lit automatiquement `journald`. Si vous voulez le fichier classique :
```bash
sudo apt install rsyslog
```

**`named-checkconf : command not found` avec sudo**
→ sudo ne trouve pas `/usr/sbin` dans son PATH :
```bash
which named-checkconf || find /usr /sbin /bin -name named-checkconf
sudo apt install bind9utils
```

**Syntaxe `named.conf.local` invalide**
→ Inspecter et corriger le fichier :
```bash
cat -n /etc/bind/named.conf.local
sudo nano /etc/bind/named.conf.local
sudo named-checkconf && sudo systemctl start named
```

---

## 📋 Logs & Monitoring

KazyPanel écrit deux fichiers de log dans `/var/log/` :

| Fichier | Contenu |
|---------|---------|
| `kazypanel.log` | Toutes les actions (INFO, WARN) |
| `kazypanel-error.log` | Erreurs et alertes sécurité uniquement |

### Format des entrées

```
[26/03/2026 11:04:24] [INFO] [OK] LOGIN: [127.0.0.1] admin
[26/03/2026 11:05:12] [WARN] [FAIL] LOGIN: [1.2.3.4] admin
[26/03/2026 11:05:13] [ALERT] BRUTE_FORCE: 5 tentatives depuis 1.2.3.4 en moins d'1 minute
```

### Consultation depuis le panel

Le bouton **📋 Logs** dans la topbar (admin) ouvre un modal avec :
- Sélecteur de fichier (`kazypanel.log` / `kazypanel-error.log`)
- Filtre par niveau (`INFO`, `WARN`, `ERROR`)
- Colorisation des lignes
- Bouton vider

### Rotation automatique

Configurer `logrotate` pour éviter que les fichiers grossissent indéfiniment :

```bash
sudo tee /etc/logrotate.d/kazypanel << 'EOF'
/var/log/kazypanel*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
```

### Consultation en ligne de commande

```bash
# Dernières connexions
grep LOGIN /var/log/kazypanel.log | tail -20

# Tentatives échouées
grep FAIL /var/log/kazypanel.log

# Alertes brute-force
cat /var/log/kazypanel-error.log
```

---

## 🔒 Sécurité avancée

### Rate limiting intégré

KazyPanel bloque automatiquement une IP après **5 tentatives de connexion échouées** et détecte les attaques brute-force en temps réel (5 échecs en moins d'une minute → alerte dans la topbar).

Pour débloquer une IP manuellement (reset en mémoire) :
```bash
sudo systemctl restart kazypanel
```

### Audit SSH professionnel

L'onglet **Sécurité > Audit SSH** affiche :
- 4 compteurs : total tentatives, échecs, succès, IPs uniques
- Tableau avec colonnes Statut / Date-Heure / Utilisateur / IP source
- Filtres temps réel (Tout / Échecs / Succès) + recherche par IP ou nom
- Classement Top 10 IPs attaquantes avec barres de progression et médailles
- Bannissement en 1 clic directement depuis la liste
- Compatible **Debian 12** (journald) et systèmes avec `/var/log/auth.log`

### Recommandations de production

- Utiliser un **reverse proxy HTTPS** (Apache) devant le port 8080
- Ne jamais exposer le port 8080 publiquement
- Définir une clé `JWT_SECRET` longue et aléatoire dans `.env` :
```bash
JWT_SECRET=$(openssl rand -hex 64)
```
- Activer **Fail2ban** avec le filtre KazyPanel inclus dans `jail.local`
- Configurer le **PTR record** (reverse DNS) sur l'IP du serveur pour la délivrabilité mail
- Appliquer `ServerTokens Prod` + `ServerSignature Off` depuis le panel

### Filtre Fail2ban pour KazyPanel

Le fichier `/etc/fail2ban/filter.d/kazypanel.conf` est créé automatiquement. Il détecte les échecs de connexion dans `kazypanel.log` et les transmet à Fail2ban pour bannissement IP.

---

## 📱 Bot Telegram

KazyPanel intègre un bot Telegram natif — aucune dépendance externe, tout fonctionne via l'API Telegram et le long-polling intégré dans `server.js`.

### Configuration

1. Créer un bot : ouvrir Telegram → **@BotFather** → `/newbot` → copier le **token**
2. Obtenir votre Chat ID : envoyer un message à **@userinfobot**
3. Dans KazyPanel : **Configuration → Telegram** → coller Token + Chat ID → Enregistrer → Tester

### Commandes disponibles

| Commande | Description |
|----------|-------------|
| `/help` | Liste de toutes les commandes |
| `/status` | CPU, RAM, Disque, Load, Uptime |
| `/services` | État des services système |
| `/restart apache2` | Redémarrer un service |
| `/users` | Liste des utilisateurs |
| `/logs` | 15 dernières lignes du log |
| `/disk` | Espace disque par partition |

Services redémarrables : `apache2`, `mariadb`, `fail2ban`, `vsftpd`, `kazypanel`, `named`, `bind9`

### Alertes automatiques

| Événement | Déclencheur |
|-----------|-------------|
| Connexion panel échouée | Immédiat |
| Brute-force détecté | 5 tentatives / 1 minute |
| Nouveau domaine créé | Immédiat |
| Sauvegarde terminée | Immédiat + taille |
| Service arrêté | Immédiat |
| Mises à jour apt disponibles | Après vérification |
| SSL expirant ≤ 14 jours | Quotidien |
| Connexion SSH (réussie/échouée) | Toutes les 30s via journald |
| UFW désactivé / réactivé | Toutes les 60s |

### Sécurité

Seul le **Chat ID** configuré peut envoyer des commandes au bot. Tout message provenant d'un autre chat est silencieusement ignoré.

---

## ❓ FAQ

**Le panel ne démarre pas**
→ Vérifiez les logs : `journalctl -u kazypanel -f`
→ Vérifiez que Node.js ≥ 24 est installé : `node --version`

**Impossible de créer un domaine**
→ Vérifiez qu'Apache est bien installé et que `/etc/apache2/sites-available` existe
→ Le processus doit tourner en root ou avoir les permissions suffisantes

**Les emails ne s'envoient pas**
→ Vérifiez la configuration SMTP dans Configuration > Emails
→ Le port 25 est souvent bloqué par les fournisseurs VPS — utilisez le port **587 (STARTTLS)**
→ Pour Gmail, générez un **mot de passe d'application** (pas votre mot de passe habituel)

**Configuration SMTP — Fournisseurs compatibles**

KazyPanel utilise SMTP natif Node.js avec **STARTTLS sur le port 587** :

| Fournisseur | Hôte SMTP | Port |
|---|---|---|
| **Gmail** | `smtp.gmail.com` | 587 |
| **Outlook / Hotmail** | `smtp-mail.outlook.com` | 587 |
| **OVH** | `ssl0.ovh.net` | 587 |
| **Infomaniak** | `mail.infomaniak.com` | 587 |
| **Ionos (1&1)** | `smtp.ionos.fr` | 587 |
| **Gandi** | `mail.gandi.net` | 587 |
| **Mailgun** | `smtp.mailgun.org` | 587 |
| **SendGrid** | `smtp.sendgrid.net` | 587 |
| **Amazon SES** | `email-smtp.eu-west-1.amazonaws.com` | 587 |
| **Serveur perso** | `mail.votredomaine.fr` | 587 |

> ⚠️ Le port **465 (SSL direct)** n'est pas supporté — utilisez exclusivement le port **587 avec STARTTLS activé**.

> Gmail : activez la validation en deux étapes puis générez un mot de passe d'application sur [myaccount.google.com](https://myaccount.google.com) → Sécurité → Mots de passe des applications.

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

*KazyPanel v1.8.0 — Dernière mise à jour : 03 Avril 2026*

---

## Changelog

### v1.8.0 — 2026-04-13

### v1.8.0 — 2026-04-05
- • — Bot Telegram natif — long-polling intégré, 7 commandes (/status /services /restart /users /logs /disk /help)
- • — Alertes Telegram automatiques : connexion échouée, brute-force, nouveau domaine, sauvegarde, service arrêté, mises à jour apt, SSL expirant, SSH, UFW
- • — Multi-PHP par domaine — PHP 8.1 / 8.2 / 8.3 / 8.4 sélectionnable indépendamment, admin et utilisateur
- • — API REST v1 étendue — 22 routes (domaines, bases de données, monitoring, sécurité Fail2ban, templates)
- • — Monitoring SSH toutes les 30s via journald avec déduplication des alertes
- • — Monitoring UFW toutes les 60s — alerte immédiate si pare-feu désactivé ou réactivé
- • — Statut serveur enrichi — IP publique, TCP actifs, PHP installés, disques extra, auto-refresh 30s, bannière alerte seuils
- • — Modal Endpoints API dans Configuration → API avec tableaux par catégorie et badges colorés
- • — Page login — nom du site hébergeur configurable et cliquable, version depuis version.json
- 🔒 Sécurité — Rate limiter login progressif : 3 échecs → 30s, 5 → 5min, 10 → 30min avec compte à rebours visuel
- 🔒 Sécurité — Message d'erreur générique Identifiants incorrects — empêche l'énumération des comptes
- 🔒 Sécurité — Scrypt configurable via SCRYPT_COST dans .env (16384 / 32768 / 65536)
- 🐛 Fix — Fix Cannot read properties of undefined reading memory_limit — route phpconfig unifiée
- 🐛 Fix — Fix SSL domaine utilisateur affichait Aucun — vérification croisée avec fichier -le-ssl.conf
- 🐛 Fix — Fix cfgLoadDomains non défini dans applyPhpVersion — remplacé par loadDomains()
- 🐛 Fix — Fix modal PHP — s'ouvre maintenant sur l'onglet Memory par défaut sans conflit
- 🐛 Fix — Fix adminOnly retiré de /api/system/php-versions — accessible aux utilisateurs
- 🐛 Fix — Onglet Sauvegardes supprimé de Configuration — fonctionnalité déplacée dans Sécurité

### v1.8.0 — 2026-04-05

### v1.8.0 — 2026-04-03

#### 🐘 Multi-PHP par domaine
- ✨ **Sélecteur de version PHP** par domaine — PHP 8.1 / 8.2 / 8.3 / 8.4 indépendants
  - Nouvel onglet **🐘 Version** dans le modal PHP de chaque domaine
  - Cartes visuelles cliquables avec statut actif/arrêté par version
  - Version actuelle du domaine affichée avec badge **✓ Actuel**
  - Bouton **Appliquer cette version** — modifie le vhost HTTP + SSL, vérifie syntaxe Apache, recharge
  - Les autres domaines ne sont pas affectés
  - Commande d'installation affichée pour les versions manquantes
- ✨ **Route `GET /api/system/php-versions`** — détecte automatiquement toutes les versions PHP-FPM installées via `systemctl` et `/etc/php/`
- ✨ **Route `POST /api/domains/:name/php-version`** — change le socket PHP dans le vhost du domaine (HTTP + SSL), démarre PHP-FPM si arrêté, recharge Apache

#### 🌐 Site vitrine kazylax.fr
- ✨ **Section Screenshots** — 3 aperçus simulés de l'interface (Dashboard, Domaines/SSL, Score de sécurité)
- ✨ **Section Comparaison** — tableau 10 critères KazyPanel vs cPanel vs Plesk vs ISPConfig
- ✨ **Section FAQ** — 7 questions accordéon avec animation + Schema.org `FAQPage` pour Google Rich Results
- ✨ **Section Roadmap** — 4 fonctionnalités en cours/planifiées + 4 idées avec badges colorés
- ✨ **CTA Hero** — bouton "Installer maintenant" + GitHub Stars temps réel via l'API
- ✨ **Bouton retour en haut** flottant (↑), visible après 400px de scroll
- ✨ **Version cliquable** → section Changelog dans la sidebar et la stat card
- ✨ **4 nouveaux liens** dans la sidebar : Aperçu, Comparaison, FAQ, Roadmap
- 🐛 Fix : `secPane_updates` absent de `hideAllMainSections()` — le panneau Mises à jour restait visible en naviguant vers une autre section

#### 🔍 SEO
- ✨ `meta name="keywords"` ajouté
- ✨ Schema.org `FAQPage` dans le `<head>`
- ✨ `robots.txt` créé avec référence au `sitemap.xml`
- ✨ `sitemap.xml` mis à jour avec 9 URLs (nouvelles sections incluses)
- ✨ Apple Touch Icon — `kazypanel-apple-touch-icon.png` 180×180 pour iOS/Android

#### 📱 Bot Telegram
- ✨ **Bot Telegram natif** — aucune dépendance externe, long-polling intégré dans server.js
- ✨ **7 commandes disponibles** :
  - `/status` — CPU, RAM, Disque, Load, Uptime, nb utilisateurs avec barres visuelles
  - `/services` — état de Apache, MariaDB, KazyPanel, Fail2ban, vsftpd
  - `/restart apache2` — redémarrer un service (apache2, mariadb, fail2ban, vsftpd, kazypanel, named, bind9)
  - `/users` — liste des utilisateurs avec rôle et statut de suspension
  - `/logs` — 15 dernières lignes du log KazyPanel
  - `/disk` — espace disque par partition `/dev`
  - `/help` — liste de toutes les commandes
- ✨ **8 alertes automatiques** :
  - 🔐 Connexion échouée au panel (IP + utilisateur)
  - 🚨 Brute-force détecté (5 tentatives en moins d'1 minute)
  - 🌐 Nouveau domaine créé (domaine + créateur)
  - 💾 Sauvegarde terminée (nom + taille en Mo)
  - ❌ Service arrêté (quel service + qui)
  - 🔄 Mises à jour apt disponibles (nb paquets dont sécurité)
  - 🔒 Certificats SSL expirant ≤ 14 jours (check quotidien automatique)
  - 🔓 Connexions SSH réussies et échouées (via journald, check toutes les 30s)
  - 🚨 UFW désactivé / réactivé (check toutes les 60s)
- ✨ **Configuration dans Configuration → Telegram** :
  - Bot Token + Chat ID
  - Seuils d'alerte CPU/RAM/Disque configurables
  - Checkboxes pour activer/désactiver chaque type d'alerte
  - Bouton "Tester" — envoie un message de confirmation immédiat
  - Bouton "Désactiver" — vide les champs et arrête le bot
- ✨ **Sécurité** — seul le Chat ID configuré peut envoyer des commandes
- ✨ **Déduplication SSH** — un Set en mémoire évite les alertes dupliquées entre deux checks
- 🗑️ Onglet "Sauvegardes" retiré de Configuration (fonctionnalité déplacée dans Sécurité)
- ✨ **API REST v1 étendue — 22 routes** (14 nouvelles routes ajoutées) :
  - Domaines : `GET/POST /api/v1/domains`, `DELETE /api/v1/domains/:domain`, `GET /api/v1/domains/:domain/ssl`
  - BDD : `GET/POST /api/v1/users/:username/databases`, `DELETE /api/v1/users/:username/databases/:dbname`
  - Monitoring : `GET /api/v1/status/services`, `GET /api/v1/status/disk`, `GET /api/v1/users/:username/diskusage`
  - Sécurité : `GET /api/v1/security/banned`, `POST /api/v1/security/ban`, `DELETE /api/v1/security/ban/:ip`
  - Divers : `GET /api/v1/templates`
- ✨ **Modal "Endpoints" dans Configuration → API** — tableaux par catégorie avec badges de méthode colorés
- ✨ **Route utilisateur `POST /api/me/domains/:name/php-version`** — changement de version PHP accessible aux utilisateurs non-admin
- 🐛 Fix : SSL domaine utilisateur affichait "Aucun" même avec certificat valide — vérification croisée avec fichier `-le-ssl.conf`
- 🐛 Fix : `api/system/php-versions` inaccessible aux utilisateurs — `adminOnly` retiré
- 🐛 Fix : `cfgLoadDomains` non défini dans `applyPhpVersion` — remplacé par `loadDomains()`

#### 📊 Statut serveur — améliorations
- ✨ **IP publique** — affichée dans les informations système (via ipify ou hostname)
- ✨ **Connexions TCP actives** — nombre de connexions ESTABLISHED en temps réel (`ss -s`)
- ✨ **Multi-PHP dans les services** — toutes les versions PHP-FPM installées apparaissent comme cartes individuelles avec statut actif/arrêté
- ✨ **Auto-refresh 30s** — bouton toggle avec indicateur visuel (point vert animé), se désactive automatiquement si on quitte la section
- ✨ **Bannière d'alerte critique** — apparaît en rouge si CPU > 85%, RAM > 85% ou Disque > 85% avec détail des ressources concernées
- ✨ **Disques supplémentaires** — partitions `/var`, `/home`, `/tmp` affichées dans les stats rapides si montées séparément
- ✨ **Versions Apache et MariaDB** — récupérées et affichées dans les cards services
- ✨ **Grille 3 colonnes** — 3 jauges (CPU/RAM/Disque) en layout équilibré, bloc Serveur supprimé (infos déplacées dans la table "Informations système")
- ✨ **Boutons services compacts** — `▶ Start` / `↺ Restart` / `■ Stop` sur une ligne par carte, sans débordement
- 🐛 Fix : `secPane_updates` absent de `hideAllMainSections()` — panneau Mises à jour restait visible en naviguant
- 🐛 Fix : SyntaxError server.js — apostrophes dans `awk '{print $1}'` dans la chaîne JS publicIp
- 🐛 Fix : `try` orphelin double dans le bloc `extraDisks`

---

### v1.7.0 — 2026-03-31

#### 🔄 Mises à jour système
- ✨ **Nouvel onglet "Mises à jour"** dans Sécurité
  - Vérification `apt-get update` + liste complète des paquets upgradables
  - Distinction paquets de **sécurité** (badge rouge) et paquets standard
  - **Badge** sur l'onglet indiquant le nombre de mises à jour en attente
  - **Terminal streaming en temps réel** (SSE via fetch+ReadableStream, compatible auth JWT)
  - Mode **"Tout mettre à jour"** et mode **"Sécurité uniquement"**
  - Confirmation obligatoire avant toute installation avec nombre de paquets concernés
  - Cache 5 minutes pour éviter les appels apt répétés
  - `DEBIAN_FRONTEND=noninteractive` pour éviter les prompts interactifs

#### 🛡️ Sécurité Apache
- ✨ **Bloc "Sécurité Apache"** dans Configuration > Réseau
  - Configuration `ServerTokens` (Prod/Major/Minor/OS/Full) et `ServerSignature` (Off/On/Email)
  - Fichier dédié `/etc/apache2/conf-available/kazypanel-security.conf` — ne modifie jamais `security.conf` Debian
  - Vérification syntaxe Apache avant rechargement
  - **Bouton Réparer** en cas d'erreur de syntaxe (503)
  - `ServerSignature Off` + `Header always unset X-Powered-By/Server` ajoutés automatiquement à tous les nouveaux vhosts
- 🔧 `a2enconf`, `a2disconf`, `ln -sf`, `apt-get`, `apt` ajoutés à la whitelist sudo

#### 🔍 Audit SSH professionnel
- ✨ **Refonte complète** de l'onglet Audit SSH
  - 4 compteurs : Total / Échecs / Succès / IPs uniques
  - Tableau structuré avec colonnes : Statut (badge) / Date-Heure / Utilisateur / IP source
  - Filtres temps réel Tout / ❌ Échecs / ✅ Succès + recherche par IP ou nom
  - **Classement Top IPs** avec médailles 🥇🥈🥉, barres de progression proportionnelles
  - Bannissement en 1 clic sur chaque ligne et dans le classement
  - Formulaire de bannissement intégré avec choix du jail
- ✨ **Support Debian 12** — fallback automatique vers `journald` si `/var/log/auth.log` absent
  - `journalctl _SYSTEMD_UNIT=ssh.service` lu nativement
  - Parsing adapté au format ISO journald vs syslog classique
  - Affichage de la source des logs (journald / auth.log)
  - `journalctl` et `ssh -V` ajoutés à NO_SUDO_PREFIXES

#### 🐛 Corrections de bugs
- 🔴 Fix critique : `runCmdOut` utilisée avant sa déclaration (lignes 779/1193) → déplacée après `runCmd`
- 🔴 Fix critique : CORS reflétait toute origine avec `Credentials: true` → whitelist par hôte (`PANEL_ALLOWED_ORIGINS`)
- 🟠 Fix : 8 doublons `cacheInvalidate` dans les routes domaines, utilisateurs, services
- 🟠 Fix : `timedatectl set-timezone` sans guillemets → injection potentielle
- 🟠 Fix : `userOwnsDocRoot(user, null)` crashait sur `.startsWith(undefined)`
- 🟠 Fix : Path traversal potentiel sur backup download/delete → `path.resolve` + `startsWith(BACKUP_DIR + sep)`
- 🟡 Fix : 65 occurrences `parseInt()` sans base 10 sur données HTTP
- 🟡 Fix : `catch {}` silencieux sur `bcryptjs` → `console.warn` ajouté
- 🟠 Fix : `Content-Security-Policy: frame-ancestors 'self'` ajouté (X-Frame-Options déprécié)
- 🟠 Fix : doublon définition `runCmdOut` en bas du fichier supprimé
- 🟡 Fix : double commentaire `// ─── ROUTE: SAUVEGARDE` supprimé
- 🐛 Fix : Certificats SSL — affichage filtré par vhosts réels uniquement (plus de sous-domaines fantômes)
  - Croisement avec `ServerName`/`ServerAlias` des `.conf` Apache actifs
  - Domaines sans vhost affichés en `+N autre(s) dans le cert` avec tooltip
- 🐛 Fix : fonction `readApacheDirective` — template literal avec backtick invalide remplacé par concaténation

#### 🕐 Crontab simplifié (rôle utilisateur)
- ✨ **Refonte complète** de l'interface crontab utilisateur
  - 12 boutons presets visuels avec icônes et descriptions (Toutes les 5 min, Chaque nuit à 2h, etc.)
  - Formulaire guidé en **3 étapes** : Quand / Commande / Nom
  - Prévisualisation de l'expression cron qui apparaît à la sélection
  - Bouton "Ajouter" grisé tant que les champs obligatoires ne sont pas remplis
  - Suppression des 5 champs manuels (cronMin/cronHour/…) — inutiles pour les débutants
  - `renderCrontabList` amélioré : description humaine en priorité, expression cron en badge discret
- ✨ CSS `.cron-preset-card` et `.cron-preset-card.selected` ajoutés

---

### v1.6.0 — 2026-03-29

#### 🌐 API REST publique v1
- ✨ **8 endpoints API** authentifiés par clé `X-Api-Key` (étendu à 22 routes en v1.8.0)
- 🔑 Gestion des clés API dans Configuration > API
- 💳 Intégration Stripe — secret webhook configurable, URL auto-générée
- 📄 Page de commande `order.php` pour kazylax.fr

#### 🖥️ Dashboard Statut serveur
- ✨ **4 jauges circulaires SVG** animées (CPU, RAM, Disque, Serveur)
- 📈 **Graphique historique Canvas** CPU + RAM (20 mesures)
- Auto-refresh toutes les 30 secondes

#### ⚙️ Configuration > Serveur — KazyDebug
- ✨ Toggle on/off KazyDebug depuis Configuration > Serveur
- Mise à jour immédiate du `.env` sans redémarrage

#### 🛠️ KazyDebug — Éditeur système
- ✨ Bouton "Tout sélectionner" + raccourci `Ctrl+A`
- Backup automatique limité à 1 seul fichier par source
- Raccourci `Ctrl+G` pour aller à une ligne

#### 💻 Terminal SSH
- ✨ Thème Catppuccin Macchiato
- Barre de statut bas avec `cwd:` en temps réel
- `Ctrl+D`, `Ctrl+U`, ANSI 256 couleurs
- 2 nouvelles commandes rapides : `ps aux` et `netstat`

#### 🔧 Optimisations
- ⚡ Suppression dépendances : `bcryptjs`, `jsonwebtoken`, `cors`, `helmet` remplacés par implémentations natives Node.js 24
- 📦 `node_modules` réduit de ~15 Mo à 4.7 Mo

---

### v1.5.0 — 2026-03-26

#### 🔐 Page login
- ✨ Fond animé, afficher/masquer MDP, statut serveur, bannière maintenance, se souvenir de moi

#### 📧 Emails
- ✨ SMTP natif Node.js STARTTLS, template personnalisable avec variables, aperçu temps réel

#### 🛡️ Sécurité
- Score de sécurité /100, IPs bloquées, Audit SSH, graphique connexions 7 jours

#### ⚙️ Configuration
- Onglets Emails, Sauvegardes, Réseau, Clés SSH

---

### v1.4.0 — 2026-03-25

- ✨ Explorateur de fichiers utilisateur, éditeur intégré, chmod visuel, menu contextuel
- Mise à jour one-click, BIND9 dans le dashboard, logs structurés
- SMTP, clés SSH, sauvegardes planifiées, réseau FTP, NTP, expiration JWT

---

### v1.4.0 — 2026-03-23

- Première version publique stable
