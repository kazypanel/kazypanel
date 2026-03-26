# 🖥️ KazyPanel

![image](https://github.com/kazypanel/kazypanel/blob/main/accueil.png)
![image](https://github.com/kazypanel/kazypanel/blob/main/domaine.png)
![image](https://github.com/kazypanel/kazypanel/blob/main/templates.png)

> Panel d'administration web pour serveurs Apache/PHP — léger, rapide, sans dépendances lourdes.

![Version](https://img.shields.io/badge/version-1.5.0-blue)
![Node](https://img.shields.io/badge/node-%3E%3D24.0.0-green)
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
- [Explorateur de fichiers](#-explorateur-de-fichiers)
- [Templates de ressources](#-templates-de-ressources)
- [Sécurité](#-sécurité)
- [Mise à jour](#-mise-à-jour)
- [Dépannage](#-dépannage)
- [Logs & Monitoring](#-logs--monitoring)
- [Sécurité avancée](#-sécurité-avancée)
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
- 🛡️ **Pare-feu UFW** — gestion des règles depuis l'interface + profils prédéfinis
- 🚫 **Fail2ban** — surveillance, débannissement, activation/désactivation des jails
- 🗄️ **Bases de données MariaDB** — création, suppression, quotas
- 📁 **Comptes FTP** — gestion vsftpd, multi-comptes par utilisateur
- 🔗 **DNS (BIND9)** — zones, enregistrements A/AAAA/CNAME/MX/TXT
- 💾 **Sauvegardes** — création manuelle + planification automatique (cron + rétention configurable)
- 📋 **Logs Apache** — consultation par domaine
- 🕐 **Crontab** — gestion des tâches planifiées par utilisateur
- 🔑 **Connexions** — historique avec navigateur détecté, graphique 7 jours, alertes brute-force
- 📧 **SMTP** — relay email natif Node.js (STARTTLS), test d'envoi, template configurable
- 🔑 **Clés SSH** — gestion des clés autorisées (`authorized_keys`) par utilisateur
- 🌐 **Réseau FTP** — ports passifs configurables, IP publique
- ⏱️ **NTP** — serveur de temps configurable
- 📜 **Logs du panel** — consultation `kazypanel.log` / `kazypanel-error.log` avec filtres et alertes
- 🔒 **Sécurité avancée** — score /100, IPs bloquées, audit SSH, bannir/débannir en 1 clic
- 👤 **Gestion utilisateurs** — template email bienvenue personnalisable, envoi automatique à la création

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
Téléchargement de la dernière version stable (récupérée automatiquement depuis phpmyadmin.net) directement depuis le site officiel. Configuration automatique avec une clé `blowfish_secret` générée aléatoirement. Si une URL personnalisée a été fournie (ex: `pma.mondomaine.fr`), un vhost Apache dédié est créé. Sinon, phpMyAdmin est accessible via `/phpmyadmin` sur l'IP du serveur. L'URL est automatiquement injectée dans le `.env` de KazyPanel pour que le bouton phpMyAdmin dans le panel fonctionne directement.

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
| GET | `/api/status/public` | Statut serveur sans auth (page login) |
| GET | `/api/maintenance` | État bannière maintenance sans auth |
| GET/PUT/DELETE | `/api/config/email-template` | Template email de bienvenue |
| PUT | `/api/config/panel-url` | URL publique du panel |
| POST | `/api/users/welcome-email` | Envoi email de bienvenue |
| GET | `/api/security/score` | Score de sécurité /100 |
| GET | `/api/security/banned` | IPs bannies toutes jails |
| POST | `/api/security/ban` | Bannir une IP manuellement |
| GET | `/api/security/ssh-audit` | Audit tentatives SSH |
| GET | `/api/security/logins/stats` | Stats connexions 7 jours |
| GET | `/api/update/check` | Vérifier les mises à jour |
| POST | `/api/update/apply` | Appliquer une mise à jour one-click |
| GET | `/api/logs/panel` | Logs du panel (filtres niveau/type) |
| DELETE | `/api/logs/panel` | Vider les logs |
| GET | `/api/logs/alerts` | Alertes brute-force non lues |
| GET | `/api/config/general` | Paramètres généraux |
| PUT | `/api/config/defaults` | Limites par défaut utilisateurs |
| PUT | `/api/config/jwt` | Expiration des sessions |
| GET/PUT | `/api/config/smtp` | Configuration SMTP |
| POST | `/api/config/smtp/test` | Test d'envoi email |
| GET/PUT | `/api/config/backup-schedule` | Planification sauvegardes |
| GET/PUT | `/api/config/network` | Ports FTP passif + IP publique |
| GET/PUT | `/api/config/ntp` | Serveur NTP |
| GET | `/api/config/ssl-status` | Statut certificats Let's Encrypt |
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

**Via le panel (recommandé)** — cliquer sur le bouton 🔔 dans la topbar puis "Lancer la mise à jour". Le panel exécute `git pull`, `npm install` et redémarre automatiquement avec les logs en temps réel.

**Via SSH :**

```bash
cd /opt/kazypanel
git pull origin main
npm install
systemctl restart kazypanel
```

Le panel vérifie automatiquement les nouvelles versions au démarrage et affiche une notification dans la topbar.

---

## 🔧 Dépannage

**Bloqué par le rate limiting ("Trop de tentatives")**
→ Le rate limiting est en mémoire — un redémarrage du service le remet à zéro :
```bash
sudo systemctl restart kazypanel
```

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

**`named-checkconf : command not found` avec sudo**
→ sudo ne trouve pas `/usr/sbin` dans son PATH. KazyPanel résout le chemin dynamiquement — vérifier que `named-checkconf` est bien installé :
```bash
which named-checkconf || find /usr /sbin /bin -name named-checkconf
sudo apt install bind9utils
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

### Alertes brute-force

Le badge 🚨 dans la topbar s'allume si une IP déclenche une alerte. L'alerte est également écrite dans `kazypanel-error.log`.

### Recommandations de production

- Utiliser un **reverse proxy HTTPS** (Apache ou Nginx) devant le port 8080
- Ne jamais exposer le port 8080 publiquement
- Définir une clé `JWT_SECRET` longue et aléatoire dans `.env` :
```bash
JWT_SECRET=$(openssl rand -hex 64)
```
- Activer **Fail2ban** avec le filtre KazyPanel inclus dans `jail.local`
- Configurer le **PTR record** (reverse DNS) sur l'IP du serveur pour la délivrabilité mail

### Filtre Fail2ban pour KazyPanel

Le fichier `/etc/fail2ban/filter.d/kazypanel.conf` est créé automatiquement. Il détecte les échecs de connexion dans `kazypanel.log` et les transmet à Fail2ban pour bannissement IP.

---



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

KazyPanel utilise SMTP natif Node.js avec **STARTTLS sur le port 587** — compatible avec tout serveur SMTP standard :

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

*KazyPanel v1.5.0 — Dernière mise à jour : Mars 2026*

## Changelog

### v1.5.0 — 2026-03-26

#### 🔐 Page login
- ✨ **Fond animé** — grille de points en mouvement + orbe lumineux flottant
- 👁 **Afficher/masquer le mot de passe** — bouton dédié
- 🟢 **Statut serveur** — indicateurs Apache / MariaDB / KazyPanel visibles avant connexion
- ⚠️ **Bannière maintenance** — affichée sans connexion si maintenance activée
- 💾 **Se souvenir de moi** — username mémorisé en localStorage
- ⌨️ **Navigation clavier** — Enter username → focus password → Enter → login
- 🔴 **Animation shake** sur erreur de connexion

#### 📧 Emails
- ✨ **SMTP natif Node.js** — STARTTLS sur port 587, zéro dépendance externe
- 📝 **Template email personnalisable** — sujet + corps avec variables `{{username}}`, `{{password}}`, `{{role}}`, `{{panelUrl}}`, `{{date}}`
- 👁 **Aperçu en temps réel** avec données fictives
- 📧 **Bouton "Template email"** dans Gestion des utilisateurs
- 🌐 **URL publique du panel** configurable (utilisée dans les mails)
- ✉️ **Envoi automatique** à la création d'utilisateur si email fourni

#### 🛡️ Sécurité
- 📊 **Score de sécurité** — 7 vérifications, note /100, grade A/B/C/D
- 🚫 **IPs bloquées** — liste toutes jails Fail2ban, débannir/bannir en 1 clic
- 🔍 **Audit SSH** — analyse `/var/log/auth.log`, top 10 IPs attaquantes
- 📈 **Graphique connexions** — barres OK/FAIL sur 7 jours

#### ⚙️ Configuration
- 📧 **Onglet Emails** — SMTP + limites par défaut + expiration JWT + URL publique
- 💾 **Onglet Sauvegardes** — planification cron avec raccourcis + rétention
- 🌐 **Onglet Réseau** — ports FTP passif + IP publique + certificats SSL + NTP
- 🔑 **Onglet Clés SSH** — ajout/suppression `authorized_keys` par utilisateur

#### 🐛 Corrections
- Fix : suppression utilisateur — `sudo rm -rf` pour les dossiers `/var/www/`
- Fix : sections admin (Sécurité, DNS) visibles pour les utilisateurs
- Fix : `userFilesSection` persistait lors de la navigation
- Fix : IDs dupliqués dans les formulaires (`logLinesSelect`, `genPwBtn`, `profileDiskRow`)
- Fix : BIND9 et UFW sans uptime dans le dashboard Services

#### 🔧 install.sh
- ✨ **Question URL publique** pendant l'installation (pré-remplit `{{panelUrl}}`)
- 📄 **`panel_config.json` initial** créé avec l'URL et phpMyAdmin configurés
- 🔄 **`backup-cron.js`** créé automatiquement si absent après `git clone`
- 🛡️ Jail Fail2ban `[kazypanel]` ajouté automatiquement
- 📋 Logrotate configuré à l'installation
- 📦 Paquet `s-nail` ajouté (SMTP)

### v1.4.0 — 2026-03-25
- ✨ **Explorateur de fichiers utilisateur** — navigation arborescence, vue liste/grille, fil d'Ariane
- ✏️ **Éditeur de fichiers intégré** — édition en ligne avec coloration (PHP, HTML, CSS, JS, JSON, .htaccess…)
- 🔒 **Gestion des permissions** (chmod) — interface visuelle avec cases à cocher
- 🖱️ **Menu contextuel clic droit** — ouvrir, éditer, télécharger, renommer, supprimer, chmod
- ⬆️ **Upload de fichiers** — multi-fichiers avec barre de progression
- 🔄 **Mise à jour one-click** depuis le modal — git pull + npm install + restart avec logs en temps réel
- 🗄️ **BIND9** ajouté au dashboard statut, uptime et contrôle des services
- 📋 **Logs panel améliorés** — format structuré (INFO/WARN/ERROR), fichier d'erreurs séparé, alertes brute-force, modal de consultation avec filtres
- 🔑 **Historique connexions enrichi** — navigateur détecté, IP dans Détails
- 📧 **Configuration SMTP** — relay email avec test d'envoi intégré
- 🔑 **Gestion clés SSH** — ajout/suppression `authorized_keys` par utilisateur
- 💾 **Sauvegardes planifiées** — cron configurable + rétention automatique
- 🌐 **Configuration réseau FTP** — ports passifs et IP publique configurables
- ⏱️ **NTP** — serveur de temps configurable depuis le panel
- 📜 **Statut SSL** — expiration des certificats Let's Encrypt dans Configuration
- ⚙️ **Limites par défaut** — configurables pour les nouveaux utilisateurs
- 🔐 **Expiration JWT** — durée de session configurable (1h à 30j)
- 🐛 Fix : `named-checkconf` / `named-checkzone` — résolution dynamique du chemin
- 🐛 Fix : modal Mise à jour — version lue depuis `version.json` local en priorité
- 🐛 Fix : IDs dupliqués dans les formulaires

### v1.4.0 — 2026-03-23
