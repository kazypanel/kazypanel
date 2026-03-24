#!/usr/bin/env bash
# ============================================================
#  KazyPanel — Script d'installation complet
#  Version : 1.3.0
#  OS cible : Ubuntu 20.04 / 22.04 / 24.04 — Debian 11 / 12
#  Auteur   : kazylax.fr
# ============================================================
set -euo pipefail

# ── Couleurs ─────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓${NC}  $*"; }
info() { echo -e "${CYAN}  →${NC}  $*"; }
warn() { echo -e "${YELLOW}  ⚠${NC}  $*"; }
err()  { echo -e "${RED}  ✗${NC}  $*"; exit 1; }
step() { echo -e "\n${BOLD}${BLUE}▶ $*${NC}"; }

# ── Bannière ─────────────────────────────────────────────────
clear
echo -e "${BOLD}${BLUE}"
cat << 'EOF'
  ██╗  ██╗ █████╗ ███████╗██╗   ██╗██████╗  █████╗ ███╗   ██╗███████╗██╗
  ██║ ██╔╝██╔══██╗╚════██║╚██╗ ██╔╝██╔══██╗██╔══██╗████╗  ██║██╔════╝██║
  █████╔╝ ███████║    ██╔╝ ╚████╔╝ ██████╔╝███████║██╔██╗ ██║█████╗  ██║
  ██╔═██╗ ██╔══██║   ██╔╝   ╚██╔╝  ██╔═══╝ ██╔══██║██║╚██╗██║██╔══╝  ██║
  ██║  ██╗██║  ██║   ██║     ██║   ██║     ██║  ██║██║ ╚████║███████╗███████╗
  ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝     ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
EOF
echo -e "${NC}${BOLD}                     Panel d'hébergement — v1.3.0${NC}"
echo -e "${CYAN}                        github.com/kazypanel/kazypanel${NC}\n"
echo -e "  ${YELLOW}Ce script va installer et configurer :${NC}"
echo -e "  Node.js 24, Apache2, PHP 8.4, MariaDB, vsftpd,"
echo -e "  BIND9, Certbot, phpMyAdmin, UFW, Fail2ban et KazyPanel\n"
echo -e "  ${RED}⚠  Exécuter uniquement sur un serveur vierge en root.${NC}\n"

# ── Vérifications préliminaires ──────────────────────────────
step "Vérifications système"

[[ $EUID -ne 0 ]] && err "Ce script doit être exécuté en root (sudo bash install.sh)"

# Détecter l'OS
if [[ -f /etc/os-release ]]; then
  source /etc/os-release
  OS_NAME=$ID
  OS_VERSION=$VERSION_ID
else
  err "Impossible de détecter l'OS"
fi

[[ "$OS_NAME" =~ ^(ubuntu|debian)$ ]] || err "OS non supporté : $OS_NAME. Utilisez Ubuntu ou Debian."
ok "OS : $PRETTY_NAME"

# Vérifier l'architecture
ARCH=$(uname -m)
[[ "$ARCH" == "x86_64" ]] || warn "Architecture $ARCH détectée — le script est optimisé pour x86_64"
ok "Architecture : $ARCH"

# Vérifier la RAM (minimum 512 Mo recommandé)
RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
if [[ $RAM_MB -lt 512 ]]; then
  warn "RAM faible : ${RAM_MB} Mo détectés (512 Mo minimum recommandé)"
else
  ok "RAM : ${RAM_MB} Mo"
fi

# Vérifier la connexion internet
if ! ping -c1 -W3 8.8.8.8 &>/dev/null; then
  err "Pas de connexion internet détectée"
fi
ok "Connexion internet : OK"

# ── Collecte des paramètres ──────────────────────────────────
step "Configuration de l'installation"

echo ""
# Port du panel
read -rp "  $(echo -e "${CYAN}Port du panel${NC} [8080] : ")" PANEL_PORT
PANEL_PORT=${PANEL_PORT:-8080}

# Mot de passe admin
while true; do
  read -rsp "  $(echo -e "${CYAN}Mot de passe admin${NC} (min 5 car., maj+min+chiffre+spécial) : ")" ADMIN_PASSWORD
  echo ""
  if [[ ${#ADMIN_PASSWORD} -ge 5 ]] && \
     [[ "$ADMIN_PASSWORD" =~ [A-Z] ]] && \
     [[ "$ADMIN_PASSWORD" =~ [a-z] ]] && \
     [[ "$ADMIN_PASSWORD" =~ [0-9] ]] && \
     [[ "$ADMIN_PASSWORD" =~ [^a-zA-Z0-9] ]]; then
    break
  fi
  warn "Mot de passe trop faible. Réessayez."
done

# Mot de passe MariaDB root
read -rsp "  $(echo -e "${CYAN}Mot de passe root MariaDB${NC} (laisser vide = sans mot de passe) : ")" DB_ROOT_PASS
echo ""

# Version PHP
read -rp "  $(echo -e "${CYAN}Version PHP${NC} [8.4] : ")" PHP_VERSION
PHP_VERSION=${PHP_VERSION:-8.4}

# phpMyAdmin URL
read -rp "  $(echo -e "${CYAN}URL phpMyAdmin${NC} (optionnel, ex: https://pma.mondomaine.fr) : ")" PMA_URL
PMA_URL=${PMA_URL:-""}

# Répertoire d'installation fixe
INSTALL_DIR="/opt/kazypanel"

# Générer une clé JWT aléatoire
JWT_SECRET=$(openssl rand -hex 64)

echo ""
echo -e "  ${BOLD}Récapitulatif :${NC}"
echo -e "  • Port panel      : ${CYAN}${PANEL_PORT}${NC}"
echo -e "  • Version PHP     : ${CYAN}${PHP_VERSION}${NC}"
echo -e "  • Répertoire      : ${CYAN}${INSTALL_DIR}${NC}"
[[ -n "$PMA_URL" ]] && echo -e "  • phpMyAdmin URL  : ${CYAN}${PMA_URL}${NC}"
echo ""
read -rp "  Continuer l'installation ? [O/n] : " CONFIRM
[[ "${CONFIRM,,}" == "n" ]] && { echo "Installation annulée."; exit 0; }

# ── Début de l'installation ──────────────────────────────────
LOGFILE="/var/log/kazypanel-install.log"
exec > >(tee -a "$LOGFILE") 2>&1
info "Logs disponibles dans $LOGFILE"

# ── Mise à jour système ──────────────────────────────────────
step "Mise à jour du système"
apt-get update -qq
apt-get upgrade -y -qq
ok "Système mis à jour"

# ── Paquets de base ──────────────────────────────────────────
step "Installation des paquets de base"
apt-get install -y -qq \
  curl wget gnupg2 ca-certificates lsb-release \
  software-properties-common apt-transport-https \
  git unzip tar openssl ufw fail2ban \
  net-tools dnsutils htop
ok "Paquets de base installés"

# ── Node.js 24 ───────────────────────────────────────────────
step "Installation de Node.js 24"
if ! command -v node &>/dev/null || [[ $(node -v | cut -d. -f1 | tr -d 'v') -lt 24 ]]; then
  curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
  apt-get install -y -qq nodejs
  ok "Node.js $(node -v) installé"
else
  ok "Node.js $(node -v) déjà présent"
fi

# ── Apache2 ──────────────────────────────────────────────────
step "Installation d'Apache2"
apt-get install -y -qq apache2
a2enmod rewrite ssl proxy proxy_http proxy_fcgi headers setenvif
systemctl enable apache2
systemctl start apache2
ok "Apache2 $(apache2 -v 2>&1 | head -1 | awk '{print $3}') installé et démarré"

# ── PHP ──────────────────────────────────────────────────────
step "Installation de PHP ${PHP_VERSION}-FPM"

# Ajouter le dépôt ondrej/php si nécessaire
if ! apt-cache show "php${PHP_VERSION}-fpm" &>/dev/null; then
  info "Ajout du dépôt ondrej/php..."
  add-apt-repository -y ppa:ondrej/php 2>/dev/null || {
    curl -fsSL https://packages.sury.org/php/apt.gpg | gpg --dearmor -o /etc/apt/trusted.gpg.d/php.gpg
    echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/php.list
  }
  apt-get update -qq
fi

apt-get install -y -qq \
  "php${PHP_VERSION}-fpm" \
  "php${PHP_VERSION}-cli" \
  "php${PHP_VERSION}-mysql" \
  "php${PHP_VERSION}-curl" \
  "php${PHP_VERSION}-gd" \
  "php${PHP_VERSION}-mbstring" \
  "php${PHP_VERSION}-xml" \
  "php${PHP_VERSION}-zip" \
  "php${PHP_VERSION}-intl" \
  "php${PHP_VERSION}-bcmath" \
  "php${PHP_VERSION}-opcache"

a2enmod "proxy_fcgi" setenvif
a2enconf "php${PHP_VERSION}-fpm"
systemctl enable "php${PHP_VERSION}-fpm"
systemctl start "php${PHP_VERSION}-fpm"
ok "PHP ${PHP_VERSION}-FPM installé et démarré"

# ── MariaDB ──────────────────────────────────────────────────
step "Installation de MariaDB"
apt-get install -y -qq mariadb-server mariadb-client
systemctl enable mariadb
systemctl start mariadb

# Sécurisation MariaDB
info "Sécurisation MariaDB..."
if [[ -n "$DB_ROOT_PASS" ]]; then
  mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASS}';" 2>/dev/null || \
  mysqladmin -u root password "${DB_ROOT_PASS}" 2>/dev/null || true
  MYSQL_CMD="mysql -uroot -p${DB_ROOT_PASS}"
else
  MYSQL_CMD="mysql -uroot"
fi
$MYSQL_CMD -e "DELETE FROM mysql.user WHERE User='';" 2>/dev/null || true
$MYSQL_CMD -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" 2>/dev/null || true
$MYSQL_CMD -e "DROP DATABASE IF EXISTS test;" 2>/dev/null || true
$MYSQL_CMD -e "FLUSH PRIVILEGES;" 2>/dev/null || true
ok "MariaDB $(mariadbd --version 2>&1 | awk '{print $5}' | tr -d ',') installé et sécurisé"

# ── vsftpd ───────────────────────────────────────────────────
step "Installation et configuration de vsftpd"
apt-get install -y -qq vsftpd

# Sauvegarder la config originale
cp /etc/vsftpd.conf /etc/vsftpd.conf.bak

# Créer le fichier userlist
touch /etc/vsftpd.userlist
chmod 644 /etc/vsftpd.userlist

# Détecter l'IP publique du serveur
SERVER_PUBLIC_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null \
  || curl -s --max-time 5 https://ifconfig.me 2>/dev/null \
  || hostname -I | awk '{print $1}')

cat > /etc/vsftpd.conf << VSFTPD
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
xferlog_file=/var/log/vsftpd.log
xferlog_std_format=YES
idle_session_timeout=600
data_connection_timeout=120
ftpd_banner=KazyPanel FTP Server
chroot_local_user=YES
allow_writeable_chroot=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
ssl_enable=NO
userlist_enable=YES
userlist_file=/etc/vsftpd.userlist
userlist_deny=NO
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=50000
pasv_address=${SERVER_PUBLIC_IP}
check_shell=NO
vsftpd_log_file=/var/log/vsftpd.log
log_ftp_protocol=YES
VSFTPD

systemctl enable vsftpd
systemctl restart vsftpd
ok "vsftpd installé et configuré (IP: ${SERVER_PUBLIC_IP})"

# ── BIND9 ────────────────────────────────────────────────────
step "Installation de BIND9 (DNS)"
apt-get install -y -qq bind9 bind9utils bind9-doc dnsutils

# Créer le répertoire des zones
mkdir -p /etc/bind/zones
chown -R bind:bind /etc/bind/zones

# Activer BIND9
systemctl enable named 2>/dev/null || systemctl enable bind9
systemctl start named 2>/dev/null || systemctl start bind9
ok "BIND9 installé et démarré"

# ── Certbot ──────────────────────────────────────────────────
step "Installation de Certbot (Let's Encrypt)"
apt-get install -y -qq certbot python3-certbot-apache
ok "Certbot installé"

# ── SSL vsftpd (FTP explicite / FTPES) ───────────────────────
step "Configuration SSL pour vsftpd (FTP explicite)"

FTP_CERT=""
FTP_KEY=""

# Chercher un certificat Let's Encrypt existant
LETSENCRYPT_LIVE="/etc/letsencrypt/live"
if [ -d "$LETSENCRYPT_LIVE" ]; then
  FIRST_CERT=$(ls "$LETSENCRYPT_LIVE" 2>/dev/null | head -1)
  if [ -n "$FIRST_CERT" ]; then
    FTP_CERT="$LETSENCRYPT_LIVE/$FIRST_CERT/fullchain.pem"
    FTP_KEY="$LETSENCRYPT_LIVE/$FIRST_CERT/privkey.pem"
    info "Certificat Let's Encrypt trouvé : $FIRST_CERT"
  fi
fi

# Sinon générer un certificat auto-signé
if [ -z "$FTP_CERT" ] || [ ! -f "$FTP_CERT" ]; then
  info "Génération d'un certificat auto-signé pour vsftpd..."
  mkdir -p /etc/ssl/kazypanel
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/ssl/kazypanel/vsftpd.key \
    -out /etc/ssl/kazypanel/vsftpd.crt \
    -subj "/C=FR/ST=France/L=Paris/O=KazyPanel/CN=${SERVER_PUBLIC_IP}" \
    2>/dev/null
  chmod 600 /etc/ssl/kazypanel/vsftpd.key
  chmod 644 /etc/ssl/kazypanel/vsftpd.crt
  FTP_CERT="/etc/ssl/kazypanel/vsftpd.crt"
  FTP_KEY="/etc/ssl/kazypanel/vsftpd.key"
  warn "Certificat auto-signé généré — remplacez-le par un certificat Let's Encrypt après installation"
fi

# Mettre à jour vsftpd.conf avec SSL
cat >> /etc/vsftpd.conf << VSFTPDSSL

# ── SSL / FTP Explicite (FTPES) ──────────────────────────────
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=NO
force_local_logins_ssl=NO
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
rsa_cert_file=${FTP_CERT}
rsa_private_key_file=${FTP_KEY}
VSFTPDSSL

# Retirer l'ancienne ligne ssl_enable=NO
sed -i '/^ssl_enable=NO$/d' /etc/vsftpd.conf

systemctl restart vsftpd
ok "vsftpd SSL configuré — FTP explicite (FTPES) actif"
info "Certificat : $FTP_CERT"
info "Pour utiliser un certificat Let's Encrypt : editez /etc/vsftpd.conf et remplacez rsa_cert_file/rsa_private_key_file"

# ── phpMyAdmin ───────────────────────────────────────────────
step "Installation de phpMyAdmin"

# Installer les dépendances
apt-get install -y -qq php-mbstring php-xml php-zip php-json php-curl dbconfig-no-thanks

# Télécharger phpMyAdmin (dernière version stable)
PMA_DIR="/var/www/html/phpmyadmin"
PMA_ARCHIVE="/tmp/phpmyadmin.tar.gz"

info "Récupération de la dernière version de phpMyAdmin..."
PMA_VERSION=$(curl -s https://www.phpmyadmin.net/home_page/version.txt 2>/dev/null | head -1 | tr -d '[:space:]')
if [[ -z "$PMA_VERSION" ]]; then
  warn "Impossible de récupérer la dernière version — utilisation de la version de secours 5.2.2"
  PMA_VERSION="5.2.2"
fi
info "Version phpMyAdmin : ${PMA_VERSION}"

wget -q "https://files.phpmyadmin.net/phpMyAdmin/${PMA_VERSION}/phpMyAdmin-${PMA_VERSION}-all-languages.tar.gz" \
  -O "$PMA_ARCHIVE" || {
  warn "Téléchargement phpMyAdmin échoué — installation via apt..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq phpmyadmin
  PMA_APT=true
}

if [[ -z "${PMA_APT:-}" ]]; then
  mkdir -p "$PMA_DIR"
  tar -xzf "$PMA_ARCHIVE" -C /tmp
  cp -r /tmp/phpMyAdmin-${PMA_VERSION}-all-languages/. "$PMA_DIR/"
  rm -rf "$PMA_ARCHIVE" "/tmp/phpMyAdmin-${PMA_VERSION}-all-languages"
  chown -R www-data:www-data "$PMA_DIR"

  # Configuration phpMyAdmin
  cp "$PMA_DIR/config.sample.inc.php" "$PMA_DIR/config.inc.php"
  PMA_SECRET=$(openssl rand -base64 32)
  sed -i "s|\$cfg\['blowfish_secret'\] = ''|\$cfg['blowfish_secret'] = '${PMA_SECRET}'|" \
    "$PMA_DIR/config.inc.php"

  # Dossier temporaire
  mkdir -p "$PMA_DIR/tmp"
  chmod 777 "$PMA_DIR/tmp"
fi

# Créer le vhost Apache pour phpMyAdmin
PMA_VHOST_URL=""
if [[ -n "$PMA_URL" ]]; then
  # Extraire le hostname de l'URL fournie
  PMA_HOST=$(echo "$PMA_URL" | sed 's|https\?://||' | sed 's|/.*||')
  cat > /etc/apache2/sites-available/phpmyadmin.conf << PMACONF
<VirtualHost *:80>
    ServerName ${PMA_HOST}
    DocumentRoot ${PMA_DIR}
    ErrorLog \${APACHE_LOG_DIR}/phpmyadmin-error.log
    CustomLog \${APACHE_LOG_DIR}/phpmyadmin-access.log combined
    <Directory ${PMA_DIR}>
        Options SymLinksIfOwnerMatch
        DirectoryIndex index.php
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
PMACONF
  a2ensite phpmyadmin.conf
  PMA_VHOST_URL="http://${PMA_HOST}"
else
  # Accessible via /pma sur le serveur
  cat > /etc/apache2/conf-available/phpmyadmin.conf << PMACONF
Alias /pma ${PMA_DIR}
<Directory ${PMA_DIR}>
    Options SymLinksIfOwnerMatch
    DirectoryIndex index.php
    AllowOverride All
    Require all granted
    <IfModule mod_php.c>
        php_admin_value upload_tmp_dir /tmp
        php_admin_value open_basedir ${PMA_DIR}:/tmp
    </IfModule>
</Directory>
PMACONF
  a2enconf phpmyadmin.conf
  PMA_VHOST_URL="http://${SERVER_PUBLIC_IP}/pma"
  # Mettre à jour .env avec l'URL auto-détectée si non fournie
  PMA_URL="$PMA_VHOST_URL"
fi

systemctl reload apache2
ok "phpMyAdmin installé → ${PMA_VHOST_URL}"

# ── UFW ──────────────────────────────────────────────────────
step "Configuration UFW"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow "${PANEL_PORT}/tcp"
ufw allow 21/tcp
ufw allow 40000:50000/tcp   # FTP passif
ufw allow 53/tcp                 # DNS TCP
ufw allow 53/udp                 # DNS UDP
echo "y" | ufw enable
ok "UFW configuré et activé"

# ── Fail2ban ─────────────────────────────────────────────────
step "Configuration Fail2ban"
cat > /etc/fail2ban/jail.local << 'F2B'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
backend  = systemd

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s

[apache-auth]
enabled  = true
port     = http,https
logpath  = %(apache_error_log)s

[vsftpd]
enabled  = true
port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(vsftpd_log)s
maxretry = 3
F2B

systemctl enable fail2ban
systemctl restart fail2ban
ok "Fail2ban configuré et démarré"

# ── Répertoires web ──────────────────────────────────────────
step "Création des répertoires"
mkdir -p /var/www/admin
mkdir -p /var/www/html
chown -R www-data:www-data /var/www/html
ok "Répertoires créés"

# ── Installation de KazyPanel ────────────────────────────────
step "Installation de KazyPanel"

if [[ -d "$INSTALL_DIR" ]]; then
  warn "Le répertoire $INSTALL_DIR existe déjà"
  read -rp "  Écraser ? [o/N] : " OVERWRITE
  if [[ "${OVERWRITE,,}" == "o" ]]; then
    rm -rf "$INSTALL_DIR"
  else
    err "Installation annulée"
  fi
fi

# Cloner le dépôt
info "Clonage du dépôt GitHub..."
git clone https://github.com/kazypanel/kazypanel.git "$INSTALL_DIR" || {
  warn "Clonage GitHub échoué — création du répertoire manuellement"
  mkdir -p "$INSTALL_DIR"
}

cd "$INSTALL_DIR"

# Créer le dossier public si absent
mkdir -p public

# Installer les dépendances Node
info "Installation des dépendances Node.js..."
npm install --production --silent
ok "Dépendances installées"

# ── Fichier .env ─────────────────────────────────────────────
step "Création du fichier de configuration .env"
cat > "$INSTALL_DIR/.env" << ENV
# ── KazyPanel Configuration ──────────────────────────────────
PORT=${PANEL_PORT}

# Sécurité JWT (NE PAS MODIFIER après le premier démarrage)
JWT_SECRET=${JWT_SECRET}

# Compte administrateur
ADMIN_PASSWORD=${ADMIN_PASSWORD}

# Base de données MariaDB
DB_ROOT_PASS=${DB_ROOT_PASS}

# Version PHP
PHP_VERSION=${PHP_VERSION}

# phpMyAdmin (optionnel)
PMA_URL=${PMA_URL}
ENV

chmod 600 "$INSTALL_DIR/.env"
ok "Fichier .env créé (chmod 600)"

# ── Fichier .env.example ─────────────────────────────────────
cat > "$INSTALL_DIR/.env.example" << 'ENVEX'
PORT=8080
JWT_SECRET=changez_cette_valeur_en_production
ADMIN_PASSWORD=Admin@1234!
DB_ROOT_PASS=
PHP_VERSION=8.4
PMA_URL=
ENVEX

# ── Détection de l'utilisateur sudo ─────────────────────────
step "Détection de l'utilisateur de service"

SERVICE_USER="root"

# Chercher un utilisateur non-root avec sudo ALL=(ALL) ou sudo ALL
SUDO_USER_FOUND=""

# Méthode 1 : chercher dans /etc/sudoers et /etc/sudoers.d/
while IFS= read -r line; do
  # Ignorer commentaires et lignes vides
  [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
  # Détecter les lignes du type : username ALL=(ALL:ALL) ALL ou username ALL=(ALL) ALL
  if echo "$line" | grep -qP '^[a-z_][a-z0-9_-]*\s+ALL=\(ALL'; then
    CANDIDATE=$(echo "$line" | awk '{print $1}')
    # Vérifier que c'est bien un utilisateur existant et non root
    if id "$CANDIDATE" &>/dev/null && [ "$CANDIDATE" != "root" ]; then
      SUDO_USER_FOUND="$CANDIDATE"
      break
    fi
  fi
done < <(grep -rh '' /etc/sudoers /etc/sudoers.d/ 2>/dev/null)

# Méthode 2 : chercher dans le groupe sudo
if [ -z "$SUDO_USER_FOUND" ]; then
  while IFS= read -r u; do
    [ "$u" != "root" ] && id "$u" &>/dev/null && { SUDO_USER_FOUND="$u"; break; }
  done < <(getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n')
fi

# Méthode 3 : chercher dans le groupe wheel (CentOS/Fedora)
if [ -z "$SUDO_USER_FOUND" ]; then
  while IFS= read -r u; do
    [ "$u" != "root" ] && id "$u" &>/dev/null && { SUDO_USER_FOUND="$u"; break; }
  done < <(getent group wheel 2>/dev/null | cut -d: -f4 | tr ',' '\n')
fi

if [ -n "$SUDO_USER_FOUND" ]; then
  SERVICE_USER="$SUDO_USER_FOUND"
  ok "Utilisateur de service détecté : ${CYAN}${SERVICE_USER}${NC}"
else
  warn "Aucun utilisateur sudo trouvé — service lancé en root (déconseillé)"
  SERVICE_USER="root"
fi

# ── Créer le fichier sudoers pour KazyPanel ───────────────────
if [ "$SERVICE_USER" != "root" ]; then
  info "Création du fichier sudoers pour $SERVICE_USER..."
  cat > /etc/sudoers.d/kazypanel << SUDOERS
# KazyPanel — permissions sudo pour $SERVICE_USER
$SERVICE_USER ALL=(root) NOPASSWD: \\
    /usr/sbin/a2ensite, \\
    /usr/sbin/a2dissite, \\
    /usr/sbin/a2enmod, \\
    /usr/bin/systemctl, \\
    /usr/sbin/useradd, \\
    /usr/sbin/userdel, \\
    /usr/sbin/usermod, \\
    /usr/sbin/chpasswd, \\
    /bin/chown, \\
    /usr/bin/chown, \\
    /bin/chmod, \\
    /usr/bin/chmod, \\
    /bin/mkdir, \\
    /usr/bin/mkdir, \\
    /bin/cp, \\
    /usr/bin/cp, \\
    /bin/rm, \\
    /usr/bin/rm, \\
    /usr/sbin/rndc, \\
    /usr/sbin/named-checkzone, \\
    /usr/sbin/named-checkconf, \\
    /usr/bin/certbot, \\
    /usr/sbin/ufw, \\
    /usr/bin/fail2ban-client, \\
    /usr/sbin/sshd, \\
    /usr/bin/hostnamectl, \\
    /usr/bin/timedatectl, \\
    /usr/bin/du, \\
    /usr/bin/crontab, \\
    /bin/tar, \\
    /usr/bin/tar, \\
    /usr/sbin/apache2ctl, \\
    /usr/sbin/apachectl, \\
    /bin/bash, \\
    /usr/bin/passwd
SUDOERS
  chmod 440 /etc/sudoers.d/kazypanel
  # Valider la syntaxe sudoers
  if visudo -c -f /etc/sudoers.d/kazypanel &>/dev/null; then
    ok "Fichier sudoers créé pour $SERVICE_USER"
  else
    warn "Erreur dans le fichier sudoers — retour sur root"
    rm -f /etc/sudoers.d/kazypanel
    SERVICE_USER="root"
  fi
fi

# ── Service systemd ──────────────────────────────────────────
step "Création du service systemd"
cat > /etc/systemd/system/kazypanel.service << SERVICE
[Unit]
Description=KazyPanel — Panel d'hébergement
Documentation=https://github.com/kazypanel/kazypanel
After=network.target mariadb.service apache2.service
Wants=mariadb.service apache2.service

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/node ${INSTALL_DIR}/server.js
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
EnvironmentFile=${INSTALL_DIR}/.env

# Limites système
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable kazypanel
systemctl start kazypanel
sleep 2

# Vérifier que le service tourne
if systemctl is-active --quiet kazypanel; then
  ok "Service KazyPanel démarré"
else
  warn "Le service KazyPanel n'a pas démarré — vérifiez les logs : journalctl -u kazypanel -f"
fi

# ── Configuration Apache par défaut ─────────────────────────
step "Configuration Apache"

# Désactiver le vhost par défaut
a2dissite 000-default.conf 2>/dev/null || true

# Vhost par défaut minimal
cat > /etc/apache2/sites-available/kazypanel-default.conf << 'APACHECONF'
<VirtualHost *:80>
    ServerName localhost
    DocumentRoot /var/www/html
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
APACHECONF

a2ensite kazypanel-default.conf
systemctl reload apache2
ok "Apache configuré"

# ── Permissions finales ──────────────────────────────────────
step "Ajustement des permissions"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR"
chmod 600 "$INSTALL_DIR/.env"
ok "Permissions configurées pour $SERVICE_USER"

# ── Résumé de l'installation ─────────────────────────────────
SERVER_IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║         ✅  Installation terminée avec succès !       ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}  📋 Informations de connexion :${NC}"
echo -e "  ┌─────────────────────────────────────────────────┐"
echo -e "  │  🔗 URL        : ${CYAN}http://${SERVER_IP}:${PANEL_PORT}${NC}"
echo -e "  │  👤 Login      : ${CYAN}admin${NC}"
echo -e "  │  🔑 Mot passe  : ${CYAN}${ADMIN_PASSWORD}${NC}"
echo -e "  │  👤 Service    : ${CYAN}${SERVICE_USER}${NC}"
echo -e "  └─────────────────────────────────────────────────┘"
echo ""
echo -e "${BOLD}  🛠  Services installés :${NC}"
echo -e "  ✓ Node.js    $(node -v)"
echo -e "  ✓ Apache2    $(apache2 -v 2>&1 | head -1 | awk '{print $3}')"
echo -e "  ✓ PHP        ${PHP_VERSION}-FPM"
echo -e "  ✓ MariaDB    $(mysql --version | awk '{print $5}' | tr -d ',')"
echo -e "  ✓ vsftpd     $(vsftpd -v 2>&1 | awk '{print $NF}')"
echo -e "  ✓ BIND9      $(named -v 2>&1 | awk '{print $3}')"
echo -e "  ✓ Certbot    $(certbot --version 2>&1 | awk '{print $2}')"
echo -e "  ✓ phpMyAdmin ${PMA_VERSION:-installé} → ${PMA_VHOST_URL:-/phpmyadmin}"
echo -e "  ✓ UFW        actif"
echo -e "  ✓ Fail2ban   actif"
echo ""
echo -e "${BOLD}  📁 Fichiers importants :${NC}"
echo -e "  • Répertoire  : ${CYAN}${INSTALL_DIR}${NC}"
echo -e "  • Config      : ${CYAN}${INSTALL_DIR}/.env${NC}"
echo -e "  • Logs panel  : ${CYAN}journalctl -u kazypanel -f${NC}"
echo -e "  • Logs install: ${CYAN}${LOGFILE}${NC}"
echo ""
echo -e "${BOLD}  🔧 Commandes utiles :${NC}"
echo -e "  systemctl status kazypanel"
echo -e "  systemctl restart kazypanel"
echo -e "  journalctl -u kazypanel -f"
echo ""
echo -e "${YELLOW}  ⚠  Pensez à sécuriser votre accès (reverse proxy HTTPS recommandé)${NC}"
echo -e "${YELLOW}  ⚠  Conservez le fichier .env en lieu sûr${NC}"
echo ""
