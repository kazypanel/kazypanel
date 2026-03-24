#!/bin/bash

# ==================================================================
#  KazyPanel - Publication GitHub (Version Manuelle README)
#  Usage : bash publish.sh
# ==================================================================

# Couleurs
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'
MUTED='\033[0;90m'; NC='\033[0m'

PANEL_DIR="/opt/kazypanel"

# Fonctions d'affichage
step()    { echo -e "\n${CYAN}[*]${NC} ${WHITE}$1${NC}"; }
ok()      { echo -e "  ${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "  ${YELLOW}[!]${NC}  $1"; }
error()   { echo -e "\n  ${RED}[X]${NC} $1\n"; exit 1; }
divider() { echo -e "${MUTED}--------------------------------------------------${NC}"; }

# -- Header --------------------------------------------------------
clear
echo ""
echo -e "${BLUE}+--------------------------------------------------+${NC}"
echo -e "${BLUE}|${WHITE}        🚀  KazyPanel - Publication GitHub        ${BLUE}|${NC}"
echo -e "${BLUE}+--------------------------------------------------+${NC}"
echo ""

# -- Vérifications -------------------------------------------------
step "Vérification de l'environnement..."
command -v git  &>/dev/null || error "Git non installé"
command -v node &>/dev/null || error "Node.js non installé"
[ -d "$PANEL_DIR" ]         || error "Dossier $PANEL_DIR introuvable"
cd "$PANEL_DIR" || error "Impossible d'accéder à $PANEL_DIR"

# Gestion de l'agent SSH (Évite de redemander la passphrase)
if [ -z "$SSH_AUTH_SOCK" ]; then
  step "Activation de l'agent SSH..."
  eval "$(ssh-agent -s)" > /dev/null
  ssh-add ~/.ssh/id_ed25519
fi

# Correction des permissions .git
if [ ! -w ".git/objects" ]; then
  warn "Permissions .git incorrectes - correction..."
  sudo chown -R debian:debian "$PANEL_DIR"
  ok "Permissions corrigées"
fi

ok "Environnement OK"

# -- Identité Git --------------------------------------------------
git config --global user.email "kazylax1981@gmail.com"
git config --global user.name "KazyPanel"

# -- Gestion de la Version -----------------------------------------
echo ""
divider
CURRENT_VERSION=$(grep -oP "KAZYPANEL_VERSION = '\K[^']+" server.js 2>/dev/null || echo "1.0.0")
echo -e "  Version actuelle : ${YELLOW}v${CURRENT_VERSION}${NC}"
echo -e "  Nouvelle version ${MUTED}(Entrée = garder v${CURRENT_VERSION})${NC} :"
read -p "  -> " NEW_VERSION
[ -z "$NEW_VERSION" ] && NEW_VERSION="$CURRENT_VERSION"
echo "$NEW_VERSION" | grep -qP '^\d+\.\d+\.\d+$' || error "Format invalide. Utiliser X.Y.Z"

# -- Saisie du Changelog -------------------------------------------
echo ""
divider
step "Changelog ${MUTED}(0 pour terminer)${NC}"
CHANGELOG_JSON=""
INDEX=0
TYPES=("new" "fix" "security" "break")

while true; do
  echo -e "  ${MUTED}Entrée $((INDEX+1)) - Type :${NC}"
  echo -e "    ${CYAN}1${NC}) ✨ Nouveau  ${CYAN}2${NC}) 🐛 Fix  ${CYAN}3${NC}) 🔒 Sécurité  ${CYAN}4${NC}) ⚠️  Breaking  ${CYAN}0${NC}) Terminer"
  read -p "  -> " TYPE_CHOICE
  [ "$TYPE_CHOICE" = "0" ] || [ -z "$TYPE_CHOICE" ] && break
  [[ "$TYPE_CHOICE" =~ ^[1-4]$ ]] || { warn "Choix invalide"; continue; }
  
  read -p "  -> Description : " ENTRY_TEXT
  [ -z "$ENTRY_TEXT" ] && { warn "Vide, ignoré"; continue; }
  
  ENTRY_TEXT_ESC=$(echo "$ENTRY_TEXT" | sed 's/"/\\"/g')
  [ $INDEX -gt 0 ] && CHANGELOG_JSON="${CHANGELOG_JSON},"
  CHANGELOG_JSON="${CHANGELOG_JSON}{\"type\": \"${TYPES[$((TYPE_CHOICE-1))]}\", \"text\": \"${ENTRY_TEXT_ESC}\"}"
  
  echo -e "  ${GREEN}+${NC} Ajouté : ${ENTRY_TEXT}"
  INDEX=$((INDEX+1))
done

# -- Mise à jour server.js -----------------------------------------
step "Mise à jour server.js..."
TMP_SRV="/tmp/kp_server_$$.js"
node - "$NEW_VERSION" "$TMP_SRV" << 'JSEOF'
const fs   = require('fs');
const ver  = process.argv[2];
const dest = process.argv[3];
const now  = new Date().toLocaleDateString('fr-FR', {
  day:'2-digit', month:'2-digit', year:'numeric',
  hour:'2-digit', minute:'2-digit'
});
const c = fs.readFileSync('server.js', 'utf8')
  .replace(/const KAZYPANEL_VERSION = '[^']+'/, "const KAZYPANEL_VERSION = '" + ver + "'")
  .replace(/(\* Dernière modification : ).*/, "$1" + now);
fs.writeFileSync(dest, c);
JSEOF
sudo cp "$TMP_SRV" server.js && sudo chmod 644 server.js
rm -f "$TMP_SRV"
node --check server.js && ok "server.js mis à jour (v${NEW_VERSION})" || error "Erreur syntaxe server.js"

# -- Mise à jour version.json --------------------------------------
step "Mise à jour version.json..."
RELEASE_DATE=$(date +%Y-%m-%d)
cat > version.json << EOF
{
  "version": "${NEW_VERSION}",
  "releaseDate": "${RELEASE_DATE}",
  "downloadUrl": "https://github.com/kazypanel/kazypanel/archive/refs/heads/main.zip",
  "changelog": [${CHANGELOG_JSON}]
}
EOF
ok "version.json mis à jour"

# -- Publication Git -----------------------------------------------
echo ""
divider
step "Synchronisation GitHub..."

# Pull préventif pour fusionner les changements distants (README inclus)
git pull origin main --no-rebase --no-edit || warn "Synchronisation locale requise (possible conflit)"

# Ajout des fichiers SANS le README.md
git add server.js public/index.html version.json
[ -f "install.sh" ] && git add install.sh

git commit -m "🚀 Release v${NEW_VERSION} (code update)" || warn "Rien à commiter"

# Push vers GitHub
if git push origin main; then
  ok "Push réussi !"
else
  error "Échec du push. Vérifiez manuellement avec 'git status'."
fi

# -- Redémarrage ---------------------------------------------------
step "Redémarrage du service..."
if systemctl is-active --quiet kazypanel; then
    sudo systemctl restart kazypanel && ok "KazyPanel redémarré"
else
    warn "Service kazypanel non détecté, redémarrage ignoré."
fi

# -- Résumé --------------------------------------------------------
echo ""
divider
echo -e "${GREEN}  ✅  v${NEW_VERSION} publiée avec succès (Code uniquement)${NC}"
echo -e "  ${MUTED}N'oubliez pas de mettre à jour votre README manuellement !${NC}"
echo ""
