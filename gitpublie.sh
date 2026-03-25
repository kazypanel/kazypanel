#!/bin/bash

# ══════════════════════════════════════════════════════════════════
#  KazyPanel — Publication GitHub (Version SSH Optimisée)
#  Usage : bash publish.sh
# ══════════════════════════════════════════════════════════════════

# Couleurs
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'
MUTED='\033[0;90m'; NC='\033[0m'

PANEL_DIR="/opt/kazypanel"

# Fonctions d'affichage
step()    { echo -e "\n${CYAN}▶${NC} ${WHITE}$1${NC}"; }
ok()      { echo -e "  ${GREEN}✓${NC} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $1"; }
error()   { echo -e "\n  ${RED}✗${NC} $1\n"; exit 1; }
divider() { echo -e "${MUTED}──────────────────────────────────────────────────${NC}"; }

# ── Header ────────────────────────────────────────────────────────
clear
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${WHITE}        🚀  KazyPanel — Publication GitHub        ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ── Vérifications ─────────────────────────────────────────────────
step "Vérification de l'environnement..."
command -v git  &>/dev/null || error "Git non installé"
command -v node &>/dev/null || error "Node.js non installé"
command -v python3 &>/dev/null || error "Python3 non installé (requis pour le README)"
[ -d "$PANEL_DIR" ]         || error "Dossier $PANEL_DIR introuvable"
cd "$PANEL_DIR" || error "Impossible d'accéder à $PANEL_DIR"

[ -d ".git" ]                         || error "Dépôt Git non initialisé"
[ -f "server.js" ]                    || error "server.js introuvable"
[ -f "public/index.html" ]            || error "public/index.html introuvable"
git remote get-url origin &>/dev/null || error "Remote 'origin' non configuré"

# Gestion de l'agent SSH (pour ne pas bloquer sur la passphrase)
if [ -z "$SSH_AUTH_SOCK" ]; then
  step "Activation de l'agent SSH..."
  eval "$(ssh-agent -s)" > /dev/null
  ssh-add ~/.ssh/id_ed25519
fi

# Correction des permissions si nécessaire
if [ ! -w ".git/objects" ]; then
  warn "Permissions .git incorrectes — correction..."
  sudo chown -R debian:debian "$PANEL_DIR"
  ok "Permissions corrigées"
fi

ok "Environnement OK"

# ── Identité Git ──────────────────────────────────────────────────
git config --global user.email "kazylax1981@gmail.com"
git config --global user.name "KazyPanel"

# ── Gestion de la Version ─────────────────────────────────────────
echo ""
divider
CURRENT_VERSION=$(grep -oP "KAZYPANEL_VERSION = '\K[^']+" server.js 2>/dev/null || echo "1.0.0")
echo -e "  Version actuelle : ${YELLOW}v${CURRENT_VERSION}${NC}"
echo -e "  Nouvelle version ${MUTED}(Entrée = garder v${CURRENT_VERSION})${NC} :"
read -p "  → " NEW_VERSION
[ -z "$NEW_VERSION" ] && NEW_VERSION="$CURRENT_VERSION"
echo "$NEW_VERSION" | grep -qP '^\d+\.\d+\.\d+$' || error "Format invalide. Utiliser X.Y.Z"

# ── Saisie du Changelog ───────────────────────────────────────────
echo ""
divider
step "Changelog ${MUTED}(0 pour terminer)${NC}"
CHANGELOG_JSON=""
INDEX=0
TYPES=("new" "fix" "security" "break")
TYPE_LABELS=("✨ Nouveau" "🐛 Fix" "🔒 Sécurité" "⚠️  Breaking")

while true; do
  echo -e "  ${MUTED}Entrée $((INDEX+1)) — Type :${NC}"
  echo -e "    ${CYAN}1${NC}) ✨ Nouveau  ${CYAN}2${NC}) 🐛 Fix  ${CYAN}3${NC}) 🔒 Sécurité  ${CYAN}4${NC}) ⚠️  Breaking  ${CYAN}0${NC}) Terminer"
  read -p "  → " TYPE_CHOICE
  [ "$TYPE_CHOICE" = "0" ] || [ -z "$TYPE_CHOICE" ] && break
  [[ "$TYPE_CHOICE" =~ ^[1-4]$ ]] || { warn "Choix invalide"; continue; }
  
  read -p "  → Description : " ENTRY_TEXT
  [ -z "$ENTRY_TEXT" ] && { warn "Vide, ignoré"; continue; }
  
  ENTRY_TEXT_ESC=$(echo "$ENTRY_TEXT" | sed 's/"/\\"/g')
  [ $INDEX -gt 0 ] && CHANGELOG_JSON="${CHANGELOG_JSON},"
  CHANGELOG_JSON="${CHANGELOG_JSON}{\"type\": \"${TYPES[$((TYPE_CHOICE-1))]}\", \"text\": \"${ENTRY_TEXT_ESC}\"}"
  
  echo -e "  ${GREEN}+${NC} Ajouté : ${ENTRY_TEXT}"
  INDEX=$((INDEX+1))
done

# ── Mise à jour server.js ─────────────────────────────────────────
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

# ── Mise à jour version.json ──────────────────────────────────────
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

# ── Mise à jour README.md ─────────────────────────────────────────
step "Mise à jour README.md..."
if [ -f "README.md" ]; then
  # Mise à jour du badge de version
  sed -i "s|badge/version-[0-9.]*-blue|badge/version-${NEW_VERSION}-blue|g" README.md
  
  # Script Python pour gérer intelligemment la section Changelog
  python3 - "$NEW_VERSION" "$RELEASE_DATE" << 'MDEOF'
import sys, re, json
ver, date = sys.argv[1], sys.argv[2]
try:
    with open('version.json') as f: entries = json.load(f).get('changelog', [])
except: entries = []

labels = {'new':'✨ Nouveau','fix':'🐛 Fix','security':'🔒 Sécurité','break':'⚠️  Breaking'}
new_entry = f"### v{ver} — {date}\n"
for e in entries:
    new_entry += f"- {labels.get(e.get('type',''),'•')} — {e.get('text','')}\n"

with open('README.md', 'r') as f: content = f.read()

# On insère la nouvelle version juste après le titre ## Changelog
if "## Changelog" in content:
    pattern = r"(## Changelog\n\n)"
    content = re.sub(pattern, r"\1" + new_entry + "\n", content)
else:
    content += "\n## Changelog\n\n" + new_entry

with open('README.md', 'w') as f: f.write(content)
MDEOF
  ok "README.md mis à jour"
fi

# ── Publication Git ───────────────────────────────────────────────
echo ""
divider
step "Synchronisation GitHub..."
git add server.js public/index.html version.json README.md
[ -f "install.sh" ] && git add install.sh

git commit -m "🚀 Release v${NEW_VERSION}" || warn "Rien à commiter"

# Push (Utilise la clé SSH configurée plus haut)
if git push origin main; then
  ok "Push réussi !"
else
  error "Échec du push. Vérifiez votre connexion SSH."
fi

# ── Redémarrage ───────────────────────────────────────────────────
step "Redémarrage du service..."
sudo systemctl restart kazypanel && ok "KazyPanel redémarré"

# ── Résumé ────────────────────────────────────────────────────────
echo ""
divider
echo -e "${GREEN}  ✅  Publication de la v${NEW_VERSION} réussie !${NC}"
echo ""
