#!/bin/bash

# ══════════════════════════════════════════════════════════════════
#  KazyPanel — Publication GitHub
#  Usage : bash publish.sh
# ══════════════════════════════════════════════════════════════════

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'
MUTED='\033[0;90m'; NC='\033[0m'

PANEL_DIR="/opt/kazypanel"

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
[ -d "$PANEL_DIR" ]         || error "Dossier $PANEL_DIR introuvable"
cd "$PANEL_DIR"
[ -d ".git" ]                         || error "Dépôt Git non initialisé"
[ -f "server.js" ]                    || error "server.js introuvable"
[ -f "public/index.html" ]            || error "public/index.html introuvable"
git remote get-url origin &>/dev/null || error "Remote 'origin' non configuré"

# Corriger les permissions .git si nécessaire
if [ ! -w ".git/objects" ]; then
  warn "Permissions .git incorrectes — correction..."
  sudo chown -R debian:debian "$PANEL_DIR/.git"
  sudo chown -R debian:debian "$PANEL_DIR"
  ok "Permissions corrigées"
fi

ok "Environnement OK"

# ── Git identity ──────────────────────────────────────────────────
git config --global user.email "kazylax1981@gmail.com"
git config --global user.name "KazyPanel"

# ── Version ───────────────────────────────────────────────────────
echo ""
divider
CURRENT_VERSION=$(grep -oP "KAZYPANEL_VERSION = '\K[^']+" server.js 2>/dev/null || echo "1.0.0")
echo ""
echo -e "  Version actuelle : ${YELLOW}v${CURRENT_VERSION}${NC}"
echo -e "  Nouvelle version ${MUTED}(Entrée = garder v${CURRENT_VERSION})${NC} :"
read -p "  → " NEW_VERSION
[ -z "$NEW_VERSION" ] && NEW_VERSION="$CURRENT_VERSION"
echo "$NEW_VERSION" | grep -qP '^\d+\.\d+\.\d+$' || error "Format invalide. Utiliser X.Y.Z"

# ── Changelog ─────────────────────────────────────────────────────
echo ""
divider
echo ""
step "Changelog ${MUTED}(0 pour terminer)${NC}"
echo ""
CHANGELOG_JSON=""
INDEX=0
TYPES=("new" "fix" "security" "break")
TYPE_LABELS=("✨ Nouveau" "🐛 Fix" "🔒 Sécurité" "⚠️  Breaking")

while true; do
  echo -e "  ${MUTED}Entrée $((INDEX+1)) — Type :${NC}"
  echo -e "    ${CYAN}1${NC}) ✨ Nouveau   ${CYAN}2${NC}) 🐛 Fix   ${CYAN}3${NC}) 🔒 Sécurité   ${CYAN}4${NC}) ⚠️  Breaking   ${CYAN}0${NC}) Terminer"
  read -p "  → " TYPE_CHOICE
  [ "$TYPE_CHOICE" = "0" ] || [ -z "$TYPE_CHOICE" ] && break
  [[ "$TYPE_CHOICE" =~ ^[1-4]$ ]] || { warn "Choix invalide"; continue; }
  echo -e "  ${MUTED}Description :${NC}"
  read -p "  → " ENTRY_TEXT
  [ -z "$ENTRY_TEXT" ] && { warn "Vide, ignoré"; continue; }
  ENTRY_TEXT_ESC=$(echo "$ENTRY_TEXT" | sed 's/"/\\"/g')
  [ $INDEX -gt 0 ] && CHANGELOG_JSON="${CHANGELOG_JSON},"
  CHANGELOG_JSON="${CHANGELOG_JSON}
    { \"type\": \"${TYPES[$((TYPE_CHOICE-1))]}\", \"text\": \"${ENTRY_TEXT_ESC}\" }"
  echo -e "  ${GREEN}+${NC} ${TYPE_LABELS[$((TYPE_CHOICE-1))]} — ${ENTRY_TEXT}"
  INDEX=$((INDEX+1))
  echo ""
done

# ── Mise à jour version dans server.js ────────────────────────────
echo ""
divider
step "Mise à jour server.js → v${NEW_VERSION}..."
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
CHECK=$(grep -oP "KAZYPANEL_VERSION = '\K[^']+" server.js)
[ "$CHECK" = "$NEW_VERSION" ] && ok "server.js → v${NEW_VERSION}" || error "Impossible de mettre à jour la version"

# Validation syntaxe
node --check server.js && ok "Syntaxe server.js valide" || error "Erreur de syntaxe — publication annulée"

# ── Mise à jour version.json ──────────────────────────────────────
step "Mise à jour version.json..."
RELEASE_DATE=$(date +%Y-%m-%d)
cat > version.json << EOF
{
  "version": "${NEW_VERSION}",
  "releaseDate": "${RELEASE_DATE}",
  "downloadUrl": "https://github.com/kazypanel/kazypanel/archive/refs/heads/main.zip",
  "changelog": [${CHANGELOG_JSON}
  ]
}
EOF
ok "version.json → v${NEW_VERSION}"

# ── Mise à jour README.md ─────────────────────────────────────────
step "Mise à jour README.md..."
if [ -f "README.md" ]; then
  sed -i "s|badge/version-[0-9.]*-blue|badge/version-${NEW_VERSION}-blue|g" README.md
  python3 - "$NEW_VERSION" "$RELEASE_DATE" << 'MDEOF'
import sys, re, json
ver  = sys.argv[1]
date = sys.argv[2]
try:    entries = json.load(open('version.json')).get('changelog', [])
except: entries = []
labels = {'new':'✨ Nouveau','fix':'🐛 Fix','security':'🔒 Sécurité','break':'⚠️  Breaking'}
lines  = [f"## Changelog\n\n### v{ver} — {date}"]
for e in entries:
    lines.append(f"- {labels.get(e.get('type',''),'•')} — {e.get('text','')}")
new_section = '\n'.join(lines) + '\n'
content = open('README.md').read()
if '## Changelog' in content:
    content = re.sub(r'## Changelog.*', new_section, content, flags=re.DOTALL)
else:
    content += '\n' + new_section
open('README.md','w').write(content)
MDEOF
  ok "README.md mis à jour"
else
  warn "README.md introuvable — ignoré"
fi

# ── Publication Git ───────────────────────────────────────────────
echo ""
divider
step "Synchronisation avec GitHub..."

# S'assurer d'être sur main
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
if [ "$BRANCH" != "main" ]; then
  warn "Branche courante : $BRANCH — passage sur main..."
  git checkout main 2>/dev/null || git checkout -b main
fi

# Fetch remote
git fetch origin main 2>/dev/null || true

# Rebase propre
if git rebase origin/main 2>/dev/null; then
  ok "Synchronisation OK"
else
  git rebase --abort 2>/dev/null || true
  warn "Rebase impossible — merge..."
  git merge origin/main --no-edit 2>/dev/null || warn "Merge ignoré — poursuite"
fi

# Ajouter uniquement les fichiers cibles
step "Ajout des fichiers..."
git add server.js public/index.html version.json README.md
[ -f "install.sh" ] && git add install.sh || true
ok "Fichiers ajoutés"

# Commit
step "Commit..."
if git commit -m "Release v${NEW_VERSION}"; then
  ok "Commit : Release v${NEW_VERSION}"
else
  warn "Rien à commiter"
fi

# Push
step "Push vers GitHub..."
if git push origin main; then
  ok "Push réussi → github.com/kazypanel/kazypanel"
else
  warn "Push rejeté — resynchronisation..."
  git fetch origin main
  if git rebase origin/main; then
    git push origin main \
      && ok "Push réussi après resync" \
      || error "Échec du push — vérifiez le token GitHub"
  else
    git rebase --abort 2>/dev/null || true
    error "Conflit non résolu — lancez 'git status' pour diagnostiquer"
  fi
fi

# ── Redémarrage KazyPanel ─────────────────────────────────────────
echo ""
step "Redémarrage de KazyPanel..."
if systemctl is-active --quiet kazypanel 2>/dev/null; then
  sudo systemctl restart kazypanel && ok "KazyPanel redémarré"
elif command -v pm2 &>/dev/null && pm2 list 2>/dev/null | grep -q kazypanel; then
  pm2 restart kazypanel && ok "KazyPanel redémarré (pm2)"
else
  warn "Redémarrage manuel requis : sudo systemctl restart kazypanel"
fi

# ── Résumé ────────────────────────────────────────────────────────
echo ""
divider
echo ""
echo -e "${GREEN}  ✅  v${NEW_VERSION} publiée avec succès !${NC}"
echo ""
echo -e "  ${MUTED}GitHub :${NC} https://github.com/kazypanel/kazypanel"
echo -e "  ${MUTED}Panel  :${NC} https://panel.kazylax.fr"
echo ""
