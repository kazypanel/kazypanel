#!/bin/bash

# ══════════════════════════════════════════════════════════════════
#  KazyPanel — Correction automatique + Publication GitHub
#  Usage : bash publish.sh
# ══════════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'
MUTED='\033[0;90m'; NC='\033[0m'

PANEL_DIR="/opt/kazypanel"
SERVER_FILE="server.js"
HTML_FILE="public/index.html"
FIX_SCRIPT="/tmp/kp_autofix.py"

step()    { echo -e "${CYAN}▶${NC} ${WHITE}$1${NC}"; }
ok()      { echo -e "  ${GREEN}✓${NC} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $1"; }
error()   { echo -e "  ${RED}✗${NC} $1"; exit 1; }
divider() { echo -e "${MUTED}──────────────────────────────────────────────────${NC}"; }

# ── Header ────────────────────────────────────────────────────────
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${WHITE}   🔧  KazyPanel — Correction + Publication       ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ── Vérifications ─────────────────────────────────────────────────
step "Vérification de l'environnement..."
command -v git     &>/dev/null || error "Git non installé"
command -v node    &>/dev/null || error "Node.js non installé"
command -v python3 &>/dev/null || error "Python3 non installé"
[ -d "$PANEL_DIR" ]  || error "Dossier $PANEL_DIR introuvable"
cd "$PANEL_DIR"
[ -d ".git" ]         || error "Dépôt Git non initialisé"
[ -f "$SERVER_FILE" ] || error "$SERVER_FILE introuvable"
[ -f "$HTML_FILE" ]   || error "$HTML_FILE introuvable"
git remote get-url origin &>/dev/null || error "Remote 'origin' non configuré"
ok "Environnement OK"

echo ""
divider

# ── Version ───────────────────────────────────────────────────────
CURRENT_VERSION=$(grep -oP "KAZYPANEL_VERSION = '\K[^']+" "$SERVER_FILE" 2>/dev/null || echo "1.0.0")
echo ""
step "Version actuelle : ${YELLOW}v${CURRENT_VERSION}${NC}"
echo -e "  Nouvelle version ${MUTED}(Entrée = garder v${CURRENT_VERSION})${NC} :"
read -p "  → " NEW_VERSION
[ -z "$NEW_VERSION" ] && NEW_VERSION="$CURRENT_VERSION"
echo "$NEW_VERSION" | grep -qP '^\d+\.\d+\.\d+$' || error "Format invalide. Utiliser X.Y.Z"

echo ""
divider
echo ""

# ── Écrire le script Python de corrections ────────────────────────
step "Application des corrections automatiques..."
echo ""

python3 - "$SERVER_FILE" "$HTML_FILE" << 'PYEOF'
import re, sys

sf = sys.argv[1]
hf = sys.argv[2]
server = open(sf).read()
html   = open(hf).read()
sc = False
hc = False

# Fix 1 : top -bn1 → /proc/stat
if 'top -bn1' in server:
    server = server.replace(
        "top -bn1 | grep 'Cpu(s)' | awk '{print 100 - $8}' | cut -d. -f1 || echo 0",
        "cat /proc/stat | awk 'NR==1{idle=$5;total=0;for(i=2;i<=NF;i++)total+=$i;print int((1-idle/total)*100)}'"
    )
    print('FIX: CPU top -bn1 → /proc/stat'); sc = True

# Fix 2 : diskusage null check
n2 = "app.get('/api/me/diskusage', authMiddleware, async (req, res) => {\n  const user = USERS.find(u => u.id === req.user.id);\n  const userDir"
if n2 in server:
    server = server.replace(n2, n2.replace("  const userDir", "  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });\n  const userDir"))
    print('FIX: diskusage null check'); sc = True

# Fix 3 : JWT_SECRET (géré via .env)

# Fix 4 : == → === pour u.id
c4 = server.count('u.id == req.user.id')
if c4 > 0:
    server = server.replace('u.id == req.user.id', 'u.id === parseInt(req.user.id)')
    print(f'FIX: {c4} comparaisons == corrigees'); sc = True

# Fix 5 : Log rotation
L_OLD = "try { fs.appendFileSync(CONFIG.LOG_FILE, entry + '\\n'); } catch {}"
L_NEW = "try {\n    try { if (fs.statSync(CONFIG.LOG_FILE).size > 10*1024*1024) fs.renameSync(CONFIG.LOG_FILE, CONFIG.LOG_FILE+'.bak'); } catch {}\n    fs.appendFileSync(CONFIG.LOG_FILE, entry + '\\n');\n  } catch {}"
if L_OLD in server:
    server = server.replace(L_OLD, L_NEW)
    print('FIX: log rotation 10Mo'); sc = True

# Fix 6 : require inline
R_OLD = "    const { execSync } = require('child_process');\n    const raw = execSync("
R_NEW = "    const raw = require('child_process').execSync("
if R_OLD in server:
    server = server.replace(R_OLD, R_NEW)
    print('FIX: require() sorti de la route'); sc = True

# Fix 7 : localStorage → sessionStorage
for o, n in [
    ("localStorage.setItem('hp_token'",    "sessionStorage.setItem('hp_token'"),
    ("localStorage.getItem('hp_token'",    "sessionStorage.getItem('hp_token'"),
    ("localStorage.removeItem('hp_token'", "sessionStorage.removeItem('hp_token'"),
    ("localStorage.setItem('hp_role'",     "sessionStorage.setItem('hp_role'"),
    ("localStorage.getItem('hp_role'",     "sessionStorage.getItem('hp_role'"),
    ("localStorage.removeItem('hp_role'",  "sessionStorage.removeItem('hp_role'"),
]:
    if o in html: html = html.replace(o, n); hc = True
if hc: print('FIX: localStorage → sessionStorage')

# Fix 8 : scripts Cloudflare
if 'cdn-cgi' in html:
    html = re.sub(r'<script data-cfasync="false" src="/cdn-cgi/[^"]*"></script>(<script>.*?</script>)?', '', html, flags=re.DOTALL)
    html = re.sub(r'<a href="/cdn-cgi/l/email-protection"[^>]*>\[email&#160;protected\]</a>', 'admin@kazylax.fr', html)
    print('FIX: scripts Cloudflare supprimés'); hc = True

import subprocess, os
if sc:
    tmp = sf + '.tmp'
    open(tmp, 'w').write(server)
    subprocess.run(['sudo', 'cp', tmp, sf], check=True)
    subprocess.run(['sudo', 'chmod', '644', sf], check=True)
    os.remove(tmp)
if hc:
    tmp = hf + '.tmp'
    open(tmp, 'w').write(html)
    subprocess.run(['sudo', 'cp', tmp, hf], check=True)
    subprocess.run(['sudo', 'chmod', '644', hf], check=True)
    os.remove(tmp)

print('---CHECKS---')
print('OK' if 'top -bn1' not in server          else 'SKIP', ': top -bn1 absent')
print('OK' if 'if (!user) return res.status(404)' in server else 'SKIP', ': diskusage null check')
print('OK' if 'size > 10*1024*1024' in server    else 'SKIP', ': log rotation')
print('OK' if 'sessionStorage' in html           else 'SKIP', ': sessionStorage')
print('OK' if 'cdn-cgi' not in html              else 'SKIP', ': Cloudflare absent')
PYEOF

echo ""
ok "Corrections terminées"
echo ""
divider

# ── Validation syntaxe ────────────────────────────────────────────
echo ""
step "Validation syntaxe server.js..."
node --check "$SERVER_FILE" 2>/dev/null && ok "Syntaxe valide" || error "Erreur de syntaxe — publication annulée"

# ── Date de modification ──────────────────────────────────────────
LAST_MODIFIED=$(date '+%d/%m/%Y %H:%M')
step "Date de modification → ${LAST_MODIFIED}..."
TMP_SRV=$(mktemp)
TMP_HTML=$(mktemp)
sed "s| \* Dernière modification : .*| * Dernière modification : ${LAST_MODIFIED}|" "$SERVER_FILE" > "$TMP_SRV"
sudo cp "$TMP_SRV" "$SERVER_FILE" && sudo chmod 644 "$SERVER_FILE"; rm -f "$TMP_SRV"
sed "s|<!-- KazyPanel - Dernière modification : .* -->|<!-- KazyPanel - Dernière modification : ${LAST_MODIFIED} -->|" "$HTML_FILE" > "$TMP_HTML"
sudo cp "$TMP_HTML" "$HTML_FILE" && sudo chmod 644 "$HTML_FILE"; rm -f "$TMP_HTML"
ok "Headers mis à jour"

# ── Changelog ────────────────────────────────────────────────────
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

# ── Mise à jour version ───────────────────────────────────────────
echo ""
divider
echo ""
step "Mise à jour server.js → v${NEW_VERSION}..."
TMP_VER="/tmp/kp_server_ver_$$.js"
node - "$NEW_VERSION" "$TMP_VER" << 'JSEOF'
const fs = require('fs');
const ver  = process.argv[2];
const dest = process.argv[3];
const c = fs.readFileSync('server.js','utf8')
  .replace(/const KAZYPANEL_VERSION = '[^']+'/,"const KAZYPANEL_VERSION = '"+ver+"'");
fs.writeFileSync(dest, c);
JSEOF
sudo cp "$TMP_VER" "$SERVER_FILE" && sudo chmod 644 "$SERVER_FILE"; rm -f "$TMP_VER"
CHECK=$(grep -oP "KAZYPANEL_VERSION = '\K[^']+" "$SERVER_FILE")
[ "$CHECK" = "$NEW_VERSION" ] && ok "server.js → v${NEW_VERSION}" || error "Impossible de mettre à jour la version"

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

step "Mise à jour README.md..."
if [ -f "README.md" ]; then
  # Mettre à jour le badge de version
  sed -i "s|badge/version-[0-9.]*-blue|badge/version-${NEW_VERSION}-blue|" README.md

  # Mettre à jour ou créer la section Changelog dans le README
  # Si une section ## Changelog existe, la remplacer
  if grep -q "^## Changelog" README.md; then
    # Construire le bloc changelog markdown
    CHANGELOG_MD="## Changelog\n\n### v${NEW_VERSION} — ${RELEASE_DATE}"
    if [ $INDEX -gt 0 ]; then
      CHANGELOG_MD="${CHANGELOG_MD}\n"
      # Relire les entrées depuis CHANGELOG_JSON
      while IFS= read -r line; do
        TYPE=$(echo "$line" | grep -oP '"type":\s*"\K[^"]+' || true)
        TEXT=$(echo "$line" | grep -oP '"text":\s*"\K[^"]+' || true)
        [ -z "$TYPE" ] || [ -z "$TEXT" ] && continue
        case "$TYPE" in
          new)      EMOJI="✨ Nouveau" ;;
          fix)      EMOJI="🐛 Fix" ;;
          security) EMOJI="🔒 Sécurité" ;;
          break)    EMOJI="⚠️  Breaking" ;;
          *)        EMOJI="•" ;;
        esac
        CHANGELOG_MD="${CHANGELOG_MD}\n- ${EMOJI} — ${TEXT}"
      done <<< "$(echo "${CHANGELOG_JSON}" | grep -E '"type"|"text"' | paste - -)"
    fi
    # Remplacer la section existante (jusqu'à la prochaine section ## ou fin de fichier)
    python3 - "$NEW_VERSION" "$RELEASE_DATE" << MDEOF
import sys, re
ver  = sys.argv[1]
date = sys.argv[2]
content = open('README.md').read()
# Lire le changelog JSON depuis version.json
import json
try:
    entries = json.load(open('version.json')).get('changelog', [])
except:
    entries = []
labels = {'new': '✨ Nouveau', 'fix': '🐛 Fix', 'security': '🔒 Sécurité', 'break': '⚠️  Breaking'}
lines = [f"## Changelog\n\n### v{ver} — {date}"]
for e in entries:
    label = labels.get(e.get('type',''), '•')
    lines.append(f"- {label} — {e.get('text','')}")
new_section = '\n'.join(lines) + '\n'
content = re.sub(r'^## Changelog.*', new_section, content, flags=re.MULTILINE|re.DOTALL)
open('README.md','w').write(content)
print('README Changelog mis à jour')
MDEOF
  else
    # Ajouter la section Changelog en fin de fichier
    python3 - "$NEW_VERSION" "$RELEASE_DATE" << MDEOF2
import sys, json
ver  = sys.argv[1]
date = sys.argv[2]
try:
    entries = json.load(open('version.json')).get('changelog', [])
except:
    entries = []
labels = {'new': '✨ Nouveau', 'fix': '🐛 Fix', 'security': '🔒 Sécurité', 'break': '⚠️  Breaking'}
lines = [f"\n## Changelog\n\n### v{ver} — {date}"]
for e in entries:
    label = labels.get(e.get('type',''), '•')
    lines.append(f"- {label} — {e.get('text','')}")
with open('README.md','a') as f:
    f.write('\n'.join(lines) + '\n')
print('README Changelog ajouté')
MDEOF2
  fi
  git add README.md 2>/dev/null || true
  ok "README.md → badge v${NEW_VERSION} + changelog mis à jour"
else
  warn "README.md introuvable — ignoré"
fi

# ── Git identity ─────────────────────────────────────────────────
git config --global user.email "kazylax1981@gmail.com"
git config --global user.name "KazyPanel"

# ── Git ───────────────────────────────────────────────────────────
echo ""
step "Vérification de la branche Git..."
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
if [ "$BRANCH" = "HEAD" ]; then
  warn "Detached HEAD détecté — retour sur main..."
  git checkout main 2>/dev/null || git checkout -b main
fi
git fetch origin main 2>/dev/null || true
ok "Branche : $(git rev-parse --abbrev-ref HEAD)"

step "Synchronisation remote (pull avant commit)..."
git stash 2>/dev/null || true
if git pull --rebase origin main; then
  ok "Remote synchronisé"
else
  warn "Pull --rebase échoué — tentative merge..."
  git pull origin main 2>/dev/null || warn "Pull impossible — poursuite"
fi
git stash pop 2>/dev/null || true

step "Ajout des fichiers Git..."
git add "$SERVER_FILE" "$HTML_FILE" version.json install.sh README.md 2>/dev/null || true
ok "Fichiers ajoutés"

step "Commit..."
git commit -m "Release v${NEW_VERSION}" && ok "Commit : Release v${NEW_VERSION}" || warn "Rien à commiter"

step "Push vers GitHub..."
if git push origin main; then
  ok "Push réussi → github.com/kazypanel/kazypanel"
else
  warn "Push simple échoué — tentative pull + push..."
  git stash 2>/dev/null || true
  git pull --rebase origin main
  git stash pop 2>/dev/null || true
  git push origin main \
    && ok "Push réussi après resync" \
    || error "Échec du push — vérifiez le token GitHub"
fi

# ── Redémarrage ───────────────────────────────────────────────────
echo ""
step "Redémarrage de KazyPanel..."
if systemctl is-active --quiet kazypanel; then
    sudo systemctl restart kazypanel && ok "KazyPanel redémarré"
else
    warn "KazyPanel non actif — redémarrage manuel requis"
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
