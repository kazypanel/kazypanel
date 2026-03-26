#!/usr/bin/env node
/**
 * KazyPanel — Script de sauvegarde automatique
 * Lancé par cron, crée une archive tar.gz horodatée dans /opt/kazypanel/backups/
 * et supprime les anciennes sauvegardes selon la rétention configurée.
 */
'use strict';

const { execSync } = require('child_process');
const fs   = require('fs');
const path = require('path');

const INSTALL_DIR  = path.resolve(__dirname);
const BACKUP_DIR   = path.join(INSTALL_DIR, 'backups');
const CONFIG_FILE  = path.join(INSTALL_DIR, 'panel_config.json');

// Charger la config
let retain = 7;
try {
  const cfg = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  retain = cfg.backupSchedule?.retain || 7;
} catch {}

// Créer le dossier si nécessaire
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });

// Nom de la sauvegarde
const timestamp  = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
const backupName = `kazypanel-backup-${timestamp}.tar.gz`;
const backupPath = path.join(BACKUP_DIR, backupName);

// Créer l'archive (exclure node_modules, backups, logs)
try {
  execSync(
    `tar -czf "${backupPath}" \
      --exclude="${INSTALL_DIR}/node_modules" \
      --exclude="${INSTALL_DIR}/backups" \
      --exclude="${INSTALL_DIR}/.git" \
      -C "${path.dirname(INSTALL_DIR)}" "${path.basename(INSTALL_DIR)}"`,
    { timeout: 120000 }
  );
  console.log(`[${new Date().toISOString()}] Sauvegarde créée : ${backupName}`);
} catch (err) {
  console.error(`[${new Date().toISOString()}] Erreur sauvegarde : ${err.message}`);
  process.exit(1);
}

// Supprimer les sauvegardes excédentaires (plus anciennes)
const files = fs.readdirSync(BACKUP_DIR)
  .filter(f => f.startsWith('kazypanel-backup-') && f.endsWith('.tar.gz'))
  .map(f => ({ name: f, mtime: fs.statSync(path.join(BACKUP_DIR, f)).mtime }))
  .sort((a, b) => b.mtime - a.mtime);

if (files.length > retain) {
  const toDelete = files.slice(retain);
  for (const f of toDelete) {
    try {
      fs.unlinkSync(path.join(BACKUP_DIR, f.name));
      console.log(`[${new Date().toISOString()}] Supprimé : ${f.name}`);
    } catch {}
  }
}
