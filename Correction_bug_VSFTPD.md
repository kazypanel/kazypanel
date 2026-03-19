# 🛠️ KazyPanel — Correction vsftpd (utilisateur non-root)

> Ce guide documente tous les problèmes rencontrés et leurs solutions lors de l'utilisation de KazyPanel avec un utilisateur non-root (ex: `debian`) sur un VPS Debian.

---

## Contexte

KazyPanel tourne sous l'utilisateur `debian` (non-root) pour des raisons de sécurité.  
vsftpd nécessite des droits root pour modifier ses fichiers de configuration et gérer les comptes système.  
Sans configuration adaptée, les utilisateurs FTP ne peuvent pas se connecter.

---

## Problèmes rencontrés et solutions

### 1. `fs.writeFileSync` sans droits suffisants

**Symptôme :** Les utilisateurs créés depuis le panel n'apparaissent pas dans `/etc/vsftpd.userlist` et ne peuvent pas se connecter en FTP.

**Cause :** `server.js` utilisait `fs.writeFileSync()` et `fs.appendFileSync()` directement sur des fichiers appartenant à `root` :
- `/etc/vsftpd.userlist`
- `/etc/vsftpd.conf`

**Solution :** Écriture dans un fichier temporaire `/tmp`, puis copie avec `sudo cp` :

```js
const tmpList = `/tmp/kp_userlist_${Date.now()}`;
fs.writeFileSync(tmpList, lines.join('\n') + '\n');
await runCmd(`sudo cp "${tmpList}" "/etc/vsftpd.userlist" && sudo chmod 644 "/etc/vsftpd.userlist"; rm -f "${tmpList}"`);
```

---

### 2. `chpasswd` sans sudo

**Symptôme :** Le mot de passe FTP n'est jamais défini pour les nouveaux utilisateurs. La connexion échoue avec `Please login with USER and PASS`.

**Cause :** `setSystemPassword()` utilisait `spawn('chpasswd')` sans sudo.

**Solution :** Passer `sudo` comme premier argument de `spawn` :

```js
// Avant
const proc = spawn('chpasswd', [], { timeout: 10000 });

// Après
const proc = spawn('sudo', ['chpasswd'], { timeout: 10000 });
```

---

### 3. `pam_service_name=ftp` incorrect

**Symptôme :** Connexion refusée même avec un utilisateur valide et un mot de passe correct. Aucune erreur visible dans les logs.

**Cause :** vsftpd cherchait `/etc/pam.d/ftp` au lieu de `/etc/pam.d/vsftpd`.

**Solution :** Dans `/etc/vsftpd.conf` :

```ini
# Avant
pam_service_name=ftp

# Après
pam_service_name=vsftpd
```

```bash
sudo systemctl restart vsftpd
```

---

### 4. `local_root=/var/www/$USER` non interprété

**Symptôme :** Connexion refusée avec le message :
```
500 OOPS: cannot change directory:/var/www/$USER
```

**Cause :** vsftpd n'interprète pas les variables shell comme `$USER`. Il cherche littéralement un dossier nommé `/var/www/$USER`.

**Solution :** Supprimer ou commenter cette ligne dans `/etc/vsftpd.conf` :

```ini
#local_root=/var/www/$USER
```

vsftpd utilise alors automatiquement le répertoire home défini dans `/etc/passwd` pour chaque utilisateur.

```bash
sudo systemctl restart vsftpd
```

---

### 5. SSL/TLS explicite non configuré

**Symptôme :** FileZilla en mode FTPES (FTP explicite sur TLS) refuse la connexion.

**Cause :** `ssl_enable=YES` était présent mais les paramètres SSL (certificat, clé, options TLS) manquaient.

**Solution :** Ajouter dans `/etc/vsftpd.conf` :

```ini
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=NO
force_local_logins_ssl=NO
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
rsa_cert_file=/etc/letsencrypt/live/panel.kazylax.fr/fullchain.pem
rsa_private_key_file=/etc/letsencrypt/live/panel.kazylax.fr/privkey.pem
```

> ⚠️ Remplacez `panel.kazylax.fr` par votre propre domaine.

```bash
sudo systemctl restart vsftpd
```

---

## Configuration vsftpd.conf finale

```ini
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
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=NO
force_local_logins_ssl=NO
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
rsa_cert_file=/etc/letsencrypt/live/VOTRE_DOMAINE/fullchain.pem
rsa_private_key_file=/etc/letsencrypt/live/VOTRE_DOMAINE/privkey.pem
userlist_enable=YES
userlist_file=/etc/vsftpd.userlist
userlist_deny=NO
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=50000
pasv_address=VOTRE_IP
check_shell=NO
vsftpd_log_file=/var/log/vsftpd.log
log_ftp_protocol=YES
#local_root=/var/www/$USER
```

---

## Configuration sudoers requise

Créez `/etc/sudoers.d/kazypanel` pour permettre à `debian` d'exécuter les commandes nécessaires sans mot de passe :

```bash
sudo nano /etc/sudoers.d/kazypanel
```

```
debian ALL=(root) NOPASSWD: \
    /usr/sbin/a2ensite, \
    /usr/sbin/a2dissite, \
    /usr/sbin/a2enmod, \
    /usr/bin/systemctl, \
    /usr/sbin/useradd, \
    /usr/sbin/userdel, \
    /usr/sbin/usermod, \
    /usr/sbin/chpasswd, \
    /bin/chown, \
    /bin/chmod, \
    /bin/mkdir, \
    /bin/cp, \
    /bin/rm, \
    /usr/sbin/rndc, \
    /usr/sbin/named-checkzone, \
    /usr/sbin/named-checkconf, \
    /usr/bin/certbot, \
    /usr/sbin/ufw, \
    /usr/bin/fail2ban-client, \
    /usr/sbin/sshd, \
    /usr/bin/hostnamectl, \
    /usr/bin/timedatectl, \
    /usr/bin/du, \
    /usr/bin/crontab, \
    /bin/tar, \
    /usr/sbin/apache2ctl, \
    /usr/sbin/apachectl, \
    /bin/bash
```

```bash
sudo chmod 440 /etc/sudoers.d/kazypanel
sudo visudo -c -f /etc/sudoers.d/kazypanel
```

---

## Vérifications utiles

```bash
# vsftpd écoute sur le port 21 ?
sudo ss -tlnp | grep 21

# Les ports passifs sont ouverts ?
sudo ufw status | grep -E "21|40000"

# L'utilisateur est dans la userlist ?
grep nomutilisateur /etc/vsftpd.userlist

# Le compte système existe ?
id nomutilisateur

# Tester la connexion FTP en local
ftp 127.0.0.1

# Voir les logs en temps réel
sudo journalctl -u vsftpd -f
sudo journalctl -f | grep -i "ftp\|pam\|vsftpd\|auth"
```

---

## Réinitialiser le mot de passe d'un utilisateur FTP

Si un utilisateur ne peut pas se connecter suite à un problème de synchronisation du mot de passe :

```bash
sudo passwd nomutilisateur
```

Puis depuis le panel : **Admin → Utilisateurs → FTP → Changer le mot de passe** pour resynchroniser.

---

## Paramètres FileZilla recommandés

| Paramètre | Valeur |
|---|---|
| Protocole | FTP |
| Chiffrement | FTP explicite sur TLS |
| Mode de transfert | Passif |
| Port | 21 |
| Hôte | votre IP ou domaine |
