#!/bin/bash
# Rootfs : un conteneur Ubuntu fabrique le système qui sera copié ensuite sur l'image montée,
# ainsi que l'initramfs qui déverrouille la racine chiffrée
set -euo pipefail
cd "$(dirname "$0")"
. ./env.sh

require_mounted

SCRIPT=$(cat <<'EOS'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
# busybox-static et cpio servent seulement à fabriquer l'initramfs, ils sont retirés ensuite
apt-get install -y systemd-sysv udev login util-linux iproute2 kmod libbpf1 rsyslog \
	apparmor ufw cryptsetup-bin busybox-static cpio
apt-get clean

# Comptes root et user (UID 1000, sans sudo) ; le compte ubuntu de l'image est retiré
userdel -r ubuntu 2>/dev/null || true
useradd -m -s /bin/bash -u 1000 user
chmod 0750 /home/user
echo "root:$ROOT_PASSWORD" | chpasswd
echo "user:$USER_PASSWORD" | chpasswd

# —— PAM (modules de libpam-modules uniquement) ——————————————————

# Verrouillage après 5 échecs en 15 min, pendant 10 min ; root n'est jamais verrouillé
cat > /etc/security/faillock.conf <<'EOF'
deny = 5
fail_interval = 900
unlock_time = 600
audit
EOF

# Authentification : délai après échec, faillock autour de pam_unix, mot de passe vide refusé
cat > /etc/pam.d/common-auth <<'EOF'
auth	optional			pam_faildelay.so delay=4000000
auth	requisite			pam_faillock.so preauth
auth	[success=2 default=ignore]	pam_unix.so
auth	[default=die]			pam_faillock.so authfail
auth	requisite			pam_deny.so
auth	required			pam_permit.so
EOF

# Compte : une connexion réussie remet le compteur faillock à zéro
cat > /etc/pam.d/common-account <<'EOF'
account	[success=1 new_authtok_reqd=done default=ignore]	pam_unix.so
account	requisite			pam_deny.so
account	required			pam_permit.so
account	required			pam_faillock.so
EOF

# Changement de mot de passe : 12 caractères minimum, 5 anciens mots de passe interdits.
# pam_pwhistory demande le nouveau mot de passe, pam_unix le reprend (use_authtok)
cat > /etc/pam.d/common-password <<'EOF'
password	requisite			pam_pwhistory.so remember=5 enforce_for_root
password	[success=1 default=ignore]	pam_unix.so obscure use_authtok try_first_pass minlen=12 yescrypt
password	requisite			pam_deny.so
password	required			pam_permit.so
EOF

# su réservé aux membres du groupe root : user ne peut pas devenir root par su
sed -i -E 's/^#[[:space:]]*(auth[[:space:]]+required[[:space:]]+pam_wheel\.so)[[:space:]]*$/\1 use_uid/' /etc/pam.d/su
grep -q '^auth[[:space:]]\+required[[:space:]]\+pam_wheel\.so use_uid' /etc/pam.d/su || { echo "pam_wheel non activé dans /etc/pam.d/su"; exit 1; }

# Connexion limitée aux consoles locales, et seulement pour root et user
sed -i -E 's/^#[[:space:]]*(account[[:space:]]+required[[:space:]]+pam_access\.so.*)$/\1/' /etc/pam.d/login
grep -q '^account[[:space:]]\+required[[:space:]]\+pam_access\.so' /etc/pam.d/login || { echo "pam_access non activé dans /etc/pam.d/login"; exit 1; }
cat > /etc/security/access.conf <<'EOF'
+:root user:LOCAL
-:ALL:ALL
EOF

# Pas de fichier core, nombre de processus borné pour user (fork bomb)
cat > /etc/security/limits.d/90-hardening.conf <<'EOF'
*	hard	core	0
user	hard	nproc	1024
EOF

# umask 027 (appliqué par pam_umask), 3 essais et 60 s pour se connecter
sed -i -E 's/^UMASK[[:space:]].*/UMASK\t\t027/' /etc/login.defs
sed -i -E 's/^LOGIN_RETRIES[[:space:]].*/LOGIN_RETRIES\t\t3/' /etc/login.defs
sed -i -E 's/^LOGIN_TIMEOUT[[:space:]].*/LOGIN_TIMEOUT\t\t60/' /etc/login.defs

# —— Système ———————————————————————————————————————

# Console série
systemctl enable serial-getty@ttyS0.service

# Racine ouverte par l'initramfs (sans udev) : pas de fsck au boot, systemd attendrait
# un périphérique que udev ne déclare jamais prêt. /tmp sans noexec : l'EDR doit voir
# l'exécution de binaires déposés dans /tmp (bprm_check_security), que noexec bloquerait avant lui
cat > /etc/fstab <<'EOF'
/dev/mapper/root	/		ext4	defaults,errors=remount-ro		0 0
LABEL=boot		/boot		ext4	defaults,nodev,nosuid,noexec		0 2
tmpfs			/tmp		tmpfs	defaults,nodev,nosuid,mode=1777,size=512M	0 0
tmpfs			/dev/shm	tmpfs	defaults,nodev,nosuid,noexec		0 0
proc			/proc		proc	defaults,hidepid=invisible		0 0
EOF

# systemd refuse une unité .mount pour /sys/fs/bpf : service oneshot à la place
cat > /etc/systemd/system/bpffs.service <<'EOF'
[Unit]
Description=Mount BPF filesystem
DefaultDependencies=no
Before=sysinit.target
ConditionPathIsMountPoint=!/sys/fs/bpf

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/mount -t bpf -o mode=0700 bpf /sys/fs/bpf

[Install]
WantedBy=sysinit.target
EOF
systemctl enable bpffs.service

# Réseau : DHCP sur la carte QEMU, IPv4 seulement (IPv6 désactivé au boot)
mkdir -p /etc/systemd/network
cat > /etc/systemd/network/20-wired.network <<'EOF'
[Match]
Name=en*

[Network]
DHCP=ipv4
LinkLocalAddressing=no
IPv6AcceptRA=no
EOF
systemctl enable systemd-networkd.service

# Paramètres noyau. Les clés précédées de - sont ignorées si l'option n'est pas compilée
cat > /etc/sysctl.d/90-hardening.conf <<'EOF'
# Fuites d'adresses et de journaux noyau
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
# bpf() interdit aux non privilégiés jusqu'au redémarrage ; JIT BPF durci
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
# ptrace réservé à CAP_SYS_PTRACE (l'EDR, placé avant yama, voit quand même la tentative)
kernel.yama.ptrace_scope = 2
kernel.perf_event_paranoid = 2
kernel.sysrq = 0
kernel.randomize_va_space = 2
kernel.core_pattern = |/bin/false
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
dev.tty.ldisc_autoload = 0
-vm.unprivileged_userfaultfd = 0
# Réseau
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
EOF

# Ctrl-Alt-Suppr et shell de débogage désactivés
systemctl mask ctrl-alt-del.target debug-shell.service

# —— Pare-feu (ufw, règles iptables) ———————————————————————
# Tout est refusé par défaut (entrant, sortant, routé) ; seuls sortent le DHCP vers QEMU
# et le syslog TCP vers le manager Wazuh (10.0.2.2:514). Le hook socket_connect de l'EDR
# s'exécute avant le pare-feu : il voit et journalise quand même les connexions qu'il bloque.
# Configuration écrite directement : ufw ne peut pas charger de règles dans le conteneur.
# Les lignes "### tuple ###" sont celles que ufw relit pour "ufw status"
sed -i -E 's/^IPV6=.*/IPV6=no/' /etc/default/ufw
sed -i -E 's/^DEFAULT_INPUT_POLICY=.*/DEFAULT_INPUT_POLICY="DROP"/' /etc/default/ufw
sed -i -E 's/^DEFAULT_OUTPUT_POLICY=.*/DEFAULT_OUTPUT_POLICY="DROP"/' /etc/default/ufw
sed -i -E 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="DROP"/' /etc/default/ufw
grep -q '^### RULES ###$' /etc/ufw/user.rules || { echo "/etc/ufw/user.rules inattendu"; exit 1; }
sed -i '/^### RULES ###$/r /dev/stdin' /etc/ufw/user.rules <<'EOF'

### tuple ### allow udp 67 0.0.0.0/0 68 0.0.0.0/0 out
-A ufw-user-output -p udp --dport 67 --sport 68 -j ACCEPT

### tuple ### allow tcp 514 10.0.2.2 any 0.0.0.0/0 out
-A ufw-user-output -p tcp -d 10.0.2.2 --dport 514 -j ACCEPT
EOF
grep -q -- '-d 10.0.2.2 --dport 514 -j ACCEPT' /etc/ufw/user.rules || { echo "règle ufw Wazuh absente"; exit 1; }
sed -i -E 's/^ENABLED=.*/ENABLED=yes/' /etc/ufw/ufw.conf
sed -i -E 's/^LOGLEVEL=.*/LOGLEVEL=low/' /etc/ufw/ufw.conf
grep -q '^ENABLED=yes' /etc/ufw/ufw.conf || { echo "ufw non activé"; exit 1; }
systemctl enable ufw.service

# —— Expéditeur : edr.log vers le manager Wazuh ———————————————————
# rsyslog garde sa perte de privilèges (utilisateur syslog, membre de adm) :
# edr.log est lisible par le groupe adm. edrd doit écrire en ajout sans recréer le fichier
install -m 0640 -o root -g adm /dev/null /var/log/edr.log
cat > /etc/rsyslog.d/edr.conf <<'EOF'
module(load="imfile")
template(name="edr_raw" type="string" string="%rawmsg%\n")
input(type="imfile" File="/var/log/edr.log" Tag="edr" ruleset="edr_forward")
ruleset(name="edr_forward") {
    action(type="omfwd" target="10.0.2.2" port="514" protocol="tcp" template="edr_raw"
           action.resumeRetryCount="-1"
           queue.type="LinkedList" queue.filename="edr_fwd" queue.maxDiskSpace="50m" queue.saveOnShutdown="on")
}
EOF
systemctl enable rsyslog.service

# —— AppArmor ———————————————————————————————————————
# Profil rsyslogd fourni par Ubuntu, en mode enforce : on y ajoute la lecture de edr.log,
# l'état d'imfile et la file d'attente, et l'envoi TCP vers Wazuh
profile=/etc/apparmor.d/usr.sbin.rsyslogd
[ -f "$profile" ] || { echo "$profile absent"; exit 1; }
grep -q 'local/usr.sbin.rsyslogd' "$profile" || { echo "$profile n'inclut pas local/usr.sbin.rsyslogd"; exit 1; }
rm -f /etc/apparmor.d/disable/usr.sbin.rsyslogd
cat > /etc/apparmor.d/local/usr.sbin.rsyslogd <<'EOF'
/var/log/edr.log r,
/var/spool/rsyslog/ r,
/var/spool/rsyslog/** rwk,
network inet stream,
EOF

# Profil du démon EDR (installé par 3-install.sh), en mode complain : les accès hors
# profil sont journalisés, pas refusés. Le passer en enforce (aa-enforce) une fois que
# "journalctl -k | grep edrd" ne montre plus d'ALLOWED, pour ne pas casser la démo
cat > /etc/apparmor.d/usr.sbin.edrd <<'EOF'
abi <abi/4.0>,
include <tunables/global>

profile edrd /usr/sbin/edrd flags=(complain) {
  include <abstractions/base>

  # Chargement des programmes BPF-LSM, ring buffer, épinglage
  capability bpf,
  capability perfmon,
  capability sys_admin,
  capability sys_resource,
  # Rotation de edr.log : le nouveau fichier reprend root:adm 0640
  capability chown,
  capability fowner,

  # bpffs, si bpffs.service ne l'a pas monté
  mount fstype=bpf -> /sys/fs/bpf/,

  /usr/sbin/edrd mr,
  /sys/kernel/btf/vmlinux r,
  /sys/devices/system/cpu/possible r,
  /sys/devices/system/cpu/online r,
  @{PROC}/sys/kernel/unprivileged_bpf_disabled r,
  @{PROC}/@{pid}/fdinfo/* r,
  /sys/fs/bpf/ r,
  /sys/fs/bpf/edr/ rw,
  /sys/fs/bpf/edr/** rw,
  /var/log/ r,
  /var/log/edr.log rw,
  /var/log/edr.log.[0-9]* rw,

  include if exists <local/usr.sbin.edrd>
}
EOF
systemctl enable apparmor.service

# —— Initramfs ——————————————————————————————————————
# busybox statique + cryptsetup : ouvre la racine LUKS, puis switch_root vers systemd
ird=/tmp/initramfs
mkdir -p "$ird"/{bin,sbin,dev,proc,sys,run,newroot,lib/x86_64-linux-gnu,lib64}
cp "$(command -v busybox)" "$ird/bin/busybox"
for applet in sh mount umount mkdir cat sleep seq poweroff switch_root; do
	ln -s busybox "$ird/bin/$applet"
done

# cryptsetup et ses bibliothèques, aux emplacements où le chargeur les cherche
cp /usr/sbin/cryptsetup "$ird/sbin/cryptsetup"
for lib in $(ldd /usr/sbin/cryptsetup | grep -o '/[^ ]*'); do
	case "$lib" in
	*/ld-linux-x86-64.so.2) cp -L "$lib" "$ird/lib64/" ;;
	*) cp -L "$lib" "$ird/lib/x86_64-linux-gnu/" ;;
	esac
done
# Chargée à l'exécution par les fils d'argon2 (absente de ldd)
cp -L /usr/lib/x86_64-linux-gnu/libgcc_s.so.1 "$ird/lib/x86_64-linux-gnu/"

# Console initiale : le noyau l'ouvre avant que /init monte devtmpfs
mknod -m 600 "$ird/dev/console" c 5 1

cat > "$ird/init" <<'EOF'
#!/bin/sh
# Initramfs EDR2600 : ouvre la racine chiffrée (LUKS) puis passe la main à systemd.
# Pas de shell de secours : en cas d'échec la machine s'éteint
export PATH=/bin:/sbin
# Sans udev, libdevmapper crée lui-même /dev/mapper/root
export DM_DISABLE_UDEV=1

fail() {
	echo "initramfs : $1, arrêt" >&2
	sleep 5
	poweroff -f
}

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /run/cryptsetup

uuid=
for arg in $(cat /proc/cmdline); do
	case "$arg" in
	cryptroot=UUID=*) uuid=${arg#cryptroot=UUID=} ;;
	esac
done
[ -n "$uuid" ] || fail "cryptroot=UUID=... absent de la ligne de commande"

# Les disques apparaissent de façon asynchrone : attente jusqu'à 10 s
dev=
for try in $(seq 10); do
	for d in /dev/sd?[0-9] /dev/vd?[0-9]; do
		[ -b "$d" ] || continue
		if [ "$(cryptsetup luksUUID "$d" 2>/dev/null)" = "$uuid" ]; then
			dev=$d
			break 2
		fi
	done
	sleep 1
done
[ -n "$dev" ] || fail "partition LUKS $uuid introuvable"

cryptsetup open --tries 3 "$dev" root || fail "déverrouillage refusé"
mount -o ro -t ext4 /dev/mapper/root /newroot || fail "montage de la racine impossible"

# switch_root de busybox ne déplace pas les pseudo-systèmes : /dev garde
# /dev/mapper/root, systemd remonte /proc et /sys
mount --move /dev /newroot/dev
umount /proc /sys
exec switch_root /newroot /sbin/init
EOF
chmod 0700 "$ird/init"

(cd "$ird" && find . -print0 | cpio --null -o -H newc -R 0:0 --quiet | gzip -9) > /tmp/initramfs-edr.img
rm -rf "$ird"
apt-get purge -y busybox-static cpio

# --one-file-system laisse /proc, /sys et /dev en dossiers vides ; /my-rootfs est exclu (il change pendant la lecture).
# /.dockerenv est exclu : systemd se croirait dans un conteneur Docker et ne monterait
# pas securityfs, donc AppArmor ne chargerait aucun profil
tar -c --one-file-system --exclude=./my-rootfs --exclude=./tmp/initramfs-edr.img --exclude=./.dockerenv -C / . \
	| tar -x -p --numeric-owner -C /my-rootfs
rm -f /my-rootfs/.dockerenv
install -m 0600 /tmp/initramfs-edr.img /my-rootfs/boot/initramfs-edr.img
EOS
)

docker run --rm -e ROOT_PASSWORD -e USER_PASSWORD -v "$MNT:/my-rootfs" ubuntu:24.04 bash -c "$SCRIPT"
