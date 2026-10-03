#!/bin/bash
# Rootfs : un conteneur Ubuntu fabrique le système qui sera copié ensuite sur l'image montée
set -euo pipefail
cd "$(dirname "$0")"
. ./env.sh

require_mounted

SCRIPT=$(cat <<'EOS'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y systemd-sysv udev login util-linux iproute2 kmod libbpf1 rsyslog
apt-get clean

# Comptes root et user (UID 1000, sans sudo) ; le compte ubuntu de l'image est retiré
userdel -r ubuntu 2>/dev/null || true
useradd -m -s /bin/bash -u 1000 user
echo "root:$ROOT_PASSWORD" | chpasswd
echo "user:$USER_PASSWORD" | chpasswd

# Console série et montage de la racine par étiquette
systemctl enable serial-getty@ttyS0.service
echo 'LABEL=rootfs / ext4 defaults,errors=remount-ro 0 1' > /etc/fstab

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

# Réseau : DHCP sur la carte QEMU
mkdir -p /etc/systemd/network
cat > /etc/systemd/network/20-wired.network <<'EOF'
[Match]
Name=en*

[Network]
DHCP=yes
EOF
systemctl enable systemd-networkd.service

# Expéditeur : edr.log vers le manager Wazuh
install -m 0600 /dev/null /var/log/edr.log
sed -i 's/^\$PrivDrop/#&/' /etc/rsyslog.conf
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

# --one-file-system laisse /proc, /sys et /dev en dossiers vides ; /my-rootfs est exclu (il change pendant la lecture)
tar -c --one-file-system --exclude=./my-rootfs -C / . | tar -x -p --numeric-owner -C /my-rootfs
EOS
)

docker run --rm -e ROOT_PASSWORD -e USER_PASSWORD -v "$MNT:/my-rootfs" ubuntu:24.04 bash -c "$SCRIPT"
