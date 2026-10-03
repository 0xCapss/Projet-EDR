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
apt-get install -y systemd-sysv udev login util-linux iproute2 kmod libbpf1
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

# --one-file-system exclut /proc, /sys, /dev et /my-rootfs (laissés en dossiers vides)
tar -c --one-file-system -C / . | tar -x -p --numeric-owner -C /my-rootfs
rmdir /my-rootfs/my-rootfs
EOS
)

docker run --rm -e ROOT_PASSWORD -e USER_PASSWORD -v "$MNT:/my-rootfs" ubuntu:24.04 bash -c "$SCRIPT"
