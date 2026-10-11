#!/bin/bash
# Installation du noyau, de ses modules et de GRUB dans l'image montée
set -euo pipefail
cd "$(dirname "$0")"
. ./env.sh

require_mounted
LOOP=$(findmnt -no SOURCE "$MNT/boot")
LOOP=${LOOP%p1}
[ -f "$MNT/boot/initramfs-edr.img" ] || { echo "initramfs absente (lancer 2-rootfs.sh)"; exit 1; }

# Noyau sur /boot (partition en clair), modules sur la racine chiffrée
sudo cp "$KDIR/arch/x86/boot/bzImage" "$MNT/boot/vmlinuz-$KVER"
sudo make -C "$KDIR" INSTALL_MOD_PATH="$MNT" modules_install
sudo rm -f "$MNT/lib/modules/$KVER/build"

# Ligne de commande : racine en lecture seule (systemd la remonte selon fstab),
# IPv6 coupé, durcissement mémoire, debugfs fermé, lockdown selon env.sh
UUID=$(sudo cryptsetup luksUUID "${LOOP}p2")
CMDLINE="cryptroot=UUID=$UUID ro console=ttyS0 ipv6.disable=1"
CMDLINE="$CMDLINE slab_nomerge init_on_free=1 page_alloc.shuffle=1 pti=on randomize_kstack_offset=on debugfs=off"
if [ -n "$KERNEL_LOCKDOWN" ]; then
	CMDLINE="$CMDLINE lockdown=$KERNEL_LOCKDOWN"
fi

# Configuration du grub : /boot est la partition 1, les chemins partent de sa racine
sudo mkdir -p "$MNT/boot/grub"
sudo tee "$MNT/boot/grub/grub.cfg" >/dev/null <<EOF
serial
terminal_input serial
terminal_output serial
set root=(hd0,msdos1)
menuentry "EDR2600" {
    linux /vmlinuz-$KVER $CMDLINE
    initrd /initramfs-edr.img
}
EOF

# GRUB s'installe dans le disque entier
sudo grub-install --directory=/usr/lib/grub/i386-pc --boot-directory="$MNT/boot" "$LOOP"

# /boot réservé à root
sudo chmod -R go-rwx "$MNT/boot"

# Identité de la machine
echo edr | sudo tee "$MNT/etc/hostname" >/dev/null
sudo tee "$MNT/etc/hosts" >/dev/null <<EOF
127.0.0.1 localhost
127.0.1.1 edr
EOF

sudo ln -sf ../run/systemd/resolve/stub-resolv.conf "$MNT/etc/resolv.conf"
sudo cp issue-edr2600 "$MNT/etc/issue"
