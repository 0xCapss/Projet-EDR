#!/bin/bash
# Installation du noyau, de ses modules et de GRUB dans l'image montée
set -euo pipefail
cd "$(dirname "$0")"
. ./env.sh

require_mounted
LOOP=$(findmnt -no SOURCE "$MNT")
LOOP=${LOOP%p1}

# Noyau et modules
sudo mkdir -p "$MNT/boot/grub"
sudo cp "$KDIR/arch/x86/boot/bzImage" "$MNT/boot/vmlinuz-$KVER"
sudo make -C "$KDIR" INSTALL_MOD_PATH="$MNT" modules_install
sudo rm -f "$MNT/lib/modules/$KVER/build"

# Configuration du grub
sudo tee "$MNT/boot/grub/grub.cfg" >/dev/null <<EOF
serial
terminal_input serial
terminal_output serial
set root=(hd0,1)
menuentry "EDR2600" {
    linux /boot/vmlinuz-$KVER root=/dev/sda1 rw console=ttyS0
}
EOF

# GRUB s'installe dans le disque entier
sudo grub-install --directory=/usr/lib/grub/i386-pc --boot-directory="$MNT/boot" "$LOOP"

# Identité de la machine
echo edr | sudo tee "$MNT/etc/hostname" >/dev/null
sudo tee "$MNT/etc/hosts" >/dev/null <<EOF
127.0.0.1 localhost
127.0.1.1 edr
::1 localhost ip6-localhost ip6-loopback
EOF

sudo ln -sf ../run/systemd/resolve/stub-resolv.conf "$MNT/etc/resolv.conf"

# EDR : démon edrd, outil edrctl et service systemd (démarré au boot)
make -C src
sudo make -C src install DESTDIR="$MNT"
sudo cp issue-edr2600 "$MNT/etc/issue"
