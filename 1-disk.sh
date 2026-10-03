#!/bin/bash
# Image disque : table MBR, partition ext4 rootfs, montée sur /tmp/my-rootfs
set -euo pipefail
cd "$(dirname "$0")"
. ./env.sh

detach_image
rm -f "$IMG"
truncate -s 8G "$IMG"

# Partition à 1 MiB : espace libre pour GRUB
parted -s "$IMG" mklabel msdos mkpart primary ext4 1MiB 100% set 1 boot on

LOOP=$(sudo losetup -Pf --show "$IMG")
echo "Périphérique : $LOOP"

# Formater la partition, jamais le disque entier
sudo partprobe "$LOOP"
[ -b "${LOOP}p1" ] || { echo "${LOOP}p1 absent"; exit 1; }
sudo mkfs.ext4 -q -L rootfs "${LOOP}p1"

mkdir -p "$MNT"
sudo mount "${LOOP}p1" "$MNT"
findmnt "$MNT"
