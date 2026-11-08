#!/bin/bash
# Image disque : table MBR, /boot en clair, racine ext4 chiffrée LUKS2, montées sur /tmp/my-rootfs
set -euo pipefail
cd "$(dirname "$0")"
. ./env.sh

command -v cryptsetup >/dev/null || { echo "cryptsetup absent (paquet cryptsetup-bin)"; exit 1; }

detach_image
rm -f "$IMG"
truncate -s 8G "$IMG"

# Partition 1 à 1 MiB (espace libre pour GRUB) : /boot, lue par GRUB donc non chiffrée
# (noyau, initramfs, grub.cfg). Partition 2 : conteneur LUKS2 de la racine
parted -s "$IMG" mklabel msdos \
	mkpart primary ext4 1MiB 257MiB set 1 boot on \
	mkpart primary 257MiB 100%

LOOP=$(sudo losetup -Pf --show "$IMG")
echo "Périphérique : $LOOP"

# Formater les partitions, jamais le disque entier.
# partprobe fait recréer loopXp1/p2 par udev : on attend qu'il ait fini avant mkfs
sudo partprobe "$LOOP"
sudo udevadm settle
for part in "${LOOP}p1" "${LOOP}p2"; do
	[ -b "$part" ] || { echo "$part absent"; exit 1; }
done
sudo mkfs.ext4 -q -L boot "${LOOP}p1"

# LUKS2 AES-XTS. Coût argon2id fixé (4 passes, 128 MiB, 1 fil) plutôt que mesuré sur
# l'hôte : la VM sous QEMU est bien plus lente et peut avoir peu de mémoire.
# printf sans retour à la ligne : même phrase que celle tapée au démarrage
printf '%s' "$LUKS_PASSPHRASE" | sudo cryptsetup luksFormat --batch-mode --type luks2 \
	--cipher aes-xts-plain64 --key-size 512 --hash sha256 \
	--pbkdf argon2id --pbkdf-force-iterations 4 --pbkdf-memory 131072 --pbkdf-parallel 1 \
	--key-file - "${LOOP}p2"
printf '%s' "$LUKS_PASSPHRASE" | sudo cryptsetup open --key-file - "${LOOP}p2" "$CRYPT_NAME"
sudo mkfs.ext4 -q -L rootfs "/dev/mapper/$CRYPT_NAME"

mkdir -p "$MNT"
sudo mount "/dev/mapper/$CRYPT_NAME" "$MNT"
sudo mkdir -p "$MNT/boot"
sudo mount "${LOOP}p1" "$MNT/boot"
findmnt -R "$MNT"
