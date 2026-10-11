# Variables et fonctions communes aux scripts de fabrication

IMG=ubuntu.img
MNT=/tmp/my-rootfs
KVER=7.2.8
KDIR=kernel/linux-$KVER

export ROOT_PASSWORD=Ecole2600
export USER_PASSWORD=Hacker2600

# Racine chiffrée : nom du volume ouvert sur l'hôte et phrase de passe demandée au démarrage
CRYPT_NAME=edr-root
LUKS_PASSPHRASE=Disk2600

# Mode lockdown du noyau (integrity, confidentiality ou vide pour le désactiver).
# integrity refuse les modules non signés : le bonus rootkit se fait sur une autre machine
KERNEL_LOCKDOWN=integrity

export PATH="$PATH:/sbin:/usr/sbin"

# Démonte l'image (racine et /boot), ferme le volume LUKS et détache ses loop
detach_image() {
	if mountpoint -q "$MNT"; then
		sudo umount -R "$MNT"
	fi
	if [ -e "/dev/mapper/$CRYPT_NAME" ]; then
		sudo cryptsetup close "$CRYPT_NAME"
	fi
	for loop in $(losetup -j "$IMG" 2>/dev/null | cut -d: -f1); do
		sudo losetup -d "$loop"
	done
}

require_mounted() {
	mountpoint -q "$MNT" || { echo "$MNT n'est pas monté (lancer 1-disk.sh)"; exit 1; }
	mountpoint -q "$MNT/boot" || { echo "$MNT/boot n'est pas monté (lancer 1-disk.sh)"; exit 1; }
}
