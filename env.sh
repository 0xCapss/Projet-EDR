# Variables et fonctions communes aux scripts de fabrication

IMG=ubuntu.img
MNT=/tmp/my-rootfs
KVER=7.2.8
KDIR=kernel/linux-$KVER

export ROOT_PASSWORD=Ecole2600
export USER_PASSWORD=Hacker2600

export PATH="$PATH:/sbin:/usr/sbin"

# Démonte l'image et détache ses loop
detach_image() {
	if mountpoint -q "$MNT"; then
		sudo umount "$MNT"
	fi
	for loop in $(losetup -j "$IMG" 2>/dev/null | cut -d: -f1); do
		sudo losetup -d "$loop"
	done
}

require_mounted() {
	mountpoint -q "$MNT" || { echo "$MNT n'est pas monté (lancer 1-disk.sh)"; exit 1; }
}
