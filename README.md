# Mini EDR - Noyau Linux (École 2600)

EDR minimal pour Linux reposant sur BPF-LSM. Ce dépôt contient la plateforme de test (noyau, image LFS) et, à terme, l'EDR (`edr.bpf.c`, `edrd`, `edrctl`).


## Plateforme

| Élément | Choix |
|---|---|
| Noyau | Linux 7.2.8 compilé par nous (`BPF_LSM`, `DEBUG_INFO_BTF`, `LSM="landlock,lockdown,yama,bpf"`) |
| Système | Ubuntu 24.04 (rootfs fabriqué via Docker), systemd |
| Disque | image MBR, une partition ext4 étiquetée `rootfs`, GRUB BIOS |
| Rendu | QCOW2 compressé (`rendu/disk.qcow2`) |

La configuration du noyau et sa justification sont dans `kernel/defconfig-edr` et `kernel/config-edr.annoté.md`.

## Prérequis (hôte Debian/Ubuntu)

```
sudo apt install docker.io qemu-system-x86 qemu-utils parted e2fsprogs grub-pc-bin \
    build-essential flex bison bc libelf-dev libssl-dev dwarves curl
```

Prévoir environ 15 Go libres (arbre du noyau compilé, image de 8 Go en fichier sparse) et 20 à 30 minutes pour la première compilation du noyau.

## Fabrication

Lancer les scripts depuis ce dossier, dans l'ordre. `sudo` sera demandé par les étapes qui touchent aux loop.

| Script | Rôle |
|---|---|
| `0-kernel.sh` | télécharge la source, configure, vérifie les flags, compile |
| `1-disk.sh` | crée `ubuntu.img`, partitionne, formate, monte sur `/tmp/my-rootfs` |
| `2-rootfs.sh` | fabrique le rootfs Ubuntu dans un conteneur et le copie sur l'image |
| `3-install.sh` | installe noyau, modules, GRUB et la configuration de la machine |
| `4-qcow2.sh` | démonte l'image et produit `rendu/disk.qcow2` |

`env.sh` regroupe les variables communes (version du noyau, mots de passe, chemins).

## Démarrage de la VM

```
qemu-system-x86_64 -drive file=rendu/disk.qcow2,format=qcow2 -nographic -m 2G
```

## Comptes

| Compte | Mot de passe | Rôle |
|---|---|---|
| `root` | `Ecole2600` | démarre l'EDR|
| `user` | `Hacker2600` | attaquant simulé |


SELinux est compilé (hérité de `defconfig`) mais inactif.

## Contenu du dépôt

```
env.sh, 0-kernel.sh … 4-qcow2.sh   fabrication
kernel/defconfig-edr               configuration minimale du noyau
kernel/config-edr.annoté.md        options retenues et justification
20261001-edr.pdf                   sujet
architecture-miniEDR.pdf           architecture cible
```


