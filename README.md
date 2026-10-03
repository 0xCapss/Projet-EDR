# Mini EDR — Noyau Linux (École 2600)

EDR minimal pour Linux reposant sur BPF-LSM. Ce dépôt contient la plateforme de test (noyau, image LFS) et, à terme, l'EDR (`edr.bpf.c`, `edrd`, `edrctl`).

Dépôt privé, réservé au groupe : le sujet interdit tout code similaire entre groupes.

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

Les scripts se lancent depuis ce dossier, dans l'ordre. `sudo` est demandé par les étapes qui touchent aux loop devices.

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

Pour quitter QEMU : `Ctrl-A` puis `X`. Prévoir `-m 2G` : la valeur par défaut est trop faible.

## Comptes

| Compte | Mot de passe | Rôle |
|---|---|---|
| `root` | `Ecole2600` | démarre l'EDR, démontre les blocages |
| `user` | `Hacker2600` | attaquant simulé (UID 1000, sans sudo) |

## Vérifier la plateforme

Dans la VM :

```
uname -r                                                   # 7.2.8
zcat /proc/config.gz | grep -E 'BPF_LSM|DEBUG_INFO_BTF|CONFIG_LSM='
ls -l /sys/kernel/btf/vmlinux                              # BTF présent (CO-RE)
mount | grep bpf                                           # bpf monté, mode=700
mount -t securityfs securityfs /sys/kernel/security && cat /sys/kernel/security/lsm
                                                           # contient bpf, pas selinux
```

`/sys/fs/bpf` est monté au boot par `bpffs.service`. systemd refuse une unité `.mount` pour ce chemin, d'où le service `oneshot`. `securityfs` n'est pas monté automatiquement : il ne sert qu'à cette vérification.

SELinux est compilé (hérité de `defconfig`) mais inactif : il ne figure pas dans `CONFIG_LSM`.

## Contenu du dépôt

```
env.sh, 0-kernel.sh … 4-qcow2.sh   fabrication
issue-edr2600                      bannière de connexion
kernel/defconfig-edr               configuration minimale du noyau
kernel/config-edr.annoté.md        options retenues et justification
20261001-edr.pdf                   sujet
architecture-miniEDR.pdf           architecture cible
```

Non versionnés (voir `.gitignore`) : images disque, source du noyau, fichiers générés.

## État

- Noyau et système validés à la main : démarrage, flags BPF-LSM, `bpffs` persistant.
- Chaîne `1-disk.sh` à `4-qcow2.sh` : à valider de bout en bout, puis démarrer le QCOW2 produit.
- À faire : réseau de la VM, `edr.bpf.c`, `edrd` (+ service systemd), `edrctl`, documentation utilisateur, scénarios de démonstration.
