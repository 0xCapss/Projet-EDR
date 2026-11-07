# Mini EDR - Noyau Linux (École 2600)

EDR minimal pour Linux reposant sur BPF-LSM. Ce dépôt contient la plateforme de test (noyau, image LFS) et l'EDR (`edr.bpf.c`, `edrd`, `edrctl`).

- [Guide d'utilisation](docs/utilisation.md) : démarrer l'EDR, utiliser `edrctl`, lire les alertes, scénarios de démo


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
| `admin` | `SecretPassword` | Compte SIEM Wazuh |


SELinux est compilé (hérité de `defconfig`) mais inactif.

## SIEM (Wazuh)

Hors livrable, pour la démonstration. Version Wazuh 4.14.8 (manager, indexer, dashboard) tourne sous Docker Compose dans `Wazuh/wazuh-docker-4.14.8/single-node/`.

```
cd Wazuh/wazuh-docker-4.14.8/single-node
docker compose -f generate-indexer-certs.yml run --rm generator   # une seule fois
docker compose up -d
```

Dashboard : `https://localhost`)



Les certificats générés ne sont pas versionnés.

## EDR (`src/`)

Prérequis supplémentaires sur l'hôte : `clang`, `bpftool`, `libbpf-dev`. `make -C src` génère `vmlinux.h` depuis le BTF du noyau compilé, puis `edr.bpf.o`, le squelette, `edrd` et `edrctl` (libbpf liée statiquement). `3-install.sh` installe les deux binaires et le service `edrd`, activé au boot.

| Fichier | Rôle |
|---|---|
| `edr.h` | événement, structures des maps, chemins de `edrd` dans `/sys/fs/bpf/edr/` |
| `edr.bpf.c` | hooks BPF-LSM |
| `edrd.c` | charge le BPF, épingle les maps (`/sys/fs/bpf/edr/<map>`) et les liens (`/sys/fs/bpf/edr/links/<hook>`), lit le ring buffer, écrit `/var/log/edr.log` ; état du démon dans la map `daemon_state` |
| `log.c`, `log.h` | une ligne JSON par événement (`time`, `hook`, `event`, `action`, `pid`, `ppid`, `uid`, `comm`, `path`), échappement, rotation à 10 Mio × 5 |
| `edrctl.c` | outil de contrôle : `status`, `watch`, `block`, `jail`, `stats` (voir le guide) |
| `edrd.service` | unité systemd, redémarrage automatique |

Les liens sont épinglés : si `edrd` s'arrête, le blocage continue et les maps sont réutilisées au redémarrage. `edrd -u` détache tous les hooks et supprime `/sys/fs/bpf/edr/`.

## Contenu du dépôt

```
env.sh, 0-kernel.sh … 4-qcow2.sh   fabrication
issue-edr2600                      bannière de connexion
kernel/defconfig-edr               configuration minimale du noyau
kernel/config-edr.annoté.md        options retenues et justification
Wazuh/…/single-node/               SIEM (Docker Compose, configuration, règles)
src/                               EDR : edr.bpf.c, edrd, edrctl, service
docs/                              guide d'utilisation
20261001-edr.pdf                   sujet
architecture-miniEDR.pdf           architecture cible
```


