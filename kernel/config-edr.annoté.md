# Configuration du noyau — Mini EDR (linux-7.2.8)

Base : `make defconfig` (x86_64), puis les modifications ci-dessous.
Fichiers associés :
- `defconfig-edr` : configuration minimale (273 lignes), obtenue par `make savedefconfig`. Elle suffit à régénérer le `.config` complet avec `make defconfig KBUILD_DEFCONFIG=...` ou `cp defconfig-edr .config && make olddefconfig`.
- `.config` : configuration complète (~5500 lignes, dont l'essentiel vient de `defconfig`).

## 1. Options exigées

| Option | Valeur | Rôle | Fonctionnalité concerné |
|---|---|---|---|
| `CONFIG_BPF` | `y` | Noyau BPF de base | tout l'EDR |
| `CONFIG_BPF_SYSCALL` | `y` | Appel système `bpf()` : charger programmes, maps, liens | `edrd` (libbpf), `edrctl` (maps pinnées) |
| `CONFIG_BPF_JIT` | `y` | Compile le bytecode BPF en code natif ; sans lui, interprète lent | performances des hooks |
| `CONFIG_BPF_LSM` | `y` | Autorise les programmes `SEC("lsm/...")`. Dépend de `BPF_SYSCALL` et `SECURITY` | les 7 hooks BPF-LSM |
| `CONFIG_LSM` | `"landlock,lockdown,yama,bpf"` | Liste ordonnée des LSM actifs au boot. `bpf` doit y figurer, sinon les programmes BPF-LSM ne sont jamais appelés | tous les hooks |
| `CONFIG_DEBUG_INFO_BTF` | `y` | Génère `/sys/kernel/btf/vmlinux`, indispensable à CO-RE. Exige `pahole` (paquet `dwarves`) à la compilation | portabilité de `edr.bpf.c` (`vmlinux.h`) |

## 2. Options modifiées par rapport à `defconfig`

| Option | Avant | Après | Raison |
|---|---|---|---|
| `CONFIG_DEBUG_INFO_NONE` | `y` | désactivée | Bloquait `DEBUG_INFO_BTF` |
| `CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT` | `n` | `y` | Format DWARF requis par `DEBUG_INFO_BTF` |
| `CONFIG_SECURITY_YAMA` | `n` | `y` | Restreint `ptrace` ; complète le hook `ptrace_access_check` |
| `CONFIG_SECURITY_LOCKDOWN_LSM` | `n` | `y` | LSM de base de la liste par défaut du noyau |
| `CONFIG_SECURITY_LANDLOCK` | `n` | `y` | LSM de base de la liste par défaut du noyau |
| `CONFIG_MODULE_SIG` | `n` | `y` | Imposé par `SECURITY_LOCKDOWN_LSM` (`select MODULE_SIG if MODULES`). Le noyau signe ses modules, la clé est générée à la compilation |
| `CONFIG_MODULE_SIG_FORCE` | — | **`n`** | Volontairement désactivé : exiger des modules signés ferait refuser tout `.ko` par la vérification de signature avant que le hook `kernel_load_data` ne s'exécute. Le blocage des modules doit venir de BPF-LSM, pas de la signature (et le bonus rootkit exige des `.ko` non signés) |
| `CONFIG_MODULE_SIG_ALL`, `CONFIG_MODULE_SIG_SHA512` | — | `y` | Signature automatique des modules compilés avec le noyau, avec SHA-512 |
| `CONFIG_LSM` | liste de 11 LSM | `landlock,lockdown,yama,bpf` | Ne lister que les LSM réellement compilés |

## 3. Options héritées de `defconfig`, nécessaires au boot de la VM

Ces options n'ont pas été modifiées. Elles sont listées parce que le démarrage sans initramfs (`root=/dev/sda1`) en dépend.

| Option | Valeur | Pourquoi c'est nécessaire |
|---|---|---|
| `CONFIG_EXT4_FS` | `y` (en dur) | Monter le rootfs sans initramfs : un module ne serait pas chargeable avant le montage de `/` |
| `CONFIG_SATA_AHCI`, `CONFIG_BLK_DEV_SD` | `y` | Disque vu comme `/dev/sda` avec `-hda` sous QEMU |
| `CONFIG_VIRTIO_BLK` | `y` | Disque virtio (`/dev/vda`), option de repli |
| `CONFIG_SERIAL_8250_CONSOLE` | `y` | Console série `console=ttyS0` (`-nographic`) |
| `CONFIG_DEVTMPFS`, `CONFIG_DEVTMPFS_MOUNT` | `y` | `/dev` peuplé automatiquement |
| `CONFIG_CGROUPS`, `CONFIG_FHANDLE`, `CONFIG_AUTOFS_FS`, `CONFIG_SECCOMP` | `y` | Prérequis de systemd (Ubuntu) |
| `CONFIG_MODULES` | `y` | Nécessaire pour la démo : `insmod` d'un `.ko` doit être tenté, puis bloqué par `kernel_load_data` |
| `CONFIG_E1000`, `CONFIG_VIRTIO_NET` | `y` | Réseau QEMU, utile pour le hook `socket_connect` et le lien vers Wazuh |

## 4. Choix de sécurité à justifier dans le rapport

### SELinux et AppArmor
- **AppArmor** : non compilé (`CONFIG_SECURITY_APPARMOR` non défini). Un AppArmor activé sans profils n'apporterait aucune protection.
- **SELinux** : compilé (`CONFIG_SECURITY_SELINUX=y`, hérité de `defconfig`) mais **inactif**. Un LSM n'est initialisé au boot que s'il figure dans `CONFIG_LSM` (ou dans le paramètre `lsm=`) ; `selinux` n'y figure pas, donc ses hooks ne sont pas enregistrés.  la VM n'embarque ni politique SELinux ni Le confinement est assuré par BPF-LSM.


### Limitation de l'API `bpf()` pour un utilisateur non privilégié
`CONFIG_BPF_UNPRIV_DEFAULT_OFF` : à activer si l'on veut que `kernel.unprivileged_bpf_disabled` soit à 1 dès le démarrage. L'architecture (flux user → maps pinnées, cellule ✕) l'exige. Sinon, le positionner par `sysctl` dans le script de démarrage.

## 5. Régénérer la configuration

```
cp defconfig-edr linux-7.2.8/.config
make -C linux-7.2.8 olddefconfig
```
