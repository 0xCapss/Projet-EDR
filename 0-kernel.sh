#!/bin/bash
# Noyau : Configuration du noyau
set -euo pipefail
cd "$(dirname "$0")"
. ./env.sh

command -v pahole >/dev/null || { echo "pahole absent (paquet dwarves), requis par DEBUG_INFO_BTF"; exit 1; }

if [ ! -d "$KDIR" ]; then
	mkdir -p kernel
	# HTTPS imposé, puis contrôle de l'archive contre les empreintes publiées par kernel.org
	url="https://cdn.kernel.org/pub/linux/kernel/v${KVER%%.*}.x"
	curl --proto '=https' --tlsv1.2 -fL -o "kernel/linux-$KVER.tar.xz" "$url/linux-$KVER.tar.xz"
	curl --proto '=https' --tlsv1.2 -fL -o kernel/sha256sums.asc "$url/sha256sums.asc"
	(cd kernel && grep " linux-$KVER.tar.xz\$" sha256sums.asc | sha256sum -c -)
	tar -xf "kernel/linux-$KVER.tar.xz" -C kernel
	rm "kernel/linux-$KVER.tar.xz" kernel/sha256sums.asc
fi

cd "$KDIR"
make defconfig

# BPF-LSM et CO-RE (BTF)
scripts/config --enable BPF_SYSCALL --enable BPF_JIT --enable BPF_LSM
scripts/config --disable DEBUG_INFO_NONE --enable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT --enable DEBUG_INFO_BTF

# Les programmes BPF-LSM s'attachent par trampoline BPF : il faut que les
# fonctions noyau aient un emplacement patchable (sinon attach -> EBUSY)
scripts/config --enable FUNCTION_TRACER --enable DYNAMIC_FTRACE

# LSM actifs : AppArmor remplace SELinux (compilé mais inactif jusqu'ici).
# Le noyau s'arrête au premier LSM qui refuse : bpf passe avant yama, landlock
# et apparmor pour que l'EDR voie toutes les tentatives, même celles qu'ils bloqueraient
scripts/config --enable SECURITY_YAMA --enable SECURITY_LOCKDOWN_LSM --enable SECURITY_LANDLOCK
scripts/config --enable SECURITY_APPARMOR --disable SECURITY_SELINUX
scripts/config --set-str LSM "lockdown,bpf,landlock,yama,apparmor"

# Lockdown impose MODULE_SIG
scripts/config --enable MODULE_SIG --disable MODULE_SIG_FORCE

scripts/config --enable SECURITYFS --enable IKCONFIG --enable IKCONFIG_PROC

# bpf() réservé aux processus privilégiés dès le démarrage
scripts/config --enable BPF_UNPRIV_DEFAULT_OFF

# Filtrage réseau par cgroup : utilisé par le confinement systemd des services
# (IPAddressDeny de journald, networkd, logind…), sinon ignoré avec un avertissement
scripts/config --enable CGROUP_BPF

# Racine chiffrée : initramfs, dm-crypt et AES-XTS compilés en dur (pas de modules dans l'initramfs)
scripts/config --enable BLK_DEV_INITRD --enable RD_GZIP
scripts/config --enable MD --enable BLK_DEV_DM --enable DM_CRYPT
scripts/config --enable CRYPTO_AES --enable CRYPTO_AES_NI_INTEL --enable CRYPTO_XTS --enable CRYPTO_SHA256
scripts/config --enable CRYPTO_USER_API_HASH --enable CRYPTO_USER_API_SKCIPHER

# Pare-feu : nf_tables et la couche de compatibilité iptables utilisées par ufw (iptables-nft)
scripts/config --enable NETFILTER --enable NETFILTER_ADVANCED --enable NF_CONNTRACK
scripts/config --enable NF_TABLES --enable NF_TABLES_INET --enable NF_TABLES_IPV4 \
	--enable NFT_COMPAT --enable NFT_CT --enable NFT_LOG --enable NFT_LIMIT --enable NFT_REJECT
scripts/config --enable NETFILTER_XTABLES --enable NETFILTER_XT_MATCH_CONNTRACK \
	--enable NETFILTER_XT_MATCH_STATE --enable NETFILTER_XT_MATCH_ADDRTYPE \
	--enable NETFILTER_XT_MATCH_LIMIT --enable NETFILTER_XT_MATCH_RECENT \
	--enable NETFILTER_XT_MATCH_MULTIPORT --enable NETFILTER_XT_MATCH_COMMENT \
	--enable NETFILTER_XT_TARGET_LOG
scripts/config --enable IP_NF_IPTABLES --enable IP_NF_FILTER --enable IP_NF_TARGET_REJECT

# Durcissement mémoire et fuites d'information
scripts/config --enable HARDENED_USERCOPY --enable FORTIFY_SOURCE
scripts/config --enable SLAB_FREELIST_RANDOM --enable SLAB_FREELIST_HARDENED --enable SHUFFLE_PAGE_ALLOCATOR
scripts/config --enable INIT_ON_ALLOC_DEFAULT_ON --enable RANDOMIZE_KSTACK_OFFSET_DEFAULT
scripts/config --enable BUG_ON_DATA_CORRUPTION --enable LIST_HARDENED --enable SCHED_STACK_END_CHECK
scripts/config --enable SECURITY_DMESG_RESTRICT
scripts/config --enable LEGACY_VSYSCALL_NONE --disable LEGACY_VSYSCALL_XONLY

# Fonctions inutiles à la VM et exploitables : remplacement du noyau (kexec), mise en
# veille sur disque, lecture de la mémoire (/proc/kcore, /dev/mem, /dev/port),
# ABI 32 bits, LDT, binfmt_misc (persistance), io_uring (contourne la surveillance
# par appels système), injection de saisie par TIOCSTI, accès direct aux ports d'E/S.
# EXPERT rend réglables MODIFY_LDT_SYSCALL et IO_URING, sinon olddefconfig les remet à y
scripts/config --enable EXPERT
scripts/config --disable KEXEC --disable KEXEC_FILE --disable CRASH_DUMP --disable HIBERNATION
scripts/config --disable PROC_KCORE --disable DEVMEM --disable DEVPORT
scripts/config --disable IA32_EMULATION --disable X86_X32_ABI --disable MODIFY_LDT_SYSCALL
scripts/config --disable BINFMT_MISC --disable IO_URING --disable LEGACY_TIOCSTI --disable X86_IOPL_IOPERM

make olddefconfig

for opt in BPF_SYSCALL BPF_JIT BPF_LSM DEBUG_INFO_BTF SECURITYFS IKCONFIG_PROC \
	FUNCTION_TRACER DYNAMIC_FTRACE DYNAMIC_FTRACE_WITH_DIRECT_CALLS \
	SECURITY_APPARMOR BPF_UNPRIV_DEFAULT_OFF CGROUP_BPF \
	BLK_DEV_INITRD RD_GZIP BLK_DEV_DM DM_CRYPT CRYPTO_XTS \
	NF_TABLES NFT_COMPAT NETFILTER_XT_MATCH_CONNTRACK NETFILTER_XT_TARGET_LOG \
	HARDENED_USERCOPY SLAB_FREELIST_HARDENED SECURITY_DMESG_RESTRICT; do
	[ "$(scripts/config --state "$opt")" = y ] || { echo "CONFIG_$opt n'est pas activé"; exit 1; }
done
for opt in SECURITY_SELINUX KEXEC HIBERNATION PROC_KCORE DEVMEM IA32_EMULATION \
	MODIFY_LDT_SYSCALL BINFMT_MISC IO_URING; do
	[ "$(scripts/config --state "$opt")" != y ] || { echo "CONFIG_$opt est encore activé"; exit 1; }
done
grep -qx 'CONFIG_LSM="lockdown,bpf,landlock,yama,apparmor"' .config || { echo "CONFIG_LSM inattendu"; exit 1; }

make -j"$(nproc)"

# Configuration minimale à rendre
make savedefconfig
mv defconfig ../defconfig-edr
