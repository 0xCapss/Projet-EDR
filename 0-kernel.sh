#!/bin/bash
# Noyau : Configuration du noyau
set -euo pipefail
cd "$(dirname "$0")"
. ./env.sh

command -v pahole >/dev/null || { echo "pahole absent (paquet dwarves), requis par DEBUG_INFO_BTF"; exit 1; }

if [ ! -d "$KDIR" ]; then
	mkdir -p kernel
	curl -L -o "kernel/linux-$KVER.tar.xz" "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-$KVER.tar.xz"
	tar -xf "kernel/linux-$KVER.tar.xz" -C kernel
	rm "kernel/linux-$KVER.tar.xz"
fi

cd "$KDIR"
make defconfig

# BPF-LSM et CO-RE (BTF)
scripts/config --enable BPF_SYSCALL --enable BPF_JIT --enable BPF_LSM
scripts/config --disable DEBUG_INFO_NONE --enable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT --enable DEBUG_INFO_BTF

# Les programmes BPF-LSM s'attachent par trampoline BPF : il faut que les
# fonctions noyau aient un emplacement patchable (sinon attach -> EBUSY)
scripts/config --enable FUNCTION_TRACER --enable DYNAMIC_FTRACE

# LSM actifs
scripts/config --enable SECURITY_YAMA --enable SECURITY_LOCKDOWN_LSM --enable SECURITY_LANDLOCK
scripts/config --set-str LSM "landlock,lockdown,yama,bpf"

# Lockdown impose MODULE_SIG
scripts/config --enable MODULE_SIG --disable MODULE_SIG_FORCE

scripts/config --enable SECURITYFS --enable IKCONFIG --enable IKCONFIG_PROC

make olddefconfig

for opt in BPF_SYSCALL BPF_JIT BPF_LSM DEBUG_INFO_BTF SECURITYFS IKCONFIG_PROC \
	FUNCTION_TRACER DYNAMIC_FTRACE DYNAMIC_FTRACE_WITH_DIRECT_CALLS; do
	[ "$(scripts/config --state "$opt")" = y ] || { echo "CONFIG_$opt n'est pas activé"; exit 1; }
done
grep -q '^CONFIG_LSM=.*bpf' .config || { echo "bpf absent de CONFIG_LSM"; exit 1; }

make -j"$(nproc)"

# Configuration minimale à rendre
make savedefconfig
mv defconfig ../defconfig-edr
