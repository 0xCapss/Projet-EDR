# Mini EDR: BPF agent (edr.bpf.c), daemon (edrd) and control tool (edrctl)
#
#   make                  build edr.bpf.o, edr.skel.h, edrd and edrctl
#   make install DESTDIR=/tmp/my-rootfs
#
# vmlinux.h is generated from the BTF of the target kernel, so that CO-RE
# relocations match the kernel we compiled.

CLANG     ?= clang
CC        ?= gcc
BPFTOOL   ?= $(or $(shell command -v bpftool),/usr/sbin/bpftool)
ARCH      ?= x86
VMLINUX   ?= $(firstword $(wildcard ../kernel/linux-*/vmlinux) /sys/kernel/btf/vmlinux)

PREFIX    ?= /usr
DESTDIR   ?=

# -Wno-missing-declarations: the vmlinux.h dumped from 7.x has empty forward
# declarations inside structs
# -idirafter: <linux/errno.h> includes <asm/errno.h>, which lives in the
# multiarch directory on Debian/Ubuntu
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Werror \
	     -Wno-missing-declarations -I. \
	     -idirafter /usr/include/$(shell uname -m)-linux-gnu

# Hardening (ANSSI C rules: warnings as errors, FORTIFY, stack protector,
# full RELRO, PIE). libbpf is linked statically: the LFS ships an older one.
CFLAGS   ?= -O2 -g
CFLAGS   += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -Wformat=2 -Wshadow \
	    -Wconversion -Wno-sign-conversion -D_FORTIFY_SOURCE=2 \
	    -fstack-protector-strong -fPIE -I.
LDFLAGS  += -pie -Wl,-z,relro,-z,now
LDLIBS    = -Wl,-Bstatic -lbpf -Wl,-Bdynamic -lelf -lz

.PHONY: all clean install
# A failed recipe must not leave a half-written target behind (an empty
# vmlinux.h would be taken as up to date and break every later build)
.DELETE_ON_ERROR:

all: edrd edrctl

vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX) format c > $@.tmp
	mv $@.tmp $@

edr.bpf.o: edr.bpf.c edr.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

edr.skel.h: edr.bpf.o
	$(BPFTOOL) gen skeleton $< name edr > $@

edrd.o: edrd.c edr.skel.h edr.h log.h
log.o: log.c log.h edr.h

edrd: edrd.o log.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

edrctl.o: edrctl.c edr.h

edrctl: edrctl.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

install: edrd edrctl
	install -D -m 0755 edrd $(DESTDIR)$(PREFIX)/sbin/edrd
	install -D -m 0755 edrctl $(DESTDIR)$(PREFIX)/sbin/edrctl
	install -D -m 0644 edrd.service $(DESTDIR)/lib/systemd/system/edrd.service
	install -d $(DESTDIR)/etc/systemd/system/multi-user.target.wants
	ln -sf /lib/systemd/system/edrd.service \
		$(DESTDIR)/etc/systemd/system/multi-user.target.wants/edrd.service

clean:
	rm -f edrd edrctl *.o edr.skel.h vmlinux.h
