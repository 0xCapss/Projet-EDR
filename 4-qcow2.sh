#!/bin/bash
# Rendu : image QCOW2 compressée
set -euo pipefail
cd "$(dirname "$0")"
. ./env.sh

detach_image
mkdir -p rendu
qemu-img convert -O qcow2 -c "$IMG" rendu/disk.qcow2
ls -lh rendu/disk.qcow2
