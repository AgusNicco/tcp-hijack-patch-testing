#!/bin/bash
# Run every attack on the booted kernel.
#   usage: kernels/run.sh KERNEL 1-attack/guest.sh KERNEL
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/results/$1
python3 -u "$HERE/attack.py" "$OUT"
python3 -u "$HERE/outgoing.py" "$OUT"
python3 -u "$HERE/established.py" "$OUT"
python3 -u "$HERE/sweep.py" "$OUT"
dmesg | grep -iE "kasan|bug:|warning:" > "$OUT/dmesg.txt" || true
