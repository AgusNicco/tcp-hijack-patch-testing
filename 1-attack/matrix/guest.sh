#!/bin/bash
# Run the attack matrix on the booted kernel. Stage 2 takes its cases from
# the stage-1 positives of base, the kernel with the bug, so run base first.
# Each part is skipped when its output is already there, so the script can be
# run again to add a part without repeating the rest.
#   usage: kernels/run.sh KERNEL 1-attack/matrix/guest.sh KERNEL
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/../results/matrix/$1
CASES=$HERE/../results/matrix/base/stage1-positives.jsonl.gz
mkdir -p "$OUT"
[ -f "$OUT/stage1.json" ] || python3 -u "$HERE/stage1.py" "$OUT"
[ -f "$OUT/stage2.jsonl.gz" ] ||
	python3 -u "$HERE/stage2.py" "$OUT" "$CASES" --kinds listener,pair,low
[ -f "$OUT/connections.jsonl.gz" ] ||
	python3 -u "$HERE/stage2.py" "$OUT" "$CASES" --kinds client,child \
		--name connections
# The same question in the other order: the attacker is already on the port
# when the victim starts. Stage 1 only, since it is what decides whether this
# order admits anything the other one did not.
[ -f "$OUT/port-first.json" ] ||
	python3 -u "$HERE/stage1.py" "$OUT" --pre-all --three 0 \
		--name port-first
dmesg | grep -iE "kasan|bug:|warning:" > "$OUT/dmesg.txt" || true
