#!/bin/bash
# Run every sequence set on the booted kernel, saving what the kernel logged
# during each set. A set whose results are already there is skipped, so a
# new set can be added without repeating the others.
#   usage: kernels/run.sh KERNEL 3-bind-behaviour/guest.sh KERNEL
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/results/$1
# timewait runs last: its TIME_WAIT sockets outlive it by a minute.
for set in pairs triples quads closes latelisten widepairs widetriples \
	   maptriples maplatelisten timewait; do
	[ -f "$OUT/$set.txt.gz" ] && continue
	dmesg -C
	python3 "$HERE/sequences.py" "$OUT" "$set" --jobs "$(nproc)"
	dmesg | grep -iE "kasan|bug:|warning:|rcu.*stall|lockdep" \
		> "$OUT/dmesg-$set.txt" || true
	echo "$set: kernel log reports: $(wc -l < "$OUT/dmesg-$set.txt")"
done
