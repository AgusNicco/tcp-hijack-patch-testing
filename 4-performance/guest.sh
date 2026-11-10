#!/bin/bash
# Run every timing on the booted kernel.
#   usage: kernels/run.sh KERNEL-perf 4-performance/guest.sh KERNEL
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$HERE/bin
OUT=$HERE/results/$1
REPEATS=5
mkdir -p "$OUT"
: > "$OUT/bench.txt"
ip link set lo up
for dev in dum1 dum2; do
	ip link add "$dev" type dummy
	ip link set "$dev" up
done
for scenario in group group-plain specific alternating mixed; do
	for n in 256 1024 4096 16384; do
		"$BIN/bench" "$scenario" "$n" "$REPEATS" >> "$OUT/bench.txt"
	done
done

# The reproducer binds port 9999 and a Unix socket in its working directory.
cd /tmp
ulimit -n 65536
for _ in $(seq "$REPEATS"); do
	t0=$(date +%s%N)
	"$BIN/bacik" > /dev/null
	t1=$(date +%s%N)
	echo $(( (t1 - t0) / 1000 ))
done | sort -n | awk -v r="$REPEATS" '{ t[NR] = $1 / 1000 }
	END { printf "bacik 16384 %.2f %.2f %.2f\n", t[int((r + 1) / 2)], t[1], t[r] }' >> "$OUT/bench.txt"
dmesg | grep -iE "bug:|warning:|rcu.*stall" > "$OUT/dmesg.txt" || true
cat "$OUT/bench.txt"
