#!/bin/bash
# Time bind() and listen() on the five performance kernels.
#   usage: 4-performance/run.sh        (after kernels/build-perf.sh)
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$HERE/..
mkdir -p "$HERE/bin"
gcc -O2 -Wall -o "$HERE/bin/bench" "$HERE/bench.c"
gcc -O2 -o "$HERE/bin/bacik" "$HERE/bacik-2017.c" -lpthread
for k in base proposed-patch full-scan-alternative \
	 base-without-first-bind-fix proposed-patch-without-first-bind-fix; do
	CPUS=8 "$ROOT/kernels/run.sh" "$k-perf" 4-performance/guest.sh "$k"
done
python3 "$HERE/report.py"
