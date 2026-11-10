#!/bin/bash
# Run the bind sequences on the three kernels and compare them.
#   usage: 3-bind-behaviour/run.sh        (after kernels/build-all.sh)
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$HERE/..
for k in base proposed-patch full-scan-alternative; do
	CPUS=8 "$ROOT/kernels/run.sh" "$k" 3-bind-behaviour/guest.sh "$k"
done
for s in pairs triples quads closes latelisten widepairs widetriples \
	 maptriples maplatelisten timewait; do
	python3 "$HERE/compare.py" "$s" base proposed-patch full-scan-alternative \
		> "$HERE/results/compare-$s.txt"
	sed -n '/^agree/,/^excluded/p' "$HERE/results/compare-$s.txt" | sed "s/^/$s: /"
done
