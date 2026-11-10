#!/bin/bash
# Trace which of the patch's code paths each scenario of scenarios.py reaches.
# Runs on the host's own kernel, each scenario in a fresh network namespace.
#   usage: sudo 2-reachability/scenarios/run.sh [N]
# Writes 2-reachability/results/scenarios.txt (counts per port) and
# scenarios-summary.txt (the table).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
N=${1:-1000}
OUT=$HERE/../results/scenarios.txt
{
	echo "kernel: $(uname -r)"
	echo "N:      $N"
} > "$OUT"
for s in connect data port0 named group group-strict group-specific; do
	echo "=== $s" >> "$OUT"
	bpftrace -q "$HERE/../fastreuse.bt" bindpaths >> "$OUT" 2>&1 &
	BT=$!
	sleep 5
	unshare -n python3 "$HERE/scenarios.py" "$s" "$N"
	sleep 1
	kill -INT "$BT"
	wait "$BT" || true
done
python3 "$HERE/../report.py" scenarios
