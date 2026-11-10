#!/bin/bash
# Run the attack on the three kernels and compare them.
#   usage: 1-attack/run.sh        (after kernels/build-all.sh)
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$HERE/..
for k in base proposed-patch full-scan-alternative; do
	CPUS=4 "$ROOT/kernels/run.sh" "$k" 1-attack/guest.sh "$k"
done
python3 "$HERE/report.py"
