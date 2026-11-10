#!/bin/bash
# Run the attack matrix on the three kernels, base first.
#   usage: 1-attack/matrix/run.sh        (after kernels/build-all.sh)
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$HERE/../..
for k in base proposed-patch full-scan-alternative; do
	CPUS=8 "$ROOT/kernels/run.sh" "$k" 1-attack/matrix/guest.sh "$k"
done
python3 "$HERE/report.py"
