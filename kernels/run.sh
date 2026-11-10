#!/bin/bash
# Boot a kernel built by build.sh under virtme-ng and run a command as root.
#   usage: [CPUS=n] kernels/run.sh NAME COMMAND...
# The repository is visible in the guest at the same path; only the results
# folders are writable, so everything a test writes there ends up on the host.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
NAME=$1; shift
IMG=$ROOT/kernels/$NAME/bzImage
[ -f "$IMG" ] || { echo "no kernel at $IMG (run kernels/build.sh first)" >&2; exit 1; }
RW=()
# vng joins repeated --rwdir options without a separator; the trailing space
# keeps them apart.
for d in "$ROOT"/*/results; do RW+=(--rwdir "$d "); done
cd "$ROOT"
exec vng -r "$IMG" --user root --cpus "${CPUS:-2}" --memory 4G \
	"${RW[@]}" --exec "cd $ROOT && $*"
