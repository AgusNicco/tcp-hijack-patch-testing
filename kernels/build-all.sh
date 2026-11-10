#!/bin/bash
# Build the three test kernels from a net checkout at 19a227903e65.
#   usage: kernels/build-all.sh SRCDIR
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC=$1
"$ROOT/kernels/build.sh" "$SRC" base
"$ROOT/kernels/build.sh" "$SRC" proposed-patch "$ROOT/patches/proposed-patch.patch"
"$ROOT/kernels/build.sh" "$SRC" full-scan-alternative "$ROOT/patches/full-scan-alternative.patch"
