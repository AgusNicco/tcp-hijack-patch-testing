#!/bin/bash
# Build the kernels for the performance tests, without KASAN, from a net
# checkout at 19a227903e65. The last two revert the first-bind fix
# (947ccedf683e), as on kernels from v6.8 that do not have it.
#   usage: kernels/build-perf.sh SRCDIR
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC=$1
P=$ROOT/patches
export FRAG=$ROOT/kernels/config-perf.fragment
"$ROOT/kernels/build.sh" "$SRC" base-perf
"$ROOT/kernels/build.sh" "$SRC" proposed-patch-perf "$P/proposed-patch.patch"
"$ROOT/kernels/build.sh" "$SRC" full-scan-alternative-perf "$P/full-scan-alternative.patch"
"$ROOT/kernels/build.sh" "$SRC" base-without-first-bind-fix-perf "$P/revert-first-bind-fix.patch"
"$ROOT/kernels/build.sh" "$SRC" proposed-patch-without-first-bind-fix-perf \
	"$P/revert-first-bind-fix.patch" "$P/proposed-patch.patch"
