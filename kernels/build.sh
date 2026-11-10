#!/bin/bash
# Build a kernel for the bind tests, optionally with patches applied.
#   usage: [FRAG=fragment] kernels/build.sh SRCDIR NAME [PATCH...]
# FRAG defaults to kernels/config.fragment. The config is generated from scratch
# (virtme-ng defaults plus FRAG; an existing .config would win over FRAG) and checked
# against the fragment before compiling, and checked again afterwards: every
# option the fragment sets must be in the final .config, or the build stops.
# The exact inputs are recorded next to the kernel image, so every result can
# be traced back to what produced it.
set -eu
SRC=$1; NAME=$2; shift 2
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/$NAME
FRAG=$(realpath "${FRAG:-$HERE/config.fragment}")
PATCHES=()
for p in "$@"; do PATCHES+=("$(realpath "$p")"); done
set -- "${PATCHES[@]+"${PATCHES[@]}"}"

check_config() {
	local bad=0 line opt want have
	while read -r line; do
		case "$line" in
		"# CONFIG_"*" is not set") opt=${line#\# }; opt=${opt%% *}; want=n ;;
		CONFIG_*=*) opt=${line%%=*}; want=${line#*=} ;;
		*) continue ;;
		esac
		have=$(sed -n "s/^$opt=//p" .config)
		[ -n "$have" ] || have=n
		if [ "$have" != "$want" ]; then
			echo "config: $opt is $have, $(basename "$FRAG") wants $want" >&2
			bad=1
		fi
	done < "$FRAG"
	return $bad
}

mkdir -p "$OUT"
cd "$SRC"
git checkout -q -- .
BASE=$(git rev-parse HEAD)
for p in "$@"; do git apply "$p"; done
rm -f .config
vng --kconfig --config "$FRAG" >"$OUT/build.log" 2>&1
check_config || { echo "config check failed before building" >&2; git checkout -q -- .; exit 1; }
vng --build --config "$FRAG" >>"$OUT/build.log" 2>&1
check_config || { echo "config check failed after building" >&2; git checkout -q -- .; exit 1; }
{
	echo "name:        $NAME"
	echo "base:        $BASE"
	echo "patches:     ${*:-none}"
	echo "config:      $(basename "$FRAG")"
	echo "built:       $(date -Is)"
	echo "host:        $(uname -r) $(nproc) cpus"
	echo "kernel:      $(file -b arch/x86/boot/bzImage | sed -n "s/.*version \([^ ]*\).*/\1/p")"
	for p in "$@"; do echo "patch-sha256: $(sha256sum "$p")"; done
} > "$OUT/kernel.txt"
cp .config "$OUT/config"
cp arch/x86/boot/bzImage "$OUT/bzImage"
git checkout -q -- .
echo "built $NAME (metadata in $OUT)"
