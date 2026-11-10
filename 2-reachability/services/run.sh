#!/bin/bash
# When does the code the patch changes run on a host with real services?
# Measures, with ../fastreuse.bt, every process on the host's own kernel in
# six phases: starting the services of services.sh, leaving them idle, traffic
# to all of them at once, a desktop user browsing the web with Firefox,
# reloading or restarting the services, and stopping them.
#   usage: sudo 2-reachability/services/run.sh [SECONDS]
# Writes 2-reachability/results/services/PHASE.txt (counts per port),
# PHASE.log and summary.txt (the tables).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/../results/services
SECS=${1:-60}
mkdir -p "$OUT"
docker build -q -t bindtests-fastapi "$HERE/fastapi" > /dev/null
docker build -q -t bindtests-firefox "$HERE/firefox" > /dev/null

phase() {
	local name=$1
	local f=$OUT/$name.txt
	shift
	{
		echo "kernel:  $(uname -r)"
		echo "phase:   $name"
		echo "started: $(date -Is)"
	} > "$f"
	bpftrace -q "$HERE/../fastreuse.bt" any >> "$f" 2>&1 &
	local bt=$!
	sleep 5
	"$@" > "$OUT/$name.log" 2>&1
	sleep 1
	kill -INT "$bt"
	wait "$bt" || true
	echo "finished: $(date -Is)" >> "$f"
	grep -v "^@" "$f" || true
}

trap '"$HERE/services.sh" stop > /dev/null 2>&1' EXIT
phase start "$HERE/services.sh" start
phase idle sleep "$SECS"
phase traffic "$HERE/services.sh" traffic "$SECS" "$OUT/traffic-load.txt"
phase browsing "$HERE/services.sh" browse 120 "$OUT/browsing-load.txt"
phase reload "$HERE/services.sh" reload
phase stop "$HERE/services.sh" stop
trap - EXIT
python3 "$HERE/../report.py" services
