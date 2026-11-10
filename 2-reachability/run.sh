#!/bin/bash
# Run both reachability tests on the host's own kernel.
#   usage: sudo 2-reachability/run.sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
"$HERE/scenarios/run.sh" 1000
"$HERE/services/run.sh" 60
