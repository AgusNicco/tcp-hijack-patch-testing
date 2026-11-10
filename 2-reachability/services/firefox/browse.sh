#!/bin/sh
# Browse like a desktop user: open each URL in headless Firefox and keep the
# page open for PAGE seconds, so its scripts, images and video load, until
# SECONDS have passed. Prints the pages visited.
#   usage: browse.sh SECONDS PAGE URL...
SECS=$1
PAGE=$2
shift 2
cd /tmp
end=$(( $(date +%s) + SECS ))
n=0
while [ "$(date +%s)" -lt "$end" ]; do
	for url in "$@"; do
		[ "$(date +%s)" -lt "$end" ] || break
		timeout "$PAGE" firefox-esr --headless "$url" > /dev/null 2>&1
		# timeout exits with 124 when the page stayed open the whole time
		[ $? -eq 124 ] && n=$((n + 1))
	done
done
echo "Firefox pages visited: $n"
