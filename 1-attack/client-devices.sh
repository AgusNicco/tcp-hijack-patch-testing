#!/bin/bash
# Which device do real clients bind, when they fetch real websites?
#
# The matrix finds that a connected socket can only be interfered with when
# it is bound to a device: of its 24 connection victim shapes, every one that
# could be destroyed is device-bound, and none of the sixteen without a
# device was touched by any attack. That turns the question "are ordinary
# clients exposed?" into a question about the clients themselves, which this
# answers by watching their sockets rather than by reading their source.
#
# ss prints "%interface" after the local address when a socket is bound to
# one, so the first thing the script does is bind a socket to an interface on
# purpose and check that the suffix shows up. Without that control, a run
# where nothing is bound and a run where the check is broken look the same.
#
#   usage: sudo 1-attack/client-devices.sh        (on the host, needs the net)
#
# Needs curl, and for the browser half an /opt/ffroot chroot holding
# firefox-esr. The browser half is skipped when that is not there.
set -u
FF=${FFROOT:-/opt/ffroot}
IFACE=${IFACE:-$(ip -o -4 route show default | awk '{print $5; exit}')}
SITES="https://example.com/ https://www.google.com/ https://www.wikipedia.org/
       https://www.youtube.com/ https://github.com/"

sockets() {     # $1 = extended regex for the process name ss prints
	ss -tnpH state established 2>/dev/null | grep -E "\"($1)" |
		awk '{split($0, u, "\""); print "    " $3 "  ->  " $4 "   (" u[2] ")"}' |
		sort -u
}

echo "=== control: a socket bound to $IFACE on purpose, which must show %$IFACE"
python3 -c "
import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, sys.argv[1].encode())
s.connect(('example.com', 443))
time.sleep(4)" "$IFACE" &
ctl=$!
sleep 1.5
ss -tnpH state established | grep "pid=$ctl," |
	awk '{print "    " $3 "  ->  " $4}'
wait $ctl 2>/dev/null

echo "=== curl, as it comes"
for url in $SITES; do
	timeout 8 curl -s -o /dev/null --limit-rate 1 "$url" &
	sleep 2.5
	sockets curl
	wait 2>/dev/null
done

if [ ! -x "$FF/usr/bin/firefox-esr" ] && [ ! -x "$FF/usr/lib/firefox-esr/firefox-esr" ]; then
	echo "=== Firefox: no chroot at $FF, skipped"
	exit 0
fi
echo "=== Firefox (headless), as it comes"
mount -t proc proc "$FF/proc" 2>/dev/null
mount -t tmpfs tmpfs "$FF/tmp" 2>/dev/null
mount --bind /dev "$FF/dev" 2>/dev/null
# The image ships an empty resolv.conf; give it the host's resolver.
mount --bind "$(readlink -f /etc/resolv.conf)" "$FF/etc/resolv.conf" 2>/dev/null
for url in https://www.google.com/ https://www.youtube.com/; do
	echo "  $url"
	chroot "$FF" /bin/sh -c \
		"cd /tmp && HOME=/tmp timeout 16 firefox-esr --headless '$url' >/dev/null 2>&1" &
	sleep 10
	sockets "firefox|Socket Process|Web Content|Isolated"
	wait 2>/dev/null
done
for d in etc/resolv.conf dev tmp proc; do umount "$FF/$d" 2>/dev/null; done
