#!/usr/bin/env python3
"""Capture the packets that end a device-bound connection when the attacker
binds its address and port and connects to its peer.

  usage: why-connections-die.py        (as root, in the guest)

The matrix records that such a connection stops working, but not how. This
runs one case of each kind with a capture on the peer's link, so the sequence
that ends it is on record rather than reasoned about:

  outgoing   a connected socket bound to a device, as a client gets when it
             pins itself to an interface
  accepted   the server side of a connection, from a listener bound to a
             device, which the child inherits

In each case the victim's connection is made first, then the attacker binds
the victim's exact address and port -- which the bug admits, because the
attacker's earlier socket names a different device -- and calls connect() to
the victim's peer. Then the peer sends on the victim's connection.
"""

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env      # noqa: E402
import space    # noqa: E402

PORT = 24000
# (family, address, v6only, device, SO_REUSEADDR, SO_REUSEPORT)
SEED_V4_ABSENT_DEV = (space.V4, "0.0.0.0", None, "absent", 0, 1)
SEED_V4_ANY = (space.V4, "0.0.0.0", None, None, 0, 1)
HIJACK_V4_ANY = (space.V4, "0.0.0.0", None, None, 0, 1)
HIJACK_V6_DUAL = (space.V6, "::", False, None, 0, 1)


def capture(path):
    p = subprocess.Popen(
        ["ip", "netns", "exec", "peer", "tcpdump", "-ni", "vp",
         "--immediate-mode", "tcp", "-w", path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.6)             # let it attach before anything is sent
    return p


def show(path):
    out = subprocess.run(["tcpdump", "-nr", path, "-ttt"],
                         capture_output=True, text=True)
    text = out.stdout.strip() or out.stderr.strip()
    for line in text.splitlines():
        print("   " + line)


def attack(port, seed, hijack, dest):
    with env.attacker():
        s, scode = env.bind(seed, port)
        h, hcode = env.bind(hijack, port)
    print("   attacker's earlier socket: %s, victim's own address and port: %s"
          % (scode, hcode))
    if h is None:
        return s, None
    h.settimeout(2)
    try:
        h.connect(dest)
        print("   attacker's connect(): accepted")
    except OSError as e:
        print("   attacker's connect(): %s" % env.code(e))
    return s, h


def finish(peer, conn_id, victim, mine, path, cap):
    r = peer.cmd("send", conn_id, "PING")
    print("   peer sends on the victim's connection: %s" % " ".join(r))
    victim.settimeout(1.5)
    try:
        print("   victim receives: %d bytes" % len(victim.recv(64)))
    except OSError as e:
        print("   victim receives: nothing (%s)" % env.code(e))
    time.sleep(0.6)
    env.reset_close(mine)
    # tcpdump writes the file as it goes; it has to be stopped before the
    # file can be read back, or there is nothing in it yet.
    cap.terminate()
    cap.wait(5)
    show(path)


def outgoing(peer, path):
    print("=== a client pinned to an interface, connected out")
    v = env.new_socket((space.V4, None, None, "vh", 0, 0))
    v.settimeout(3)
    v.connect((space.PEER_V4, PORT))
    port, dest = v.getsockname()[1], v.getpeername()
    r = peer.cmd("grab", port)
    print("   victim's local port %d, peer %s, peer sees %s"
          % (port, dest, r[2] if r[0] == "ok" else r))
    cap = capture(path)
    s, h = attack(port, SEED_V4_ABSENT_DEV, HIJACK_V4_ANY, dest)
    second = peer.cmd("grab", port)
    if second[0] == "ok":
        print("   peer now also holds a connection from %s on that port"
              % second[2])
    finish(peer, r[1], v, [v, s, h], path, cap)


def accepted(peer, path):
    print("=== the server side of a connection, listener bound to a device")
    port = PORT + 1
    srv, code = env.bind((space.V6, "::", True, "vh", 0, 0), port)
    if srv is None:
        print("   the listener could not bind: %s" % code)
        return
    srv.listen(8)
    r = peer.cmd("connect", int(space.V6), space.HOST_V6, port, "-")
    if r[0] != "ok":
        print("   the peer could not connect: %s" % " ".join(r))
        env.reset_close([srv])
        return
    conn_id = r[1]
    srv.settimeout(3)
    child, peername = srv.accept()
    print("   the connection the listener accepted, from %s" % (peername,))
    cap = capture(path)
    s, h = attack(port, SEED_V4_ANY, HIJACK_V6_DUAL, peername[:2])
    finish(peer, conn_id, child, [child, srv, s, h], path, cap)


def main():
    env.setup_network()
    peer = env.Helper("peer")
    peer.cmd("listen", PORT)
    outgoing(peer, "/tmp/die-out.pcap")
    print()
    accepted(peer, "/tmp/die-acc.pcap")
    peer.stop()


if __name__ == "__main__":
    main()
