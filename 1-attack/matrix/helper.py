#!/usr/bin/env python3
"""The other end of the attack matrix's connections, run in its own network
namespace so it behaves like another machine. One command per line on stdin,
one answer per line on stdout:

  listen PORT                 accept connections on [::]:PORT, both families
  connect FAM ADDR PORT DEV   connect out; answers "ok ID LOCALPORT"
  send ID TEXT                send on a connection held at this end
  grab PORT                   take the accepted connection whose remote port
                              is PORT and hold it by id, so a later
                              connection from the same port cannot be
                              mistaken for it; answers "ok ID REMOTEADDR"
  probe FAM ADDR PORT DEV N   N fresh connections; each reads what the
                              server sends first; answers "ok V A NONE"
  closeall                    reset and drop every held connection

DEV is an interface name for a link-local address, or "-".
"""

import errno
import select
import socket
import struct
import sys
import threading
import time

held = {}
accepted = {}
lock = threading.Lock()
LINGER0 = struct.pack("ii", 1, 0)


def addr(fam, a, port, dev):
    if fam == socket.AF_INET6 and dev != "-":
        return (a, port, 0, socket.if_nametoindex(dev))
    return (a, port)


def acceptor(srv):
    while True:
        conn, peer = srv.accept()
        with lock:
            # Several connections can share a remote port while differing in
            # remote address, so they are kept in arrival order, not replaced.
            accepted.setdefault(peer[1], []).append((conn, peer[0]))


def reply(text):
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def err(e):
    return errno.errorcode.get(e.errno, str(e.errno)) if e.errno else "timeout"


for line in sys.stdin:
    cmd, *args = line.split()
    try:
        if cmd == "listen":
            srv = socket.socket(socket.AF_INET6)
            srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("::", int(args[0])))
            srv.listen(4096)
            threading.Thread(target=acceptor, args=(srv,), daemon=True).start()
            reply("ok")
        elif cmd == "connect":
            fam = int(args[0])
            s = socket.socket(fam)
            s.settimeout(3)
            s.connect(addr(fam, args[1], int(args[2]), args[3]))
            held[s.fileno()] = s
            reply("ok %d %d" % (s.fileno(), s.getsockname()[1]))
        elif cmd == "send":
            held[int(args[0])].sendall(args[1].encode())
            reply("ok")
        elif cmd == "grab":
            got = None
            for _ in range(100):      # the accept thread may not have run yet
                with lock:
                    queue = accepted.get(int(args[0]))
                    if queue:
                        got = queue.pop(0)
                if got is not None:
                    break
                time.sleep(0.01)
            if got is None:
                reply("err noconn")
            else:
                conn, remote = got
                held[conn.fileno()] = conn
                reply("ok %d %s" % (conn.fileno(), remote))
        elif cmd == "probe":
            fam, port, n = int(args[0]), int(args[2]), int(args[4])
            counts = {"V": 0, "A": 0, "NONE": 0}
            for _ in range(n):
                s = socket.socket(fam)
                s.settimeout(1.0)
                try:
                    s.connect(addr(fam, args[1], port, args[3]))
                    got = s.recv(16)[:1].decode(errors="replace")
                    counts[got if got in counts else "NONE"] += 1
                except OSError:
                    counts["NONE"] += 1
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER0)
                s.close()
            reply("ok %d %d %d" % (counts["V"], counts["A"], counts["NONE"]))
        elif cmd == "closeall":
            with lock:
                conns = list(held.values())
                for queue in accepted.values():
                    conns += [c for c, _ in queue]
                held.clear()
                accepted.clear()
            for c in conns:
                try:
                    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER0)
                except OSError:
                    pass
                c.close()
            reply("ok")
        else:
            reply("err unknown")
    except OSError as e:
        reply("err %s" % err(e))
