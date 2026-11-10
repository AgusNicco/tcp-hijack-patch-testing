#!/usr/bin/env python3
"""Is a service that binds both families really out of reach?

For the services that bind both IPv4 and IPv6, try every seed shape an
unprivileged user can bind, and for each one that the kernel admits, try
every socket shape that overlaps the service. A pair that both binds is an
attack; none that binds is evidence that there is no seed, rather than a
claim that there is none.

  usage: sweep.py OUTDIR [SERVICE...]        (as root)

Each seed shape gets a fresh service on a fresh port, so one attempt cannot
leave a summary behind that changes the next. Writes OUTDIR/sweep.txt.

Only services that every overlap probe overlaps are swept, which is the
services that cover both families. Against any other service, a probe that
does not overlap it binds, is closed, and leaves the port's summary
describing it, so the seed that follows is not the only thing on the port's
record. attack.py covers those services directly.
"""

import errno
import os
import pwd
import socket
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import services                                            # noqa: E402

SO_REUSEPORT = getattr(socket, "SO_REUSEPORT", 15)
SO_BINDTOIFINDEX = getattr(socket, "SO_BINDTOIFINDEX", 62)
NOBODY = pwd.getpwnam("nobody")
PORT = 19400

V4, V6 = socket.AF_INET, socket.AF_INET6

# (label, family, address, IPV6_V6ONLY, device, SO_REUSEADDR)
SEEDS = [
    ("0.0.0.0", V4, "0.0.0.0", None, None, False),
    ("0.0.0.0 + absent device", V4, "0.0.0.0", None, "absent", False),
    ("0.0.0.0 + lo", V4, "0.0.0.0", None, "lo", False),
    ("0.0.0.0 + SO_REUSEADDR", V4, "0.0.0.0", None, None, True),
    ("127.0.0.2", V4, "127.0.0.2", None, None, False),
    ("127.0.0.2 + absent device", V4, "127.0.0.2", None, "absent", False),
    ("[::] v6only", V6, "::", True, None, False),
    ("[::] v6only + absent device", V6, "::", True, "absent", False),
    ("[::] v6only + SO_REUSEADDR", V6, "::", True, None, True),
    ("[::] dual-stack", V6, "::", False, None, False),
    ("[::] dual-stack + absent device", V6, "::", False, "absent", False),
    ("[::1]", V6, "::1", False, None, False),
    ("[::2]", V6, "::2", False, None, False),
    ("[::ffff:127.0.0.2] mapped", V6, "::ffff:127.0.0.2", False, None, False),
    ("[fe80::1%lo] link-local", V6, "fe80::1%lo", False, None, False),
    ("[::1] v6only", V6, "::1", True, None, False),
]

# The sockets that overlap a service listening on every address.
HIJACKS = [
    ("0.0.0.0", V4, "0.0.0.0", None),
    ("127.0.0.1", V4, "127.0.0.1", None),
    ("[::] dual-stack", V6, "::", False),
    ("[::1] dual-stack", V6, "::1", False),
    ("[::] v6only", V6, "::", True),
]


def make(family, addr, v6only, device, reuseaddr, port):
    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        if v6only is not None:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, int(v6only))
        if reuseaddr:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
        if device == "absent":
            # SO_BINDTOIFINDEX does not check that the interface exists.
            s.setsockopt(socket.SOL_SOCKET, SO_BINDTOIFINDEX, 4242)
        elif device:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                         device.encode())
        s.bind(socket.getaddrinfo(addr, port, family,
                                  socket.SOCK_STREAM)[0][4])
        return s, "ok"
    except OSError as e:
        s.close()
        return None, errno.errorcode.get(e.errno, str(e.errno))


def child(port, wfd, index):
    """Try one seed shape, and under it every socket that overlaps the
    service. Only one shape per service instance, so nothing an earlier
    attempt left in the port's summary can change this one."""
    os.setgroups([])
    os.setgid(NOBODY.pw_gid)
    os.setuid(NOBODY.pw_uid)
    out = os.fdopen(wfd, "w")

    # Which shapes overlap this service? The ones the kernel refuses on
    # their own are the ones worth trying under a seed.
    overlapping = []
    for label, family, addr, v6only in HIJACKS:
        s, res = make(family, addr, v6only, None, False, port)
        if s:
            s.close()
        else:
            overlapping.append((label, family, addr, v6only, res))
    out.write("overlapping %d\n" % len(overlapping))

    slabel, sfamily, saddr, sv6only, sdev, sreuse = SEEDS[index]
    seed, sres = make(sfamily, saddr, sv6only, sdev, sreuse, port)
    if not seed:
        out.write("seed %-30s refused, %s\n" % (slabel, sres))
    else:
        results = []
        for hlabel, hfamily, haddr, hv6only, _ in overlapping:
            h, hres = make(hfamily, haddr, hv6only, None, False, port)
            if h:
                h.close()
            results.append("%s=%s" % (hlabel.replace(" ", "_"), hres))
        seed.close()
        out.write("seed %-30s admitted, then %s\n"
                  % (slabel, " ".join(results)))
    out.flush()
    os._exit(0)


def main():
    if os.getuid() != 0:
        sys.exit("run as root: the services run as root")
    outdir = sys.argv[1]
    wanted = [w.lower() for w in sys.argv[2:]]
    os.makedirs(outdir, exist_ok=True)
    services.setup_addresses()

    lines, port = ["kernel %s" % os.uname().release], PORT
    for cls, config, label in services.CATALOGUE:
        if config != "default" or (wanted and cls.name.lower() not in wanted):
            continue
        lines.append("")
        lines.append("service %s, %s" % (cls.name, label))
        for i in range(len(SEEDS)):
            # A fresh service on a fresh port for every seed shape.
            service = cls(port + i, config, None)
            try:
                service.start()
                if i == 0:
                    lines.append("  listening on %s"
                                 % services.listeners(port + i))
                r, w = os.pipe()
                pid = os.fork()
                if pid == 0:
                    os.close(r)
                    child(port + i, w, i)
                os.close(w)
                with os.fdopen(r) as f:
                    got = [line.rstrip("\n") for line in f]
                os.waitpid(pid, 0)
                head = [x for x in got if x.startswith("overlapping")]
                if i == 0:
                    lines.append("  %s of %d socket shapes overlap it"
                                 % (head[0].split()[1], len(HIJACKS)))
                    if int(head[0].split()[1]) < len(HIJACKS):
                        lines.append("  not swept: a probe that does not "
                                     "overlap it leaves a summary behind; "
                                     "see attack.py")
                        break
                lines += ["  " + x for x in got if x.startswith("seed ")]
            except Exception as e:
                lines.append("  seed %d FAILED %s" % (i, e))
            finally:
                service.stop()
        port += len(SEEDS)
        print("\n".join(lines[-len(SEEDS) - 3:]))

    with open(os.path.join(outdir, "sweep.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
