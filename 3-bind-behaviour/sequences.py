#!/usr/bin/env python3
"""Replay TCP bind sequences on the running kernel and record every result.

Run as root inside a test kernel; compare.py compares the results of
different kernels.

  usage: sequences.py OUTDIR SET [--quads N] [--seed S] [--jobs J]

  pairs        every ordered pair of socket configurations
  triples      any configuration, then two SO_REUSEPORT sockets of one owner:
               the shortest sequences in which the port's cache can cover
               a socket other than the one it holds
  quads        N random sequences of four configurations (default 200000)
  closes       each triple, with its first or its second socket closed
               before the third binds
  timewait     a socket left in TIME_WAIT on the port, then any
               configuration, then an SO_REUSEPORT socket of one owner
  widepairs    every ordered pair from the wider address pool
  widetriples  the triples, from the wider address pool
  latelisten   a socket that binds without listening, an SO_REUSEPORT
               socket, then the first or the second starts listening, then
               another SO_REUSEPORT socket of the same owner
  maptriples   the triples, from the base pool plus ::ffff:0.0.0.0
  maplatelisten  latelisten, from the same pool

Each socket of a sequence is created, bound to the sequence's port and, if
its configuration says so, put in listen(). Sockets stay open until the
sequence ends, so each one is checked against all earlier ones. The result
of a sequence is two characters per step, for bind() and listen():

  o  succeeded       u  EADDRINUSE      -  not attempted
  n  EADDRNOTAVAIL   i  EINVAL          x  any other error

A step that closes an earlier socket records "c-" ("--" if that socket was
never bound); a step that leaves a socket in TIME_WAIT records "t-". A
timewait sequence is not measured, and its first step records "D-", when
its port was not empty before it started, or "tG" when its TIME_WAIT socket
was gone by the end; compare.py leaves those out.

Writes OUTDIR/SET.txt.gz (one line per sequence, in enumeration order) and
OUTDIR/SET.json (summary).
"""

import argparse
import errno
import gzip
import itertools
import json
import os
import platform
import random
import socket
import struct
import subprocess
import sys
import time

SO_REUSEPORT = getattr(socket, "SO_REUSEPORT", 15)
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)

OWNERS = {"u1": 1001, "u2": 1002}
ADDRESSES = [
    ("v4", "0.0.0.0"),
    ("v4", "10.0.0.1"),
    ("v6", "::"),
    ("v6", "fd00::1"),
    ("v6", "::ffff:10.0.0.1"),
    ("v6only", "::"),
    ("v6only", "fd00::1"),
]
DEVICES = [None, "dum1", "dum2"]

# (owner, family, address, device, SO_REUSEADDR, SO_REUSEPORT, listen)
CONFIGS = [(o, f, a, d, ra, rp, ls)
           for o in OWNERS for f, a in ADDRESSES for d in DEVICES
           for ra in (0, 1) for rp in (0, 1) for ls in (0, 1)]
REUSEPORT_U1 = [c for c in CONFIGS if c[0] == "u1" and c[5]]

# The wider pool adds a second specific address in each family, loopback and
# a link-local address. ::1 cannot be bound by a device-bound socket, and an
# address scoped to dum1 is kept off dum2 so that a configuration's device is
# the device the socket ends up with.
ADDRESSES_WIDE = ADDRESSES + [
    ("v4", "10.0.0.2"),
    ("v4", "127.0.0.1"),
    ("v6", "fd00::2"),
    ("v6", "::1"),
    ("v6", "::ffff:10.0.0.2"),
    ("v6", "fe80::1%dum1"),
]
DEVICES_FOR = {"::1": [None], "fe80::1%dum1": [None, "dum1"]}
CONFIGS_WIDE = [(o, f, a, d, ra, rp, ls)
                for o in OWNERS for f, a in ADDRESSES_WIDE
                for d in DEVICES_FOR.get(a, DEVICES)
                for ra in (0, 1) for rp in (0, 1) for ls in (0, 1)]
REUSEPORT_U1_WIDE = [c for c in CONFIGS_WIDE if c[0] == "u1" and c[5]]

# The mapped pool adds the IPv4-mapped wildcard to the base pool: as the
# cached socket, ::ffff:0.0.0.0 covers every IPv4-mapped address.
ADDRESSES_MAPPED = ADDRESSES + [("v6", "::ffff:0.0.0.0")]
CONFIGS_MAPPED = [(o, f, a, d, ra, rp, ls)
                  for o in OWNERS for f, a in ADDRESSES_MAPPED
                  for d in DEVICES
                  for ra in (0, 1) for rp in (0, 1) for ls in (0, 1)]
REUSEPORT_U1_MAPPED = [c for c in CONFIGS_MAPPED if c[0] == "u1" and c[5]]

# Sockets left in TIME_WAIT on the port: (owner, family, address,
# SO_REUSEADDR, SO_REUSEPORT). Each connects to a helper listener on its own
# address and closes first, so it is the side that ends in TIME_WAIT.
TW_SHAPES = [(o, f, a, ra, rp)
             for o in OWNERS
             for f, a in (("v4", "10.0.0.1"), ("v6", "fd00::1"),
                          ("v6", "::ffff:10.0.0.1"))
             for ra in (0, 1) for rp in (0, 1)]
TIME_WAIT_SECONDS = 90     # TCP_TIMEWAIT_LEN is 60 s, and its timer can fire
                           # late; a port is reused only after this
HELPER_PORT = 15000        # one helper listener per job, on HELPER_PORT + job

CODES = {errno.EADDRINUSE: "u", errno.EADDRNOTAVAIL: "n", errno.EINVAL: "i"}


def describe(cfg):
    if cfg[0] == "close":
        return f"close socket {cfg[1] + 1}"
    if cfg[0] == "listen":
        return f"socket {cfg[1] + 1} starts listening"
    if cfg[0] == "tw":
        o, f, a, ra, rp = cfg[1]
        opts = [n for n, on in (("reuseaddr", ra), ("reuseport", rp)) if on]
        return f"{o} {f} {a} TIME_WAIT {' '.join(opts) or '-'}"
    o, f, a, d, ra, rp, ls = cfg
    opts = [n for n, on in (("reuseaddr", ra), ("reuseport", rp),
                            ("listen", ls)) if on]
    return f"{o} {f} {a} dev={d or '-'} {' '.join(opts) or '-'}"


def latelisten(configs, reuseport):
    return itertools.chain(
        ((c, r1, ("listen", 0), r2)
         for c, r1, r2 in itertools.product(configs, reuseport, reuseport)
         if not c[6]),
        ((c, r1, ("listen", 1), r2)
         for c, r1, r2 in itertools.product(configs, reuseport, reuseport)
         if not r1[6]))


def sequences(name, quads=200000, seed=1):
    if name == "pairs":
        return itertools.product(CONFIGS, repeat=2)
    if name == "triples":
        return itertools.product(CONFIGS, REUSEPORT_U1, REUSEPORT_U1)
    if name == "quads":
        rng = random.Random(seed)
        return (tuple(rng.choice(CONFIGS) for _ in range(4))
                for _ in range(quads))
    if name == "closes":
        return ((c, r1, ("close", k), r2)
                for c, r1, r2 in itertools.product(CONFIGS, REUSEPORT_U1,
                                                   REUSEPORT_U1)
                for k in (0, 1))
    if name == "timewait":
        return ((("tw", t), c, r)
                for t in TW_SHAPES for c in CONFIGS for r in REUSEPORT_U1)
    if name == "latelisten":
        return latelisten(CONFIGS, REUSEPORT_U1)
    if name == "maptriples":
        return itertools.product(CONFIGS_MAPPED, REUSEPORT_U1_MAPPED,
                                 REUSEPORT_U1_MAPPED)
    if name == "maplatelisten":
        return latelisten(CONFIGS_MAPPED, REUSEPORT_U1_MAPPED)
    if name == "widepairs":
        return itertools.product(CONFIGS_WIDE, repeat=2)
    if name == "widetriples":
        return itertools.product(CONFIGS_WIDE, REUSEPORT_U1_WIDE,
                                 REUSEPORT_U1_WIDE)
    raise ValueError(name)


def sockaddr(a, port):
    if "%" in a:
        addr, dev = a.split("%")
        return (addr, port, 0, socket.if_nametoindex(dev))
    return (a, port)


def code(e):
    return CODES.get(e.errno, "x")


def open_socket(cfg, port):
    """Returns (socket or None, two-character result)."""
    o, f, a, d, ra, rp, ls = cfg
    # The owner is the fsuid at socket creation (sk_uid); bind() and listen()
    # do not check the caller's credentials for ports above 1023.
    os.seteuid(OWNERS[o])
    try:
        s = socket.socket(socket.AF_INET if f == "v4" else socket.AF_INET6,
                          socket.SOCK_STREAM)
    finally:
        os.seteuid(0)
    if f != "v4":
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, f == "v6only")
    if ra:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if rp:
        s.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
    if d:
        s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, d.encode())
    try:
        s.bind(sockaddr(a, port))
    except OSError as e:
        s.close()
        return None, code(e) + "-"
    if not ls:
        return s, "o-"
    try:
        s.listen(8)
    except OSError as e:
        return s, "o" + code(e)
    return s, "oo"


TCP_CLOSE = 7


def make_timewait(tw, port, helper):
    """Bind a socket of shape tw to the port, connect it to the helper
    listener and close it first, so that it is left in TIME_WAIT."""
    o, f, a, ra, rp = tw
    os.seteuid(OWNERS[o])
    try:
        s = socket.socket(socket.AF_INET if f == "v4" else socket.AF_INET6,
                          socket.SOCK_STREAM)
    finally:
        os.seteuid(0)
    if f != "v4":
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    if ra:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if rp:
        s.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
    try:
        s.bind((a, port))
    except OSError as e:
        s.close()
        return code(e) + "-"
    s.connect((a, helper.getsockname()[1]))
    conn, _ = helper.accept()
    s.close()                                   # our side closes first
    conn.settimeout(5)
    while conn.recv(64):
        pass                                    # its FIN has arrived
    conn.shutdown(socket.SHUT_WR)
    # Our socket is in TIME_WAIT once it has acknowledged the helper's FIN,
    # which is when the helper's side reaches TCP_CLOSE.
    deadline = time.time() + 5
    while time.time() < deadline:
        info = conn.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 8)
        if info[0] == TCP_CLOSE:
            conn.close()
            return "t-"
        time.sleep(0.0002)
    conn.close()
    return "x-"


def run(seq, port, helper=None):
    held, out = {}, []
    for k, step in enumerate(seq):
        if step[0] == "close":
            s = held.pop(step[1], None)
            if s:
                s.close()
            out.append("c-" if s else "--")
            continue
        if step[0] == "listen":
            s = held.get(step[1])
            if not s:
                out.append("--")
                continue
            try:
                s.listen(8)
                out.append("Lo")
            except OSError as e:
                out.append("L" + code(e))
            continue
        if step[0] == "tw":
            out.append(make_timewait(step[1], port, helper))
            continue
        s, res = open_socket(step, port)
        if s:
            held[k] = s
        out.append(res)
    for s in held.values():
        s.close()
    return "".join(out)


def setup(name):
    cmds = [
        "ip link set lo up",
        "sysctl -qw net.ipv6.conf.all.accept_dad=0",
        "sysctl -qw net.ipv6.conf.default.accept_dad=0",
    ]
    for dev in ("dum1", "dum2"):
        if os.path.exists(f"/sys/class/net/{dev}"):
            continue
        cmds += [f"ip link add {dev} type dummy", f"ip link set {dev} up",
                 f"ip addr add 10.0.0.1/24 dev {dev}",
                 f"ip addr add 10.0.0.2/24 dev {dev}",
                 f"ip addr add fd00::1/64 dev {dev} nodad",
                 f"ip addr add fd00::2/64 dev {dev} nodad"]
        if dev == "dum1":
            cmds += [f"ip addr add fe80::1/64 dev {dev} nodad"]
    for c in cmds:
        subprocess.run(c.split(), check=True)
    # Every address must be bindable on every device it is paired with, or
    # results would measure the setup rather than the conflict check.
    for f, a in ADDRESSES_WIDE:
        for d in DEVICES_FOR.get(a, DEVICES):
            s, res = open_socket(("u1", f, a, d, 0, 0, 0), 9)
            if res != "o-":
                sys.exit(f"setup: cannot bind {f} {a} dev={d}: {res}")
            s.close()
    # And a TIME_WAIT step must really leave a TIME_WAIT socket on the port.
    # (Only before the timewait set. The check uses empty ports from
    # 19000-19999, since its own TIME_WAIT sockets stay for a minute.)
    if name != "timewait":
        return
    # The set keeps tens of thousands of TIME_WAIT sockets alive at once;
    # past this limit (16384 in the test guest) the kernel destroys a
    # closing socket instead of leaving it in TIME_WAIT.
    subprocess.run(["sysctl", "-qw", "net.ipv4.tcp_max_tw_buckets=1000000"],
                   check=True)
    helper = helper_listener(HELPER_PORT - 1)
    ports = (p for p in range(19000, 20000) if port_empty(p))
    for tw in TW_SHAPES:
        port = next(ports)
        if make_timewait(tw, port, helper) != "t-" or not in_timewait(port):
            sys.exit(f"setup: no TIME_WAIT socket for {tw}")
    helper.close()


def port_empty(port):
    """Is nothing at all on this port? A plain dual-stack wildcard socket
    without reuse options conflicts with any socket there, TIME_WAIT
    included, so its bind succeeds only on an empty port."""
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    try:
        s.bind(("::", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def helper_listener(port):
    h = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    h.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    h.bind(("::", port))
    h.listen(64)
    h.settimeout(5)
    return h


def in_timewait(port):
    """Is a socket on this local port in TIME_WAIT, per /proc/net/tcp*?"""
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        with open(path) as f:
            next(f)
            for line in f:
                col = line.split()
                if int(col[1].rsplit(":", 1)[1], 16) == port and col[3] == "06":
                    return True
    return False


def worker(name, args, job, path):
    seqs = sequences(name, args.quads, args.seed)
    if args.limit:
        seqs = itertools.islice(seqs, args.limit)
    if name != "timewait":
        port_lo = 20000 + job * 4000
        with open(path, "w") as out:
            for i, seq in enumerate(seqs):
                if i % args.jobs == job:
                    out.write(run(seq, port_lo + (i // args.jobs) % 4000) + "\n")
        return
    # A TIME_WAIT socket outlives its sequence for 60 s, so a port is only
    # reused once it has gone.
    span = 40000 // args.jobs
    port_lo = 20000 + job * span
    last = {}
    helper = helper_listener(HELPER_PORT + job)
    with open(path, "w") as out:
        for i, seq in enumerate(seqs):
            if i % args.jobs != job:
                continue
            port = port_lo + (i // args.jobs) % span
            wait = last.get(port, -1e9) + TIME_WAIT_SECONDS - time.time()
            if wait > 0:
                time.sleep(wait)
            if not port_empty(port):
                res = "D-" + "--" * (len(seq) - 1)
            else:
                res = run(seq, port, helper)
                if res.startswith("t-") and port_empty(port):
                    res = "tG" + res[2:]
            out.write(res + "\n")
            last[port] = time.time()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("set", choices=["pairs", "triples", "quads", "closes",
                                    "timewait", "widepairs", "widetriples",
                                    "latelisten", "maptriples",
                                    "maplatelisten"])
    ap.add_argument("--quads", type=int, default=200000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--jobs", type=int, default=os.cpu_count())
    ap.add_argument("--limit", type=int, default=0,
                    help="only the first N sequences (for trying it out)")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    setup(args.set)

    start = time.time()
    parts = [os.path.join(args.outdir, f"{args.set}.part{j}")
             for j in range(args.jobs)]
    pids = []
    for j, path in enumerate(parts):
        pid = os.fork()
        if pid == 0:
            worker(args.set, args, j, path)
            os._exit(0)
        pids.append(pid)
    for pid in pids:
        if os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]):
            sys.exit("a worker failed")

    counts, total = {}, 0
    files = [open(p) for p in parts]
    with gzip.open(os.path.join(args.outdir, f"{args.set}.txt.gz"), "wt") as out:
        for lines in itertools.zip_longest(*files):
            for line in lines:
                if line is None:
                    continue
                out.write(line)
                total += 1
                for c in line.strip():
                    counts[c] = counts.get(c, 0) + 1
    for f, p in zip(files, parts):
        f.close()
        os.unlink(p)

    summary = {
        "set": args.set,
        "sequences": total,
        "quads": args.quads if args.set == "quads" else None,
        "seed": args.seed if args.set == "quads" else None,
        "kernel": platform.release(),
        "seconds": round(time.time() - start, 1),
        "result_codes": dict(sorted(counts.items())),
    }
    with open(os.path.join(args.outdir, f"{args.set}.json"), "w") as f:
        json.dump(summary, f, indent=1)
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
