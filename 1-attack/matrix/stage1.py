#!/usr/bin/env python3
"""Stage 1 of the attack matrix: which attacker binds succeed where they
overlap a victim, for every victim of space.py.

  usage: stage1.py OUTDIR [--jobs N] [--three N]        (as root, in the guest)

Every trial starts from a fresh victim on a fresh port, so nothing one trial
leaves behind (such as the port's bind cache) can change the next. For
each victim, and for each socket the attacker may hold before the victim
starts:

  1. every attacker socket on its own, bound and put in listen(): that is
     also the control for everything below
  2. every ordered pair (s, h) where s binds on its own: a pair whose s is
     refused on its own is the same trial as h alone
  3. a random sample of three-socket sequences (--three per victim, seed 1)

A pair or triple is a positive when its last socket binds and listens while
the same socket on its own does not: the earlier sockets made the
difference.

Writes OUTDIR/stage1-alone.jsonl.gz (every single-socket result),
OUTDIR/stage1-positives.jsonl.gz (every positive) and OUTDIR/stage1.json
(counts per victim).
"""

import argparse
import contextlib
import fcntl
import gzip
import json
import os
import random
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env      # noqa: E402
import space    # noqa: E402

HIGH, LOW = (20000, 3000), (400, 70)
PEER_PORT = 7000
EPHEMERAL_LOW = 50000       # env.py sets ip_local_port_range to 50000-60999
CLIENT_LOCK = "/tmp/matrix-client-victim.lock"


def check_port_plan(jobs):
    """Every job's trial ports must stay below the ephemeral range, where
    client victims get their ports."""
    if HIGH[0] + jobs * HIGH[1] > EPHEMERAL_LOW:
        sys.exit("%d jobs would put trial ports in the ephemeral range" % jobs)


@contextlib.contextmanager
def one_client_victim(v):
    """A client victim gets its port from connect(), and Linux lets two
    connections to different destinations share a local port, so two jobs'
    client victims could sit on the same port, and each job's attacker
    sockets would meet the other's. Only one client victim exists at a
    time."""
    if v["kind"] != "client":
        yield
        return
    with open(CLIENT_LOCK, "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


class Ports:
    def __init__(self, base, size):
        self.base, self.size, self.i = base, size, 0

    def next(self):
        self.i = (self.i + 1) % self.size
        return self.base + self.i


class Worker:
    def __init__(self, job, args):
        self.job, self.args = job, args
        self.high = Ports(HIGH[0] + job * HIGH[1], HIGH[1])
        self.low = Ports(LOW[0] + job * LOW[1], LOW[1])
        self.peer = env.Helper("peer")
        self.peer.cmd("listen", PEER_PORT + job)
        self.held = 0

    def tidy(self):
        """Drop the peer's old connections now and then. Only ever before a
        victim's connection is made: resetting a live victim closes its
        socket, which frees its port and would let any bind through."""
        self.held += 1
        if self.held >= 200:
            self.peer.cmd("closeall")
            self.held = 0

    @staticmethod
    def alive(victim):
        """Is the victim's connection still established?"""
        try:
            info = victim[-1].getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 1)
            return info[0] == 1                         # TCP_ESTABLISHED
        except OSError:
            return False

    def make_victim(self, v, port):
        """The victim's sockets, its result codes, and the port to attack."""
        k = v["kind"]
        if k == "client":
            self.tidy()
            fam, _, _, dev, ra, _ = v["socks"][0]
            s = env.new_socket((fam, None, None, dev, ra, 0))
            dest = env.sockaddr(fam, v["peer"], PEER_PORT + self.job)
            try:
                s.settimeout(3)
                s.connect(dest)
            except OSError as e:
                s.close()
                return [], env.code(e), None
            return [s], "o", s.getsockname()[1]
        socks, codes = [], ""
        for spec in v["socks"]:
            s, c = env.bind(spec, port)
            if s is not None:
                try:
                    s.listen(64)
                except OSError:
                    c = "L"
            codes += c
            if s is not None:
                socks.append(s)
            elif v.get("tolerance") == "abort":
                env.reset_close(socks)
                return [], codes, None
        if not socks:
            return [], codes, None
        if k == "child":
            self.tidy()
            dfam, daddr = v["dest"]
            dev = "vp" if daddr in space.LINK_LOCAL else "-"
            r = self.peer.cmd("connect", int(dfam), daddr, port, dev)
            if r[0] != "ok":
                env.reset_close(socks)
                return [], codes + "c", None
            socks[0].settimeout(3)
            try:
                child, _ = socks[0].accept()
            except OSError:
                env.reset_close(socks)
                return [], codes + "c", None
            socks.append(child)
        return socks, codes, port

    def trial(self, v, pre, seq):
        """Returns (victim codes, squat code, codes of each attacker socket,
        listen code of the last one)."""
        with one_client_victim(v):
            return self._trial(v, pre, seq)

    def _trial(self, v, pre, seq):
        port = (self.low if v["kind"] == "low" else self.high).next()
        mine, qcode = [], "-"
        if pre is not None:
            with env.attacker():
                q, qcode = env.bind(space.ATTACKER_SOCKETS[pre], port)
            mine.append(q)
        victim, vcodes, target = self.make_victim(v, port)
        if target is None:
            env.reset_close(mine + victim)
            return vcodes, qcode, None, None
        codes, lcode = [], "-"
        with env.attacker():
            for n, idx in enumerate(seq):
                s, c = env.bind(space.ATTACKER_SOCKETS[idx], target)
                codes.append(c)
                mine.append(s)
                if n == len(seq) - 1 and s is not None:
                    try:
                        s.listen(64)
                        lcode = "o"
                    except OSError as e:
                        lcode = env.code(e)
        if v["kind"] in ("client", "child") and not self.alive(victim):
            codes = "lost"              # the victim is gone: not a result
        env.reset_close(mine + victim)
        return vcodes, qcode, codes, lcode

    def trial_kept(self, v, pre, seq):
        """A trial, run once more if its victim's connection was lost."""
        r = self.trial(v, pre, seq)
        return self.trial(v, pre, seq) if r[2] == "lost" else r

    def run_victim(self, v, alone_out, pos_out):
        counts = {"victim": v["id"], "trials": 0, "positives": 0,
                  "invalid": None, "pre": {}}
        rng = random.Random(1000003 + v["id"])
        for pre in space.pre_states(v, self.args.pre_all):
            pool = (range(len(space.ATTACKER_SOCKETS)) if pre is None
                    else space.REUSEPORT_SOCKETS)
            alone, works_alone = {}, set()
            for s in pool:
                vc, qc, codes, lc = self.trial_kept(v, pre, (s,))
                counts["trials"] += 1
                if codes == "lost":
                    counts["lost_victim"] = counts.get("lost_victim", 0) + 1
                    alone[s] = "lost"
                    continue
                if codes is None:
                    if pre is None:
                        counts["invalid"] = vc
                        return counts
                    alone_out.write(json.dumps(
                        {"victim": v["id"], "pre": pre, "victim_codes": vc,
                         "squat": qc, "absent": True}) + "\n")
                    break
                alone[s] = codes[0]
                if codes[0] == "o" and lc == "o":
                    works_alone.add(s)
                alone_out.write(json.dumps(
                    {"victim": v["id"], "pre": pre, "socket": s,
                     "victim_codes": vc, "squat": qc, "bind": codes[0],
                     "listen": lc}) + "\n")
            if not alone:
                continue
            seeds = [s for s in pool if alone[s] == "o"]
            pairs = [(s, h) for s in seeds for h in pool]
            triples = []
            if pre is None and seeds:
                for _ in range(self.args.three):
                    triples.append((rng.choice(seeds), rng.choice(list(pool)),
                                    rng.choice(list(pool))))
            positives = 0
            for seq in pairs + triples:
                vc, qc, codes, lc = self.trial_kept(v, pre, seq)
                counts["trials"] += 1
                if codes == "lost":
                    counts["lost_victim"] = counts.get("lost_victim", 0) + 1
                    continue
                if codes is None:
                    continue
                if (codes[-1] == "o" and lc == "o"
                        and seq[-1] not in works_alone):
                    positives += 1
                    pos_out.write(json.dumps(
                        {"victim": v["id"], "pre": pre, "seq": seq,
                         "victim_codes": vc, "squat": qc, "codes": codes,
                         "listen": lc}) + "\n")
            counts["positives"] += positives
            counts["pre"][str(pre)] = {"seeds": len(seeds),
                                       "pairs": len(pairs),
                                       "triples": len(triples),
                                       "positives": positives}
        return counts


def worker(job, args, victims, outdir):
    w = Worker(job, args)
    part = os.path.join(outdir, "%s-%%s.part%d" % (args.name, job))
    alone = gzip.open(part % "alone" + ".gz", "wt")
    pos = gzip.open(part % "positives" + ".gz", "wt")
    out = []
    progress = part % "progress"
    for n, v in enumerate(victims):
        out.append(w.run_victim(v, alone, pos))
        with open(progress, "w") as f:
            f.write("%d/%d\n" % (n + 1, len(victims)))
    alone.close()
    pos.close()
    with open(part % "counts", "w") as f:
        json.dump(out, f)
    w.peer.stop()
    os._exit(0)


def merge(outdir, jobs, stem, what):
    final = os.path.join(outdir, "%s-%s.jsonl.gz" % (stem, what))
    with gzip.open(final, "wt") as out:
        for j in range(jobs):
            part = os.path.join(outdir, "%s-%s.part%d.gz" % (stem, what, j))
            with gzip.open(part, "rt") as f:
                for line in f:
                    out.write(line)
            os.unlink(part)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--jobs", type=int, default=os.cpu_count())
    ap.add_argument("--three", type=int, default=5000)
    ap.add_argument("--victims", default="")
    ap.add_argument("--pre-all", action="store_true",
                    help="also let the attacker hold a socket on the port "
                         "before every victim starts, not only the victims "
                         "that bind a known port at startup")
    ap.add_argument("--name", default="stage1", help="name of the output")
    args = ap.parse_args()
    check_port_plan(args.jobs)
    os.makedirs(args.outdir, exist_ok=True)
    env.setup_network()
    victims = space.victims()
    if args.victims:
        keep = {int(x) for x in args.victims.split(",")}
        victims = [v for v in victims if v["id"] in keep]
    start = time.time()
    pids = []
    for j in range(args.jobs):
        mine = victims[j::args.jobs]
        pid = os.fork()
        if pid == 0:
            worker(j, args, mine, args.outdir)
        pids.append(pid)
    for pid in pids:
        os.waitpid(pid, 0)
    merge(args.outdir, args.jobs, args.name, "alone")
    merge(args.outdir, args.jobs, args.name, "positives")
    counts = []
    for j in range(args.jobs):
        p = os.path.join(args.outdir, "%s-counts.part%d" % (args.name, j))
        with open(p) as f:
            counts += json.load(f)
        os.unlink(p)
        os.unlink(os.path.join(args.outdir,
                               "%s-progress.part%d" % (args.name, j)))
    counts.sort(key=lambda c: c["victim"])
    summary = {"kernel": os.uname().release,
               "seconds": round(time.time() - start),
               "attacker_on_the_port_first": args.pre_all,
               "victims": len(victims),
               "trials": sum(c["trials"] for c in counts),
               "positives": sum(c["positives"] for c in counts),
               "per_victim": counts}
    with open(os.path.join(args.outdir, "%s.json" % args.name), "w") as f:
        json.dump(summary, f, indent=1)
    print("%s: %d victims, %d trials, %d positives, %d s"
          % (args.name, summary["victims"], summary["trials"],
             summary["positives"], summary["seconds"]))


if __name__ == "__main__":
    main()
