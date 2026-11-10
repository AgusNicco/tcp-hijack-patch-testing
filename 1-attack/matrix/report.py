#!/usr/bin/env python3
"""Turn the attack matrix's results into tables, written to
1-attack/results/matrix/summary.txt.

For every victim:
  stage 1  how many attacker sequences were tried, and how many give the
           attacker a bind that overlaps the victim, on each kernel
  stage 2  for listeners: whether the attacker answers the clients the
           victim itself serves (its own clients), whether it answers
           clients on addresses the victim leaves empty, and whether the
           victim can bind its address again; for connections: whether the
           attacker gets the connection's four-tuple and what the peer's next
           data reaches
"""

import gzip
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import space    # noqa: E402

RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                       "results", "matrix")
KERNELS = [("base", "Current kernel"), ("proposed-patch", "With the patch"),
           ("full-scan-alternative", "Full check always")]
PROVISIONAL = {}


def jsonl(path):
    if not os.path.exists(path):
        return []
    with gzip.open(path, "rt") as f:
        return [json.loads(line) for line in f]


def load(kernel):
    """Stage-1 counts, the listener runs, and the connection runs. The
    connection runs live in their own file; where an older stage-2 file still
    holds some, the separate file wins."""
    d = os.path.join(RESULTS, kernel)
    s1 = {}
    if os.path.exists(os.path.join(d, "stage1.json")):
        with open(os.path.join(d, "stage1.json")) as f:
            s1 = {c["victim"]: c for c in json.load(f)["per_victim"]}
    conn = jsonl(os.path.join(d, "connections.jsonl.gz"))
    kinds = {v["id"]: v["kind"] for v in space.victims()}
    stage2 = jsonl(os.path.join(d, "stage2.jsonl.gz"))
    def connection(r):
        return ("case" in r
                and kinds[r["case"]["victim"]] in ("client", "child"))

    is_conn = [r for r in stage2 if connection(r)]
    rest = [r for r in stage2 if not connection(r)]
    if not conn and is_conn:
        # An earlier pass measured connections by the port the peer saw,
        # which cannot tell the victim's connection from one the attacker
        # opened from the same port. Used until the separate pass is there.
        conn, PROVISIONAL[kernel] = is_conn, True
    return s1, rest, conn


def own(baseline):
    """The destinations the victim answers on its own."""
    return {a for a, c in (baseline or {}).items()
            if isinstance(c, list) and c[0] > 0}


def listener_outcome(recs, baseline):
    """Which of the victim's own addresses some attack answered on, with a
    single socket and with one copy per CPU; which addresses the victim does
    not answer on at all but the attacker does; and whether any attack left
    the victim unable to bind its address again."""
    mine = own(baseline)
    out = {"plain": set(), "cpu": set(), "elsewhere": set(),
           "restart": "yes"}
    for r in recs:
        p = r.get("probes") or {}
        answered = {a for a, c in p.items()
                    if isinstance(c, list) and c[1] > 0}
        key = "plain" if r.get("copies", 1) == 1 else "cpu"
        out[key] |= answered & mine
        out["elsewhere"] |= answered - mine
        again = r.get("restart")
        if again and not r.get("absent") and set(again) - {"o"}:
            # A service with two sockets can come back holding only one.
            worst = "no" if "o" not in again else "only partly"
            if worst == "no" or out["restart"] == "yes":
                out["restart"] = worst
    return out


def connection_outcome(recs):
    """What each attack did to a live connection.

    destroyed  the peer could no longer send on it, or the victim never got
               what the peer sent: the connection is gone
    identity   the peer ended up with a connection from the victim's own
               address and port that the attacker holds, in its place
    segments   the attacker's socket was given the connection's segments,
               counted by the kernel whether or not recv() could return them
    """
    out = {"cases": 0, "needed_bug": 0, "destroyed": 0, "identity": 0,
           "segments": 0, "read": 0}
    for r in recs:
        if "connect" not in r:
            continue
        out["cases"] += 1
        if r["case"]["why"] != "positive":
            continue
        out["needed_bug"] += 1
        if (r.get("peer_send") != "ok"
                or not isinstance(r.get("victim_rx"), int)):
            out["destroyed"] += 1
        mine = r.get("attacker_own_connection")
        if r["connect"] == "o" and mine and mine == r.get("peer_sees"):
            out["identity"] += 1
        segs = r.get("attacker_segs")
        if segs and None not in segs and segs[1] > segs[0]:
            out["segments"] += 1
        out["read"] += bool(r.get("attacker_rx"))
    return out


ORDER = ["10.9.0.1", "fd09::1", "fe80::1", "127.0.0.1", "::1"]


def addrs(s):
    return ", ".join(a for a in ORDER if a in s) or "-"


def table(title, header, rows):
    widths = [max(len(h), *(len(str(r[i])) for r in rows))
              for i, h in enumerate(header)]
    out = [title, ""]
    out.append("  ".join(h.ljust(w) for h, w in zip(header, widths)))
    out.append("  ".join("-" * w for w in widths))
    for r in rows:
        out.append("  ".join(str(c).ljust(w) for c, w in zip(r, widths)))
    return "\n".join(out)


def port_first_rows():
    """The other ordering: the attacker is already on the port when the victim
    starts.

    A sequence counts here only if the victim refuses that socket on its own,
    with nothing else held. Without that test the count is dominated by the
    attacker getting past its own squatting socket, which it owns and is
    welcome to; the table reports that share separately.
    """
    rows = []
    for kernel, label in KERNELS:
        d = os.path.join(RESULTS, kernel)
        counts = os.path.join(d, "port-first.json")
        if not os.path.exists(counts):
            continue
        with open(counts) as f:
            summary = json.load(f)
        refused = {}
        for a in jsonl(os.path.join(d, "stage1-alone.jsonl.gz")):
            if a.get("pre") is None and "socket" in a:
                refused.setdefault(a["victim"], {})[a["socket"]] = (
                    a["bind"] == "o" and a["listen"] == "o")
        normal = {}
        for p in jsonl(os.path.join(d, "stage1-positives.jsonl.gz")):
            normal.setdefault(p["victim"], set()).add(p["seq"][-1])
        real, own, fresh = set(), 0, set()
        for p in jsonl(os.path.join(d, "port-first-positives.jsonl.gz")):
            h = p["seq"][-1]
            if refused.get(p["victim"], {}).get(h, True):
                own += 1                        # not refused by the victim
                continue
            real.add((p["victim"], h))
            if h not in normal.get(p["victim"], ()):
                fresh.add((p["victim"], h))
        rows.append([label, "{:,}".format(summary["trials"]),
                     "{:,}".format(own), len(real), len(fresh)])
    return rows


def summary_rows(victims, data):
    """One row per kernel: the whole result in six numbers."""
    rows = []
    for k, label in KERNELS:
        s1, rest, conn = data[k]
        if not s1:
            continue
        recs = rest + conn
        base_lines = {r["baseline"]: r["probes"] for r in recs
                      if "baseline" in r}
        by_victim = {}
        for r in recs:
            if "case" in r:
                by_victim.setdefault(r["case"]["victim"], []).append(r)
        lost = norebind = taken = 0
        for v in victims:
            rs = by_victim.get(v["id"])
            if not rs:
                continue
            if v["kind"] in ("client", "child"):
                o = connection_outcome(rs)
                taken += (o["destroyed"] or o["identity"]
                          or o["segments"]) > 0
            else:
                o = listener_outcome(rs, base_lines.get(v["id"]))
                lost += bool(o["plain"] | o["cpu"])
                norebind += o["restart"] != "yes"
        rows.append([label, "{:,}".format(sum(c["trials"] for c in s1.values())),
                     "{:,}".format(sum(c["positives"] for c in s1.values())),
                     lost, taken, norebind])
    return rows


def main():
    victims = space.victims()
    data = {k: load(k) for k, _ in KERNELS}
    base_s1 = data["base"][0]

    out = [table(
        "What the attacker achieved, by kernel",
        ["Kernel", "Bind sequences tried", "Sequences that got over a victim",
         "Listeners that lost clients",
         "Connection kinds the attacker destroyed or took over",
         "Victims left unable to bind their address again"],
        summary_rows(victims, data))]
    if PROVISIONAL:
        out.append("Note that the live-connection figures for %s come from an "
                   "earlier pass that identified\nthe victim's connection by "
                   "its port alone, so a connection the attacker opened from\n"
                   "that same port can be counted as the victim's. Run "
                   "1-attack/matrix/run.sh again to\nadd the pass that holds "
                   "the victim's connection by identity."
                   % ", ".join(PROVISIONAL))

    pf = port_first_rows()
    if pf:
        out.append(table(
            "The attacker already holds a socket on the port when the victim "
            "starts",
            ["Kernel", "Bind sequences tried",
             "Sequences that only got past the attacker's own socket",
             "Sockets that got over the victim",
             "Of those, ones the other ordering did not already find"], pf))

    rows = []
    for v in victims:
        c = base_s1.get(v["id"])
        if c is None:
            continue
        if c.get("invalid") is not None:
            rows.append([v["id"], space.describe_victim(v), "victim cannot "
                         "bind (%s)" % c["invalid"], "", "", ""])
            continue
        cells = [v["id"], space.describe_victim(v), "{:,}".format(c["trials"])]
        for k, _ in KERNELS:
            ck = data[k][0].get(v["id"])
            cells.append("{:,}".format(ck["positives"]) if ck else "?")
        rows.append(cells)
    out.append(table("Stage 1: attacker sequences that bind over the victim",
                     ["#", "Victim", "Sequences tried"] +
                     [label for _, label in KERNELS], rows))

    for k, label in KERNELS:
        recs = data[k][1] + data[k][2]
        base_lines = {r["baseline"]: r["probes"] for r in recs
                      if "baseline" in r}
        by_victim = {}
        for r in recs:
            if "case" in r:
                by_victim.setdefault(r["case"]["victim"], []).append(r)
        lrows, crows = [], []
        for v in victims:
            rs = by_victim.get(v["id"])
            if not rs:
                continue
            if v["kind"] in ("client", "child"):
                o = connection_outcome(rs)
                crows.append([v["id"], space.describe_victim(v), o["cases"],
                              o["needed_bug"], o["destroyed"], o["identity"],
                              o["segments"], o["read"]])
            else:
                o = listener_outcome(rs, base_lines.get(v["id"]))
                lrows.append([v["id"], space.describe_victim(v),
                              addrs(own(base_lines.get(v["id"]))),
                              addrs(o["plain"]), addrs(o["cpu"]),
                              addrs(o["elsewhere"]), o["restart"]])
        if lrows:
            out.append(table(
                "Stage 2, %s: listeners" % label,
                ["#", "Victim", "Victim answers clients on",
                 "Taken by one attacker socket",
                 "Taken with a copy per CPU",
                 "Answered by the attacker where the victim answers nobody",
                 "Victim can bind again"], lrows))
        if crows:
            out.append(table(
                "Stage 2, %s: live connections" % label,
                ["#", "Victim", "Attacks tried", "Attacks needing the bug",
                 "Victim's connection destroyed",
                 "Attacker took the victim's identity at the peer",
                 "Attacker's socket given the segments",
                 "Attacker could read the data"], crows))
    text = "\n\n\n".join(out) + "\n"
    with open(os.path.join(RESULTS, "summary.txt"), "w") as f:
        f.write(text)
    print(text)


if __name__ == "__main__":
    main()
