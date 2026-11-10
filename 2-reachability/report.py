#!/usr/bin/env python3
"""Turn the per-port counts of fastreuse.bt into tables.

  usage: report.py scenarios | services

  scenarios  results/scenarios.txt -> results/scenarios-summary.txt
  services   results/services/PHASE.txt -> results/services/summary.txt
"""

import os
import re
import sys
from collections import defaultdict

RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
COUNT = re.compile(r"^@(\w+)\[(\d+)\]: (\d+)$")
CLIENTS = 65536

SCENARIOS = [
    ("connect", "connect() + accept, to one listener"),
    ("data", "one connection, 64 KiB each way"),
    ("port0", "bind to port 0, listen"),
    ("named", "bind each to its own port, listen"),
    ("group", "identical SO_REUSEPORT listeners on one port"),
    ("group-strict", "the same, after a socket without SO_REUSEPORT"),
    ("group-specific", "SO_REUSEPORT wildcard, then specific addresses"),
]

SERVICES = [
    ("OpenSSH (host)", [22]),
    ("PostgreSQL (container)", [5432]),
    ("  Docker port proxy for PostgreSQL", [15432]),
    ("nginx (container)", [80]),
    ("  Docker port proxy for nginx", [18080]),
    ("FastAPI (container)", [8000]),
    ("  Docker port proxy for FastAPI", [18000]),
    ("nginx (host network)", [18081]),
    ("HAProxy (host network)", [18443]),
    ("Hot-restart service (hand-built)", [18100]),
    ("Transparent proxy (hand-built)", [18200, 18201]),
]
PHASES = [
    ("start", "Starting the services"),
    ("idle", "Idle (60 s, services running, no load)"),
    ("traffic", "Traffic (60 s, all services under load)"),
    ("browsing", "Browsing (120 s, Firefox on real websites; services idle)"),
    ("reload", "Reloading or restarting the services"),
    ("stop", "Stopping the services"),
]
COLUMNS = [("received", "TCP packets\nreceived"), ("sent", "TCP packets\nsent"),
           ("binds", "Socket\nbinds"), ("changed_code_ran", "Times the\nchanged code ran")]


def parse(text):
    counts = defaultdict(lambda: defaultdict(int))
    for line in text.splitlines():
        m = COUNT.match(line.strip())
        if m:
            counts[m.group(1)][int(m.group(2))] += int(m.group(3))
    return counts


def table(title, rows, first="Service"):
    width = max(len(first), *(len(r[0]) for r in rows))
    heads = [h.split("\n") for _, h in COLUMNS]
    cols = [max(len(x) for x in h) for h in heads]
    out = [title, ""]
    for i in range(2):
        label = first if i == 1 else ""
        out.append(f"{label:<{width}}" + "".join(f"  {h[i]:>{w}}" for h, w in zip(heads, cols)))
    out.append("-" * width + "".join("  " + "-" * w for w in cols))
    for name, values in rows:
        out.append(f"{name:<{width}}" + "".join(f"  {v:>{w},}" for v, w in zip(values, cols)))
    return "\n".join(out)


def row(counts, ports):
    return [sum(counts[k].get(p, 0) for p in ports) for k, _ in COLUMNS]


def scenarios():
    text = open(os.path.join(RESULTS, "scenarios.txt")).read()
    header, *parts = re.split(r"^=== (\S+)$", text, flags=re.M)
    blocks = dict(zip(parts[0::2], parts[1::2]))
    rows = []
    for key, label in SCENARIOS:
        counts = parse(blocks.get(key, ""))
        rows.append((label, [sum(counts[k].values()) for k, _ in COLUMNS]))
    n = re.search(r"^N:\s+(\d+)", header, re.M).group(1)
    return table(f"Scenarios, {int(n):,} of each, in a fresh network namespace", rows,
                 first="Scenario")


def services():
    out = []
    for phase, title in PHASES:
        counts = parse(open(os.path.join(RESULTS, "services", f"{phase}.txt")).read())
        known = {p for _, ports in SERVICES for p in ports}
        rows = [(name, row(counts, ports)) for name, ports in SERVICES]
        rows.append(("Clients (load generators, Firefox)", row(counts, [CLIENTS])))
        # Port 0 holds binds that ask for any free port, and packets sent by
        # sockets that have already given their port back while closing.
        rows.append(("Bind to any free port (port 0)", [0, 0, counts["binds"].get(0, 0), 0]))
        rows.append(("Sockets that already released their port",
                     [counts["received"].get(0, 0), counts["sent"].get(0, 0), 0, 0]))
        other = {p for k, _ in COLUMNS for p in counts[k]} - known - {CLIENTS, 0}
        rows.append(("Other ports", row(counts, sorted(other))))
        out.append(table(title, rows))
    return "\n\n\n".join(out)


if __name__ == "__main__":
    what = sys.argv[1]
    text = scenarios() if what == "scenarios" else services()
    name = "scenarios-summary.txt" if what == "scenarios" else os.path.join("services", "summary.txt")
    with open(os.path.join(RESULTS, name), "w") as f:
        f.write(text + "\n")
    print(text)
