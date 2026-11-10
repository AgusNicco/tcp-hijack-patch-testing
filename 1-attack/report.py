#!/usr/bin/env python3
"""Turn results/<kernel>/attack.txt into the tables of results/summary.txt.

One table per way of attacking: the services as they bind, with one
dual-stack hijacking socket and with one per CPU bound to the clients'
interface; the services pinned to an interface; and a service whose IPv6
address the attacker held before it started. Each row gives what the service
was listening on, read from the kernel, and for its clients over each family
who answered them and how many of their requests the attacker read in
full."""

import os

RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
KERNELS = [
    ("base", "Current kernel"),
    ("proposed-patch", "With the patch"),
    ("full-scan-alternative", "Full check always"),
]
SERVICES = [
    ("nginx", "ipv4", "nginx, upstream default"),
    ("nginx", "default", "nginx, both stacks"),
    ("HAProxy", "default", "HAProxy, 127.0.0.1"),
    ("FastAPI_(uvicorn)", "default", "uvicorn, as shipped"),
    ("FastAPI_(uvicorn)", "ipv4", "uvicorn --host 0.0.0.0"),
    ("OpenSSH", "default", "OpenSSH, as shipped"),
    ("OpenSSH", "inet", "OpenSSH, IPv4 only"),
    ("PostgreSQL", "default", "PostgreSQL, as shipped"),
    ("PostgreSQL", "ipv4", "PostgreSQL, 0.0.0.0"),
    ("PostgreSQL", "all", "PostgreSQL, '*'"),
    ("Hot-restart_service", "default", "Hot-restart service"),
]
TARGETS = [("127.0.0.1", "Connections over IPv4"),
           ("::1", "Connections over IPv6")]


def load():
    runs = {}
    for kernel, label in KERNELS:
        path = os.path.join(RESULTS, kernel, "attack.txt")
        if not os.path.exists(path):
            continue
        for line in open(path):
            if not line.startswith("service="):
                continue
            row = dict(p.split("=", 1) for p in line.split() if "=" in p)
            key = (row["service"], row["config"], row["pinned"], row["axis"],
                   row.get("squat", "no") != "no", label)
            runs.setdefault(key, {})[row.get("target")] = row
    return runs


def cell(row):
    if row is None:
        return "-"
    if "FAILED" in str(row):
        return "failed"
    return "%s / %s / %s" % (row["answered_service"], row["answered_attacker"],
                             row.get("attacker_read", "?"))


def attacker_bind(row):
    """The attacker stops at the seed when the kernel refuses it: with no
    seed on the port there is nothing to vouch for the hijack."""
    if row.get("bind") == "not_attempted":
        return "seed refused (%s)" % row.get("seed", "?")
    return row.get("bind", "?")


def table(runs, title, pinned, axis, squat, seeded_only=False):
    heads = ["Service", "Kernel", "Listening on", "Attacker's bind"] + \
        [t for _, t in TARGETS]
    rows = []
    for service, config, label in SERVICES:
        for _, kernel in KERNELS:
            by_target = runs.get((service, config, pinned, axis, squat, kernel))
            if not by_target:
                continue
            any_row = next(iter(by_target.values()))
            if seeded_only and any_row.get("bind") == "not_attempted":
                continue
            rows.append([label, kernel, any_row.get("listening", "?"),
                         attacker_bind(any_row)] +
                        [cell(by_target.get(a)) for a, _ in TARGETS])
    if not rows:
        return ""
    widths = [max(len(h), *(len(r[i]) for r in rows))
              for i, h in enumerate(heads)]
    out = [title, "Each connection column: of 50 connections a test client "
           "made to the service, answered by the service / answered by the "
           "attacker / requests the attacker read in full.", ""]
    out.append("  ".join(h.ljust(w) for h, w in zip(heads, widths)).rstrip())
    out.append("  ".join("-" * w for w in widths))
    last = None
    for r in rows:
        if last is not None and r[0] != last:
            out.append("")
        last = r[0]
        out.append("  ".join(v.ljust(w) for v, w in zip(r, widths)).rstrip())
    return "\n".join(out)


def main():
    runs = load()
    text = "\n\n\n".join(x for x in (
        table(runs, "Services already running, as configured; one dual-stack hijacking socket",
              "no", "v6only", False),
        table(runs, "Services already running, as configured; one hijacking socket per CPU, "
                    "bound to the clients' interface, with SO_INCOMING_CPU",
              "no", "v6only-cpu", False),
        table(runs, "Pinned to an interface; clients connect to the address "
                    "the service itself holds", "lo", "device", False),
        table(runs, "The attacker holds the service's IPv6 address before it "
                    "starts, then attacks as in the second table",
              "no", "v6only-cpu", True),
    ) if x) + "\n"
    with open(os.path.join(RESULTS, "summary.txt"), "w") as f:
        f.write(text)
    print(text)


if __name__ == "__main__":
    main()
