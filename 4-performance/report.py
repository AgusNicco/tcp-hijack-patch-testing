#!/usr/bin/env python3
"""Turn results/<kernel>/bench.txt into one table per scenario, written to
results/summary.txt."""

import os

RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
KERNELS = [
    ("base", "Current\nkernel"),
    ("proposed-patch", "With the\npatch"),
    ("full-scan-alternative", "Full check\nalways"),
    ("base-without-first-bind-fix", "Current kernel,\nno 947ccedf683e"),
    ("proposed-patch-without-first-bind-fix", "With the patch,\nno 947ccedf683e"),
]
SCENARIOS = [
    ("group", "Identical SO_REUSEPORT listeners on an empty port"),
    ("group-plain", "Identical SO_REUSEPORT listeners, after a socket without SO_REUSEPORT"),
    ("specific", "Listeners on specific addresses, after an SO_REUSEPORT wildcard listener"),
    ("alternating", "Wildcard listeners bound to two devices in turn"),
    ("mixed", "Listeners alternating between 0.0.0.0 and specific addresses"),
    ("bacik", "Bacik's 2017 reproducer: 64 threads, 16,384 listeners"),
]


def load(kernel):
    times = {}
    path = os.path.join(RESULTS, kernel, "bench.txt")
    if os.path.exists(path):
        for line in open(path):
            scenario, n, median, _, _ = line.split()
            times[scenario, int(n)] = float(median)
    return times


def main():
    data = {k: load(k) for k, _ in KERNELS}
    heads = [h.split("\n") for _, h in KERNELS]
    widths = [max(len(x) for x in h) for h in heads]
    out = ["Median time of the bind() and listen() calls, in milliseconds,",
           "over 5 runs.", ""]
    for scenario, title in SCENARIOS:
        ns = sorted({n for k in data for (s, n) in data[k] if s == scenario})
        out += [title, ""]
        for i in range(2):
            label = "Sockets" if i == 1 else ""
            out.append(f"{label:<8}" + "".join(f"  {h[i]:>{w}}" for h, w in zip(heads, widths)))
        out.append("-" * 8 + "".join("  " + "-" * w for w in widths))
        for n in ns:
            cells = [data[k].get((scenario, n)) for k, _ in KERNELS]
            out.append(f"{n:>8,}" + "".join(
                f"  {'' if c is None else f'{c:,.2f}':>{w}}" for c, w in zip(cells, widths)))
        out += ["", ""]
    text = "\n".join(out).rstrip() + "\n"
    with open(os.path.join(RESULTS, "summary.txt"), "w") as f:
        f.write(text)
    print(text)


if __name__ == "__main__":
    main()
