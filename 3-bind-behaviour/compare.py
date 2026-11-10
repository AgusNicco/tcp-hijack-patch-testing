#!/usr/bin/env python3
"""Compare the results of one sequence set on three kernels.

  usage: compare.py SET BASE PATCHED REFERENCE [--examples N]

REFERENCE is the kernel that always takes the full conflict check. Every
sequence falls in one class:

  agree       all three kernels give the same results
  fixed       base differs from the reference, the patched kernel does not
  unchanged   base and patched agree with each other, not with the reference
  regressed   the patched kernel differs from the reference, base does not
  other       all three differ
  excluded    not measured on some kernel: a timewait sequence whose port
              was not empty or whose TIME_WAIT socket was gone (D or G)

Sequences that do not agree are grouped by the first call whose result
differs from the reference, and a few of each group are shown.
"""

import argparse
import gzip
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sequences  # noqa: E402

RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")


def load(kernel, name):
    d = os.path.join(RESULTS, kernel)
    with open(os.path.join(d, f"{name}.json")) as f:
        meta = json.load(f)
    with gzip.open(os.path.join(d, f"{name}.txt.gz"), "rt") as f:
        return meta, [line.strip() for line in f]


def first_change(a, b):
    for k in range(0, len(a), 2):
        if a[k:k + 2] != b[k:k + 2]:
            step = "bind" if a[k] != b[k] else "listen"
            return f"{step}() of socket {k // 2 + 1}: {a[k:k + 2]} -> {b[k:k + 2]}"
    return None


def show(seq, results):
    lines = []
    for i, cfg in enumerate(seq):
        cells = "  ".join(f"{k}={r[2 * i:2 * i + 2]}" for k, r in results.items())
        lines.append(f"      {i + 1}. {sequences.describe(cfg):58} {cells}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("set")
    ap.add_argument("base")
    ap.add_argument("patched")
    ap.add_argument("reference")
    ap.add_argument("--examples", type=int, default=3)
    args = ap.parse_args()

    names = (args.base, args.patched, args.reference)
    loaded = [load(k, args.set) for k in names]
    metas = [m for m, _ in loaded]
    for m in metas[1:]:
        for key in ("sequences", "quads", "seed"):
            if m[key] != metas[0][key]:
                sys.exit(f"{key} differs between the kernels' runs")
    base, patched, ref = (r for _, r in loaded)
    seqs = sequences.sequences(args.set, metas[0]["quads"], metas[0]["seed"])

    classes = Counter()
    groups, examples = Counter(), {}
    for i, seq in enumerate(seqs):
        b, p, r = base[i], patched[i], ref[i]
        if any(c in x for x in (b, p, r) for c in "DG"):
            cls = "excluded"
        elif b == p == r:
            cls = "agree"
        elif p == r:
            cls = "fixed"
        elif b == p:
            cls = "unchanged"
        elif b == r:
            cls = "regressed"
        else:
            cls = "other"
        classes[cls] += 1
        if cls in ("agree", "excluded"):
            continue
        key = (cls, first_change(b if b != r else p, r))
        groups[key] += 1
        examples.setdefault(key, [])
        if len(examples[key]) < args.examples:
            examples[key].append((i, seq, dict(zip(names, (b, p, r)))))

    print(f"set {args.set}: {metas[0]['sequences']} sequences")
    for k, m in zip(names, metas):
        print(f"  {k:12} kernel {m['kernel']}, {m['seconds']} s, codes {m['result_codes']}")
    print()
    for cls in ("agree", "fixed", "unchanged", "regressed", "other", "excluded"):
        print(f"{cls:10} {classes[cls]}")
    for key, n in sorted(groups.items(), key=lambda kv: (kv[0][0], -kv[1])):
        cls, change = key
        print(f"\n{cls}, {change}: {n}")
        for i, seq, res in examples[key]:
            print(f"    sequence {i}")
            print(show(seq, res))


if __name__ == "__main__":
    main()
