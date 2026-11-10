# 4. What does the patch cost?

Commit 637bc8bbe6c0 (2017) added the cache's `FASTREUSEPORT_STRICT` state,
which the patch narrows, to keep binding many identical `SO_REUSEPORT`
sockets fast. This tests that
the patch keeps those performance benefits. It uses the test the
original commit was trying to optimize for.

`bench.c` times the `bind()` and `listen()` calls of N identical
`SO_REUSEPORT` sockets of one owner on one port, after a socket without
`SO_REUSEPORT` is already on it, on kernels without KASAN; median of 5 runs.
This is the table in the commit message, plus the last two columns.

```
     N     current   full check  this patch  current, no 947ccedf683e  this patch, no 947ccedf683e
   256     0.13 ms      0.58 ms     0.15 ms                   0.13 ms                      0.14 ms
  1024     0.63 ms      8.07 ms     0.69 ms                   0.60 ms                      0.59 ms
  4096     2.63 ms    154.32 ms     2.83 ms                   2.44 ms                      2.54 ms
 16384     9.80 ms   5874.11 ms     9.86 ms                   9.70 ms                      9.96 ms
```

- This is the workload 637bc8bbe6c0 added `FASTREUSEPORT_STRICT` for, and the
  patch keeps it on the fast path. Bacik's reproducer from that series, the same
  workload in 64 threads: 4531.88 ms current, 10328.09 ms full check,
  4647.94 ms with this patch.
- 16384 listeners alternating between `0.0.0.0` and specific addresses
  stay on the fast path: 15.85 ms against 15.26 ms on the current kernel
  (4422.48 ms with the full check).
- The one case this patch sends to the full check: 16384 wildcard
  listeners alternating between two devices took 2791.25 ms instead of
  9.33 ms (5550.72 ms with the full check).
- **no 947ccedf683e:** that commit (v7.4-rc1) changed how the cache is set up
  on a port's first bind, and the stable kernels from v6.8 this patch will be
  backported to lack it, so it was also measured reverted
  (`patches/revert-first-bind-fix.patch`).

Other scenarios and the other kernels' figures: `results/summary.txt`. No
kernel logged a warning or bug.

## Files

- `bench.c`: the timing program
- `bacik-2017.c`: the reproducer Josef Bacik attached to the cover letter of
  the series that added `FASTREUSEPORT_STRICT`, "[PATCH 0/6 net-next][V3] Rework
  inet_csk_get_port" (Message-ID
  `<1484165171-19210-1-git-send-email-jbacik@fb.com>`, 11 Jan 2017),
  unmodified: 64 threads binding and listening 16,384 identical
  `SO_REUSEPORT` dual-stack sockets on a port whose first listener was bound
  without `SO_REUSEPORT`
- `guest.sh`: runs every timing on one booted kernel
- `report.py`: writes `results/summary.txt`, the tables above
- `results/<kernel>/bench.txt`: scenario, sockets, median, minimum and
  maximum, in milliseconds

## Running

```sh
kernels/build-perf.sh path/to/net/checkout
4-performance/run.sh
```
