# TCP SO_REUSEPORT bind cache fix: tests

This repository holds the tests behind the patch "tcp: Fix the
SO_REUSEPORT bind cache admitting a conflicting socket"
(`patches/proposed-patch.patch`). The tests run on three kernels built from
`net` at `19a227903e65` (v7.4-rc1): the current kernel, the kernel with the
patch, and a test-only kernel that never uses the bind cache and always runs
the full conflict check, which serves as the reference for correct
behaviour.

## Where to find things

- `reproducer.py`, `reproducer.c`: minimal reproducers of the bug. The C
  version can run the victim and the attacker as two different users
  (`./reproducer victim PORT`, then `./reproducer attack PORT`).
- `1-attack/`: an unprivileged process uses the bug to take over TCP
  traffic from services run by other users (nginx, HAProxy, uvicorn,
  OpenSSH, PostgreSQL), and the patch stops it. `1-attack/matrix/` repeats
  the attack over every socket a victim and an attacker can have.
- `2-reachability/`: how often the code the patch changes runs, to judge
  how much its performance matters.
- `3-bind-behaviour/`: millions of bind sequences run on the three kernels,
  to check that the patch only changes the binds it is meant to.
- `4-performance/`: `bind()` and `listen()` timings, including the workload
  the cache was added for. The numbers in the commit message come from
  here.
- `kernels/`: build scripts, config fragments and each kernel's build
  metadata. `kernels/run.sh` boots a kernel under
  [virtme-ng](https://github.com/arighi/virtme-ng) and runs a test in it.
- `patches/`: the patch, the reference kernel's patch, and
  `revert-first-bind-fix.patch`, which reverts 947ccedf683e so the
  performance tests also cover the stable kernels that lack it.

Each test folder has its own README with its results and how to run it.
