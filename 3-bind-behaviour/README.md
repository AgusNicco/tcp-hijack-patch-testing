# 3. Does the patch change only the binds it is meant to?

These tests check that the patch changes only the behaviour it intends to
change: the result of a bind where the current kernel lets in a socket that
conflicts with another, and nowhere else. The bind cache the patch changes
decides whether a bind skips the conflict check, so any mistake in it shows
up as a bind that succeeds or fails when it should not.

Each test opens a few sockets one after another on one port and records
whether each `bind()` and `listen()` succeeds. Every test runs on three
kernels: the current kernel (`base`), the proposed patch
(`proposed-patch`), and a kernel that never uses the cache and always runs
the full conflict check (`full-scan-alternative`). The last one's results
are the correct ones by construction, so the patch is right if it matches
them everywhere, and the tests need no hand-written model of the conflict
rules.

## Results

```
Set             Tests run    Same result on   Fixed by the patch   Broken by the patch
                             all 3 kernels
-------------   ----------   --------------   ------------------   -------------------
pairs              112,896          112,896                    0                     0
triples          2,370,816        2,266,428              104,388                     0
quads              200,000          197,049                2,951                     0
closes           4,741,632        4,637,244              104,388                     0
latelisten       2,370,816        2,308,932               61,884                     0
timewait           677,376          673,488                3,888                     0
widepairs          331,776          331,776                    0                     0
widetriples     11,943,936       11,755,104              188,832                     0
maptriples       3,538,944        3,394,236              144,708                     0
maplatelisten    3,538,944        3,452,616               86,328                     0
```

"Fixed" means the current kernel's results differ from the full check's and
the patch's match them. In every one of those tests the current kernel let a
`bind()` succeed that the full check refuses with `EADDRINUSE`, and the patch
refuses it too. The patch never lets through a bind the current kernel
refuses.

Note that with two sockets the port's cache cannot cover a conflicting
socket, so the 2-socket sets (`pairs`, `widepairs`) agree on all three
kernels; they show that the patch changes nothing there.

No kernel logged a KASAN report, warning or bug during any set
(`results/<kernel>/dmesg-<set>.txt`).

## What the tests cover

A socket in a test is one of 336 configurations: one of two unprivileged
owners; IPv4, dual-stack IPv6 or IPv6-only; a wildcard, specific or
IPv4-mapped address; no bound device or one of two; `SO_REUSEADDR` on or
off; `SO_REUSEPORT` on or off; and whether it calls `listen()`.

```
Set           Tests
-----------   ------------------------------------------------------------
pairs         every ordered pair of configurations
triples       any configuration, then two SO_REUSEPORT sockets of one
              owner: the shortest tests in which the cache can cover a
              socket other than the one it holds
quads         200,000 random sequences of four configurations (seed 1)
closes        each triple, with its first or its second socket closed
              before the third binds
latelisten    a socket that binds without listening, an SO_REUSEPORT
              socket, then the first or the second starts listening, then
              another SO_REUSEPORT socket of the same owner
timewait      a socket left in TIME_WAIT on the port, then any
              configuration, then an SO_REUSEPORT socket of one owner
widepairs     every ordered pair from the wider pool
widetriples   the triples, from the wider pool
maptriples    the triples, from the mapped pool
maplatelisten latelisten, from the mapped pool
```

The wider pool has 576 configurations. It adds a second specific address in
each family (`10.0.0.2`, `fd00::2`, `::ffff:10.0.0.2`), loopback
(`127.0.0.1`, `::1`) and a link-local address (`fe80::1` on `dum1`).
`::1` is never bound to a device, and the link-local address is bound only
on `dum1` or on no device.

The mapped pool adds the IPv4-mapped wildcard, `::ffff:0.0.0.0`, to the 336
configurations (384 in all). As the cached socket it covers every
IPv4-mapped address, a case no other pool exercises.

The socket left in TIME_WAIT is one of 24 shapes: either owner; `10.0.0.1`,
`fd00::1` or `::ffff:10.0.0.1`; `SO_REUSEADDR` and `SO_REUSEPORT` on or off.
It connects to a listener and closes first, so it is the side that ends in
TIME_WAIT. A test counts only if its port was empty when it started and its
TIME_WAIT socket was still there when it ended; none was left out in this
run. The set runs last, because its TIME_WAIT sockets stay on their ports
for a minute after it ends.

## Files

- `sequences.py`: runs the tests on the booted kernel
- `guest.sh`: runs every set on one kernel and saves what the kernel logged
  during each set
- `compare.py`: compares the three kernels and writes `results/compare-*.txt`,
  which lists examples of every group
- `results/<kernel>/<set>.txt.gz`: one line per test, in the order
  `sequences.py` generates them, two characters per socket for `bind()` and
  `listen()` (`o` succeeded, `u` `EADDRINUSE`, `-` not attempted; `c-` a
  socket closed, `t-` a socket left in TIME_WAIT, `Lo` an earlier socket
  started listening)
- `results/<kernel>/dmesg-<set>.txt`: what the kernel logged during that set

## Running

```sh
kernels/build-all.sh path/to/net/checkout
3-bind-behaviour/run.sh
```
