# The attack matrix

## Why this exists

The rest of `1-attack` attacks services the way an attacker would: pick a
service, pick a trick, see what happens. That answers "can this be done",
but it leaves open the question underneath it — *which* sockets can be
attacked, and by *what*. A trick that fails might fail because the victim is
safe, or because that particular attempt was built wrong.

This directory settles that by brute force. It enumerates the kinds of
socket a program can end up with, enumerates the sockets an unprivileged
attacker can ask the kernel for, and tries every combination of the two. The
result is a per-victim answer that does not depend on anyone having thought
of the right trick: either some sequence of attacker sockets gets over that
victim, or none of the thousands tried does.

The same cases then run on all three kernels — the current one, the one with
the patch, and the one that always runs the full check — so the patch is
judged on exactly what worked without it.

## What a victim and an attacker are here

`space.py` defines both.

A **victim** is what a program ends up holding, 183 of them:

| Kind | What it is | How many |
| --- | --- | --- |
| listener | one listening socket, every address × device × SO_REUSEADDR × SO_REUSEPORT | 132 |
| listener pair | an IPv4 and an IPv6 socket on one port, as dual-stack services bind, each both tolerating and aborting on a failed bind | 24 |
| low port | listeners on a port below 1024 | 3 |
| outgoing connection | a connected socket whose local port the kernel chose | 12 |
| accepted connection | the server side of a connection, as `accept()` returns it | 12 |

Addresses cover the wildcards, loopback, a routable address of each family,
a link-local address, and the IPv4-mapped forms; devices cover none, the
interface the traffic uses, loopback, and an index that does not exist.

An **attacker socket** is one request an unprivileged process can make: a
family, an address, `IPV6_V6ONLY`, a bound device, `SO_REUSEADDR` and
`SO_REUSEPORT`, 260 of them. Every attacker socket is created with the
effective uid of `nobody`, which also clears the effective capabilities, so
nothing succeeds because the test ran as root.

## How it runs

**Stage 1 — which binds succeed** (`stage1.py`). Every trial starts a fresh
victim on a fresh port, so nothing a previous trial left behind can change
the next. For each victim, and for each socket the attacker may already hold
before the victim starts:

1. every attacker socket alone — this is also the control for the rest;
2. every ordered pair, for the sockets that bind alone;
3. a sample of three-socket sequences.

A sequence counts only when its last socket binds *and* listens while that
same socket alone does not. That difference is the whole point: it means the
earlier sockets, not the last one, got it past the check.

**Stage 2 — what the attacker gets** (`stage2.py`), run with real traffic on
the binds stage 1 found:

- *Listeners.* The victim answers `V`, the attacker's socket answers `A`.
  Clients connect from another network namespace to each address the host
  has, and locally to loopback. Each case runs twice, once with a single
  attacker socket and once with one copy per CPU carrying `SO_INCOMING_CPU`,
  which raises its score in the listener lookup. Each victim also runs once
  with no attacker, to record which clients it answers by itself — without
  that, an address no one answers looks the same as one the attacker took.
  Finally the victim is stopped and started again, to see whether the
  attacker's leftover sockets keep it from binding.
- *Connections.* The attacker connects from its socket to the victim's peer.
  The peer then sends on the victim's connection, which it has held by
  identity since before the attack, and the record says who received it. A
  connection the attacker opened of its own rather than taking the victim's
  is recorded separately: both have the same local port, so counting by port
  alone would read one as the other.

Connection cases are in `connections.jsonl.gz` and the rest in
`stage2.jsonl.gz`.

## What it found

The per-victim tables are in `../results/matrix/summary.txt`; `report.py`
rebuilds them from the raw results. The headline:

| Kernel | Bind sequences tried | Sequences that got over a victim |
| --- | --- | --- |
| Current kernel | 9,085,670 | 114,513 |
| With the patch | 9,085,670 | 0 |
| Full check always | 9,085,670 | 0 |

Note that the patch and the always-full-check kernel agree exactly, on every
victim, so the patch's zero is not "it blocked the attacks we thought of".
Every sequence that worked uses one of the two axes the bind cache does
not describe — a different device, or a different v6only scope — and no
third mechanism turned up anywhere in the space.

The other ordering — the attacker already holding a socket on the port when
the victim starts — was tried over a further 22,884,117 sequences per
kernel, and found **nothing the first ordering had not already found**. It
only changes the outcome where it changes what the victim *is*: a service
that carries on after a failed bind comes up single-family, and is then
exposed as a single-family service, which the first ordering covers too.

Note that this pass needs its own baseline. A sequence counts only when the
victim refuses that socket on its own with nothing else held; otherwise the
count is dominated by the attacker getting past its own squatting socket,
which it owns and is entitled to — 48,871 of the sequences on the current
kernel. `report.py` separates the two. The patched kernel and the
full-check reference have none of either kind.

Note that trials with an outgoing-connection victim run one at a time,
across all jobs. Such a victim gets its port from `connect()`, and Linux
lets two connections to different destinations share a local port, so two
jobs' victims could sit on the same port and each job's attacker sockets
would meet the other's. An earlier run without this showed 35 such
spurious positives on the patched and full-check kernels.

Note what this pass does *not* cover. It holds the squat on the port the
victim is about to use, which works for a listener, a pair and a low port,
and for an accepted connection through its listener's port. An outgoing
connection has no such port: its socket autobinds an ephemeral one, so the
squat sits somewhere else and the question is never put to those 12
victims. It is answered elsewhere instead — `../outgoing.py` measures that
an outgoing `connect()` never lands on a port an attacker holds through
`bind()`, because the ephemeral search skips ports where a conflict exists.

What an attacker got on the current kernel, by what the victim is:

| Victim | What the attacker takes |
| --- | --- |
| listener on `0.0.0.0`, or `[::]` IPv6-only, or a link-local address | every one of its clients, if it does not set `SO_REUSEPORT` |
| listener bound to a device, any address | every one of its clients, `SO_REUSEPORT` or not |
| listener on `[::]` dual-stack, or on one specific address | nothing of its traffic |
| almost any listener, 136 of the 140 measured | its ability to bind that address again |
| connected socket bound to a device, outgoing or accepted | the connection itself: it is destroyed, and for an outgoing one the peer is left holding a connection on the victim's own address and port that the attacker holds |
| connected socket with no device | nothing |

Note that all 68 listeners that lost clients lost *every* client, never a
part of them, so there is no half-working state for an operator to notice.
That is a property of the kernel, not of how many clients were tried: over
102,560 groups of six connections to one address, **not one group split**
between the victim and the attacker. Every group went entirely to one of
them, or to neither, so the lookup settles a destination deterministically
and six connections measure it as well as six hundred would.

Note how a live connection dies, which `why-connections-die.py` captures on
the peer's link rather than leaving to reasoning. The attacker's `connect()`
sends a SYN carrying the victim's four-tuple; the peer's established socket
answers it with a challenge ACK, as RFC 5961 says to; that ACK arrives at
the attacker's socket in `SYN_SENT`, where it acknowledges nothing, so the
kernel answers it with a RST — and that RST carries the victim's four-tuple,
so it tears down the peer's side of the victim's connection. The attacker
crafts nothing; both the SYN and the RST are ordinary kernel output. Its
retried SYN is then answered normally, which is why an outgoing connection
ends up replaced by one the attacker holds, while for the server side of a
connection the retry reaches an ephemeral port with nothing listening and
comes back as a RST, so the attacker is left with ECONNREFUSED and the
victim with a dead connection.

Note that eight of the connection attacks work on all three kernels,
including the patched one, and they are not this bug. Those victims set
`SO_REUSEADDR` on their own connected socket, and `inet_csk_bind_conflict()`
lets two `SO_REUSEADDR` sockets share an address and port when neither is
listening, without comparing uid. So a process that sets `SO_REUSEADDR` and
binds a device on a socket it connects out from can have that connection
destroyed by any other user, with no bug involved. The patch leaves this
alone, as it should; it is counted separately so it is not read as a
regression.

Note that `SO_REUSEPORT` protecting a listener is an accident of the lookup,
not a defence anyone chose. Two rules combine: an IPv6 socket with
`SO_REUSEPORT` is put at the tail of the hash bucket and everything else at
the head (`inet_hashtables.c`, `__inet_hash`), and `inet_lhash2_lookup`
stops at the first socket that beats the best so far and has `SO_REUSEPORT`,
without scoring the rest. A victim with it set therefore ends the walk
before the attacker's higher-scoring socket is reached — unless the attacker
can use an IPv4 socket, which goes to the head in front of the victim, which
is why a device-bound victim falls either way.

Note that "its ability to bind that address again" is what reaches nearly
every victim, including the ones whose traffic is safe. Without the bug an
attacker cannot bind the port at all while the service holds it, so it would
have to win a race at the service's next restart; with the bug it can sit on
the port beside the running service and hold it from the moment the service
stops. On the current kernel 136 of the 140 listeners and pairs measured
could not bind their address again; the four that could are IPv4-and-IPv6
pairs on one specific address each that give up when either bind fails.
Under the patch that becomes **none at all**: 128 bind again in full, and
the remaining 12 come back missing one family, because the attacker is
holding that address through an ordinary bind that was always allowed.

## Running it

```
kernels/build-all.sh          # once, builds the three KASAN kernels
1-attack/matrix/run.sh        # all three kernels, then the tables
```

Each part is skipped when its output file is already there, so `run.sh` can
be run again to add a missing part without repeating the rest. Results land
in `1-attack/results/matrix/<kernel>/`, and `report.py` writes the tables to
`1-attack/results/matrix/summary.txt`.
