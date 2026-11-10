"""The space the attack matrix covers: every victim and every attacker socket,
as plain data with stable indices, so a result can always be traced back to
exactly what was run.

The network (see env.py): this host's veth "vh" faces a peer namespace that
stands in for another machine on the link, and a second veth "vo" leads to
another link, which only serves as "some other real device".

A socket is (family, address, IPV6_V6ONLY, device, SO_REUSEADDR,
SO_REUSEPORT). The device is None, "absent" (an interface index with no
interface behind it, which SO_BINDTOIFINDEX accepts), or a name.
"""

import itertools
import random
import socket

V4, V6 = socket.AF_INET, socket.AF_INET6

HOST_V4, PEER_V4 = "10.9.0.1", "10.9.0.2"
HOST_V6, PEER_V6 = "fd09::1", "fd09::2"
HOST_LL, PEER_LL = "fe80::1", "fe80::2"
LINK_LOCAL = (HOST_LL, PEER_LL)

# Every address an attacker socket can take: wildcards of each kind, the
# addresses this host has, and IPv4-mapped forms.
ATTACKER_ADDRESSES = [
    (V4, "0.0.0.0", None),
    (V4, "127.0.0.1", None),
    (V4, "127.0.0.2", None),
    (V4, HOST_V4, None),
    (V6, "::", True),
    (V6, "::", False),
    (V6, "::1", False),
    (V6, "::1", True),
    (V6, HOST_V6, False),
    (V6, HOST_V6, True),
    (V6, HOST_LL, False),
    (V6, "::ffff:127.0.0.1", False),
    (V6, "::ffff:" + HOST_V4, False),
]
ATTACKER_DEVICES = [None, "absent", "vh", "vo", "lo"]

ATTACKER_SOCKETS = [
    (fam, addr, v6only, dev, ra, rp)
    for (fam, addr, v6only) in ATTACKER_ADDRESSES
    for dev in ATTACKER_DEVICES
    for ra in (0, 1) for rp in (0, 1)
]

# The smaller pool used where the full one would be too large: the sockets
# that can matter as a seed or a hijack, which need SO_REUSEPORT.
REUSEPORT_SOCKETS = [i for i, s in enumerate(ATTACKER_SOCKETS)
                     if s[5] and not s[4]]
# Plain binds an attacker can make to sit on a port before a service starts.
SQUAT_SOCKETS = [i for i, s in enumerate(ATTACKER_SOCKETS)
                 if not s[4] and s[3] in (None, "absent")]

VICTIM_ADDRESSES = [
    (V4, "0.0.0.0", None),
    (V4, "127.0.0.1", None),
    (V4, HOST_V4, None),
    (V6, "::", False),
    (V6, "::1", False),
    (V6, HOST_V6, False),
    (V6, "::ffff:" + HOST_V4, False),
    (V6, "::", True),
    (V6, "::1", True),
    (V6, HOST_V6, True),
    (V6, HOST_LL, False),
]
VICTIM_DEVICES = [None, "vh", "lo"]

BOTH_FAMILY_PAIRS = [
    ((V4, "0.0.0.0", None), (V6, "::", True)),
    ((V4, "127.0.0.1", None), (V6, "::1", True)),
    ((V4, HOST_V4, None), (V6, HOST_V6, True)),
]


def victims():
    """Every victim, as a dict. kind is one of:

      listener  one listening socket
      pair      a listener on each family, as PostgreSQL and nginx bind;
                "continue" keeps whichever bind succeeded, "abort" gives up
                on both, which are the two ways real services react
      low       a listener on a port below 1024
      client    an outgoing connection from this host to the peer
      child     a connection the peer made to a listener on this host
    """
    out = []
    for (fam, addr, v6only), dev, ra, rp in itertools.product(
            VICTIM_ADDRESSES, VICTIM_DEVICES, (0, 1), (0, 1)):
        out.append({"kind": "listener",
                    "socks": [(fam, addr, v6only, dev, ra, rp)]})
    for (a, b), dev, ra, tol in itertools.product(
            BOTH_FAMILY_PAIRS, (None, "vh"), (0, 1), ("continue", "abort")):
        out.append({"kind": "pair", "tolerance": tol,
                    "socks": [a + (dev, ra, 0), b + (dev, ra, 0)]})
    for socks in ([(V4, "0.0.0.0", None, None, 0, 0)],
                  [(V6, "::", False, None, 0, 0)],
                  [(V4, "0.0.0.0", None, None, 0, 0),
                   (V6, "::", True, None, 0, 0)]):
        out.append({"kind": "low", "tolerance": "continue", "socks": socks})
    for (fam, peer), dev, ra in itertools.product(
            ((V4, PEER_V4), (V6, PEER_V6), (V6, PEER_LL)), (None, "vh"),
            (0, 1)):
        out.append({"kind": "client", "family": fam, "peer": peer,
                    "socks": [(fam, None, None, dev, ra, 0)]})
    for (fam, laddr, v6only), dests in (
            ((V4, "0.0.0.0", None), [(V4, HOST_V4)]),
            ((V6, "::", False), [(V4, HOST_V4), (V6, HOST_V6), (V6, HOST_LL)]),
            ((V6, "::", True), [(V6, HOST_V6), (V6, HOST_LL)])):
        for dev, dest in itertools.product((None, "vh"), dests):
            out.append({"kind": "child", "dest": dest,
                        "socks": [(fam, laddr, v6only, dev, 0, 0)]})
    for i, v in enumerate(out):
        v["id"] = i
    return out


def pre_states(victim, every=False):
    """What the attacker holds before the victim starts: nothing, or one
    squatting socket. Squats are tried for a victim that binds a known port
    at startup, and for every victim when `every` is set, which answers the
    same question in the other order: the attacker is on the port first and
    the victim arrives afterwards."""
    yield None
    if every or victim["kind"] in ("pair", "low"):
        for q in SQUAT_SOCKETS:
            yield q


def describe_socket(s):
    fam, addr, v6only, dev, ra, rp = s
    if addr is None:
        where = "autobind"
    elif fam == V4:
        where = addr
    else:
        where = "[%s]" % addr
        if v6only:
            where += " v6only"
        elif addr == "::":
            where += " dual-stack"
    opts = (["dev=%s" % dev] if dev else []) + \
        (["SO_REUSEADDR"] if ra else []) + (["SO_REUSEPORT"] if rp else [])
    return " ".join([where] + opts)


def describe_victim(v):
    k = v["kind"]
    socks = " + ".join(describe_socket(s) for s in v["socks"])
    if k == "listener":
        return "listener " + socks
    if k == "pair":
        return "listeners %s (%s if one bind fails)" % (socks, v["tolerance"])
    if k == "low":
        return "listener(s) on a port below 1024: " + socks
    if k == "client":
        return "outgoing connection %s -> %s" % (socks, v["peer"])
    return "accepted connection on listener %s, from the peer to %s" % (
        socks, v["dest"][1])
