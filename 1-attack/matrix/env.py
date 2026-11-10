"""The network, the helpers at the other end, and socket creation for the
attack matrix. Run as root in the guest.

The attacker's sockets are made with the effective uid of nobody, so they
belong to nobody and every check is made without capabilities: switching the
effective uid away from 0 clears the effective capability set, and switching
back restores it.
"""

import contextlib
import errno
import os
import pwd
import select
import socket
import struct
import subprocess

import space

SO_REUSEPORT = getattr(socket, "SO_REUSEPORT", 15)
SO_BINDTOIFINDEX = getattr(socket, "SO_BINDTOIFINDEX", 62)
SO_INCOMING_CPU = getattr(socket, "SO_INCOMING_CPU", 49)
NOBODY = pwd.getpwnam("nobody").pw_uid
ABSENT_IFINDEX = 4242
LINGER0 = struct.pack("ii", 1, 0)
HERE = os.path.dirname(os.path.abspath(__file__))

CODES = {errno.EADDRINUSE: "u", errno.EACCES: "a", errno.EADDRNOTAVAIL: "n",
         errno.EINVAL: "i", errno.ENODEV: "d", errno.EPERM: "p"}


def sh(cmd):
    subprocess.run(cmd, shell=True, capture_output=True)


def setup_network():
    """vh <-> vp leads to the namespace "peer", the other machine on this
    link; vo <-> vq to "other", a second link."""
    for name in ("peer", "other"):
        sh("ip netns del %s" % name)
    sh("ip link del vh; ip link del vo")
    sh("ip link set lo up")
    sh("sysctl -qw net.ipv6.conf.all.accept_dad=0 "
       "net.ipv6.conf.default.accept_dad=0")
    sh("sysctl -qw net.ipv4.ip_local_port_range='50000 60999'")
    for here, there, ns in (("vh", "vp", "peer"), ("vo", "vq", "other")):
        sh("ip netns add %s" % ns)
        sh("ip link add %s type veth peer name %s" % (here, there))
        sh("ip link set %s netns %s" % (there, ns))
        sh("ip netns exec %s sysctl -qw net.ipv6.conf.all.accept_dad=0" % ns)
        sh("ip -n %s link set lo up" % ns)
    for cmd in ("ip addr add %s/24 dev vh" % space.HOST_V4,
                "ip addr add %s/64 dev vh nodad" % space.HOST_V6,
                "ip addr add %s/64 dev vh nodad" % space.HOST_LL,
                "ip link set vh up",
                "ip -n peer addr add %s/24 dev vp" % space.PEER_V4,
                "ip -n peer addr add %s/64 dev vp nodad" % space.PEER_V6,
                "ip -n peer addr add %s/64 dev vp nodad" % space.PEER_LL,
                "ip -n peer link set vp up",
                "ip addr add 10.8.0.1/24 dev vo",
                "ip addr add fe80::11/64 dev vo nodad",
                "ip link set vo up",
                "ip -n other link set vq up"):
        sh(cmd)


def ifindex(name):
    return ABSENT_IFINDEX if name == "absent" else socket.if_nametoindex(name)


def sockaddr(fam, addr, port):
    if fam == socket.AF_INET6 and addr in space.LINK_LOCAL:
        return (addr, port, 0, ifindex("vh"))
    return (addr, port) if fam == socket.AF_INET else (addr, port, 0, 0)


def code(e):
    """One letter per common errno, "x" and the number for anything else."""
    return CODES.get(e.errno) or "x%d" % (e.errno or 0)


@contextlib.contextmanager
def attacker():
    os.seteuid(NOBODY)
    try:
        yield
    finally:
        os.seteuid(0)


def new_socket(spec):
    """A socket with every option of spec set, not yet bound."""
    fam, addr, v6only, dev, ra, rp = spec
    s = socket.socket(fam, socket.SOCK_STREAM)
    if fam == socket.AF_INET6 and v6only is not None:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, int(v6only))
    if ra:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if rp:
        s.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
    if dev:
        s.setsockopt(socket.SOL_SOCKET, SO_BINDTOIFINDEX, ifindex(dev))
    return s


def bind(spec, port):
    """Make and bind one socket. Returns (socket or None, one-letter code)."""
    try:
        s = new_socket(spec)
    except OSError as e:
        return None, code(e)
    try:
        s.bind(sockaddr(spec[0], spec[1], port))
        return s, "o"
    except OSError as e:
        s.close()
        return None, code(e)


def reset_close(socks):
    for s in socks:
        if s is None:
            continue
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER0)
        except OSError:
            pass
        s.close()


class Helper:
    """helper.py in a namespace ("peer"), or on this host (ns=None)."""

    def __init__(self, ns=None):
        argv = ["python3", "-u", os.path.join(HERE, "helper.py")]
        if ns:
            argv = ["ip", "netns", "exec", ns] + argv
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True,
                                     bufsize=1)

    def cmd(self, *words):
        line = " ".join(str(w) for w in words)
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        # No helper command takes more than a few seconds.
        if not select.select([self.proc.stdout], [], [], 60)[0]:
            raise RuntimeError("helper did not answer: " + line)
        return self.proc.stdout.readline().split()

    def stop(self):
        self.proc.stdin.close()
        self.proc.wait(5)

