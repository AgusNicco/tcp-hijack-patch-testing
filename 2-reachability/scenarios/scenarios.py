#!/usr/bin/env python3
"""Common socket operations, one scenario per run, for run.sh to trace.

  usage: scenarios.py SCENARIO [N]        (in a fresh network namespace)

  connect          N connections to a listener, each accepted
  data             one connection, N messages of 64 KiB each way
  port0            N sockets bound to port 0, then listening
  named            N sockets, each on its own port, listening
  group            N identical SO_REUSEPORT listeners on one port
  group-strict     the same, after a socket without SO_REUSEPORT has been
                   bound to another address on the port
  group-specific   an SO_REUSEPORT wildcard listener, then N listeners on
                   specific addresses of the same port

The process names itself "bindpaths" so the trace can count only it.
"""

import ctypes
import socket
import subprocess
import sys

N = int(sys.argv[2]) if len(sys.argv) > 2 else 1000
PORT = 7000


def name_process():
    libc = ctypes.CDLL(None)
    libc.prctl(15, b"bindpaths", 0, 0, 0)    # PR_SET_NAME


def listener(addr, port, reuseport=False):
    s = socket.socket()
    if reuseport:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind((addr, port))
    s.listen(N + 8)
    return s


def connect():
    srv = listener("127.0.0.1", PORT)
    for _ in range(N):
        c = socket.create_connection(("127.0.0.1", PORT))
        a, _ = srv.accept()
        c.close()
        a.close()


def data():
    srv = listener("127.0.0.1", PORT)
    c = socket.create_connection(("127.0.0.1", PORT))
    a, _ = srv.accept()
    msg = b"x" * 65536
    for _ in range(N):
        for tx, rx in ((c, a), (a, c)):
            tx.sendall(msg)
            got = 0
            while got < len(msg):
                got += len(rx.recv(len(msg) - got))


def port0():
    return [listener("127.0.0.1", 0) for _ in range(N)]


def named():
    return [listener("127.0.0.1", PORT + i) for i in range(N)]


def group():
    return [listener("127.0.0.1", PORT, True) for _ in range(N)]


def group_strict():
    plain = socket.socket()
    plain.bind(("127.0.0.2", PORT))
    return [plain] + group()


def group_specific():
    first = listener("0.0.0.0", PORT, True)
    addrs = [f"127.0.{i // 250}.{i % 250 + 1}" for i in range(N)]
    return [first] + [listener(a, PORT, True) for a in addrs]


SCENARIOS = {
    "connect": connect,
    "data": data,
    "port0": port0,
    "named": named,
    "group": group,
    "group-strict": group_strict,
    "group-specific": group_specific,
}

if __name__ == "__main__":
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    name_process()
    held = SCENARIOS[sys.argv[1]]()
