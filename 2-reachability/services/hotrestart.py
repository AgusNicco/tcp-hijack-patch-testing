#!/usr/bin/env python3
"""A hand-built HTTP service that restarts without closing its port, as
Envoy and HAProxy do: on SIGHUP it opens a new group of SO_REUSEPORT
listeners on the same port, then closes the old group.

  usage: hotrestart.py PORT [LISTENERS]
"""

import selectors
import signal
import socket
import sys

PORT = int(sys.argv[1])
LISTENERS = int(sys.argv[2]) if len(sys.argv) > 2 else 4
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n"

sel = selectors.DefaultSelector()
restart = False


def open_group():
    group = []
    for _ in range(LISTENERS):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.bind(("::", PORT))
        s.listen(128)
        s.setblocking(False)
        sel.register(s, selectors.EVENT_READ)
        group.append(s)
    return group


def on_hup(signum, frame):
    global restart
    restart = True


signal.signal(signal.SIGHUP, on_hup)
group = open_group()
while True:
    for key, _ in sel.select(timeout=0.5):
        try:
            conn, _ = key.fileobj.accept()
        except BlockingIOError:
            continue
        conn.settimeout(2)
        try:
            conn.recv(4096)
            conn.sendall(RESPONSE)
        except OSError:
            pass
        conn.close()
    if restart:
        restart = False
        old, group = group, open_group()
        for s in old:
            sel.unregister(s)
            s.close()
