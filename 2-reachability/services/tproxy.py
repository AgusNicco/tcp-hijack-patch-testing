#!/usr/bin/env python3
"""A hand-built transparent proxy endpoint: SO_REUSEPORT listeners with
IP_TRANSPARENT on PORT, answering connections that a TPROXY rule redirects
to it from another port. Each accepted connection keeps the original
destination port, so __inet_inherit_port() adds it to that port's bind
bucket and updates the bucket's summary: the one way an incoming connection
reaches the code the patch changes.

  usage: tproxy.py PORT [LISTENERS]        (in the proxy's network namespace)
"""

import selectors
import socket
import sys

IP_TRANSPARENT = 19
PORT = int(sys.argv[1])
LISTENERS = int(sys.argv[2]) if len(sys.argv) > 2 else 4
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n"

sel = selectors.DefaultSelector()
for _ in range(LISTENERS):
    s = socket.socket()
    s.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(("0.0.0.0", PORT))
    s.listen(256)
    s.setblocking(False)
    sel.register(s, selectors.EVENT_READ)

while True:
    for key, _ in sel.select():
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
