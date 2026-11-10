#!/usr/bin/env python3
"""Send HTTP requests to each TARGET for SECONDS. For each target, half the
threads open a new connection for every request and half keep a connection
open for as long as the server allows.

  usage: load.py SECONDS THREADS TARGET...      TARGET is host:port or [v6]:port

Prints the requests and errors per target.
"""

import socket
import sys
import threading
import time

SECONDS, THREADS = float(sys.argv[1]), int(sys.argv[2])
TARGETS = sys.argv[3:]
counts = {t: [0, 0] for t in TARGETS}
lock = threading.Lock()


def parse(target):
    host, port = target.rsplit(":", 1)
    return host.strip("[]"), int(port)


def request(sock, host):
    sock.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    head, body = buf.split(b"\r\n\r\n", 1)
    head = head.lower()
    length = int(head.split(b"content-length:")[1].split(b"\r\n")[0])
    while len(body) < length:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("closed")
        body += chunk
    return b"connection: close" not in head


def worker(target, keep):
    host, port = parse(target)
    end = time.time() + SECONDS
    sock = None
    while time.time() < end:
        try:
            if sock is None:
                sock = socket.create_connection((host, port), timeout=5)
            alive = request(sock, host)
            ok = 1
        except OSError:
            alive, ok = False, 0
        if not (keep and alive) and sock is not None:
            sock.close()
            sock = None
        with lock:
            counts[target][0 if ok else 1] += 1
        if not ok:
            time.sleep(0.1)


threads = [threading.Thread(target=worker, args=(t, i % 2 == 1))
           for t in TARGETS for i in range(THREADS)]
for t in threads:
    t.start()
for t in threads:
    t.join()
for t, (ok, err) in counts.items():
    print(f"{t:24} {ok:8} requests {err:6} errors")
