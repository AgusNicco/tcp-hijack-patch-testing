#!/usr/bin/env python3
"""The services 1-attack runs as the victim: the ones 2-reachability uses,
here running natively rather than in containers.

Each runs in the configuration its own package ships, so what the attack
finds is what the service chose, not a shape picked to make it vulnerable.
Where an administrator's choice changes the answer, that configuration is
run as well and labelled as such. Every service also runs pinned to an
interface, which no service does by itself: that is the harness imposing
the shape a VRF or a BindToDevice= unit would produce.

Every service answers a probe of its own protocol, and listeners() reports
the addresses it really bound, read from the kernel.
"""

import os
import shutil
import signal
import socket
import struct
import subprocess
import time

HTTP_PROBE = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
PG_PROBE = struct.pack("!II", 8, 80877103)      # SSLRequest
TMP = "/tmp/attack"
# Built here, not in the repository, so every service's user can read it.
SHIM = TMP + "/pin-to-device.so"


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    return path


def wait_until(check, seconds=20):
    for _ in range(int(seconds * 10)):
        if check():
            return True
        time.sleep(0.1)
    return False


def hexaddr(text):
    """One address from /proc/net/tcp*, which prints it as little-endian
    words of hex."""
    words = [text[i:i + 8] for i in range(0, len(text), 8)]
    packed = b"".join(int(w, 16).to_bytes(4, "little") for w in words)
    family = socket.AF_INET if len(packed) == 4 else socket.AF_INET6
    return socket.inet_ntop(family, packed)


def listeners(port):
    """The addresses something is listening on at this port, from the
    kernel rather than from a configuration file."""
    found = set()
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                next(f)
                for line in f:
                    col = line.split()
                    addr, p = col[1].rsplit(":", 1)
                    if col[3] == "0A" and int(p, 16) == port:   # TCP_LISTEN
                        found.add(hexaddr(addr))
        except OSError:
            pass
    return ",".join(sorted(found)) or "none"


def setup_addresses():
    """Give the loopback the addresses the seed shapes use, so a seed that
    is refused was refused by the conflict check and not for want of an
    address to bind."""
    for args in (["ip", "addr", "add", "::2/128", "dev", "lo"],
                 ["ip", "addr", "add", "fe80::1/64", "dev", "lo", "nodad"]):
        subprocess.run(args, capture_output=True)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)


def reachable(port, family=socket.AF_INET, addr="127.0.0.1"):
    try:
        socket.create_connection((addr, port), timeout=1).close()
        return True
    except OSError:
        return False


class Service:
    """A victim service. `families` is "ipv4" or "both"; `pin` is an
    interface to pin every listening socket to, or None."""

    probe = HTTP_PROBE

    def __init__(self, port, config="default", pin=None):
        self.port, self.config, self.pin = port, config, pin
        self.proc = None

    def env(self):
        env = dict(os.environ)
        if self.pin:
            env["LD_PRELOAD"] = SHIM
            env["PIN_DEV"] = self.pin
        return env

    def up(self):
        return reachable(self.port)

    def logfile(self):
        return "%s/%s-stderr.log" % (TMP, type(self).__name__.lower())

    def popen(self, argv):
        """Start the service, keeping its stderr: a service that cannot bind
        says so there, which is how restart() tells a lost address from a
        service that simply kept running."""
        os.makedirs(TMP, exist_ok=True)
        self.proc = subprocess.Popen(argv, env=self.env(),
                                     stdout=subprocess.DEVNULL,
                                     stderr=open(self.logfile(), "w"))

    def start(self):
        self.spawn()
        if not wait_until(self.up):
            raise RuntimeError("%s did not start" % self.name)

    def restart(self):
        """Did the service bind its address again, as a restart would, while
        the attacker holds the port? A service that cannot bind exits, and
        one that goes into the background reports it from spawn(). Whether
        the port answers afterwards is not the test: the attacker may be the
        one answering."""
        try:
            self.spawn()
        except Exception as e:
            return "no (%s)" % e
        time.sleep(2)
        died = self.proc is not None and self.proc.poll() is not None
        try:
            with open(self.logfile()) as f:
                complained = "in use" in f.read()
        except OSError:
            complained = False
        if died or complained:
            return "no (EADDRINUSE)"
        self.stop()
        return "yes"

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None


class Nginx(Service):
    name = "nginx"
    conf = TMP + "/nginx.conf"

    def spawn(self):
        # Ubuntu ships "listen 80 default_server; listen [::]:80 ...".
        listen = "\t\tlisten %d;\n" % self.port
        if self.config == "default":
            listen += "\t\tlisten [::]:%d;\n" % self.port
        write(self.conf, "daemon on;\nworker_processes 2;\n"
              "pid %s/nginx.pid;\nerror_log %s/nginx.log;\n"
              "events { worker_connections 256; }\nhttp {\n\taccess_log off;\n"
              "\tclient_body_temp_path %s/nginx-tmp;\n\tserver {\n%s"
              '\t\tlocation / { return 200 "service\\n"; }\n\t}\n}\n'
              % (TMP, TMP, TMP, listen))
        rc = subprocess.run(["/usr/sbin/nginx", "-c", self.conf],
                            env=self.env(), capture_output=True)
        if rc.returncode:
            raise RuntimeError("EADDRINUSE")

    def stop(self):
        subprocess.run(["/usr/sbin/nginx", "-c", self.conf, "-s", "quit"],
                       capture_output=True)
        wait_until(lambda: not self.up(), 8)


class Haproxy(Service):
    name = "HAProxy"
    conf = TMP + "/haproxy.cfg"

    def spawn(self):
        # HAProxy ships no bind line at all; an administrator writes one.
        binds = "\tbind 127.0.0.1:%d\n" % self.port
        if self.config == "both":
            binds += "\tbind [::1]:%d\n" % self.port
        write(self.conf,
              "global\n\tdaemon\n\tpidfile %s/haproxy.pid\n"
              "defaults\n\tmode http\n\ttimeout connect 2s\n"
              "\ttimeout client 5s\n\ttimeout server 5s\n"
              "frontend f\n%s"
              '\thttp-request return status 200 content-type text/plain '
              'string "service\\n"\n' % (TMP, binds))
        rc = subprocess.run(["/usr/sbin/haproxy", "-f", self.conf],
                            env=self.env(), capture_output=True)
        if rc.returncode:
            raise RuntimeError("EADDRINUSE")

    def stop(self):
        try:
            with open(TMP + "/haproxy.pid") as f:
                for pid in f.read().split():
                    os.kill(int(pid), signal.SIGTERM)
        except (OSError, ValueError):
            pass
        wait_until(lambda: not self.up(), 8)


class Uvicorn(Service):
    name = "FastAPI (uvicorn)"

    def spawn(self):
        app = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "2-reachability", "services", "fastapi")
        # uvicorn's own default host is 127.0.0.1.
        host = "127.0.0.1" if self.config == "default" else "0.0.0.0"
        self.popen(["python3", "-m", "uvicorn", "app:app", "--app-dir", app,
                    "--host", host, "--port", str(self.port),
                    "--workers", "2"])


class Sshd(Service):
    name = "OpenSSH"
    conf = TMP + "/sshd_config"
    # A client sends its identification string as soon as it connects
    # (RFC 4253, 4.2), without waiting for the server's.
    probe = b"SSH-2.0-OpenSSH_9.6p1 probe\r\n"

    def spawn(self):
        os.makedirs(TMP, exist_ok=True)
        os.makedirs("/run/sshd", exist_ok=True)   # sshd's privsep directory
        key = TMP + "/ssh_host_key"
        if not os.path.exists(key):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-f", key], check=True)
        # sshd's default is AddressFamily any.
        family = "any" if self.config == "default" else "inet"
        write(self.conf, "Port %d\nAddressFamily %s\nHostKey %s\n"
              "PidFile %s/sshd.pid\nUsePAM no\nMaxStartups 500\n"
              "LogLevel ERROR\n" % (self.port, family, key, TMP))
        self.popen(["/usr/sbin/sshd", "-D", "-e", "-f", self.conf])


class Postgres(Service):
    name = "PostgreSQL"
    probe = PG_PROBE
    data = TMP + "/pgdata"
    # With listen_addresses='*' PostgreSQL binds 0.0.0.0 and [::], and when
    # one of them fails it logs a warning and serves on the other.
    carries_on = ("all",)

    def bindir(self):
        base = "/usr/lib/postgresql"
        return os.path.join(base, sorted(os.listdir(base))[-1], "bin")

    def spawn(self):
        if not os.path.exists(self.data):
            os.makedirs(TMP, exist_ok=True)
            shutil.chown(TMP, "postgres")
            subprocess.run(
                ["su", "postgres", "-c",
                 "%s/initdb -D %s -A trust" % (self.bindir(), self.data)],
                check=True, capture_output=True)
        # PostgreSQL ships listen_addresses = 'localhost'.
        listen = {"default": "localhost", "ipv4": "0.0.0.0",
                  "all": "'*'"}[self.config]
        # su clears LD_PRELOAD when it changes user, so the pinning shim has
        # to be set inside the command it runs.
        pin = "LD_PRELOAD=%s PIN_DEV=%s " % (SHIM, self.pin) if self.pin else ""
        self.popen(
            ["su", "postgres", "-c",
             "%sexec %s/postgres -D %s -p %d -k %s -c listen_addresses=%s"
             % (pin, self.bindir(), self.data, self.port, TMP, listen)])


class HotRestart(Service):
    """The service from 2-reachability that replaces its SO_REUSEPORT
    listeners on SIGHUP, as Envoy and HAProxy do. It binds [::] dual-stack,
    so it covers both families."""

    name = "Hot-restart service"

    def spawn(self):
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "..", "2-reachability", "services",
                              "hotrestart.py")
        self.popen(["python3", script, str(self.port)])


# (class, configuration, what that configuration is)
CATALOGUE = [
    (Nginx, "default", "as the package ships it"),
    (Nginx, "ipv4", "listen 80 only, an administrator's choice"),
    (Haproxy, "default", "one IPv4 bind, an administrator's choice"),
    (Uvicorn, "default", "as the package ships it"),
    (Uvicorn, "ipv4", "--host 0.0.0.0, an administrator's choice"),
    (Sshd, "default", "as the package ships it"),
    (Sshd, "inet", "AddressFamily inet, an administrator's choice"),
    (Postgres, "default", "as the package ships it"),
    (Postgres, "ipv4", "listen_addresses=0.0.0.0, an administrator's choice"),
    (Postgres, "all", "listen_addresses='*', an administrator's choice"),
    (HotRestart, "default", "dual-stack [::], as it is written"),
]
