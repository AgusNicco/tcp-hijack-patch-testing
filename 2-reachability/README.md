# 2. When does the changed code run?

These tests measure how often the code the patch changes runs, in multiple
socket operations and on a host running multiple services, a desktop
browser, and handbuilt services. The purpose is to see how performance relevant the code is.
The kernel code suggests it should run only during service startup; here it
is tested empirically. These are not performance tests; see
[4-performance](../4-performance/) for those. Note that according to the performance tests
this patch has no measurable downside so high or low reachability would not be an argument for or against this patch,
but it is still helpful to put in context how frequently the code runs. 

The patch changes `sk_reuseport_match()`. By the code, it runs only when a
socket takes a port: on `bind()` and `listen()` of an `SO_REUSEPORT` socket,
when the port's bind cache is in `FASTREUSEPORT_STRICT` state and has the
same owner. It also runs from `__inet_inherit_port()` when a connection is
accepted on another port than the listener's, which happens behind a
transparent proxy (TPROXY). Sending or receiving packets, `connect()` and
other accepted connections do not call it. The tests help confirm these 
assumptions.

Every table counts, per service or scenario, TCP packets received and sent,
`bind()` calls (not `listen()`), and the times the changed code ran. All of
it was measured with `fastreuse.bt` on the host's own kernel,
7.0.0-1014-gcp.


## Services and a desktop browser

Everything is in `services/`:

- OpenSSH, the host's own
- PostgreSQL, nginx with `reuseport` and FastAPI (uvicorn, 4 workers), in
  containers with published ports, behind Docker's port proxy
- nginx with `reuseport` and HAProxy, in containers on the host network
- `hotrestart.py` (hand-built): replaces its group of `SO_REUSEPORT`
  listeners on `SIGHUP`, as Envoy and HAProxy do
- `tproxy.py` (hand-built): a transparent proxy with `SO_REUSEPORT`
  listeners behind a TPROXY rule, intercepting connections to four addresses
- Firefox (headless, in a container), browsing real websites: YouTube home
  and a video, a Google search, Wikipedia, GitHub, Reddit, Amazon, BBC News
  and Stack Overflow, each page kept open for 15 s

The phases are: start the services, leave them idle, load them with traffic,
browse the web with Firefox, reload or restart them, and stop them. Traffic
is HTTP to every web service (half the clients reconnect for each
request), pgbench opening a new connection per transaction inside the
container and through the published port, and SSH handshakes. Every service
answered without errors (`results/services/traffic-load.txt`).

### Starting the services

```
                                          TCP packets  TCP packets  Socket         Times the
Service                                      received         sent   binds  changed code ran
----------------------------------------  -----------  -----------  ------  ----------------
OpenSSH (host)                                    105           68       0                 0
PostgreSQL (container)                            115           68       2                 0
  Docker port proxy for PostgreSQL                  0            0       1                 0
nginx (container)                                   6            3      16                31
  Docker port proxy for nginx                       6            3       1                 0
FastAPI (container)                                 5            3       1                 0
  Docker port proxy for FastAPI                     5            3       1                 0
nginx (host network)                                6            3      16                31
HAProxy (host network)                              6            2       1                 1
Hot-restart service (hand-built)                    5            4       4                 7
Transparent proxy (hand-built)                      5            4       4                 7
Clients (load generators, Firefox)                274          317       0                 0
Bind to any free port (port 0)                      0            0       1                 0
Sockets that already released their port            0            0       0                 0
Other ports                                         9            7       1                 1
```

Note that each nginx opens 16 listeners (8 workers, IPv4 and IPv6). In 3 of
the 31 runs per nginx the socket differed from the port's cached socket:
the IPv4 and IPv6 listeners share the port.

### Idle (60 s, services running, no load)

```
                                          TCP packets  TCP packets  Socket         Times the
Service                                      received         sent   binds  changed code ran
----------------------------------------  -----------  -----------  ------  ----------------
OpenSSH (host)                                    210          181       0                 0
PostgreSQL (container)                              0            0       0                 0
  Docker port proxy for PostgreSQL                  0            0       0                 0
nginx (container)                                   0            0       0                 0
  Docker port proxy for nginx                       0            0       0                 0
FastAPI (container)                                 1            2       0                 0
  Docker port proxy for FastAPI                     1            2       0                 0
nginx (host network)                                0            0       0                 0
HAProxy (host network)                              0            0       0                 0
Hot-restart service (hand-built)                    0            0       0                 0
Transparent proxy (hand-built)                      0            0       0                 0
Clients (load generators, Firefox)                666          510       0                 0
Bind to any free port (port 0)                      0            0       0                 0
Sockets that already released their port            0            0       0                 0
Other ports                                        25           22       0                 0
```

Note that the packets in this phase come from outside the test: OpenSSH is
the VM's own sshd, carrying the SSH session that runs the test, and the
client row is the host's own outgoing connections.

### Traffic (60 s, all services under load)

```
                                          TCP packets  TCP packets  Socket         Times the
Service                                      received         sent   binds  changed code ran
----------------------------------------  -----------  -----------  ------  ----------------
OpenSSH (host)                                  8,430        5,211       0                 0
PostgreSQL (container)                        245,897      187,732       0                 0
  Docker port proxy for PostgreSQL             76,594       59,767       0                 0
nginx (container)                             237,388      151,839       0                 0
  Docker port proxy for nginx                 237,462      151,835       0                 0
FastAPI (container)                           175,656      102,397       0                 0
  Docker port proxy for FastAPI               141,227       69,762       0                 0
nginx (host network)                          635,841      456,205       0                 0
HAProxy (host network)                        139,583       58,200       0                 0
Hot-restart service (hand-built)              509,236      404,896       0                 0
Transparent proxy (hand-built)              2,584,417    1,973,269       0           506,334
Clients (load generators, Firefox)          4,478,154    4,969,115       0                 0
Bind to any free port (port 0)                      0            0       0                 0
Sockets that already released their port            0       22,079       0                 0
Other ports                                        22           20       0                 0
```

During traffic the changed code ran only for the transparent proxy: once 
for every connection it accepted (506,335 requests) except the
first, which created the port's bind bucket (506,334 runs). A redirected
connection keeps the port it was addressed to, and accepting it updates that
port's bind cache. That path runs no conflict check, so the patch can
only change whether the cached socket is replaced: 403,419 of the connections
went to another address than the cached socket's and replaced it, which the
current kernel also does.

### Browsing (120 s, Firefox on real websites; services idle)

```
                                          TCP packets  TCP packets  Socket         Times the
Service                                      received         sent   binds  changed code ran
----------------------------------------  -----------  -----------  ------  ----------------
OpenSSH (host)                                    101           85       0                 0
PostgreSQL (container)                              0            0       0                 0
  Docker port proxy for PostgreSQL                  0            0       0                 0
nginx (container)                                   0            0       0                 0
  Docker port proxy for nginx                       0            0       0                 0
FastAPI (container)                                 7           14       0                 0
  Docker port proxy for FastAPI                     7           14       0                 0
nginx (host network)                                0            0       0                 0
HAProxy (host network)                              0            0       0                 0
Hot-restart service (hand-built)                    0            0       0                 0
Transparent proxy (hand-built)                      0            0       0                 0
Clients (load generators, Firefox)              8,069        5,626       0                 0
Bind to any free port (port 0)                      0            0       0                 0
Sockets that already released their port            0            2       0                 0
Other ports                                        45           42       0                 0
```

Note that Firefox, a desktop client, only makes outgoing connections; they
are counted in the clients row. It visited 8 pages
(`results/services/browsing-load.txt`). Sites that Firefox reaches over
QUIC, which runs on UDP, are not counted in a TCP table.

### Reloading or restarting the services

```
                                          TCP packets  TCP packets  Socket         Times the
Service                                      received         sent   binds  changed code ran
----------------------------------------  -----------  -----------  ------  ----------------
OpenSSH (host)                                     12           10       0                 0
PostgreSQL (container)                              0            0       2                 0
  Docker port proxy for PostgreSQL                  0            0       1                 0
nginx (container)                                   0            0       0                 0
  Docker port proxy for nginx                       0            0       0                 0
FastAPI (container)                                 0            0       1                 0
  Docker port proxy for FastAPI                     0            0       1                 0
nginx (host network)                                0            0       0                 0
HAProxy (host network)                              0            0       0                 0
Hot-restart service (hand-built)                    0            0      20                40
Transparent proxy (hand-built)                      0            0       0                 0
Clients (load generators, Firefox)                 74           71       0                 0
Bind to any free port (port 0)                      0            0       1                 0
Sockets that already released their port            0            0       0                 0
Other ports                                         2            2       1                 1
```

Note that reloading nginx opens no new sockets, and restarting OpenSSH binds
nothing: on Ubuntu, systemd holds port 22. The hot-restart service binds
new listeners for each of its 5 restarts.

### Stopping the services

```
                                          TCP packets  TCP packets  Socket         Times the
Service                                      received         sent   binds  changed code ran
----------------------------------------  -----------  -----------  ------  ----------------
OpenSSH (host)                                      4            4       0                 0
PostgreSQL (container)                              0            0       0                 0
  Docker port proxy for PostgreSQL                  0            0       0                 0
nginx (container)                                   0            0       0                 0
  Docker port proxy for nginx                       0            0       0                 0
FastAPI (container)                                 0            0       0                 0
  Docker port proxy for FastAPI                     0            0       0                 0
nginx (host network)                                0            0       0                 0
HAProxy (host network)                              0            0       0                 0
Hot-restart service (hand-built)                    0            0       0                 0
Transparent proxy (hand-built)                      0            0       0                 0
Clients (load generators, Firefox)                 28           25       0                 0
Bind to any free port (port 0)                      0            0       0                 0
Sockets that already released their port            0            0       0                 0
Other ports                                         0            0       0                 0
```

Note that the host's kernel predates 947ccedf683e ("tcp: Fix fastreuse cache
initialization on first bind"), so every `SO_REUSEPORT` port on it is in the
state where the changed code runs from its first socket. On `base`, a port
holding only one owner's `SO_REUSEPORT` sockets, such as the proxy's, skips
it; that is from the code and not measured here. Every kernel from v6.8
without 947ccedf683e behaves like the host.

"Sockets that already released their port" are packets sent by closing
sockets after they gave their port back, such as resets.

## Running

Needs root, bpftrace with BTF, Docker, TPROXY support and internet access
(for Firefox).

```sh
sudo 2-reachability/run.sh
```

`results/scenarios.txt` and `results/services/PHASE.txt` hold the counts per
port; `report.py` turns them into `results/scenarios-summary.txt` and
`results/services/summary.txt`, the tables above.
