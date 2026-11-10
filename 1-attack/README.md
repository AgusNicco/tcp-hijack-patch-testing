# 1. Can an unprivileged user take over a service with it?

These tests show how an unprivileged user abuses the bug to bind to ports from other processes and hijack traffic. It compares the results on kernels with and without the patch. The attacker runs as `nobody` in a forked child. Every port above 1024 is exposed.

The attack consists of binding two SO_REUSEPORT sockets to the victim's port: first a seed, a socket that does not conflict with the service, then a hijack socket, which will be listening on the victim's address and port. The kernel should have refused the hijack socket, because the victim socket never agreed to share its port, but it admitted it because the seed had become the port's cached socket and the cache covers the hijack's address, so the kernel skipped the conflict check. The attack is possible any time a victim socket binds only to an IPv4 or IPv6 address or when it is bound to a network interface. Note that even when a victim service prefers binding to both IPv4 and IPv6, an attacker can trick it into binding to only one by occupying the other one on the same port before it starts, and hence making it vulnerable.

## Results

The table below shows the results of a scenario where an unprivileged process abuses the bug to hijack the traffic of other processes that are running widely used services. They are all already listening on a port when the attack begins. In the last two columns, (x/y/z) means (victim receives / attacker receives / attacker responds).

```
Service                  Kernel          Listening on  Attacker's bind            Connections over IPv4  Connections over IPv6
-----------------------  --------------  ------------  -------------------------  ---------------------  ---------------------
nginx, upstream default  Current kernel  0.0.0.0       succeeded                  0 / 50 / 50            0 / 50 / 50
nginx, upstream default  With the patch  0.0.0.0       EADDRINUSE                 50 / 0 / 0             0 / 0 / 0

nginx, both stacks       Current kernel  0.0.0.0,::    seed refused (EADDRINUSE)  50 / 0 / 0             50 / 0 / 0
nginx, both stacks       With the patch  0.0.0.0,::    seed refused (EADDRINUSE)  50 / 0 / 0             50 / 0 / 0

HAProxy, 127.0.0.1       Current kernel  127.0.0.1     succeeded                  50 / 0 / 0             0 / 50 / 50
HAProxy, 127.0.0.1       With the patch  127.0.0.1     EADDRINUSE                 50 / 0 / 0             0 / 0 / 0

uvicorn, as shipped      Current kernel  127.0.0.1     succeeded                  50 / 0 / 0             0 / 50 / 50
uvicorn, as shipped      With the patch  127.0.0.1     EADDRINUSE                 50 / 0 / 0             0 / 0 / 0

uvicorn --host 0.0.0.0   Current kernel  0.0.0.0       succeeded                  0 / 50 / 50            0 / 50 / 50
uvicorn --host 0.0.0.0   With the patch  0.0.0.0       EADDRINUSE                 50 / 0 / 0             0 / 0 / 0

OpenSSH, as shipped      Current kernel  0.0.0.0,::    seed refused (EADDRINUSE)  50 / 0 / 0             50 / 0 / 0
OpenSSH, as shipped      With the patch  0.0.0.0,::    seed refused (EADDRINUSE)  50 / 0 / 0             50 / 0 / 0

OpenSSH, IPv4 only       Current kernel  0.0.0.0       succeeded                  0 / 50 / 50            0 / 50 / 50
OpenSSH, IPv4 only       With the patch  0.0.0.0       EADDRINUSE                 50 / 0 / 0             0 / 0 / 0

PostgreSQL, as shipped   Current kernel  127.0.0.1     succeeded                  50 / 0 / 0             0 / 50 / 50
PostgreSQL, as shipped   With the patch  127.0.0.1     EADDRINUSE                 50 / 0 / 0             0 / 0 / 0

PostgreSQL, 0.0.0.0      Current kernel  0.0.0.0       succeeded                  0 / 50 / 50            0 / 50 / 50
PostgreSQL, 0.0.0.0      With the patch  0.0.0.0       EADDRINUSE                 50 / 0 / 0             0 / 0 / 0

PostgreSQL, '*'          Current kernel  0.0.0.0,::    seed refused (EADDRINUSE)  50 / 0 / 0             50 / 0 / 0
PostgreSQL, '*'          With the patch  0.0.0.0,::    seed refused (EADDRINUSE)  50 / 0 / 0             50 / 0 / 0
```

Note that a service listening on `0.0.0.0`, which is exceedingly common, loses all of its IPv4
clients to this attack, the attacker reads every request they send.


###  Services pinned to an interface

Same tests as above but the services are pinned to an interface. All clients connect over IPv4.

```
Service                  Kernel          Listening on  Attacker's bind  Connections over IPv4  Connections over IPv6
-----------------------  --------------  ------------  ---------------  ---------------------  ---------------------
nginx, upstream default  Current kernel  0.0.0.0       succeeded        0 / 50 / 50            -
nginx, upstream default  With the patch  0.0.0.0       EADDRINUSE       50 / 0 / 0             -

nginx, both stacks       Current kernel  0.0.0.0,::    succeeded        0 / 50 / 50            -
nginx, both stacks       With the patch  0.0.0.0,::    EADDRINUSE       50 / 0 / 0             -

HAProxy, 127.0.0.1       Current kernel  127.0.0.1     succeeded        0 / 50 / 50            -
HAProxy, 127.0.0.1       With the patch  127.0.0.1     EADDRINUSE       50 / 0 / 0             -

uvicorn, as shipped      Current kernel  127.0.0.1     succeeded        0 / 50 / 50            -
uvicorn, as shipped      With the patch  127.0.0.1     EADDRINUSE       50 / 0 / 0             -

uvicorn --host 0.0.0.0   Current kernel  0.0.0.0       succeeded        0 / 50 / 50            -
uvicorn --host 0.0.0.0   With the patch  0.0.0.0       EADDRINUSE       50 / 0 / 0             -

OpenSSH, as shipped      Current kernel  0.0.0.0,::    succeeded        0 / 50 / 50            -
OpenSSH, as shipped      With the patch  0.0.0.0,::    EADDRINUSE       50 / 0 / 0             -

OpenSSH, IPv4 only       Current kernel  0.0.0.0       succeeded        0 / 50 / 50            -
OpenSSH, IPv4 only       With the patch  0.0.0.0       EADDRINUSE       50 / 0 / 0             -

PostgreSQL, as shipped   Current kernel  127.0.0.1     succeeded        0 / 50 / 50            -
PostgreSQL, as shipped   With the patch  127.0.0.1     EADDRINUSE       50 / 0 / 0             -

PostgreSQL, 0.0.0.0      Current kernel  0.0.0.0       succeeded        0 / 50 / 50            -
PostgreSQL, 0.0.0.0      With the patch  0.0.0.0       EADDRINUSE       50 / 0 / 0             -

PostgreSQL, '*'          Current kernel  0.0.0.0,::    succeeded        0 / 50 / 50            -
PostgreSQL, '*'          With the patch  0.0.0.0,::    EADDRINUSE       50 / 0 / 0             -
```

Pinning opens the device axis, and the attack reaches every service,
including the ones that bind both families and the ones on a specific
address: the attacker answers all of their clients and reads every request.

### Other details

No kernel logged a KASAN report, warning or bug in this run
(`results/*/dmesg.txt`).

## Files

- `attack.py`: the attack on each service; run as root, it drops to `nobody` before the attack begins.
- `services.py`: the services, how each is started, and its protocol probe
- `established.py`: the attack on connections a pinned service accepted
- `outgoing.py`: the attack on curl's and Firefox's outgoing connections
- `sweep.py`: the seed sweep for services that cover both families
- `pin-to-device.c`: the shim that pins a service to an interface
- `guest.sh`, `report.py`: run it all on one kernel, and build the tables
- `results/<kernel>/`: `attack.txt` (one line per run and client family),
  `established.txt`, `outgoing.txt`, `sweep.txt`, `dmesg.txt`
- `results/summary.txt`: the tables for every kernel
- `client-devices.sh`: what device curl and Firefox bind on real websites
- `matrix/`: every victim shape against every attacker socket, on all three
  kernels; `matrix/README.md` explains it and `run.sh` runs it

## Running

```sh
kernels/build-all.sh path/to/net/checkout
1-attack/run.sh
```

It needs nginx, HAProxy, PostgreSQL, uvicorn, OpenSSH, curl and Firefox
installed on the host, since the guest runs from the host's filesystem.
