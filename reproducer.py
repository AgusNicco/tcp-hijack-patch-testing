# The bind the kernel refuses, and then allows.
#
# The victim is an IPv6-only listener that set no reuse option of any kind.
# The hijacking socket is a dual-stack wildcard, which overlaps it, and the
# kernel refuses it -- until one more socket of ours is on the port: an IPv4
# wildcard, which genuinely does not conflict with an IPv6-only socket, so it
# passes the full check and becomes the port's FASTREUSEPORT_STRICT summary.
# sk_reuseport_match() then finds the hijacking socket "covered" by that
# summary, and inet_csk_get_port() skips the conflict check altogether.
#
# No root, no capability, no bound device, no traffic. On a fixed kernel the
# last bind() raises EADDRINUSE, as the second attempt already did.
import socket
P = 29301
v = socket.socket(socket.AF_INET6); v.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1); v.bind(("::", P)); v.listen(1)
print("victim  [::] v6only, no reuse option:    listening")
a = socket.socket(socket.AF_INET6); a.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0); a.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
try: a.bind(("::", P)); raise SystemExit("inconclusive: it bound with no seed, so the port is not in the state this needs")
except OSError as e: print("hijack  [::] dual-stack, on its own:     %s" % e.strerror)
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1); s.bind(("0.0.0.0", P))
print("seed    0.0.0.0 SO_REUSEPORT:            bound, never listening, conflicts with nothing")
h = socket.socket(socket.AF_INET6); h.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0); h.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
h.bind(("::", P)); h.listen(1)
print("hijack  [::] dual-stack, after the seed: listening   <-- the same socket, now admitted")
