/*
 * Time the bind() and listen() calls of N TCP sockets on one port.
 *
 *   usage: bench SCENARIO N REPEATS        (as root)
 *
 *   group        N identical SO_REUSEPORT listeners on 127.0.0.1
 *   group-plain  the same, after a socket without SO_REUSEPORT on [::1]
 *   specific     after a socket without SO_REUSEPORT on [::1], an
 *                SO_REUSEPORT listener on 0.0.0.0, then N on addresses
 *                127.0.0.2, 127.0.0.3, ...
 *   alternating  after a socket without SO_REUSEPORT on [::1], N
 *                SO_REUSEPORT listeners on 0.0.0.0, bound to dum1 and dum2
 *                in turn
 *   mixed        after a socket without SO_REUSEPORT on [::1], N
 *                SO_REUSEPORT listeners alternating between 0.0.0.0 and
 *                specific addresses 127.0.0.3, 127.0.0.5, ...
 *
 * The socket without SO_REUSEPORT is IPv6-only, so it overlaps none of the
 * others; it only puts the port in FASTREUSEPORT_STRICT. Sockets are created
 * before the clock starts. Each repeat uses a fresh port. Prints the median,
 * minimum and maximum time in milliseconds.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static void die(const char *what, int i)
{
	fprintf(stderr, "%s failed at socket %d: ", what, i);
	perror(NULL);
	exit(1);
}

static int plain_v6only(int port)
{
	struct sockaddr_in6 a = { .sin6_family = AF_INET6, .sin6_port = htons(port),
				  .sin6_addr = IN6ADDR_LOOPBACK_INIT };
	int one = 1, s = socket(AF_INET6, SOCK_STREAM, 0);

	setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
	if (bind(s, (struct sockaddr *)&a, sizeof(a)))
		die("bind of the plain socket", -1);
	return s;
}

static double run(const char *scenario, int n, int port)
{
	int total = n + 1, *fd = calloc(total + 1, sizeof(int));
	struct sockaddr_in *addr = calloc(total, sizeof(*addr));
	int one = 1, plain = -1, first = 0;
	struct timespec t0, t1;

	if (strcmp(scenario, "group") != 0)
		plain = plain_v6only(port);
	if (strcmp(scenario, "specific") != 0)
		first = 1;		/* no leading wildcard listener */
	for (int i = first; i < total; i++) {
		addr[i].sin_family = AF_INET;
		addr[i].sin_port = htons(port);
		if (!strcmp(scenario, "group") || !strcmp(scenario, "group-plain"))
			addr[i].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		else if (!strcmp(scenario, "specific") && i > 0)
			addr[i].sin_addr.s_addr = htonl(INADDR_LOOPBACK + i);
		else if (!strcmp(scenario, "mixed") && i % 2 == 0)
			addr[i].sin_addr.s_addr = htonl(INADDR_LOOPBACK + i);
		else
			addr[i].sin_addr.s_addr = htonl(INADDR_ANY);
		fd[i] = socket(AF_INET, SOCK_STREAM, 0);
		if (fd[i] < 0)
			die("socket", i);
		setsockopt(fd[i], SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
		if (!strcmp(scenario, "alternating")) {
			const char *dev = i % 2 ? "dum2" : "dum1";

			if (setsockopt(fd[i], SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev)))
				die("SO_BINDTODEVICE", i);
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (int i = first; i < total; i++) {
		if (bind(fd[i], (struct sockaddr *)&addr[i], sizeof(addr[i])))
			die("bind", i);
		if (listen(fd[i], 8))
			die("listen", i);
	}
	clock_gettime(CLOCK_MONOTONIC, &t1);

	for (int i = first; i < total; i++)
		close(fd[i]);
	if (plain >= 0)
		close(plain);
	free(fd);
	free(addr);
	return (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
}

static int cmp(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
	if (argc != 4) {
		fprintf(stderr, "usage: bench SCENARIO N REPEATS\n");
		return 2;
	}
	int n = atoi(argv[2]), repeats = atoi(argv[3]);
	struct rlimit rl = { n + 64, n + 64 };
	double *t = calloc(repeats, sizeof(double));

	if (setrlimit(RLIMIT_NOFILE, &rl))
		die("setrlimit", -1);
	for (int r = 0; r < repeats; r++)
		t[r] = run(argv[1], n, 20000 + r);
	qsort(t, repeats, sizeof(double), cmp);
	printf("%s %d %.2f %.2f %.2f\n", argv[1], n, t[repeats / 2], t[0], t[repeats - 1]);
	return 0;
}
