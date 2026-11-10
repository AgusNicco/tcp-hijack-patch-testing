/*
 * Pin a service's listening sockets to an interface, as a VRF or a service's
 * own --interface option would, without changing the service:
 *
 *   LD_PRELOAD=pin-to-device.so PIN_DEV=lo <service>
 *
 * Only the test harness uses this; the attack needs nothing of the sort.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

int bind(int fd, const struct sockaddr *addr, socklen_t len)
{
	static int (*real_bind)(int, const struct sockaddr *, socklen_t);
	const char *dev = getenv("PIN_DEV");

	if (!real_bind)
		real_bind = dlsym(RTLD_NEXT, "bind");
	if (dev && *dev)
		setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev));
	return real_bind(fd, addr, len);
}
