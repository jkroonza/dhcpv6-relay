#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdbool.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>

#include "dhcpv6.h"

#define event_struct(pfx, ...) struct pfx##_event { int pfx##_fd; void (*pfx##_evhandler)(int epollfd, struct pfx##_event* ev); __VA_ARGS__ }
event_struct(base);

static
void _event_destroy(int epollfd, struct base_event* ev)
{
	epoll_ctl(epollfd, EPOLL_CTL_DEL, ev->base_fd, NULL);
	free(ev);
}
#define event_destroy(epfd, x)	do { if (x) { _event_destroy(epfd, (struct base_event*)(x)); (x) = NULL; }} while(0)
#define event_init(pfx, p, epollfd, fd, handler) ({ \
		int r = -1; \
		(p) = malloc(sizeof(*(p))); \
		if ((p)) { \
			struct epoll_event e = { \
				.events = EPOLLIN | EPOLLRDHUP | EPOLLPRI | EPOLLERR | EPOLLHUP, \
				.data.ptr = (void*)p, \
			}; \
			(p)->pfx##_fd = fd; \
			(p)->pfx##_evhandler = (handler); \
			r = epoll_ctl(epollfd, EPOLL_CTL_ADD, (fd), &e); \
		} \
		r; \
	})

/* helpers */
int getservbyname_wrap(const char* name, struct servent *serv, char**buf)
{
	int r;
	size_t buflen = 1024;
	struct servent *tmp;

	*buf = malloc(buflen);
	while (0 != (r = getservbyname_r(name, "udp", serv, *buf, buflen, &tmp))) {
		if (r == ERANGE) {
			char *t = realloc(*buf, buflen *= 2);
			if (!t) {
				free(*buf);
				*buf = NULL;
				errno = ENOMEM;
				return -1;
			}
		} else {
			errno = r;
			return -1;
		}
	}

	return r;
}

bool in_null_term_array(const char* needle, char ** haystack)
{
	while (*haystack) {
		if (strcmp(*haystack++, needle) == 0)
			return true;
	}
	return false;
}

/* signal handlers */
static volatile bool running = true;

void sig_terminate(int)
{
	running = false;
}

/* argument handling */
static
struct option options[] = {
	{ "bind",		required_argument,	NULL, 'b' },
	{ "upstream",	required_argument,	NULL, 'u' },
	{ "help",		no_argument,		NULL, 'h' },
	{ NULL, 0, NULL, 0 }
};

static
int usage(const char* progname, FILE* o, int r)
{
	fprintf(o, "USAGE: %s [options] -- interface ...\n"
			"  --upstream|-u ipv6addr\n"
			"    IPv6 address to which to relay, currently no port specification is possible.\n"
			"    Parsing is VERY rudementary, if there are colons in the name/IP (IPv6 ...), then if you\n"
			"    don't want to specify a port, just append a trailing :, eg, instead of ::1 use ::1:\n"
			"    this way the last colon is used as the host:port separator, but due to being an empty\n"
			"    string will be defaulted to dhcpv6-server.\n"
			"  --bind|-b ipv6addr\n"
			"    In some cases you may want to bind the upstream socket to a specific local address.\n"
			"    Normally we will bind to localhost:dhcpv6-server and then 'narrow' to a specific local\n"
			"    address based on upstream.  If upstream is on the local host that could cause issues.\n"
			"  --help|-h\n"
			"    This help text, and exit.\n", progname);
	return r;
}

/* Interface handlers */
struct iface;

event_struct(if_uni, struct iface* iface;);
event_struct(if_mc, struct iface* iface;);

/* forward to relay upstream */
static void relay_upstream(const struct dhcpv6_packet *);

struct iface {
	struct if_uni_event *uni;
	struct if_mc_event *mc;
	char* iface_name;
	struct in6_addr lla;
	uint32_t linkid;
	struct iface *next;
};

static struct iface *iface_head = NULL;

static
struct iface *iface_get(const char* name)
{
	struct iface *t = iface_head;
	while (t && strcmp(name, t->iface_name) != 0)
		t = t->next;

	return t;
}

static
void iface_unbind(int epollfd, struct iface* iface)
{
	event_destroy(epollfd, iface->uni);
	event_destroy(epollfd, iface->mc);
}

static
void iface_common_handler(int /* epollfd */, int rdfd, const char* ref, struct iface* iface)
{
	struct dhcpv6_packet packet;
	struct dhcpv6_packet relay;
	struct sockaddr_in6 src6;

	socklen_t srclen = sizeof(src6);

	packet.pkt_size = recvfrom(rdfd, packet.raw, sizeof(packet.raw), 0,
				(struct sockaddr*)&src6, &srclen);

	if (packet.pkt_size == (size_t)-1) {
		perror(ref);
		return;
	}

	dhcpv6_dump_packet(stdout, &packet, &src6, DHCPv6_DIRECTION_RECEIVE, ref);

	if (!dhcpv6_packet_valid(&packet))
		return; /* discard invalid packets */

	relay.msg_type = DHCPv6_MSGTYPE_RELAY_FORW;
	if (packet.msg_type == DHCPv6_MSGTYPE_RELAY_FORW) {
		relay.relay.hop_count = packet.relay.hop_count+1;
	} else {
		relay.relay.hop_count = 0;
	}

	/* here we should technically inject a GUA/LUA, but in our
	 * expected use-case (ppp) we will usually only have a LL
	 * address, if this changes, this will need adjustment */
	relay.relay.link_address = iface->lla;
	relay.relay.peer_address = src6.sin6_addr;

	relay.pkt_size = dhcpv6_min_packet_size(&relay);

	dhcpv6_append_option(&relay, DHCPv6_OPTION_INTERFACE_ID, &iface->linkid, sizeof(iface->linkid));
	dhcpv6_append_option(&relay, DHCPv6_OPTION_RELAY_MSG, packet.raw, packet.pkt_size);

	relay_upstream(&relay);
}

static
void iface_ll_handler(int epollfd, struct if_uni_event *ev)
{
	struct iface* iface = ev->iface;
	char ref[IFNAMSIZ+5];

	sprintf(ref, "%s(ll)", iface->iface_name);
	iface_common_handler(epollfd, ev->if_uni_fd, ref, iface);
}

static
void iface_mc_handler(int epollfd, struct if_mc_event *ev)
{
	struct iface* iface = ev->iface;
	char ref[IFNAMSIZ+5];

	sprintf(ref, "%s(mc)", iface->iface_name);
	iface_common_handler(epollfd, ev->if_mc_fd, ref, iface);
}

static
int _iface_bind(struct iface* iface, int epollfd, const struct sockaddr_in6 *ll)
{
	int sock_linklocal = socket(AF_INET6, SOCK_DGRAM, 0), sock_mcast = -1;
	struct ipv6_mreq mreq;
	struct sockaddr_in6 mc6a;

	if (sock_linklocal < 0)
		goto errout;

	if (bind(sock_linklocal, (const struct sockaddr*)ll, sizeof(*ll)) < 0)
		goto errout;

	memset(&mreq, 0, sizeof(mreq));
	if (inet_pton(AF_INET6, "ff02::1:2", &mreq.ipv6mr_multiaddr) < 0)
		goto errout;
	mreq.ipv6mr_interface = ll->sin6_scope_id;

	if (setsockopt(sock_linklocal, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0)
		goto errout;

	sock_mcast = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock_mcast < 0) {
		perror("socket(mcast)");
		return 1;
	}

	memset(&mc6a, 0, sizeof(mc6a));
	mc6a.sin6_family = AF_INET6;
	mc6a.sin6_port = ll->sin6_port;
	mc6a.sin6_addr = mreq.ipv6mr_multiaddr;
	mc6a.sin6_scope_id = ll->sin6_scope_id;

	if (bind(sock_mcast, (struct sockaddr *)&mc6a, sizeof(mc6a)) < 0)
		goto errout;

	if (event_init(if_uni, iface->uni, epollfd, sock_linklocal, iface_ll_handler) < 0)
		goto errout;

	if (event_init(if_mc, iface->mc, epollfd, sock_mcast, iface_mc_handler) < 0)
		goto errout;

	iface->uni->iface = iface;
	iface->mc->iface = iface;

	return 0;
errout:
	int terrno = errno;
	if (sock_linklocal >= 0)
		close(sock_linklocal);
	if (sock_mcast >= 0)
		close(sock_mcast);
	errno = terrno;
	return -1;
}

static
struct iface* iface_create(const char* name)
{
	struct iface *t = malloc(sizeof(*t));
	if (!t)
		return t;

	memset(t, 0, sizeof(*t));

	t->iface_name = strdup(name);
	if (!t->iface_name) {
		free(t);
		return NULL;
	}

	return t;
}

static
void iface_free(int epollfd, struct iface* iface)
{
	iface_unbind(epollfd, iface);
	free(iface->iface_name);
	free(iface);
}

static
struct iface *iface_bind(int epollfd, const char* name, const struct sockaddr_in6 *ll)
{
	struct iface* iface = iface_get(name);
	if (iface)
		iface_unbind(epollfd, iface);
	else if (!(iface = iface_create(name)))
		return NULL;

	iface->lla = ll->sin6_addr;
	iface->linkid = ll->sin6_scope_id;

	if (_iface_bind(iface, epollfd, ll) < 0) {
		iface_free(epollfd, iface);
		return NULL;
	}
	return iface;
}

/* upstream handler */
event_struct(upstream, char* remotename; struct sockaddr_in6 remote;);

static
void upstream_handler(int /* epollfd */, struct upstream_event* ev)
{
	struct dhcpv6_packet packet;
	struct sockaddr_in6 src6;
	socklen_t srclen = sizeof(src6);

	packet.pkt_size = recvfrom(ev->upstream_fd, packet.raw, sizeof(packet.raw), 0,
				(struct sockaddr*)&src6, &srclen);

	if (packet.pkt_size == (size_t)-1) {
		perror("recvfrom(upstream)");
		return;
	}

	dhcpv6_dump_packet(stdout, &packet, &src6, DHCPv6_DIRECTION_RECEIVE, "upstream");

	if (!dhcpv6_packet_valid(&packet) || packet.msg_type != htons(DHCPv6_MSGTYPE_RELAY_REPL))
		return;

	printf("Intend to relay from upstream to client (or another relay)\n");
}

static
struct upstream_event upstream = {
	.upstream_fd = -1,
	.upstream_evhandler = upstream_handler,
	.remotename = 0,
};

static
void relay_upstream(const struct dhcpv6_packet *pkt)
{
	dhcpv6_dump_packet(stdout, pkt, &upstream.remote, DHCPv6_DIRECTION_TRANSMIT, "upstream unicast");

	if (sendto(upstream.upstream_fd, pkt->raw, pkt->pkt_size, MSG_DONTWAIT,
			(struct sockaddr*)&upstream.remote, sizeof(upstream.remote)) < 0)
		perror("send to upstream");
}

/* what can we say ... main */
int main(int argc, char ** argv)
{
	int c, epollfd, r;
	struct sockaddr_in6 sockad;
	socklen_t socklen;
	struct servent serv_server;
	char *buf_server;
	char ip6addr[INET6_ADDRSTRLEN];
	struct ifaddrs *ifap_;
	struct sigaction sa;
	sigset_t sigmask, waitmask;

	if (getservbyname_wrap("dhcpv6-server", &serv_server, &buf_server)) {
		perror("error getting service entry for dhcpv6-server");
		return 1;
	}

	memset(&sockad, 0, sizeof(sockad));
	socklen = sizeof(sockad);
	sockad.sin6_family = AF_INET6;
	sockad.sin6_port = serv_server.s_port;

	while ((c = getopt_long(argc, argv, "b:u:h", options, NULL)) != -1) {
		switch (c) {
		case 0:
			break;
		case 'h':
			return usage(*argv, stdout, 0);
		case 'b':
		case 'u':
			{
				char *host = optarg;
				char *service = strrchr(host, ':');
				if (service) {
					*service++ = 0;
					if (!*service)
						service = NULL;
				}
				struct addrinfo hints = {
					.ai_flags = 0,
					.ai_family = AF_INET6,
					.ai_socktype = SOCK_DGRAM,
					.ai_protocol = 0,
				};
				struct addrinfo *res = NULL;
				int r = getaddrinfo(host, service, &hints, &res);
				if (r) {
					fprintf(stderr, "Error parsing upstream relay address: %s\n", gai_strerror(r));
					return 1;
				}

				if (res->ai_addrlen != sizeof(upstream.remote)) {
					fprintf(stderr, "Resulting address from upstream lookup resulted in incorrectly sized sockaddr structure.\n");
					return 1;
				}

				switch (c) {
				case 'u':
					memcpy(&upstream.remote, res->ai_addr, res->ai_addrlen);
					if (service)
						*--service = ':';
					else
						upstream.remote.sin6_port = serv_server.s_port;
					upstream.remotename = optarg;
					break;
				case 'b':
					memcpy(&sockad, res->ai_addr, res->ai_addrlen);
					if (!service)
						sockad.sin6_port = serv_server.s_port;
					break;
				default:
					fprintf(stderr, "Code bug for option '%c', please file a bug.\n", c);
					return 1;
				}

				freeaddrinfo(res);
			}
			break;
		default:
		}
	}

	if (!upstream.remotename) {
		fprintf(stderr, "Upstream DHCP server address is required.\n");
		return usage(*argv, stderr, 1);
	}

	epollfd = epoll_create1(EPOLL_CLOEXEC);

	if (epollfd < 0) {
		perror("epoll_create1");
		return 1;
	}

	upstream.upstream_fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (upstream.upstream_fd < 0) {
		perror("Error creating upstream socket");
		return 1;
	}

	if (setsockopt(upstream.upstream_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
		perror("error setting SO_REUSEADDR on upstream socket");

	if (bind(upstream.upstream_fd, (struct sockaddr*)&sockad, socklen) < 0)
		perror("Error binding upstream socket to port, using ephemeral");

	if (memcmp(&sockad.sin6_addr, &in6addr_any, sizeof(in6addr_any)) == 0 && connect(upstream.upstream_fd, (struct sockaddr*)&upstream.remote, sizeof(upstream.remote)) < 0)
		perror("Error narrowing client socket");

	r = getifaddrs(&ifap_);
	if (r < 0) {
		perror("getifaddrs");
		return 1;
	}

	for (char** tmp = &argv[optind]; *tmp; ++tmp)
		printf("Permissable interface: %s\n", *tmp);

	struct sockaddr_in6* sa6;
	struct ifaddrs *ifap;
	for (ifap = ifap_; ifap; ifap = ifap->ifa_next) {
		/* only care about IPv6. */
		if (!ifap->ifa_addr || ifap->ifa_addr->sa_family != AF_INET6)
			continue;

		sa6 = (struct sockaddr_in6*)ifap->ifa_addr;

		if (!sa6->sin6_scope_id)
			continue; /* global or non-link addresses */

		if (!in_null_term_array(ifap->ifa_name, &argv[optind]))
			continue;

		if (!inet_ntop(AF_INET6, &sa6->sin6_addr, ip6addr, sizeof(ip6addr))) {
			perror("inet_ntop");
			return 1;
		}

		printf("Found %s on %s (scope=%d)\n", ip6addr, ifap->ifa_name, sa6->sin6_scope_id);

		sa6->sin6_port = serv_server.s_port;
		if (!iface_bind(epollfd, ifap->ifa_name, sa6)) {
			perror(ifap->ifa_name);
		}
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_terminate;
	if (sigaction(SIGTERM, &sa, NULL) < 0)
		perror("Signal handler: SIGTERM");
	if (sigaction(SIGINT, &sa, NULL) < 0)
		perror("Signal handler: SIGINT");

	if (sigprocmask(0, NULL, &waitmask) < 0) {
		perror("obtainig default blocked signal set");
		sigemptyset(&waitmask);
	}

	if (sigemptyset(&sigmask) < 0 ||
			sigaddset(&sigmask, SIGINT) < 0 ||
			sigaddset(&sigmask, SIGTERM) < 0)
		perror("Setting up signal mask set");

	if (sigprocmask(SIG_BLOCK, &sigmask, NULL) < 0)
		perror("blocking SIGINT+SIGTERM");

	while (running) {
		struct epoll_event events[10];
		r = epoll_pwait(epollfd, events, 10, -1, &waitmask);

		if (sigprocmask(SIG_UNBLOCK, &sigmask, NULL) < 0)
			perror("unblocking SIGINT+SIGTERM");

		if (r < 0) {
			if (errno != EAGAIN && errno != EINTR)
				perror("epoll_wait");
		} else {
			printf("%d sockets are ready.\n", r);
			for (c = 0; c < r; ++c) {
				struct base_event* ev = events[c].data.ptr;
				ev->base_evhandler(epollfd, ev);
			}
		}

		if (sigprocmask(SIG_BLOCK, &sigmask, NULL) < 0)
			perror("blocking SIGINT+SIGTERM");
	}

	printf("Terminating.\n");

	return 0;
}
