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

#include "dhcpv6.h"

int main(int argc, char ** argv)
{
	/*
	struct addrinfo *ai = NULL;
	struct addrinfo hints = {
		.ai_family = AF_INET6,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = 0,
		.ai_flags = AI_PASSIVE,
	};
	int r = getaddrinfo("%ppp1", NULL, NULL, &ai);
	if (r != 0) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(r));
		return 1;
	}
	*/

	unsigned ifi = if_nametoindex("ppp1");

	if (ifi == 0) {
		perror("if_nametoindex");
		return 1;
	}

	printf("interface index: %u\n", ifi);

	struct ifaddrs *ifap_ = NULL;
	int r = getifaddrs(&ifap_);
	if (r < 0) {
		perror("getifaddrs");
		return 1;
	}

	struct sockaddr_in6* sa6;
	struct ifaddrs *ifap;
	for (ifap = ifap_; ifap; ifap = ifap->ifa_next) {
		if (!ifap->ifa_addr || ifap->ifa_addr->sa_family != AF_INET6)
			continue;

		sa6 = (struct sockaddr_in6*)ifap->ifa_addr;
		if (sa6->sin6_scope_id != ifi)
			continue;

		char ip6str[INET6_ADDRSTRLEN];
		if (!inet_ntop(AF_INET6, &sa6->sin6_addr, ip6str, sizeof(ip6str))) {
			perror("inet_ntop");
			return 1;
		}
		printf("%s/%x/%s\n", ifap->ifa_name, ifap->ifa_flags, ip6str);
		break;
	}

	if (!ifap) {
		fprintf(stderr, "Unable to locate interface LL address.");
		return 1;
	}

	int sock_linklocal = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock_linklocal < 0) {
		perror("socket");
		return 1;
	}

	sa6->sin6_port = htons(547);

	if (bind(sock_linklocal, ifap->ifa_addr, sizeof(*sa6)) < 0) {
		perror("bind");
		return 1;
	}

	struct ipv6_mreq mreq;
	memset(&mreq, 0, sizeof(mreq));

	if (inet_pton(AF_INET6, "ff02::1:2", &mreq.ipv6mr_multiaddr) < 0) {
		perror("inet_pton(ff02::1:2)");
		return 1;
	}
	mreq.ipv6mr_interface = ifi;

	r = setsockopt(sock_linklocal, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq));
	if (r < 0) {
		perror("setsockopt(IPV6_JOIN_GROUP)");
		return 1;
	}

	int sock_mcast = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock_mcast < 0) {
		perror("socket(mcast)");
		return 1;
	}

	struct sockaddr_in6 src6;
	memset(&src6, 0, sizeof(src6));
	src6.sin6_family = AF_INET6;
	src6.sin6_port = htons(547);
	src6.sin6_addr = mreq.ipv6mr_multiaddr;
	src6.sin6_scope_id = ifi;

	if (bind(sock_mcast, (struct sockaddr *)&src6, sizeof(src6)) < 0) {
		perror("bind(mcast)");
		return 1;
	}

	while (true) {
		socklen_t srclen = sizeof(src6);
		struct dhcpv6_packet packet;

		packet.pkt_size = recvfrom(sock_mcast, packet.raw, sizeof(packet.raw), 0,
					(struct sockaddr*)&src6, &srclen);
		if (packet.pkt_size < 0) {
			perror("recvfrom");
			usleep(50);
			continue;
		}

		dhcpv6_dump_packet(stdout, &packet, &src6, DHCPv6_DIRECTION_RECEIVE, "ppp1/mc");
	}
}
