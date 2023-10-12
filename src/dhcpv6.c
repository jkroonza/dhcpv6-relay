#define _GNU_SOURCE

#include "dhcpv6.h"

#include <stddef.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <uuid/uuid.h>
#include <string.h>
#include <errno.h>

const char* dhcpv6_type2string(int msg_type)
{
	switch (msg_type) {
	case DHCPv6_MSGTYPE_SOLICIT:
			return "solicit";
	case DHCPv6_MSGTYPE_ADVERTISE:
			return "advertise";
	case DHCPv6_MSGTYPE_REQUEST:
			return "request";
	case DHCPv6_MSGTYPE_CONFIRM:
			return "confirm";
	case DHCPv6_MSGTYPE_RENEW:
			return "renew";
	case DHCPv6_MSGTYPE_REBIND:
			return "rebind";
	case DHCPv6_MSGTYPE_REPLY:
			return "reply";
	case DHCPv6_MSGTYPE_RELEASE:
			return "release";
	case DHCPv6_MSGTYPE_DECLINE:
			return "decline";
	case DHCPv6_MSGTYPE_RECONFIGURE:
			return "reconfigure";
	case DHCPv6_MSGTYPE_INFORMATION_REQUEST:
			return "information_request";
	case DHCPv6_MSGTYPE_RELAY_FORW:
			return "relay-forw";
	case DHCPv6_MSGTYPE_RELAY_REPL:
			return "relay-repl";
	default:
		return NULL;
	}
}

static
void dhcpv6_calc_packet_option_buffer(const struct dhcpv6_packet *pkt, const void **buffer, size_t *buflen)
{
	*buffer = dhcpv6_packet_is_relay(pkt) ? pkt->relay.optdata : pkt->norm.optdata;
	*buflen = pkt->pkt_size - dhcpv6_min_packet_size(pkt);
}

static
const struct dhcpv6_option* internal_option_buffer_next(const void* base, size_t buflen, const struct dhcpv6_option *last)
{
	errno = 0; /* ability to distinguish between end of headers and errors */

	const struct dhcpv6_option *next;
	if (!last) {
		next = (const struct dhcpv6_option*)base;
	} else {
		next = (const struct dhcpv6_option*)((const char*)last + ntohs(last->len) + sizeof(struct dhcpv6_option));
		buflen -= (void*)next - base;
	}

	if (buflen < sizeof(struct dhcpv6_option) || buflen < sizeof(struct dhcpv6_option) + ntohs(next->len)) {
		errno = EOVERFLOW;
		return NULL;
	}

	return next;
}

static
struct dhcpv6_packet_option* internal_buffer_option_next(
		struct dhcpv6_packet_option* res,
		const void* buffer, size_t buflen)
{
	if (!res) {
		res = malloc(sizeof(*res));
		if (!res)
			return NULL;
		res->buflen = buflen;
		res->buffer = buffer;
		res->detail = NULL;
	}

	res->detail = internal_option_buffer_next(res->buffer, res->buflen, res->detail);

	if (!res->detail) {
		int terrno = errno;
		free(res);
		errno = terrno;
		return NULL;
	}

	res->meta = dhcpv6_option_meta(ntohs(res->detail->opcode));
	return res;
}

static
struct dhcpv6_packet_option* internal_packet_option_next(
		struct dhcpv6_packet_option* res,
		const struct dhcpv6_packet* pkt)
{
	const void* optionbuffer;
	size_t bufferlen;
	dhcpv6_calc_packet_option_buffer(pkt, &optionbuffer, &bufferlen);

	if (!res) {
		res = malloc(sizeof(*res));
		if (!res)
			return NULL;
		res->buflen = 0;
		res->src_packet = pkt;
		res->detail = NULL;
	}

	res->detail = internal_option_buffer_next(optionbuffer, bufferlen, res->detail);

	if (!res->detail) {
		int terrno = errno;
		free(res);
		errno = terrno;
		return NULL;
	}

	res->meta = dhcpv6_option_meta(ntohs(res->detail->opcode));
	return res;
}

struct dhcpv6_packet_option* dhcpv6_buffer_option_head(const void* buffer, size_t buflen)
{
	return internal_buffer_option_next(NULL, buffer, buflen);
}

struct dhcpv6_packet_option* dhcpv6_packet_option_head(const struct dhcpv6_packet* pkt)
{
	return internal_packet_option_next(NULL, pkt);
}

struct dhcpv6_packet_option* dhcpv6_packet_option_next(struct dhcpv6_packet_option* opt)
{
	return opt->buflen ? internal_buffer_option_next(opt, opt->buffer, opt->buflen) : internal_packet_option_next(opt, opt->src_packet);
}

static
char* dhcpv6_duid_string(const struct dhcpv6_option* option)
{
	char *res = NULL;

	uint16_t optlen = ntohs(option->len);
	if (optlen < 2)
		return NULL;

	const struct dhcpv6_duid* duid = (const struct dhcpv6_duid*)option->payload;

	switch (ntohs(duid->type)) {
	case 1: /* llt */
		{
			if (optlen < 8)
				return NULL;
			int l = asprintf(&res, "llt hwtype %u time %d ", ntohs(duid->llt.hwtype), ntohs(duid->llt.time));
			char *t = realloc(res, l + (optlen - 8) * 2 + 1);
			if (!t) {
				free(res);
				return NULL;
			}
			res = t;
			t += l;
			for (int i = 8; i < optlen; ++i)
				t += sprintf(t, "%02x", option->payload[i]);
		}
		break;
	case 2: /* vendor-assigned */
		{
			if (optlen < 6)
				return NULL;
			int l = asprintf(&res, "enterprise %u ", ntohl(duid->vendor.enterprise_num));
			char *t = realloc(res, l + (optlen - 6) * 2 + 1);
			if (!t) {
				free(res);
				return NULL;
			}
			res = t;
			t += l;
			for (int i = 6; i < optlen; ++i)
				t += sprintf(t, "%02x", option->payload[i]);
		}
		break;
	case 3: /* lla */
		{
			if (optlen < 4)
				return NULL;
			int l = asprintf(&res, "lla hwtype %u ", ntohs(duid->lla.hwtype));
			char *t = realloc(res, l + (optlen - 4) * 2 + 1);
			if (!t) {
				free(res);
				return NULL;
			}
			res = t;
			t += l;
			for (int i = 4; i < optlen; ++i)
				t += sprintf(t, "%02x", option->payload[i]);
		}
		break;
	case 4: /* uuid */
		{
			if (optlen != 18)
				return NULL;
			asprintf(&res, "uuid %36s", "");
			uuid_unparse(duid->uuid, res + 5);
		}
		break;
	}
	return res;
}

static
char* dhcpv6_option_request_string(const struct dhcpv6_option* option)
{
	char* res = NULL;
	size_t csize = 0;
	uint16_t optlen = ntohs(option->len);
	uint16_t nopts = optlen / 2;
	uint16_t *ropt = (uint16_t*)option->payload;
	char bfr[sizeof("0x0000")];
	while (nopts--) {
		const struct dhcpv6_option_meta* meta = dhcpv6_option_meta(ntohs(*ropt));
		const char * extra;
		if (meta) {
			extra = meta->opt_string;
		} else {
			sprintf(bfr, "0x%02X", ntohs(*ropt));
			extra = bfr;
		}
		size_t extralen = strlen(extra) + (csize ? 2 : 0);
		char *t = realloc(res, csize + extralen + 1);
		if (!t) {
			free(res);
			return NULL;
		}
		res = t;
		t += csize;
		if (csize)
			t += sprintf(t, ", ");
		sprintf(t, "%s", extra);
		csize += extralen;

		ropt++;
	}

	return res;
}

static
char* dhcpv6_option_opaque_string(const struct dhcpv6_option* option)
{
	int slen = ntohs(option->len);
	char *res = malloc(slen * 2 + (slen - 1) / 4 + 1);
	if (!res)
		return NULL;
	char *p = res;
	for (int i = 0; i < slen; ++i) {
		if (i && (i % 4 == 0))
			*p++ = '-';
		sprintf(p, "%02X", option->payload[i]);
		p += 2;
	}
	return res;
}

static
char* dhcpv6_time_string(const struct dhcpv6_option* option)
{
	uint16_t optlen = ntohs(option->len);
	if (optlen != 2)
		return NULL;
	char *ret;
	uint16_t *t = (uint16_t*)option->payload;
	asprintf(&ret, "%d", ntohs(*t));
	return ret;
}

static
char* dhcpv6_ia_pd(const struct dhcpv6_option* option)
{
	const struct dhcpv6_ia_pd *pd = (const struct dhcpv6_ia_pd*)option->payload;
	uint16_t optlen = ntohs(option->len);
	if (optlen < sizeof(*pd))
		return strdup("option truncated");

	char *res;

	asprintf(&res, "iaid=%u, t1=%u, t2=%u", ntohl(pd->iaid), ntohl(pd->t1), ntohl(pd->t2));

	// TODO: parse the nested options ...

	return res;
}

static const struct dhcpv6_option_meta option_metas[] = {
	[ DHCPv6_OPTION_CLIENTID ] = {
		.opt_string = "clientid",
		.interp_to_string = dhcpv6_duid_string,
	},
	[ DHCPv6_OPTION_SERVERID ] = {
		.opt_string = "serverid",
		.interp_to_string = dhcpv6_duid_string,
	},
	[ DHCPv6_OPTION_ORO ] = {
		.opt_string = "option-request",
		.interp_to_string = dhcpv6_option_request_string,
	},
	[ DHCPv6_OPTION_ELAPSED_TIME ] = {
		.opt_string = "elapsed-time",
		.interp_to_string = dhcpv6_time_string,
	},
	[ DHCPv6_OPTION_RELAY_MSG ] = {
		.opt_string = "relay-message",
		.embed = dhcpv6_embed_packet,
	},
	[ DHCPv6_OPTION_RAPID_COMMIT ] = {
		.opt_string = "rapid-commit",
	},
	[ DHCPv6_OPTION_VENDOR_OPTS ] = {
		.opt_string = "vendor-opts",
	},
	[ DHCPv6_OPTION_INTERFACE_ID ] = {
		.opt_string = "interface-id",
		.interp_to_string = dhcpv6_option_opaque_string,
	},
	[ DHCPv6_OPTION_DNS_SERVERS ] = {
		.opt_string = "dns-servers",
	},
	[ DHCPv6_OPTION_IA_PD ] = {
		.opt_string = "ia-pd",
		.interp_to_string = dhcpv6_ia_pd,
		.embed = dhcpv6_embed_options,
		.embed_offset = sizeof(struct dhcpv6_ia_pd),
	},
};

const struct dhcpv6_option_meta* dhcpv6_option_meta(uint16_t option)
{
	if (option < (sizeof(option_metas) / sizeof(*option_metas)) && option_metas[option].opt_string)
		return &option_metas[option];

	return NULL;

}

const char* dhcpv6_validate_packet(const struct dhcpv6_packet* packet)
{
	/* for now simply check that it's at least of length 4 */
	if (packet->pkt_size < 4)
		return "Short packet";

	return NULL;
}

bool _dhcpv6_packet_valid(const struct dhcpv6_packet *pkt)
{
	return !dhcpv6_validate_packet(pkt);
}

static
void dhcpv6_dump_packet_internal(FILE* fp, int d, const struct dhcpv6_packet* packet);

#define oline(fmt, ...) fprintf(fp, "%*s" fmt "\n", d*2, "", ## __VA_ARGS__)
static
void dhcpv6_dump_packet_options_internal(FILE* fp, int d, const void* buffer, size_t buflen)
{
	DHCPv6_FOREACH_BUFFER_OPTION(buffer, buflen, opt) {
		char *interp = (opt->meta && opt->meta->interp_to_string)
			?  opt->meta->interp_to_string(opt->detail) : NULL;

		oline("option: %u/%s (len=%u)%s%s", ntohs(opt->detail->opcode),
				opt->meta ? opt->meta->opt_string : "unknown",
				ntohs(opt->detail->len), interp ? ": " : "", interp ?: "");

		free(interp);

		if (opt->meta) {
			switch (opt->meta->embed) {
			case dhcpv6_embed_none:
				break;
			case dhcpv6_embed_packet:
				{
					struct dhcpv6_packet p;
					p.pkt_size = ntohs(opt->detail->len) - opt->meta->embed_offset;
					memcpy(&p.raw, opt->detail->payload + opt->meta->embed_offset, p.pkt_size);

					const char* embedded_invalid = dhcpv6_validate_packet(&p);
					if (embedded_invalid)
						oline("** embedded packet is invalid: %s\n", embedded_invalid);

					dhcpv6_dump_packet_internal(fp, d+1, &p);
				}
				break;
			case dhcpv6_embed_options:
				dhcpv6_dump_packet_options_internal(fp, d+1, opt->detail->payload + opt->meta->embed_offset, ntohs(opt->detail->len) - opt->meta->embed_offset);
				break;
			default:
				oline("** Unknown embed mechanism.");
			}
		}
	}
}

static
void dhcpv6_dump_packet_internal(FILE* fp, int d, const struct dhcpv6_packet* packet)
{
	oline("msg-type: %s(%d)", dhcpv6_type2string(packet->msg_type), packet->msg_type);

	if (dhcpv6_packet_is_relay(packet)) {
		char ip6str[INET6_ADDRSTRLEN];
		oline("hop-count: %d", packet->relay.hop_count);
		oline("link-address: %s", inet_ntop(AF_INET6, &packet->relay.link_address, ip6str, sizeof(ip6str)));
		oline("peer-address: %s", inet_ntop(AF_INET6, &packet->relay.peer_address, ip6str, sizeof(ip6str)));
	} else {
		oline("trn-id: 0x%06X", ntohl(packet->norm.trn_id) >> 8);
	}

	const void* optionbuffer;
	size_t bufferlen;
	dhcpv6_calc_packet_option_buffer(packet, &optionbuffer, &bufferlen);
	dhcpv6_dump_packet_options_internal(fp, d, optionbuffer, bufferlen);
}
#undef oline

void dhcpv6_dump_packet(FILE* fp, const struct dhcpv6_packet* packet, const struct sockaddr_in6* remote, int direction, const char* interface)
{
	const char* dir = "(invalid direction)";
	char ip6str[INET6_ADDRSTRLEN];
	const char* invalid = dhcpv6_validate_packet(packet);

	switch (direction) {
	case DHCPv6_DIRECTION_RECEIVE:
		dir = "Received";
		break;
	case DHCPv6_DIRECTION_TRANSMIT:
		dir = "Transmit";
		break;
	}
	fprintf(fp, "%s DHCPv6 packet of %ld bytes (interface=%s)\n", dir, packet->pkt_size, interface);

	fprintf(fp, "Remote: [%s]:%u\n", inet_ntop(AF_INET6, &remote->sin6_addr, ip6str, sizeof(ip6str)),
			ntohs(remote->sin6_port));

	if (invalid)
		fprintf(fp, "Packet is invalid: %s\n", invalid);

	if (packet->pkt_size < dhcpv6_min_packet_size(packet))
		return;

	dhcpv6_dump_packet_internal(fp, 1, packet);
}

int dhcpv6_append_option(struct dhcpv6_packet* pkt, uint16_t opcode, void* payload, uint16_t payloadlen)
{
	/* can we fit the option? */
	if (pkt->pkt_size + sizeof(struct dhcpv6_option) + payloadlen > sizeof(pkt->raw)) {
		errno = ENOMEM;
		return -1;
	}

	struct dhcpv6_option *ot = (struct dhcpv6_option*)&pkt->raw[pkt->pkt_size];
	pkt->pkt_size += payloadlen + sizeof(struct dhcpv6_option);

	ot->opcode = ntohs(opcode);
	ot->len = ntohs(payloadlen);
	memcpy(ot->payload, payload, payloadlen);

	return 0;
}

const struct dhcpv6_option* dhcpv6_packet_get_option(const struct dhcpv6_packet* packet, uint16_t opcode)
{
	opcode = htons(opcode);
	DHCPv6_FOREACH_PACKET_OPTION(packet, opt) {
		if (opt->detail->opcode == opcode) {
			const struct dhcpv6_option* t = opt->detail;
			free(opt);
			return t;
		}
	}

	return NULL;
}
