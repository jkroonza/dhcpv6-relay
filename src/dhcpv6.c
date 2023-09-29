#define _GNU_SOURCE

#include "dhcpv6.h"

#include <stddef.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <uuid/uuid.h>
#include <string.h>

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

struct dhcpv6_packet_option* dhcpv6_packet_option_head(struct dhcpv6_packet* pkt)
{
	if (pkt->pkt_size < 8) /* 32-bits header, option is min 32 bits */
		return NULL;

	if (ntohs(pkt->optdata[0].len) > pkt->pkt_size - 8) /* packet (option) truncated */
		return NULL;

	struct dhcpv6_packet_option* opt = malloc(sizeof(*opt));
	opt->src_packet = pkt;
	opt->detail = pkt->optdata;
	opt->meta = dhcpv6_option_meta(ntohs(opt->detail->opcode));

	return opt;
}

struct dhcpv6_packet_option* dhcpv6_packet_option_next(struct dhcpv6_packet_option* opt)
{
	ssize_t offset = (unsigned char*)opt->detail - opt->src_packet->raw
		+ ntohs(opt->detail->len) + 4;

	if (opt->src_packet->pkt_size < offset + 4) {
		free(opt);
		return NULL;
	}

	opt->detail = (struct dhcpv6_option*)&opt->src_packet->raw[offset];
	if (opt->src_packet->pkt_size < offset + 4 + ntohs(opt->detail->len)) {
		free(opt);
		return NULL;
	}
	opt->meta = dhcpv6_option_meta(ntohs(opt->detail->opcode));
	return opt;
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

static const struct dhcpv6_option_meta option_metas[] = {
	[ DHCPv6_OPTION_CLIENTID ] = {
		.opt_string = "clientid",
		.opt_type = option_type_duid,
		.interp_to_string = dhcpv6_duid_string,
	},
	[ DHCPv6_OPTION_SERVERID ] = {
		.opt_string = "serverid",
		.opt_type = option_type_duid,
		.interp_to_string = dhcpv6_duid_string,
	},
	[ DHCPv6_OPTION_ORO ] = {
		.opt_string = "option-request",
		.opt_type = option_type_unspec,
		.interp_to_string = dhcpv6_option_request_string,
	},
	[ DHCPv6_OPTION_ELAPSED_TIME ] = {
		.opt_string = "elapsed-time",
		.opt_type = option_type_time,
		.interp_to_string = dhcpv6_time_string,
	},
	[ DHCPv6_OPTION_RAPID_COMMIT ] = {
		.opt_string = "rapid-commit",
	},
	[ DHCPv6_OPTION_VENDOR_OPTS ] = {
		.opt_string = "vendor-opts",
		.opt_type = option_type_unspec,
	},
	[ DHCPv6_OPTION_DNS_SERVERS ] = {
		.opt_string = "dns-servers",
		.opt_type = option_type_ipv6,
	},
	[ DHCPv6_OPTION_IA_PD ] = {
		.opt_string = "ia-pd",
		.opt_type = option_type_unspec,
	},
};

const struct dhcpv6_option_meta* dhcpv6_option_meta(uint16_t option)
{
	if (option < (sizeof(option_metas) / sizeof(*option_metas)) && option_metas[option].opt_string)
		return &option_metas[option];

	return NULL;

}
