#ifndef DHCPV6_H
#define DHCPV6_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define DHCPv6_MSGTYPE_SOLICIT              1
#define DHCPv6_MSGTYPE_ADVERTISE            2
#define DHCPv6_MSGTYPE_REQUEST              3
#define DHCPv6_MSGTYPE_CONFIRM              4
#define DHCPv6_MSGTYPE_RENEW                5
#define DHCPv6_MSGTYPE_REBIND               6
#define DHCPv6_MSGTYPE_REPLY                7
#define DHCPv6_MSGTYPE_RELEASE              8
#define DHCPv6_MSGTYPE_DECLINE              9
#define DHCPv6_MSGTYPE_RECONFIGURE         10
#define DHCPv6_MSGTYPE_INFORMATION_REQUEST 11
#define DHCPv6_MSGTYPE_RELAY_FORW          12
#define DHCPv6_MSGTYPE_RELAY_REPL          13

#define DHCPv6_OPTION_CLIENTID                            1
#define DHCPv6_OPTION_SERVERID                            2
#define DHCPv6_OPTION_IA_NA                               3
#define DHCPv6_OPTION_IA_TA                               4
#define DHCPv6_OPTION_IAADDR                              5
#define DHCPv6_OPTION_ORO                                 6
#define DHCPv6_OPTION_PREFERENCE                          7
#define DHCPv6_OPTION_ELAPSED_TIME                        8
#define DHCPv6_OPTION_RELAY_MSG                           9
#define DHCPv6_OPTION_AUTH                               11
#define DHCPv6_OPTION_UNICAST                            12
#define DHCPv6_OPTION_STATUS_CODE                        13
#define DHCPv6_OPTION_RAPID_COMMIT                       14
#define DHCPv6_OPTION_USER_CLASS                         15
#define DHCPv6_OPTION_VENDOR_CLASS                       16
#define DHCPv6_OPTION_VENDOR_OPTS                        17
#define DHCPv6_OPTION_INTERFACE_ID                       18
#define DHCPv6_OPTION_RECONF_MSG                         19
#define DHCPv6_OPTION_RECONF_ACCEPT                      20
#define DHCPv6_OPTION_SIP_SERVER_D                       21
#define DHCPv6_OPTION_SIP_SERVER_A                       22
#define DHCPv6_OPTION_DNS_SERVERS                        23
#define DHCPv6_OPTION_DOMAIN_LIST                        24
#define DHCPv6_OPTION_IA_PD                              25
#define DHCPv6_OPTION_IAPREFIX                           26
#define DHCPv6_OPTION_NIS_SERVERS                        27
#define DHCPv6_OPTION_NISP_SERVERS                       28
#define DHCPv6_OPTION_NIS_DOMAIN_NAME                    29
#define DHCPv6_OPTION_NISP_DOMAIN_NAME                   30
#define DHCPv6_OPTION_SNTP_SERVERS                       31
#define DHCPv6_OPTION_INFORMATION_REFRESH_TIME           32
#define DHCPv6_OPTION_BCMCS_SERVER_D                     33
#define DHCPv6_OPTION_BCMCS_SERVER_A                     34
#define DHCPv6_OPTION_GEOCONF_CIVIC                      36
#define DHCPv6_OPTION_REMOTE_ID                          37
#define DHCPv6_OPTION_SUBSCRIBER_ID                      38
#define DHCPv6_OPTION_CLIENT_FQDN                        39
#define DHCPv6_OPTION_PANA_AGENT                         40
#define DHCPv6_OPTION_NEW_POSIX_TIMEZONE                 41
#define DHCPv6_OPTION_NEW_TZDB_TIMEZONE                  42
#define DHCPv6_OPTION_ERO                                43
#define DHCPv6_OPTION_LQ_QUERY                           44
#define DHCPv6_OPTION_CLIENT_DATA                        45
#define DHCPv6_OPTION_CLT_TIME                           46
#define DHCPv6_OPTION_LQ_RELAY_DATA                      47
#define DHCPv6_OPTION_LQ_CLIENT_LINK                     48
#define DHCPv6_OPTION_MIP6_HNIDF                         49
#define DHCPv6_OPTION_MIP6_VDINF                         50
#define DHCPv6_OPTION_V6_LOST                            51
#define DHCPv6_OPTION_CAPWAP_AC_V6                       52
#define DHCPv6_OPTION_RELAY_ID                           53
#define DHCPv6_OPTION_IPv6_ADDRESS_MOS                   54
#define DHCPv6_OPTION_IPv6_FQDN_MOS                      55
#define DHCPv6_OPTION_NTP_SERVER                         56
#define DHCPv6_OPTION_V6_ACCESS_DOMAIN                   57
#define DHCPv6_OPTION_SIP_UA_CS_LIST                     58
#define DHCPv6_OPTION_BOOTFILE_URL                       59
#define DHCPv6_OPTION_BOOTFILE_PARAM                     60
#define DHCPv6_OPTION_CLIENT_ARCH_TYPE                   61
#define DHCPv6_OPTION_NII                                62
#define DHCPv6_OPTION_GEOLOCATION                        63
#define DHCPv6_OPTION_AFTR_NAME                          64
#define DHCPv6_OPTION_ERP_LOCAL_DOMAIN_NAME              65
#define DHCPv6_OPTION_RSOO                               66
#define DHCPv6_OPTION_PD_EXCLUDE                         67
#define DHCPv6_OPTION_VSS                                68
#define DHCPv6_OPTION_MIP6_IDINF                         69
#define DHCPv6_OPTION_MIP6_UDINF                         70
#define DHCPv6_OPTION_MIP6_HNP                           71
#define DHCPv6_OPTION_MIP6_HAA                           72
#define DHCPv6_OPTION_MIP6_HAF                           73
#define DHCPv6_OPTION_RDNSS_SELECTION                    74
#define DHCPv6_OPTION_KRB_PRINCIPAL_NAME                 75
#define DHCPv6_OPTION_KRB_REALM_NAME                     76
#define DHCPv6_OPTION_KRB_DEFAULT_REALM_NAME             77
#define DHCPv6_OPTION_KRB_KDC                            78
#define DHCPv6_OPTION_CLIENT_LINKLAYER_ADDR              79
#define DHCPv6_OPTION_LINK_ADDRESS                       80
#define DHCPv6_OPTION_RADIUS                             81
#define DHCPv6_OPTION_SOL_MAX_RT                         82
#define DHCPv6_OPTION_INF_MAX_RT                         83
#define DHCPv6_OPTION_ADDRSEL                            84
#define DHCPv6_OPTION_ADDRSEL_TABLE                      85
#define DHCPv6_OPTION_V6_PCP_SERVER                      86
#define DHCPv6_OPTION_DHCPV4_MSG                         87
#define DHCPv6_OPTION_DHCP4_O_DHCP6_SERVER               88
#define DHCPv6_OPTION_S46_RULE                           89
#define DHCPv6_OPTION_S46_BR                             90
#define DHCPv6_OPTION_S46_DMR                            91
#define DHCPv6_OPTION_S46_V4V6BIND                       92
#define DHCPv6_OPTION_S46_PORTPARAMS                     93
#define DHCPv6_OPTION_S46_CONT_MAPE                      94
#define DHCPv6_OPTION_S46_CONT_MAPT                      95
#define DHCPv6_OPTION_S46_CONT_LW                        96
#define DHCPv6_OPTION_4RD                                97
#define DHCPv6_OPTION_4RD_MAP_RULE                       98
#define DHCPv6_OPTION_4RD_NON_MAP_RULE                   99
#define DHCPv6_OPTION_LQ_BASE_TIME                      100
#define DHCPv6_OPTION_LQ_START_TIME                     101
#define DHCPv6_OPTION_LQ_END_TIME                       102
#define DHCPv6_OPTION_CAPTIVE_PORTAL                    103
#define DHCPv6_OPTION_MPL_PARAMETERS                    104
#define DHCPv6_OPTION_ANI_ATT                           105
#define DHCPv6_OPTION_ANI_NETWORK_NAME                  106
#define DHCPv6_OPTION_ANI_AP_NAME                       107
#define DHCPv6_OPTION_ANI_AP_BSSID                      108
#define DHCPv6_OPTION_ANI_OPERATOR_ID                   109
#define DHCPv6_OPTION_ANI_OPERATOR_REALM                110
#define DHCPv6_OPTION_S46_PRIORITY                      111
#define DHCPv6_OPTION_MUD_URL_V6                        112
#define DHCPv6_OPTION_V6_PREFIX64                       113
#define DHCPv6_OPTION_F_BINDING_STATUS                  114
#define DHCPv6_OPTION_F_CONNECT_FLAGS                   115
#define DHCPv6_OPTION_F_DNS_REMOVAL_INFO                116
#define DHCPv6_OPTION_F_DNS_HOST_NAME                   117
#define DHCPv6_OPTION_F_DNS_ZONE_NAME                   118
#define DHCPv6_OPTION_F_DNS_FLAGS                       119
#define DHCPv6_OPTION_F_EXPIRATION_TIME                 120
#define DHCPv6_OPTION_F_MAX_UNACKED_BNDUPD              121
#define DHCPv6_OPTION_F_MCLT                            122
#define DHCPv6_OPTION_F_PARTNER_LIFETIME                123
#define DHCPv6_OPTION_F_PARTNER_LIFETIME_SENT           124
#define DHCPv6_OPTION_F_PARTNER_DOWN_TIME               125
#define DHCPv6_OPTION_F_PARTNER_RAW_CLT_TIME            126
#define DHCPv6_OPTION_F_PROTOCOL_VERSION                127
#define DHCPv6_OPTION_F_KEEPALIVE_TIME                  128
#define DHCPv6_OPTION_F_RECONFIGURE_DATA                129
#define DHCPv6_OPTION_F_RELATIONSHIP_NAME               130
#define DHCPv6_OPTION_F_SERVER_FLAGS                    131
#define DHCPv6_OPTION_F_SERVER_STATE                    132
#define DHCPv6_OPTION_F_START_TIME_OF_STATE             133
#define DHCPv6_OPTION_F_STATE_EXPIRATION_TIME           134
#define DHCPv6_OPTION_RELAY_PORT                        135
#define DHCPv6_OPTION_V6_SZTP_REDIRECT                  136
#define DHCPv6_OPTION_S46_BIND_IPV6_PREFIX              137
#define DHCPv6_OPTION_IA_LL                             138
#define DHCPv6_OPTION_LLADDR                            139
#define DHCPv6_OPTION_SLAP_QUAD                         140
#define DHCPv6_OPTION_V6_DOTS_RI                        141
#define DHCPv6_OPTION_V6_DOTS_ADDRESS                   142
#define DHCPv6_OPTION_IPV6_ADDRESS_ANDSF                143
#define DHCPv6_OPTION_V6_DNR                            144
#define DHCPv6_OPTION_REGISTERED_DOMAIN                 145
#define DHCPv6_OPTION_FORWARD_DIST_MANAGER              146
#define DHCPv6_OPTION_REVERSE_DIST_MANAGER              147

struct dhcpv6_option {
	uint16_t opcode;
	uint16_t len;
	unsigned char payload[0];
} __attribute__((packed));

/* a compile failure here indicates that in6_addr isn't 16 bytes) */
typedef char __ct_test[(sizeof(struct in6_addr) == 16) - 1];

struct dhcpv6_packet {
	size_t pkt_size;
	union {
		unsigned char raw[0xffff];
		struct {
			uint8_t msg_type;
			union {
				struct {
					unsigned trn_id:24;
					struct dhcpv6_option optdata[0];
				} __attribute__((packed)) norm;
				struct {
					uint8_t hop_count;
					struct in6_addr link_address;
					struct in6_addr peer_address;
					struct dhcpv6_option optdata[0];
				} __attribute__((packed)) relay;
			};
		} __attribute__((packed));
	};
};

static
inline bool dhcpv6_packet_is_relay(const struct dhcpv6_packet *pkt)
{
	return pkt->msg_type == DHCPv6_MSGTYPE_RELAY_FORW ||
		pkt->msg_type == DHCPv6_MSGTYPE_RELAY_REPL;
}

/* this assumes that dhcp_packet_valid has passed at least basic checks */
static
inline size_t dhcpv6_min_packet_size(const struct dhcpv6_packet *pkt)
{
	if (dhcpv6_packet_is_relay(pkt))
		return sizeof(pkt->relay) + sizeof(pkt->msg_type);
	return sizeof(pkt->norm) + sizeof(pkt->msg_type);
}

const char* dhcpv6_packet_valid_reason(const struct dhcpv6_packet* packet);

/* do not invoke this directly */
bool _dhcpv6_packet_valid(const struct dhcpv6_packet *pkt);

static
inline bool dhcpv6_packet_valid(const struct dhcpv6_packet *pkt)
{
	/* we perform basic checks here prior to going off and validating the full
	 * packet */
	if (pkt->pkt_size == 0 || pkt->pkt_size > sizeof(pkt->raw))
		return false;

	if (pkt->pkt_size < dhcpv6_min_packet_size(pkt))
		return false;

	return _dhcpv6_packet_valid(pkt);
}

struct dhcpv6_option_meta {
	const char* opt_string;
	char* (*interp_to_string)(const struct dhcpv6_option*); /* need to free() result */
	bool (*validate)(const struct dhcpv6_option*); /* true it's fine, false it's not */
};

struct dhcpv6_packet_option {
	const struct dhcpv6_packet* src_packet;
	const struct dhcpv6_option* detail;
	const struct dhcpv6_option_meta* meta;
};

struct dhcpv6_duid {
	uint16_t type;
	union {
		struct {
			/* type = 1 */
			uint16_t hwtype;
			uint32_t time;
			char hwaddr[0]; /* length is option length - 8 */
		} llt;
		struct {
			/* type = 2 */
			uint32_t enterprise_num;
			char ident[0]; /* option length - 6 */
		} vendor;
		struct {
			/* type = 3 */
			uint16_t hwtype;
			char hwaddr[0]; /* option length - 4 */
		} lla;
		unsigned char uuid[16];
	};
} __attribute__((packed));

const char* dhcpv6_type2string(int msg_type);
const struct dhcpv6_option_meta* dhcpv6_option_meta(uint16_t option);

/* -1 error (errno), 0 success */
int dhcpv6_append_option(struct dhcpv6_packet* pkt, uint16_t opcode, void* payload, uint16_t payloadlen);

const struct dhcpv6_option* dhcpv6_packet_get_option(const struct dhcpv6_packet* pkt, uint16_t opcode);

struct dhcpv6_packet_option* dhcpv6_packet_option_head(const struct dhcpv6_packet*);
struct dhcpv6_packet_option* dhcpv6_packet_option_next(struct dhcpv6_packet_option*);

#define DHCPv6_FOREACH_PACKET_OPTION(p, x) for (struct dhcpv6_packet_option* x = dhcpv6_packet_option_head(p); x; x = dhcpv6_packet_option_next(x))

#define DHCPv6_DIRECTION_RECEIVE	1
#define DHCPv6_DIRECTION_TRANSMIT	2

void dhcpv6_dump_packet(FILE*, const struct dhcpv6_packet*, const struct sockaddr_in6*, int direction, const char* interface);
#endif
