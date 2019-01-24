#ifndef PACKET_H
#define PACKET_H

#include "common.h"
#include <endian.h>
#include <arpa/inet.h>

#define MAX_PKT_LEN		65535
#define MAX_IFACE_LEN	16

#define ETH_HDR_LEN		14
#define VLAN_TAG_LEN	4
#define IP_HDR_LEN		20
#define TCP_HDR_LEN		20
#define UDP_HDR_LEN		8

#define MAC_ADDR_LEN	6
#define IP_ADDR_LEN		4

#define IP_OFFSET 		0x1FFF
#define IP_FRAGOFF(ip) (ntohs(ip->frag) & IP_OFFSET)
#define TCP_FLAG(p, f)	(!!(p->tcp->flag & f))

enum eth_type {
	ETH_IP			= 0x0800,
	ETH_IPV6		= 0x86dd,
	ETH_8021Q		= 0x8100,
	ETH_8021QinQ	= 0x88a8,
	ETH_8021Q9100	= 0x9100,
	ETH_8021Q9200	= 0x9200
};

enum tcp_flag {
	TCP_FIN	= 0x01,
	TCP_SYN	= 0x02,
	TCP_RST	= 0x04,
	TCP_PSH	= 0x08,
	TCP_ACK	= 0x10,
	TCP_URG	= 0x20,
	TCP_ECE	= 0x40,
	TCP_CWR	= 0x80
};

enum state_type {
	STATE_INVALID		= 0x00,
	STATE_ESTABLISHED	= 0x01,
	STATE_NEW			= 0x02,
	STATE_RELATED		= 0x04,
	STATE_UNTRACKED		= 0x08,
};

#pragma pack(1)
typedef struct eth {
	uint8_t		src[MAC_ADDR_LEN];
	uint8_t		dst[MAC_ADDR_LEN];
	uint16_t	type;
} eth_t;

typedef struct ip {
#if defined(__LITTLE_ENDIAN)
	uint8_t		ihl: 4,
				ver: 4;
#elif defined (__BIG_ENDIAN)
	uint8_t		ver: 4,
				ihl: 4;
#else
#error	"Please fix <endian.h>"
#endif
	uint8_t		tos;
	uint16_t	len;
	uint16_t	id;
	uint16_t	frag;
	uint8_t		ttl;
	uint8_t		proto;
	uint16_t	check;
	uint32_t	src;
	uint32_t	dst;
	/*The options start here. */
} ip_t;

typedef struct tcp {
	uint16_t	src;
	uint16_t	dst;
	uint32_t	seq;
	uint32_t	ack_seq;
#if defined(__LITTLE_ENDIAN)
	uint8_t		res: 4,
				thl: 4;
#elif defined(__BIG_ENDIAN)
	uint8_t		thl: 4,
				res: 4;
#else
#error	"Please fix <endian.h>"
#endif
	uint8_t		flag;
	uint16_t	window;
	uint16_t	check;
	uint16_t	urg_ptr;
} tcp_t;

typedef struct udp {
	uint16_t	src;
	uint16_t	dst;
	uint16_t	len;
	uint16_t	check;
} udp_t;
#pragma pack()

typedef struct iface {
	char		in[MAX_IFACE_LEN];
	char		out[MAX_IFACE_LEN];
} iface_t;

typedef struct packet {
	int			len;
	int			offset;
	int			payload;
	uint8_t		*data;

	iface_t		iface;
	uint8_t		state;

	uint16_t 	eth_type;
	uint8_t  	ip_proto;
	eth_t 		*eth;
	ip_t 		*ip;
	tcp_t		*tcp;
	udp_t		*udp;
} packet_t;

#define IP_PRINT_NATIVE(n)	\
(uint32_t)((n)>>24)&0xFF,	\
(uint32_t)((n)>>16)&0xFF,	\
(uint32_t)((n)>>8)&0xFF,	\
(uint32_t)((n)&0xFF)

#define IP_FORMAT 		"%u.%u.%u.%u"
#define MAC_FORMAT		"%02X:%02X:%02X:%02X:%02X:%02X"

#define IP_PRINT(n)		IP_PRINT_NATIVE(ntohl(n))
#define MAC_PRINT(n)	n[0],n[1],n[2],n[3],n[4],n[5]

extern map_int_t m_tcp_flag[];
extern map_int_t m_state[];

#define pkt_set_state(p, s)	 (p && (p->state = s))
void pkt_set_iface(packet_t *pkt, const char *in, const char *out);
packet_t *new_tcp_pkt(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t flag);
packet_t *new_udp_pkt(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port);
void free_pkt(packet_t *pkt);
void print_pkt(packet_t *pkt);
packet_t *parse_pkt(const uint8_t *data, int len);

#endif /* PACKET_H */
