#include "packet.h"

map_int_t m_tcp_flag[] = {
	{"FIN"	, TCP_FIN},
	{"SYN"	, TCP_SYN},
	{"RST"	, TCP_RST},
	{"PSH"	, TCP_PSH},
	{"ACK"	, TCP_ACK},
	{"NONE"	, 0},
	{NULL	, -1},
};

map_int_t m_state[] = {
	{"INVALID"		, STATE_INVALID},
	{"ESTABLISHED"	, STATE_ESTABLISHED},
	{"NEW"			, STATE_NEW},
	{"RELATED"		, STATE_RELATED},
	{"UNTRACKED"	, STATE_UNTRACKED},
	{NULL			, -1},
};

uint8_t default_tcp[] = {
	//ETHER
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55,					//src mac
	0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,					//dst mac
	0x08, 0x00,											//IPV4
	//IP
	0x45, 0x00, 0x00, 0x28,								//ver ihl len
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x06, 0x00, 0x00,								////proto
	0x00, 0x00, 0x00, 0x00,								//src ip
	0x00, 0x00, 0x00, 0x00,								//dst ip
	//TCP
	0x00, 0x00, 0x00, 0x00,								//port
	0x00, 0x00, 0x00, 0x00,								//seq
	0x00, 0x00, 0x00, 0x00, 							//ack
	0x50, 0x00, 0x00, 0x00,								//thl res flag
	0x00, 0x00, 0x00, 0x00,
};

uint8_t default_udp[] = {
	//ETHER
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55,					//src mac
	0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,					//dst mac
	0x08, 0x00,											//IPV4
	//IP
	0x45, 0x00, 0x00, 0x1C,								//ver ihl len
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x11, 0x00, 0x00,								//proto
	0x00, 0x00, 0x00, 0x00,								//src ip
	0x00, 0x00, 0x00, 0x00,								//dst ip
	//UDP
	0x00, 0x00, 0x00, 0x00,								//port
	0x00, 0x00, 0x00, 0x00,								//len check
};

void pkt_set_iface(packet_t *pkt, const char *in, const char *out)
{
	if (pkt) {
		_strlcpy(pkt->iface.in, in, sizeof(pkt->iface.in));
		_strlcpy(pkt->iface.out, out, sizeof(pkt->iface.out));
	}
}

void free_pkt(packet_t *pkt)
{
	if (pkt == NULL) {
		return;
	}

	_free(pkt->data);
	_free(pkt);
}

packet_t *new_tcp_pkt(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t flag)
{
	packet_t *pkt = parse_pkt(default_tcp, sizeof(default_tcp));

	if (pkt == NULL) {
		log_err("%s %d failed\n", __FUNCTION__, __LINE__);
		return NULL;
	}

	if (pkt->eth_type == ETH_IP && pkt->ip) {
		inet_pton(AF_INET, src_ip, (struct in_addr *)&pkt->ip->src);
		inet_pton(AF_INET, dst_ip, (struct in_addr *)&pkt->ip->dst);
	} else {
		log_err("%s %d failed\n", __FUNCTION__, __LINE__);
		free_pkt(pkt);
		return NULL;
	}

	if (pkt->ip_proto == IPPROTO_TCP && pkt->tcp) {
		pkt->tcp->src = htons(src_port);
		pkt->tcp->dst = htons(dst_port);
		pkt->tcp->flag = flag;
	} else {
		log_err("%s %d failed\n", __FUNCTION__, __LINE__);
		free_pkt(pkt);
		return NULL;
	}

	return pkt;
}

packet_t *new_udp_pkt(const char *src_ip, const char *dst_ip, uint16_t src_port, uint16_t dst_port)
{
	packet_t *pkt = parse_pkt(default_udp, sizeof(default_udp));

	if (pkt == NULL) {
		log_err("%s %d failed\n", __FUNCTION__, __LINE__);
		return NULL;
	}

	if (pkt->eth_type == ETH_IP && pkt->ip) {
		inet_pton(AF_INET, src_ip, (struct in_addr *)&pkt->ip->src);
		inet_pton(AF_INET, dst_ip, (struct in_addr *)&pkt->ip->dst);
	} else {
		log_err("%s %d failed\n", __FUNCTION__, __LINE__);
		free_pkt(pkt);
		return NULL;
	}

	if (pkt->ip_proto == IPPROTO_UDP && pkt->udp) {
		pkt->udp->src = htons(src_port);
		pkt->udp->dst = htons(dst_port);
	} else {
		log_err("%s %d failed\n", __FUNCTION__, __LINE__);
		free_pkt(pkt);
		return NULL;
	}

	return pkt;
}

void print_pkt(packet_t *pkt)
{
	if (pkt == NULL) {
		log_err("%s pkt is null\n", __FUNCTION__);
		return;
	}

	printf("--------------------------------------------------\n");

	printf("[PACKET] len: %-5d offset: %-5d payload: %-5d\n\n", pkt->len, pkt->offset, pkt->payload);

	for (int i = 0; i < pkt->len; i++) {
		printf(" %02X", pkt->data[i]);

		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}

	printf("\n\n");

	printf("iface		: %s -> %s\n", pkt->iface.in, pkt->iface.out);
	printf("state		: %s\n", map_int_get_k(pkt->state, m_state));

	if (pkt->eth_type) {
		printf("ether type	: 0x%04x\n", pkt->eth_type);
		printf("src mac		: "MAC_FORMAT"\n", MAC_PRINT(pkt->eth->src));
		printf("dst mac		: "MAC_FORMAT"\n", MAC_PRINT(pkt->eth->dst));
	}

	if (pkt->eth_type == ETH_IP) {
		printf("IP frag		: %d\n", IP_FRAGOFF(pkt->ip));
		printf("src ip		: "IP_FORMAT"\n", IP_PRINT(pkt->ip->src));
		printf("dst ip		: "IP_FORMAT"\n", IP_PRINT(pkt->ip->dst));
	}

	if (pkt->ip_proto == IPPROTO_TCP) {
		printf("TCP flag	: ");

		for (int i = 0; m_tcp_flag[i].k != NULL; i++) {
			if (TCP_FLAG(pkt, m_tcp_flag[i].v)) {
				printf("[%s]", m_tcp_flag[i].k);
			}
		}

		printf("\n");
		printf("src port	: %u\n", ntohs(pkt->tcp->src));
		printf("dst port	: %u\n", ntohs(pkt->tcp->dst));

	} else if (pkt->ip_proto == IPPROTO_UDP) {
		printf("UDP\n");
		printf("src port	: %u\n", ntohs(pkt->udp->src));
		printf("dst port	: %u\n", ntohs(pkt->udp->dst));
	}

	if (pkt->payload > 0) {
		printf("--------------------------------------------------\n");

		for (int i = pkt->offset; i < pkt->len; i++) {
			printf("%c", pkt->data[i]);
		}
		printf("\n");
	}

	printf("--------------------------------------------------\n");
}

static void parse_tcp(packet_t *pkt)
{
	if (pkt->payload < TCP_HDR_LEN)  {
		log_err("%s %d length is not enough\n", __FUNCTION__, __LINE__);
	}

	pkt->tcp = (tcp_t *)&pkt->data[pkt->offset];

	int thl = pkt->tcp->thl * 4;

	if (pkt->payload < thl) {
		log_err("%s %d length is not enough\n", __FUNCTION__, __LINE__);
		return;
	}

	pkt->offset += thl;
	pkt->payload -= thl;
}

static void parse_udp(packet_t *pkt)
{
	if (pkt->payload < UDP_HDR_LEN)  {
		log_err("%s %d length is not enough\n", __FUNCTION__, __LINE__);
	}

	pkt->udp = (udp_t *)&pkt->data[pkt->offset];

	pkt->offset += UDP_HDR_LEN;
	pkt->payload -= UDP_HDR_LEN;
}

static void parse_ip(packet_t *pkt)
{
	if (pkt->payload < IP_HDR_LEN)  {
		log_err("%s %d length is not enough\n", __FUNCTION__, __LINE__);
	}

	pkt->ip = (ip_t *)&pkt->data[pkt->offset];

	int ihl = pkt->ip->ihl * 4;

	if (pkt->payload < ihl) {
		log_err("%s %d length is not enough\n", __FUNCTION__, __LINE__);
		return;
	}

	pkt->offset += ihl;
	pkt->payload -= ihl;
	pkt->ip_proto = pkt->ip->proto;

	switch (pkt->ip_proto) {
		case IPPROTO_TCP :
			parse_tcp(pkt);
			break;

		case IPPROTO_UDP :
			parse_udp(pkt);
			break;

		default :
			break;
	}
}

static void parse_eth(packet_t *pkt)
{
	if (pkt->len < ETH_HDR_LEN)  {
		log_err("%s %d length is not enough\n", __FUNCTION__, __LINE__);
	}

	uint8_t *p = &pkt->data[pkt->offset];

	pkt->eth = (eth_t *)p;
	pkt->offset += ETH_HDR_LEN;
	pkt->payload -= ETH_HDR_LEN;
	pkt->eth_type = ntohs(pkt->eth->type);

recurse:

	switch (pkt->eth_type) {
		case ETH_8021Q :
		case ETH_8021QinQ :
		case ETH_8021Q9100 :
		case ETH_8021Q9200 :
			if (pkt->payload < VLAN_TAG_LEN) {
				log_err("%s %d length is not enough\n", __FUNCTION__, __LINE__);
				return;
			}

			pkt->eth_type = ntohs(*(uint16_t *)(p + 2));
			p += VLAN_TAG_LEN;
			pkt->offset += VLAN_TAG_LEN;
			pkt->payload -= VLAN_TAG_LEN;
			goto recurse;

		case ETH_IP :
			parse_ip(pkt);
			break;

		case ETH_IPV6 :
			//TODO:
			break;

		default :
			break;
	}
}

packet_t *parse_pkt(const uint8_t *data, int len)
{
	if (0 > len && len > 65535) {
		log_err("%s packet len %d is invalid\n", __FUNCTION__, len);
		return NULL;
	}

	if (!data) {
		log_err("%s data is null\n",  __FUNCTION__);
		return NULL;
	}

	packet_t *pkt = _new(packet_t);
	pkt->len = len;
	pkt->payload = len;
	pkt->data = new(len);
	memcpy(pkt->data, data, len);
	parse_eth(pkt);

	return pkt;
}

