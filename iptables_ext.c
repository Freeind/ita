#include "iptables.h"

typedef struct match_tcp {
	uint16_t src[2];
	uint16_t dst[2];
	uint8_t opt;
	uint8_t flag;
	uint8_t flag_mask;
	uint8_t invert;
} match_tcp_t;

typedef struct match_udp {
	uint16_t src[2];
	uint16_t dst[2];
	uint8_t invert;
} match_udp_t;

typedef struct match_state {
	uint8_t state;
	uint8_t invert;
} match_state_t;

typedef struct target_reject {
	char with[32];
} target_reject_t;

enum INV_TCP_TYPE {
	INV_TCP_SRC		= 0x01,
	INV_TCP_DST		= 0x02,
	INV_TCP_OPT		= 0x04,
	INV_TCP_FLAG	= 0x08,
};

enum INV_UDP_TYPE {
	INV_UDP_SRC		= 0x01,
	INV_UDP_DST		= 0x02,
};

static void print_port(const char *type, uint16_t *port, int inv)
{
	printf("%s --%s %u", inv ? " !" : "", type, port[0]);

	if (port[1] > 0) {
		printf(":%u", port[1]);
	}
}

static void print_tcp_flag(int flag)
{
	int have = 0;

	for (int i = 0; m_tcp_flag[i].k != NULL; i++) {
		if (flag & m_tcp_flag[i].v) {
			if (have) {
				printf(",");
			} else {
				printf(" ");
			}

			printf("%s", m_tcp_flag[i].k);
			have = 1;
			flag &= ~m_tcp_flag[i].v;
		}
	}

	if (!have) {
		printf(" NONE");
	}
}

static void print_tcp(void *data)
{
	match_tcp_t *m = (match_tcp_t *)data;

	if (m->src[0]) {
		print_port("sport", m->src, m->invert & INV_TCP_SRC);
	}

	if (m->dst[0]) {
		print_port("dport", m->dst, m->invert & INV_TCP_DST);
	}

	if (m->flag_mask || m->invert & INV_TCP_FLAG) {
		printf("%s --tcp-flags", m->invert & INV_TCP_FLAG ? " !" : "");
		print_tcp_flag(m->flag_mask);
		print_tcp_flag(m->flag);
	}
}

static void print_udp(void *data)
{
	match_udp_t *m = (match_udp_t *)data;

	if (m->src[0]) {
		print_port("sport", m->src, m->invert & INV_UDP_SRC);
	}

	if (m->dst[0]) {
		print_port("dport", m->dst, m->invert & INV_UDP_DST);
	}
}

static void print_state(void *data)
{
	match_state_t *m = (match_state_t *)data;
	int have = 0;

	printf("%s --state", m->invert ? " !" : "");

	for (int i = 0; m_state[i].k != NULL; i++) {
		if (m->state & m_state[i].v) {
			if (have) {
				printf(",");
			} else {
				printf(" ");
			}

			printf("%s", m_state[i].k);
			have = 1;
		}
	}
}

static int parse_port(const char *str, uint16_t *ports)
{
	uint32_t min = 0, max = 0;

	if (sscanf(str, "%u:%u", &min, &max) > 0) {
		if (0 < min && max <= 0xFFFF) {

			if (max > 0 && min > max) {
				return -1;
			}

			ports[0] = (uint16_t)min;
			ports[1] = (uint16_t)max;
		} else {
			return -1;
		}
	} else {
		return -1;
	}

	return 0;
}

static uint8_t parse_tcp_flag(const char *str)
{
	uint8_t flag = 0;
	int i = 0;
	const char *p = str;
	char f[8] = {0};

	while (sscanf(p, "%7[^,]", f) == 1) {
		i = map_int_get_v(f, m_tcp_flag);

		if (i != -1) {
			flag |= i;
		}

		p = strchr(p, ',');

		if (p) {
			p++;
		} else {
			break;
		}
	}

	return flag;
}

static uint8_t parse_state_state(const char *str)
{
	uint8_t state = 0;
	int i = 0;
	const char *p = str;
	char f[16] = {0};

	while (sscanf(p, "%15[^,]", f) == 1) {
		i = map_int_get_v(f, m_state);

		if (i != -1) {
			state |= i;
		}

		p = strchr(p, ',');

		if (p) {
			p++;
		} else {
			break;
		}
	}

	return state;
}

static int parse_tcp(void *data, char **str, int inv)
{
	match_tcp_t *m = (match_tcp_t *)data;
	int inv_type = 0;
	char *p = *str;
	char *q = p;
	char *r = NULL;
	q = strtok(NULL, " \t\n");

	if (q == NULL) {
		log_err("opt \"%s\" arg is null", p);
		goto err;
	}

	if (strcmp(p, "--sport") == 0) {
		if (parse_port(q, m->src) != 0) {
			goto err;
		}

		inv_type = INV_TCP_SRC;
	} else if (strcmp(p, "--dport") == 0) {
		if (parse_port(q, m->dst) != 0) {
			goto err;
		}

		inv_type = INV_TCP_DST;
	} else if (strcmp(p, "--tcp-flags") == 0) {
		r = strtok(NULL, " \t\n");

		if (r == NULL) {
			log_err("opt --tcp-flags requires two args\n");
			goto err;
		}

		m->flag = parse_tcp_flag(r);
		m->flag_mask = parse_tcp_flag(q);
		q = r;
		inv_type = INV_TCP_FLAG;
	} else if (strcmp(p, "--tcp-option") == 0) {
		//TODO:
	}

	if (inv && inv_type) {
		m->invert |= inv_type;
	}

	p = q;
	return 0;
err:
	return -1;
}

static int parse_udp(void *data, char **str, int inv)
{
	match_udp_t *m = (match_udp_t *)data;
	int inv_type = 0;

	char *p = *str;
	char *q = p;
	q = strtok(NULL, " \t\n");

	if (q == NULL) {
		log_err("opt \"%s\" arg is null", p);
		goto err;
	}

	if (strcmp(p, "--sport") == 0) {
		if (parse_port(q, m->src) != 0) {
			goto err;
		}

		inv_type = INV_UDP_SRC;
	} else if (strcmp(p, "--dport") == 0) {
		if (parse_port(q, m->dst) != 0) {
			goto err;
		}

		inv_type = INV_UDP_DST;
	}

	if (inv && inv_type) {
		m->invert |= inv_type;
	}

	p = q;
	return 0;
err:
	return -1;
}

static int parse_state(void *data, char **str, int inv)
{
	match_state_t *m = (match_state_t *)data;

	char *p = *str;
	char *q = p;
	q = strtok(NULL, " \t\n");

	if (q == NULL) {
		log_err("opt \"%s\" arg is null", p);
		goto err;
	}

	if (strcmp(p, "--state") == 0) {
		m->state = parse_state_state(q);
	}

	if (inv) {
		m->invert = 1;
	}

	p = q;
	return 0;
err:
	return -1;
}

static int match_port(uint16_t port, uint16_t *range)
{

	if (range[0] == 0) {
		return 1;
	}

	if (range[1] == 0 && range[0] != port) {
		return 0;
	}

	if (range[1] > 0 && (range[0] > port || port > range[1])) {
		return 0;
	}

	return 1;
}

static int match_tcp(void *data, packet_t *pkt)
{
	match_tcp_t *m = (match_tcp_t *)data;

	if (pkt->ip_proto != IPPROTO_TCP || pkt->tcp == NULL) {
		return 0;
	}

	if (INVF(m, INV_TCP_SRC, !match_port(ntohs(pkt->tcp->src), m->src))) {
		return 0;
	}

	if (INVF(m, INV_TCP_DST, !match_port(ntohs(pkt->tcp->dst), m->dst))) {
		return 0;
	}

	if (INVF(m, INV_TCP_FLAG, !((pkt->tcp->flag & m->flag_mask) == m->flag))) {
		return 0;
	}

	return 1;
}

static int match_udp(void *data, packet_t *pkt)
{
	match_udp_t *m = (match_udp_t *)data;

	if (pkt->ip_proto != IPPROTO_UDP || pkt->udp == NULL) {
		return 0;
	}

	if (INVF(m, INV_UDP_SRC, !match_port(ntohs(pkt->udp->src), m->src))) {
		return 0;
	}

	if (INVF(m, INV_UDP_DST, !match_port(ntohs(pkt->udp->dst), m->dst))) {
		return 0;
	}

	return 1;
}

static int match_state(void *data, packet_t *pkt)
{
	match_state_t *m = (match_state_t *)data;

	if (INVF(m, 1, !(pkt->state & m->state))) {
		return 0;
	}

	return 1;
}

static void print_reject(void *data)
{
	target_reject_t *m = (target_reject_t *)data;
	printf(" --reject-with %s", m->with);
}

static int parse_reject(void *data, char **str)
{
	target_reject_t *m = (target_reject_t *)data;

	char *p = *str;
	char *q = NULL;

	p = strtok(NULL, " \t\n");

	if (p == NULL) {
		_strlcpy(m->with, "icmp-port-unreachable", sizeof(m->with));
		return 0;
	}

	q = p;
	q = strtok(NULL, " \t\n");

	if (q == NULL) {
		log_err("opt \"%s\" arg is null", p);
		goto err;
	}

	if (strcmp(p, "--reject-with") == 0) {
		_strlcpy(m->with, q, sizeof(m->with));
	}

	p = q;
	return 0;
err:
	return -1;
}

static int target_reject(void *data, packet_t *pkt)
{
	return TARGET_DROP;
}

ip_match_map_t g_match_map[] = {
	{"tcp"		, sizeof(match_tcp_t)	, print_tcp		, parse_tcp		, match_tcp},
	{"udp"		, sizeof(match_udp_t)	, print_udp		, parse_udp		, match_udp},
	{"state"	, sizeof(match_state_t)	, print_state	, parse_state	, match_state},
	{"icmp"		, 0, NULL, NULL, NULL},
	{"mark"		, 0, NULL, NULL, NULL},
	{"tcpmss"	, 0, NULL, NULL, NULL},
	{"limit"	, 0, NULL, NULL, NULL},
	{NULL		, 0, NULL, NULL, NULL},
};


ip_target_map_t g_target_map[] = {
	{"REJECT"		, sizeof(target_reject_t)	, print_reject	, parse_reject	, target_reject},
	{"SNAT"			, 0, NULL, NULL, NULL},
	{"DNAT"			, 0, NULL, NULL, NULL},
	{"MASQUERADE"	, 0, NULL, NULL, NULL},
	{"TCPMSS"		, 0, NULL, NULL, NULL},
	{NULL			, 0, NULL, NULL, NULL},
};

