#include "iptables.h"

map_int_t m_table[] = {
	{"filter"	, TABLE_FILTER},
	{"raw"		, TABLE_RAW},
	{"nat"		, TABLE_NAT},
	{"mangle"	, TABLE_MANGLE},
	{NULL		, TABLE_NONE},
};

map_int_t m_chain[] = {
	{"PREROUTING"	, CHAIN_PREROUTING},
	{"INPUT"		, CHAIN_INPUT},
	{"FORWARD"		, CHAIN_FORWARD},
	{"OUTPUT"		, CHAIN_OUTPUT},
	{"POSTROUTING"	, CHAIN_POSTROUTING},
	{NULL			, CHAIN_NONE},
};

map_int_t m_target[] = {
	{"DROP"		, TARGET_DROP},
	{"ACCEPT"	, TARGET_ACCEPT},
	{"QUEUE"	, TARGET_QUEUE},
	{"RETURN"	, TARGET_RETURN},
	{NULL		, TARGET_NONE},
};

map_int_t m_proto[] = {
	{"tcp"		, IPPROTO_TCP},
	{"sctp"		, IPPROTO_SCTP},
	{"udp"		, IPPROTO_UDP},
	{"udplite"	, IPPROTO_UDPLITE},
	{"icmp"		, IPPROTO_ICMP},
	{"icmpv6"	, IPPROTO_ICMPV6},
	{"ipv6-icmp", IPPROTO_ICMPV6},
	{"esp"		, IPPROTO_ESP},
	{"ah"		, IPPROTO_AH},
	{"ipv6-mh"	, IPPROTO_MH},
	{"mh"		, IPPROTO_MH},
	{"all"		, 0},
	{NULL		, -1},
};

ip_opt_t default_opt = {
	.list = {
		{1, 1, 0, 0, 0 },
		{1, 1, 0, 0, 0 },
		{1, 1, 0, 0, 0 },
		{1, 1, 0, 0, 0 },},
};

int match_chain(ip_chain_t *ipc, packet_t *pkt);

static void free_match(ip_match_t *ipm)
{
	if (ipm == NULL) {
		return;
	}

	list_del(&ipm->list);

	_free(ipm->data);
	_free(ipm);
}

static void free_rule(ip_rule_t *ipr)
{
	if (ipr == NULL) {
		return;
	}

	list_del(&ipr->list);

	ip_match_t *p = NULL, *q = NULL;

	list_for_each_entry_safe(p, q, &ipr->matchs, list) {
		free_match(p);
	}

	if (ipr->target_ext) {
		_free(ipr->target_ext->data);
		_free(ipr->target_ext);
	}

	_free(ipr);
}

static void free_chain(ip_chain_t *ipc)
{
	if (ipc == NULL) {
		return;
	}

	list_del(&ipc->list);

	ip_rule_t *p = NULL, *q = NULL;

	list_for_each_entry_safe(p, q, &ipc->rules, list) {
		free_rule(p);
	}


	_free(ipc);
}

static void free_table(ip_table_t *ipt)
{
	if (ipt == NULL) {
		return;
	}

	for (int i = 0; i < CHAIN_MAX; i++) {
		free_chain(ipt->chains[i]);
		ipt->chains[i] = NULL;
	}

	ip_chain_t *p = NULL, *q = NULL;

	list_for_each_entry_safe(p, q, &ipt->child_chains, list) {
		free_chain(p);
	}

	_free(ipt);
}

void free_tables(ip_tables_t *ipts)
{
	if (ipts == NULL) {
		return;
	}

	for (int i = 0; i < TABLE_MAX; i++) {
		free_table(ipts->tables[i]);
		ipts->tables[i] = NULL;
	}

	_free(ipts);
}

static void print_rule(ip_rule_t *ipr)
{
	printf("-A %s", ipr->chain->name);

	if (ipr->src.s_addr || ipr->smsk.s_addr) {
		printf("%s -%s "IP_FORMAT, ipr->invert & INV_SRC ? " !" : "", "s", IP_PRINT(ipr->src.s_addr));

		if (ipr->smsk.s_addr) {
			printf("/"IP_FORMAT, IP_PRINT(ipr->smsk.s_addr));
		}
	}

	if (ipr->dst.s_addr || ipr->dmsk.s_addr) {
		printf("%s -%s "IP_FORMAT, ipr->invert & INV_DST ? " !" : "", "d", IP_PRINT(ipr->dst.s_addr));

		if (ipr->dmsk.s_addr) {
			printf("/"IP_FORMAT, IP_PRINT(ipr->dmsk.s_addr));
		}
	}

	if (ipr->in[0] != '\0') {
		printf("%s -%s %s", ipr->invert & INV_IN ? " !" : "", "i", ipr->in);
	}

	if (ipr->out[0] != '\0') {
		printf("%s -%s %s", ipr->invert & INV_OUT ? " !" : "", "o", ipr->out);
	}

	if (ipr->proto) {
		printf("%s -%s", ipr->invert & INV_PROTO ? " !" : "", "p");
		const char *p = map_int_get_k(ipr->proto, m_proto);

		if (p) {
			printf(" %s", p);
		} else {
			printf(" %d", ipr->proto);
		}
	}

	if (ipr->frag) {
		printf("%s -%s", ipr->invert & INV_FRAG ? " !" : "", "f");
	}

	ip_match_t *ipm = NULL;
	list_for_each_entry(ipm, &ipr->matchs, list) {
		if (ipm->map) {
			printf(" -m %s", ipm->map->name);

			if (ipm->map->func_print) {
				ipm->map->func_print(ipm->data);
			}
		}
	}

	if (ipr->target != TARGET_NONE) {

		if (ipr->go) {
			printf(" -g %s", ipr->target_child->name);
		} else {
			printf(" -j");

			if (ipr->target == TARGET_EXT && ipr->target_ext && ipr->target_ext->map) {
				printf(" %s", ipr->target_ext->map->name);

				if (ipr->target_ext->map->func_print) {
					ipr->target_ext->map->func_print(ipr->target_ext->data);
				}
			} else if (ipr->target == TARGET_CHILD && ipr->target_child) {
				printf(" %s", ipr->target_child->name);
			} else {
				printf(" %s", map_int_get_k(ipr->target, m_target));
			}
		}
	}

	printf("\n");
}

static void print_chain(ip_chain_t *ipc)
{
	printf("\tChain [%s]", ipc->name);

	if (ipc->policy != TARGET_NONE) {
		printf(" (policy %s)\n", map_int_get_k(ipc->policy, m_target));
	} else {
		printf("\n");
	}

	ip_rule_t *p = NULL;
	list_for_each_entry(p, &ipc->rules, list) {
		printf("\t\t");
		print_rule(p);
	}
	printf("\n");
}

static void print_table(ip_table_t *ipt)
{
	for (int i = 0; i < CHAIN_MAX; i++) {
		if (ipt->chains[i] != NULL) {
			print_chain(ipt->chains[i]);
		}
	}

	ip_chain_t *p = NULL;
	list_for_each_entry(p, &ipt->child_chains, list) {
		print_chain(p);
	}
}

void print_tables(ip_tables_t *ipts)
{
	if (ipts == NULL) {
		return;
	}

	for (int i = 0; i < TABLE_MAX; i++) {
		if (ipts->tables[i] != NULL) {
			printf("==================================================\n");
			printf("Table %s\n", map_int_get_k(i, m_table));
			print_table(ipts->tables[i]);
		}
	}

	printf("==================================================\n");
}

static ip_chain_t *find_chain(const char *name, ip_table_t *ipt)
{
	int c = map_int_get_v(name, m_chain);
	ip_chain_t *p = NULL;

	if (c != CHAIN_NONE && ipt->chains[c] != NULL) {
		return ipt->chains[c];
	}

	list_for_each_entry(p, &ipt->child_chains, list) {
		if (strcmp(name, p->name) == 0) {
			return p;
		}
	}

	return NULL;
}

static int parse_ip(char *str, struct in_addr *addr, struct in_addr *mask)
{
	int prefix = -1;
	char ip[16] = {0};

	if (sscanf(str, "%15[^/]/%d", ip, &prefix) > 0) {

		if (inet_pton(AF_INET, ip, addr) != 1) {
			log_err("inet_pton failed: %s\n", ip);
			return -1;
		}

		if (prefix == 0) {
			mask->s_addr = 0;
		} else if (prefix > 0 && prefix <= 32) {
			mask->s_addr = htonl(0xFFFFFFFF << (32 - prefix));
		} else if (prefix == -1) {
			mask->s_addr = 0xFFFFFFFF;
		} else {
			log_err("mask \"%d\" is invalid\n", prefix);
			return -1;
		}
	} else {
		log_err("ip \"%s\" is invalid\n", str);
		return -1;
	}

	return 0;
}

static int parse_proto(char *str, uint8_t *proto)
{
	int p = map_int_get_v(str, m_proto);
	if (p == -1) {
		p = strtol(str, NULL, 10);
	}

	if (p < 0 || p > 255) {
		return -1;
	}

	*proto = p;
	return 0;
}

static ip_match_t *parse_match(char *str, ip_rule_t *ipr)
{
	ip_match_t *ipm = NULL;

	for (int i = 0; g_match_map[i].name != NULL; i++) {
		if (strcmp(str, g_match_map[i].name) == 0) {
			ipm = _new(ip_match_t);
			ipm->map = &g_match_map[i];
			ipm->data = new(g_match_map[i].data_size);
			list_add_tail(&ipm->list, &ipr->matchs);
			break;
		}
	}

	return ipm;
}

static int parse_target(char *str, ip_rule_t *ipr, ip_table_t *ipt)
{
	ipr->target = map_int_get_v(str, m_target);

	if (ipr->target == TARGET_NONE) {
		for (int i = 0; g_target_map[i].name != NULL; i++) {
			if (strcmp(str, g_target_map[i].name) == 0) {
				ipr->target_ext = _new(ip_target_t);
				ipr->target_ext->map = &g_target_map[i];
				ipr->target_ext->data = new(g_target_map[i].data_size);
				ipr->target = TARGET_EXT;
				break;
			}
		}
	}

	if (ipr->target == TARGET_NONE) {
		if ((ipr->target_child = find_chain(str, ipt)) != NULL) {
			ipr->target = TARGET_CHILD;
		}
	}

	if (ipr->target == TARGET_NONE) {
		return -1;
	}

	return 0;
}

static ip_rule_t *parse_rule(char *str, ip_table_t *ipt)
{
	char *p = NULL, *q = NULL;
	int invert = 0, inv_type = 0;
	ip_match_t *ipm = NULL;
	ip_rule_t *ipr = _new(ip_rule_t);

	ipr->target = TARGET_NONE;
	INIT_LIST_HEAD(&ipr->list);
	INIT_LIST_HEAD(&ipr->matchs);

	for (p = strtok(str, " \t\n"); p; p = strtok(NULL, " \t\n")) {
		q = p;

		if (p[0] == '!' && p[1] == '\0') {
			invert = 1;
		} else if (p[0] == '-') {

			if (p[1] != 'f' && p[1] != '-') {

				if ((q = strtok(NULL, " \t\n")) == NULL) {
					goto err;
				}
			}

			switch (p[1]) {
				case 'A' :
					ipr->chain = find_chain(q, ipt);
					if (ipr->chain) {
						list_add_tail(&ipr->list, &ipr->chain->rules);
					} else {
						goto err;
					}
					break;

				case 's' :
					if (parse_ip(q, &ipr->src, &ipr->smsk) != 0) {
						goto err;
					}
					inv_type = INV_SRC;
					break;

				case 'd' :
					if (parse_ip(q, &ipr->dst, &ipr->dmsk) != 0) {
						goto err;
					}
					inv_type = INV_DST;
					break;

				case 'i' :
					if (strlen(q) < MAX_IFACE_LEN) {
						_strlcpy(ipr->in, q, sizeof(ipr->in));
					} else {
						goto err;
					}
					inv_type = INV_IN;
					break;

				case 'o' :
					if (strlen(q) < MAX_IFACE_LEN) {
						_strlcpy(ipr->out, q, sizeof(ipr->out));
					} else {
						goto err;
					}
					inv_type = INV_OUT;
					break;

				case 'p' :
					if (parse_proto(q, &ipr->proto) != 0) {
						goto err;
					}
					inv_type = INV_PROTO;
					break;

				case 'f' :
					ipr->frag = 1;
					inv_type = INV_FRAG;
					break;

				case 'j' :
					if (parse_target(q, ipr, ipt) != 0) {
						goto err;
					}

					if (ipr->target == TARGET_EXT && ipr->target_ext &&
						ipr->target_ext->map && ipr->target_ext->map->func_parse) {
						if (ipr->target_ext->map->func_parse(ipr->target_ext->data, &q) != 0) {
							goto err;
						}
					}

					break;

				case 'g' :

					if ((ipr->target_child = find_chain(q, ipt)) != NULL) {
						ipr->target = TARGET_CHILD;
						ipr->go = 1;
					} else {
						goto err;
					}

					break;

				case 'm' :
					ipm = parse_match(q, ipr);

					if (ipm == NULL) {
						goto err;
					}

					break;

				case '-' :
					if (ipm && ipm->map && ipm->map->func_parse) {
						if (ipm->map->func_parse(ipm->data, &q, invert) != 0) {
							goto err;
						}
					}

					break;

				default :
					break;
			}

			if (invert && inv_type && ipr) {
				ipr->invert |= inv_type;
			}

			inv_type = 0;
			invert = 0;

		}

		p = q;
	}

	return ipr;
err:
	log_err("rule \"%s\" is invaild\n", p);
	free_rule(ipr);
	return NULL;
}

static ip_chain_t *parse_chain(char *str, ip_table_t *ipt)
{
	char name[MAX_CHAIN_NAME_LEN] = {0}, policy[16] = {0};
	int type = CHAIN_NONE;
	ip_chain_t *ipc = NULL;

	if (sscanf(str, ":%31s %15s", name, policy) == 2) {

		ipc = _new(ip_chain_t);

		_strlcpy(ipc->name, name, sizeof(ipc->name));
		ipc->policy = map_int_get_v(policy, m_target);

		INIT_LIST_HEAD(&ipc->list);
		INIT_LIST_HEAD(&ipc->rules);

		type = map_int_get_v(ipc->name, m_chain);

		if (type == CHAIN_NONE) {
			list_add_tail(&ipc->list, &ipt->child_chains);
		} else {
			ipt->chains[type] = ipc;
		}
	}

	return ipc;
}

static ip_table_t *parse_table(char *str, ip_tables_t *ipts)
{
	char name[16] = {0};
	int type = TABLE_NONE;
	ip_table_t *ipt = NULL;

	if (sscanf(str, "*%15s", name) == 1) {
		type = map_int_get_v(name, m_table);

		if (type == TABLE_NONE) {
			log_err("table name \"%s\" invalid\n", name);
			return NULL;
		}

		ipt = _new(ip_table_t);
		INIT_LIST_HEAD(&ipt->child_chains);
		ipts->tables[type] = ipt;
	}

	return ipt;
}

ip_tables_t *parse_tables(const char *path)
{
	FILE *fp = fopen(path, "r");
	char line[1024] = {0};
	int line_num = 0, in_table = 0;

	ip_tables_t *ipts = NULL;
	ip_table_t *ipt = NULL;

	if (fp == NULL) {
		log_err("open file \"%s\" failed: %m\n", path);
		return NULL;
	}

	ipts = _new(ip_tables_t);

	while (fgets(line, sizeof(line), fp) != NULL) {
		line_num++;

		if (line[0] == '#' || line[0] == '\n') {
			continue;

		} else if (strcmp(line, "COMMIT\n") == 0 && in_table) {
			in_table = 0;

		} else if (line[0] == '*' && !in_table) {
			if ((ipt = parse_table(line, ipts)) == NULL) {
				log_err("line: %d parse table failed\n", line_num);
			} else {
				in_table = 1;
			}

		} else if (line[0] == ':' && in_table) {
			if (parse_chain(line, ipt) == NULL) {
				log_err("line: %d parse chain failed\n", line_num);
			}

		} else if (in_table) {
			if (parse_rule(line, ipt) == NULL) {
				log_err("line: %d parse rule failed\n", line_num);
			}
		}
	}

	return ipts;
}

int match_iface(const char *rule, const char *iface)
{
	if (rule[0] == '\0') {
		return 1;
	}

	if (iface == NULL) {
		return 0;
	}

	for (int i = 0; i < MAX_IFACE_LEN; i++) {

		if (rule[i] == '+') {
			break;
		}

		if (rule[i] != iface[i]) {
			return 0;
		}

		if (rule[i] == '\0') {
			break;
		}
	}

	return 1;
}

int match_ip(ip_rule_t *ipr, packet_t *pkt)
{
	if (pkt->eth_type != ETH_IP) {
		return 0;
	}

	if (INVF(ipr, INV_SRC, (pkt->ip->src & ipr->smsk.s_addr) != ipr->src.s_addr) ||
		INVF(ipr, INV_DST, (pkt->ip->dst & ipr->dmsk.s_addr) != ipr->dst.s_addr)) {
		return 0;
	}

	if (INVF(ipr, INV_IN, !match_iface(ipr->in, pkt->iface.in))) {
		return 0;
	}

	if (INVF(ipr, INV_OUT, !match_iface(ipr->out, pkt->iface.out))) {
		return 0;
	}

	if (ipr->proto && INVF(ipr, INV_PROTO, pkt->ip_proto != ipr->proto)) {
		return 0;
	}

	if (INVF(ipr, INV_FRAG, !IP_FRAGOFF(pkt->ip) && ipr->frag)) {
		return 0;
	}

	return 1;
}

int match_rule(ip_rule_t *ipr, packet_t *pkt)
{
	static int8_t depth = 0;
	if (!match_ip(ipr, pkt)) {
		return TARGET_NONE;
	}

	ip_match_t *ipm = NULL;
	list_for_each_entry(ipm, &ipr->matchs, list) {
		if (ipm->map && ipm->map->func_match) {
			if (!(ipm->map->func_match(ipm->data, pkt))) {
				return TARGET_NONE;
			}
		}
	}

	printf("%s	: ", __FUNCTION__);
	for (int i = depth; i > 0; printf("    "), i--);
	print_rule(ipr);

	if (ipr->target == TARGET_EXT && ipr->target_ext &&
		ipr->target_ext->map && ipr->target_ext->map->func_target) {
		return ipr->target_ext->map->func_target(ipr->target_ext->data, pkt);
	}

	if (ipr->target == TARGET_CHILD && ipr->target_child) {
		depth++;
		int target = match_chain(ipr->target_child, pkt);
		depth--;
		if (target == TARGET_NONE && ipr->go) {
			return TARGET_RETURN;
		} else {
			return target;
		}
	}

	return ipr->target;
}

int match_chain(ip_chain_t *ipc, packet_t *pkt)
{
	int target = TARGET_NONE;
	ip_rule_t *ipr = NULL;

	list_for_each_entry(ipr, &ipc->rules, list) {
		target = match_rule(ipr, pkt);

		if (target == TARGET_RETURN) {
			return ipc->policy;
		}

		if (target == TARGET_DROP ||
			target == TARGET_ACCEPT ||
			target == TARGET_QUEUE) {
			return target;
		}
	}

	return ipc->policy;
}

int match_tables(ip_tables_t *ipts, packet_t *pkt, ip_opt_t *opt)
{
	if (ipts == NULL || pkt == NULL) {
		log_err("%s ipts or pkt is null\n", __FUNCTION__);
		return TARGET_NONE;
	}

	if (opt == NULL) {
		opt = &default_opt;
	}

	int target = TARGET_NONE;

	for (int i = 0; i < CHAIN_MAX; i++) {

		for (int j = 0; j < TABLE_MAX; j++) {

			if (opt->list[j][i] == 0 || ipts->tables[j] == NULL || ipts->tables[j]->chains[i] == NULL) {
				continue;
			}

			target = match_chain(ipts->tables[j]->chains[i], pkt);

			if (target == TARGET_DROP) {
				return TARGET_DROP;
			}
		}
	}
	return TARGET_ACCEPT;
}

