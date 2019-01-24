#ifndef IPTABLES_H
#define IPTABLES_H

#include "packet.h"
#include "list.h"

enum table_type {
	TABLE_RAW,
	TABLE_MANGLE,
	TABLE_NAT,
	TABLE_FILTER,
	TABLE_NONE,

};

enum chain_type {
	CHAIN_PREROUTING,
	CHAIN_INPUT,
	CHAIN_FORWARD,
	CHAIN_OUTPUT,
	CHAIN_POSTROUTING,
	CHAIN_NONE,

};

enum target_type {
	TARGET_DROP,
	TARGET_ACCEPT,
	TARGET_QUEUE,
	TARGET_RETURN,
	TARGET_EXT,
	TARGET_CHILD,
	TARGET_NONE,
};

enum INV_TYPE {
	INV_SRC   = 0x01,
	INV_DST   = 0x02,
	INV_IN    = 0x04,
	INV_OUT   = 0x08,
	INV_PROTO = 0x10,
	INV_FRAG  = 0x20,
};

#define TABLE_MAX	TABLE_NONE
#define CHAIN_MAX	CHAIN_NONE

#define MAX_CHAIN_NAME_LEN	32


typedef struct ip_opt			ip_opt_t;
typedef struct ip_match_map		ip_match_map_t;
typedef struct ip_target_map	ip_target_map_t;
typedef struct ip_match			ip_match_t;
typedef struct ip_target		ip_target_t;
typedef struct ip_rule			ip_rule_t;
typedef struct ip_chain			ip_chain_t;
typedef struct ip_table			ip_table_t;
typedef struct ip_tables		ip_tables_t;

struct ip_target_map {
	const char *name;
	size_t data_size;
	void (*func_print)(void *data);
	int (*func_parse)(void *data, char **str);
	int (*func_target)(void *data, packet_t *pkt);
};

struct ip_match_map {
	const char *name;
	size_t data_size;
	void (*func_print)(void *data);
	int (*func_parse)(void *data, char **str, int inv);
	int (*func_match)(void *data, packet_t *pkt);
};

struct ip_target {
	ip_target_map_t *map;
	void *data;
};

struct ip_match {
	ip_match_map_t *map;
	void *data;
	struct list_head list;
};

struct ip_rule {
	ip_chain_t *chain;
	struct in_addr src;
	struct in_addr dst;
	struct in_addr smsk;
	struct in_addr dmsk;
	char in[MAX_IFACE_LEN];
	char out[MAX_IFACE_LEN];
	uint8_t proto;
	uint8_t frag;
	uint8_t invert;
	uint8_t go;
	int target;
	ip_target_t *target_ext;
	ip_chain_t *target_child;
	struct list_head list;
	struct list_head matchs;
};

struct ip_chain {
	char name[MAX_CHAIN_NAME_LEN];
	int policy;
	struct list_head list;
	struct list_head rules;
};

struct ip_table {
	ip_chain_t *chains[CHAIN_MAX];
	struct list_head child_chains;
};

struct ip_tables {
	ip_table_t *tables[TABLE_MAX];
};

struct ip_opt {
	uint8_t list[TABLE_MAX][CHAIN_MAX];
};

extern ip_match_map_t g_match_map[];
extern ip_target_map_t g_target_map[];

#define INVF(ipr, flag, bool)	((bool) ^ !!((ipr)->invert & (flag)))

void free_tables(ip_tables_t *ipts);
void print_tables(ip_tables_t *ipts);
ip_tables_t *parse_tables(const char *path);
int match_tables(ip_tables_t *ipts, packet_t *pkt, ip_opt_t *opt);

#endif /* IPTABLES_H */
