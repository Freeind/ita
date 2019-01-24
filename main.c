#include "common.h"
#include "packet.h"
#include "iptables.h"

int main(int argc, char **argv)
{
	char *p = "../test.txt";

	if (argc == 2) {
		p = argv[1];
	}

	ip_tables_t *ipts = parse_tables(p);
	print_tables(ipts);

	packet_t *pkts[2];

	pkts[0] = new_tcp_pkt("192.168.1.100", "192.168.1.101", 12345, 80, TCP_SYN);
	pkts[1] = new_tcp_pkt("192.168.1.101", "192.168.1.100", 12345, 80, TCP_SYN);

	//pkts[0] = new_udp_pkt("192.168.1.100", "192.168.1.101", 12345, 80);
	//pkts[1] = new_udp_pkt("192.168.1.101", "192.168.1.100", 12345, 80);

	for (int i = 0; i < 2; i++) {

		pkt_set_iface(pkts[i], "ens33", NULL);
		pkt_set_state(pkts[i], STATE_NEW);
		print_pkt(pkts[i]);
		printf("match result\t: %s\n", match_tables(ipts, pkts[i], NULL) ? "ACCEPT" : "DROP");
		free_pkt(pkts[i]);
	}


	free_tables(ipts);
	return 0;
}
