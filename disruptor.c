#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "include/rtp.h"
#include "include/scenario.h"

/* packet, scenario and logging */

scenario_t * scenario;
uint16_t scenario_id = 0;

typedef struct disrupt_nfq_s {
	struct nfq_q_handle *qh;	/* Netfilter Queue handle */
	struct nfq_handle *h;		/* Netfilter handle */
	int32_t fd;			/* Netfilter Queue file descriptor */
	int32_t recv_pkt_sz;		/* received packet size */
	int32_t qid;			/* Netfilter Queue ID */
	char buf[4096];
} disrupt_nfq_t;

disrupt_nfq_t d_nfq; /* Disruptor Netfilter */

int disrupt_tcp_packet_analisys(unsigned char * payload_transport, int32_t pkt_id){
	struct tcphdr * tcp_header = (struct tcphdr *) payload_transport;
	unsigned char * payload_app = payload_transport + (tcp_header->doff * 4); /* Data Offset: 4 bits, The number of 32 bit words in the TCP Header. */

	/* SIP DETECTION */
	if( strncmp( payload_app, "SIP/2.0 ", 8) == 0 ){
		printf("SIP RESPONSE[%c%c%c]\n", payload_app[8], payload_app[9], payload_app[10]);
		return 1;
	}

	char *sip_found = strstr(payload_app,"sip:");
	if(!sip_found) {
		printf("TCP unknown\n");
		return 1;
	}
	int16_t sip_method_len = (unsigned char *)sip_found-payload_app - 1;
	if(sip_method_len > 30){
		printf("TCP SIP method not found...\n");
		return 1;
	}
	char sip_method[128];
	strncpy(sip_method, payload_app, sip_method_len);
	sip_method[sip_method_len] ='\0';
	if( sip_method ){
		printf("SIP REQUEST[%s]\n", sip_method);
	}
	return 1;
}

int disrupt_udp_packet_analisys(char * payload_transport, int32_t pkt_id){
	struct udphdr * udp_header = (struct udphdr *) payload_transport;
	unsigned char * payload_app = payload_transport + sizeof(struct udphdr);

	/* RTP DETECTION */
	rtp_msg_t * rtp_msg = (rtp_msg_t *) payload_app;
	if(rtp_msg->header.version == 2){
		uint16_t seq = ntohs(rtp_msg->header.seq);
		uint32_t ssrc = ntohl(rtp_msg->header.ssrc);
		uint32_t ts = ntohl(rtp_msg->header.ts);
		if(seq%100 == 0){
			printf("RTP version[%d] seq[%d] ts[%d] ssrc[%d]\n", rtp_msg->header.version, seq, ts, ssrc);
		}
		/* check scenario : if there is and active scenario is will decide what to do with the packet */
		return scenario_check_pkt(scenario, seq, pkt_id);
	}

	return 1;
}

int disrupt_ip_packet_analisys(struct nfq_data *nfa, int32_t pkt_id) {
	char *payload_data;
	uint16_t payload_len = nfq_get_payload(nfa, &payload_data);
	struct iphdr * ip_hdr = (struct iphdr *)(payload_data);

	/* Detect transport protocol */
	if ( ip_hdr->protocol == IPPROTO_TCP ) {
		return disrupt_tcp_packet_analisys(payload_data + sizeof(struct iphdr), pkt_id);
	} else if ( ip_hdr->protocol == IPPROTO_UDP ) {
		return disrupt_udp_packet_analisys(payload_data + sizeof(struct iphdr), pkt_id);
	}
}

/* Definition of callback function */
static int disruptor_nfq_call_back(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	scenario_t * scenario = (scenario_t *) data;
	int16_t verdict = 1;
	int32_t pkt_id;
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
 		pkt_id = ntohl(ph->packet_id);
	}
	verdict = disrupt_ip_packet_analisys(nfa, pkt_id); /* NF_ACCEPT:1 - NF_DROP:0 */
	return nfq_set_verdict(qh, pkt_id, verdict, 0, NULL); /* Verdict packet */
}

void disruptor_nfq_init() {
	/* Library initialisation */
	d_nfq.h = nfq_open();
	if (!d_nfq.h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}
	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(d_nfq.h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}
	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(d_nfq.h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}
}

void disruptor_nfq_bind() {
	/* Bind the program to a specific queue */
	if(!d_nfq.qid){
		d_nfq.qid=10; /* Default queue id */
	}
	printf("binding this socket to queue [%d]\n", d_nfq.qid);
	d_nfq.qh = nfq_create_queue(d_nfq.h, d_nfq.qid, &disruptor_nfq_call_back, (void *)scenario);
	if (!d_nfq.qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(d_nfq.qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}
}

void disruptor_nfq_handle_traffic() {
	/*handle the incoming packets*/

	d_nfq.fd = nfq_fd(d_nfq.h);
	while ((d_nfq.recv_pkt_sz = recv(d_nfq.fd, d_nfq.buf, sizeof(d_nfq.buf), 0)) >= 0) {
			// printf("packet received: size[%d]\n", d_nfq.recv_pkt_sz);
			nfq_handle_packet(d_nfq.h, d_nfq.buf, d_nfq.recv_pkt_sz); /* send packet to callback */
	}
}

void disruptor_command_line_options(int argc, char **argv){
	int opt;
	while ((opt = getopt(argc, argv, "hq:s:")) != -1) {
		switch (opt) {
			case 'q':
				d_nfq.qid = atoi(optarg);
				printf("disruptor_command_line_options: nfq queue id[%d]\n", d_nfq.qid);
				break;
			case 's':
				scenario_id = atoi(optarg);
				printf("disruptor_command_line_options: scenario id[%d]\n", scenario_id);
				break;
			case 'h':
				printf("-s scenario ID (check scenario.c/scenario.h)\n");
				printf("-q nfq queue id\n");
				exit(1);
				break;
			default:
				break;
		}
	}
}

void main(int argc, char **argv){
	disruptor_command_line_options(argc, argv);
	scenario = scenario_init(scenario_id);
	disruptor_nfq_init();
	disruptor_nfq_bind();
	scenario_set_queue_handle(scenario, d_nfq.qh);
	disruptor_nfq_handle_traffic();
}
