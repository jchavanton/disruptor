
#ifndef SCENARIO_FILE_H
#define SCENARIO_FILE_H

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdbool.h>
#include "../ezxml/ezxml.h"
#include "stream.h"
#include <stdint.h>


static const int32_t q_max_pkt = 10000; // max packet queue size for the scenario

enum scenario_action_e {
	A_NONE,
	A_JITTER,
	A_LOSS,
	A_BURST_LOSS,
	A_LOSS_RTCP
};

enum scenario_problem_state_e {
	PB_NONE,
	PB_INIT,
	PB_ACTIVE,
	PB_STOP
};

typedef struct disrupt_packet_s {
	int16_t size;
	uint8_t pt;
	int32_t pkt_id;
	bool rtp;
	bool rtcp;
	uint32_t ssrc;
	uint16_t seq;
	uint32_t ts;
	struct disrupt_stream_s *stream;
} disrupt_packet_t;

#define JITTER_OUT_OF_ORDER (1 << 0)
#define JITTER_FIXED_BURST_LEN (1 << 1)
#define JITTER_FIXED_BURST_INTERVAL (1 << 2)


struct scenario_s {
	ezxml_t scenario_xml;
	ezxml_t scenario_period_xml;
	enum scenario_problem_state_e pb_state; // state of the problem taking place
	int32_t pb_pkt_pos;			// current seq id in the problem
	int32_t pb_pkt_start;			// seq id when starting a problem
	int32_t pb_pkt_stop;			// seq id when stoping a problem
	int32_t pb_pkt_max;
	int16_t init_interval_occurence;	// chance of the problem taking place for each packet
	int16_t init_max_burst;			// max size of packet burst
	int32_t *queue_delay;			// packet currently delayed are queued here
	int32_t *queue_seq;			// sequence number of packet in the queue (when using RTP in clear)
	struct nfq_q_handle *qh;		// struct nfq_q_handle *qh
	int (*scenario_action)(struct scenario_s * s, struct disrupt_packet_s * p);
	int32_t period_pkt_count;		// packet count during this period
	enum scenario_action_e action;
	int16_t period_start;
	int16_t period_duration;
	int32_t period_bytes_received;
	int32_t period_pkt_loss;
	int32_t period_pkt_delayed;
	char * filename;
	int32_t params;
};

struct disrupt_socket_s {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t src_ip;
	uint32_t dst_ip;
};

struct disrupt_stream_s {
	struct disrupt_socket_s socket;
	struct scenario_s scenario;
	struct timeval start;
	int32_t id;
	struct disrupt_stream_s *previous;
	struct disrupt_stream_s *next;
};

struct disrupt_stream_s * stream_get(struct disrupt_stream_s * stream_head, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port);
struct disrupt_stream_s * stream_add(struct disrupt_stream_s * stream_head, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port);

/* initialize the scenario */
void scenario_init(struct scenario_s *);
void scenario_init_xml(struct disrupt_stream_s * stream);
bool scenario_read_period_xml(struct scenario_s * s, int32_t stream_duration);

/* set the netfilter queue handle in the scenario */
void scenario_set_queue_handle(struct scenario_s * s, struct nfq_q_handle *qh);

/* run scenario on this packet 
 * return false if the packet is stored in the scenario telling the core to return
 * return true if the packet is not touched by the scenario 
 * */
int scenario_check_pkt(struct scenario_s * s, struct disrupt_packet_s * packet, int32_t stream_duration, int32_t stream_id);

/*
 * scenario section
 * */

int scenario_action_none(struct scenario_s * s, struct disrupt_packet_s * packet);
int scenario_action_jitter(struct scenario_s * s, struct disrupt_packet_s * packet);
int scenario_action_loss(struct scenario_s * s, struct disrupt_packet_s * packet);
int scenario_action_burst_loss(struct scenario_s * s, struct disrupt_packet_s * packet);
int scenario_action_loss_rtcp(struct scenario_s * s, struct disrupt_packet_s * packet);

#endif
