#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdbool.h>

#include "stream.h"

#ifndef SCENARIO_FILE_H
#define SCENARIO_FILE_H

static const int32_t q_max_pkt = 10000; // max packet queue size for the scenario

enum scenario_action_e {
	NONE,
	JITTER
};

enum scenario_problem_state_e {
	PB_NONE,
	PB_INIT,
	PB_ACTIVE,
	PB_STOP
};

typedef struct scenario_s {
	enum scenario_problem_state_e pb_state; // state of the problem taking place
	int32_t pb_pkt_pos;			// current seq id in the problem
	int32_t pb_pkt_start;			// seq id when starting a problem
	int32_t pb_pkt_max;
	int16_t init_random_occurence;		// chance of the problem taking place for each packet
	int16_t init_max_burst;			// max size of packet burst
	//unsigned int *queue_packet_ids_delay;
	int32_t *queue_delay;			// packet currently delayed are queued here
	int32_t *queue_seq;			// sequence number of packet in the queue (when using RTP in clear)
	struct nfq_q_handle *qh; 	// struct nfq_q_handle *qh
	bool (*scenario_action)(struct scenario_s * s, int seq, u_int32_t pkt_id); 
	//bool (*scenario_fuction)(struct scenario_s * s, int seq, u_int32_t pkt_id); 

	//int scf_pkt_count;     // scenario variable that can be used to count packets       
	int32_t period_pkt_count; // packet count during this period
	//int counter1;		// generic purpose counter
	// int counter2;		// generic purpose counter
	/// REFACTOR NEW ---
	enum scenario_action_e action;
	int16_t duration;
	disrupt_stream_t d_stream;
} scenario_t;


/* initialize the scenario */
void scenario_init(scenario_t *);

/* set the netfilter queue handle in the scenario */
void scenario_set_queue_handle(scenario_t * s, struct nfq_q_handle *qh);

/* run scenario on this packet 
 * return false if the packet is stored in the scenario telling the core to return
 * return true if the packet is not touched by the scenario 
 * */
bool scenario_check_pkt(scenario_t * s, uint16_t seq, uint32_t pkt_id, int32_t stream_duration);

/*
 * scenario section
 * */

bool scenario_action_none(scenario_t * s, int seq, u_int32_t pkt_id);
bool scenario_action_jitter(scenario_t * s, int seq, u_int32_t pkt_id);

#endif
