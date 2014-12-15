#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdbool.h>

#include "stream.h"

#define Q_MAX_PKT 1000; // max packet queue size for the scenario

enum scenario_action_e {
	NONE,
	JITTER
};

typedef struct scenario_s {
	int pb;        		// pb will now take place  TODO  
	//int id;			// scenario id	
	int pb_seq_pos;		// current seq id in the problem
	int pb_seq_start;	// seq id when starting a problem
	unsigned int *queue_packet_ids_delay;
	unsigned int *jitterized_seq_numbers_during_the_call;
	struct nfq_q_handle *qh; 	// struct nfq_q_handle *qh
	bool (*scenario_action)(struct scenario_s * s, int seq, u_int32_t pkt_id); 
	//bool (*scenario_fuction)(struct scenario_s * s, int seq, u_int32_t pkt_id); 
	int scf_pkt_count;     // scenario variable that can be used to count packets       
	int counter1;		// generic purpose counter
	int counter2;		// generic purpose counter
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
