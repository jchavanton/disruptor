#include <libnetfilter_queue/libnetfilter_queue.h>

#define Q_MAX_PKT 1000; // max packet queue size for the scenario

typedef struct scenario_s {
	int pb;        		// pb will now take place  TODO  
	int id;			// scenario id	
	int pb_seq_pos;		// current seq id in the problem
	int pb_seq_start;	// seq id when starting a problem
	unsigned int *queue_packet_ids_delay;
	unsigned int *jitterized_seq_numbers_during_the_call;
	struct nfq_q_handle *qh; 	// struct nfq_q_handle *qh
	int (*scenario_function)(struct scenario_s * s, int seq, u_int32_t pkt_id); 
	int scf_pkt_count;     // scenario variable that can be used to count packets       
	int counter1;		// generic purpose counter
	int counter2;		// generic purpose counter
} scenario_t;


/* initialize the scenario */
scenario_t * scenario_init(int sc_id);

/* set the netfilter queue handle in the scenario */
void scenario_set_queue_handle(scenario_t * s, struct nfq_q_handle *qh);

/* run scenario on this packet 
 * return 1 if the packet is stored in the scenario telling the core to return
 * return 0 if the packet is not touched by the scenario 
 * */
int scenario_check_pkt(scenario_t * s, int seq, u_int32_t pkt_id);

/*
 * scenario section
 * */

int scenario_random_jitter(scenario_t * s, int seq, u_int32_t pkt_id);

int scenario_random_jitter_experiment(scenario_t * s, int seq, u_int32_t pkt_id);

int scenario_random_pkt_loss(scenario_t * s, int seq, u_int32_t pkt_id);
