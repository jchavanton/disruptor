#include "include/scenario.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/in.h>
#include <linux/netfilter.h>

scenario_t * scenario_init(int id){
	scenario_t * s;
	const int qmax_pkt = Q_MAX_PKT;
	s = (scenario_t *)malloc(sizeof(scenario_t));
	s->jitterized_seq_numbers_during_the_call = malloc(sizeof(unsigned int) * qmax_pkt);
	s->queue_packet_ids_delay = malloc(sizeof(unsigned int) * qmax_pkt);
	s->id = id;             // id of the senario to be applied
	s->pb = 0;              // starting without active problem
	s->pb_seq_pos = 0;
	s->pb_seq_start = 0;
	s->scf_pkt_count = 0;
	s->counter1=0;
	s->counter2=0;
	srand ( time(NULL) );   // random seed

	switch(s->id){   /* set the function pointer to the scenario */
		case 1:
 			s->scenario_function = scenario_random_jitter;
			printf("scenario_init: initialized id[%d][random_jitter]\n",s->id);
			break;
		case 2:
 			s->scenario_function = scenario_random_jitter_experiment;
			printf("scenario_init: initialized id[%d][random_jitter_experiment]\n",s->id);
			break;
		case 3:
 			s->scenario_function = scenario_random_pkt_loss;
			printf("scenario_init: initialized id[%d][scenario_random_pkt_loss]\n",s->id);
			break;
		default : /* undefined scenario */
			s->scenario_function = NULL;
			printf("scenario_init: initialized id[UNKNOWN]\n");
			break;
	}
	return s;
}

void scenario_set_queue_handle(scenario_t * s, struct nfq_q_handle *qh){
	s->qh = qh;
}

int scenario_check_pkt(scenario_t * s, int seq, u_int32_t pkt_id){
	if(s == NULL || s->scenario_function == NULL)
		return 0;
	return s->scenario_function(s,seq,pkt_id);
}
