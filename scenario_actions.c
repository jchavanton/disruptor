#include "include/scenario.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <libnetfilter_queue/libnetfilter_queue.h> 
#include <netinet/in.h>
#include <linux/netfilter.h>

#define SC_DELAYED_PKT 15

static int16_t sc_random(int16_t max) {
	struct timeval t;
	gettimeofday(&t,NULL);
	srandom(t.tv_usec+t.tv_sec);
	return ( ( random() % max ) + 1);
}

bool scenario_action_none(scenario_t * s, int seq, u_int32_t pkt_id){
	return true;
}

bool scenario_action_jitter(scenario_t * s, int seq, u_int32_t pkt_id){
	int var_rand = 0;
	s->counter1++;

	if(s->pb==0) {
		var_rand = sc_random(50) % 50;
	}
	else{
		var_rand = 1;
	}
	if ( (var_rand==0) && (s->pb==0) ) {   // scenario random occurance
		s->pb = 1;
	}

	if(s->pb == 0)
		printf("scenario_action[jitter]: no problem seq: %d [%d]\n",seq , s->counter1);

	if(s->pb == 1){ // initialization
		s->pb_seq_pos = 0;
		s->pb_seq_start = seq;
		s->pb = 2;
		s->scf_pkt_count = rand() % 120 +1; // in this scenario this is a random amount of packet delayed emulate congestion
		printf("scenario_action[jitter]: initialized affecting[%d]pkt[%d]\n",s->scf_pkt_count, s->counter1);
	}
	if(s->pb == 2){ // pb is initialized, start queing packets
		s->queue_packet_ids_delay[s->pb_seq_pos]=pkt_id;
		s->jitterized_seq_numbers_during_the_call[s->pb_seq_pos]=seq;
		s->pb_seq_pos++;
		if(s->pb_seq_pos == s->scf_pkt_count)
			s->pb=3;
		printf("scenario_action[jitter]: queueing seq: %d [%d]\n",seq, s->counter1);
		return false;
	}
	else if(s->pb == 3) {  // release the packets
		u_int32_t pkt_id;
		int i;
		for (i=0;i<s->scf_pkt_count;i++){
			pkt_id = s->queue_packet_ids_delay[i];
			printf("scenario_action[jitter]: delayed packet released seq: %d [%d]\n",s->jitterized_seq_numbers_during_the_call[i], s->counter1);
			nfq_set_verdict(s->qh, pkt_id , NF_ACCEPT, 0, NULL);
		}
		s->pb=0;
	}
	return true;
}
