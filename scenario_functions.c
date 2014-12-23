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

bool scenario_none(scenario_t * s, int seq, u_int32_t pkt_id){
	return true;
}

/* id 2 */
bool scenario_random_jitter_experiment(scenario_t * s, int seq, u_int32_t pkt_id){
	int var_rand = 0;
	s->counter1++;

	if( ((s->counter1 < 500) || (s->counter1 > 1500 && s->counter1 < 2500)) && (s->pb==0)){ /* high jitter only on the first 5000 packets */
		var_rand = sc_random(50) % 50;
	}
	else{
		var_rand = 1;
	}

	if ((var_rand==0) && (s->pb == 0)) {   // scenario random occurance
		s->pb = 1;
	}

	if(s->pb == 0)
		printf("random_scenario jitter: no problem seq: %d [%d]\n",seq , s->counter1);

	if(s->pb == 1){ // initialization
		s->pb_seq_pos = 0;
		s->pb_seq_start = seq;
		s->pb = 2;
		s->scf_pkt_count = rand() % 120 +1; // in this scenario this is a random amount of packet delayed emulate congestion
		printf("random_scenario jitter: initialized affecting[%d]pkt [%d]\n",s->scf_pkt_count, s->counter1);
	}
	if(s->pb == 2){ // pb is initialized, start queing packets
		s->queue_packet_ids_delay[s->pb_seq_pos]=pkt_id;
                s->jitterized_seq_numbers_during_the_call[s->pb_seq_pos]=seq;
		s->pb_seq_pos++;	
		if(s->pb_seq_pos == s->scf_pkt_count)
			s->pb=3;

		printf("random_scenario jitter: queueing seq: %d [%d]\n",seq, s->counter1);
		return false;
	}
	else if(s->pb == 3) {  // release the packets
		u_int32_t pkt_id;
		int i;
		for (i=0;i<s->scf_pkt_count;i++){
			pkt_id = s->queue_packet_ids_delay[i];
			printf("random_scenario jitter: delayed packet released seq: %d [%d]\n",s->jitterized_seq_numbers_during_the_call[i], s->counter1);
			nfq_set_verdict(s->qh, pkt_id , NF_ACCEPT, 0, NULL);
		}
		s->pb=0; //
		printf("random_scenario jitter: completed [%d]\n" ,s->counter1);
	}
	return true;
}

/* id 3 */
bool scenario_random_pkt_loss(scenario_t * s, int seq, u_int32_t pkt_id){
	int var_rand = 1;       /* initialize to no problem */
	var_rand = sc_random(9);
	if(var_rand == 1 && s->counter1 < 10000){
		printf("scenario_random_pkt_loss: dropping packet with dropcount[%d] seq: %d\n", s->counter1, seq);
		nfq_set_verdict(s->qh, pkt_id, NF_DROP, 0, NULL);
		s->counter1++;
		return false;
	}
/*
	if(s->scf_pkt_count == 0){
		var_rand = sc_random(9);
		if(var_rand == 0)
			s->scf_pkt_count=1;
	}
	if(s->scf_pkt_count > 0 && s->scf_pkt_count <= 5){     // burst of 5 pkt loss 
		s->scf_pkt_count++;
	        printf("random_scenario: dropping packet with seq: %d\n",seq);
		nfq_set_verdict(s->qh, pkt_id, NF_DROP, 0, NULL);
		return 1;
	}
	else{ 
		s->scf_pkt_count = 0;
	}
*/
	printf("scenario_random_pkt_loss: packet with seq: %d\n",seq);
	return true;
}



/* id 1 */
bool scenario_random_jitter(scenario_t * s, int seq, u_int32_t pkt_id){
	int var_rand = 0;
	s->counter1++;

	if ((s->pb==0) && (seq < 50)) {        // scenario does not trigger at the beginning of the call
		var_rand=1;
	} else{
		var_rand = sc_random(33);        // random trigger of an occurance 
	}

	if((s->pb==0) && (seq > 1500)){
		var_rand = 1;
	}

	if ((var_rand==0) && (s->pb == 0)) {   // scenario random occurance 	
		s->pb = 1;
	}

	if(s->pb == 0)
		printf("random_scenario random_jitter: no problem seq: %d [%d]\n",seq ,s->counter1);

	if(s->pb == 1){ // initialization
		s->pb_seq_pos = 0;
		s->pb_seq_start = seq;
		s->pb = 2;
		s->scf_pkt_count = rand() % 50 +5; // in this scenario this is a random amount of packet delayed emulate congestion
		printf("random_scenario random_jitter: initialized affecting[%d]pkt [%d]\n",s->scf_pkt_count ,s->counter1);
	}
	if(s->pb == 2){ // pb is initialized, start queing packets
		s->queue_packet_ids_delay[s->pb_seq_pos]=pkt_id;
                s->jitterized_seq_numbers_during_the_call[s->pb_seq_pos]=seq;
		s->pb_seq_pos++;
		if(s->pb_seq_pos == s->scf_pkt_count)
			s->pb=3;

		printf("random_scenario random_jitter: queueing seq: %d [%d]\n",seq ,s->counter1);
		return false;
	}
	else if(s->pb == 3) {  // release the packets
		u_int32_t pkt_id;
		int i;
		for (i=0;i<s->scf_pkt_count;i++){
			pkt_id = s->queue_packet_ids_delay[i];
                        printf("random_scenario random_jitter: delayed packet released seq: %d\n",s->jitterized_seq_numbers_during_the_call[i]);
	                nfq_set_verdict(s->qh, pkt_id , NF_ACCEPT, 0, NULL);
		}
		s->pb=0; // 
		printf("random_scenario random_jitter: completed\n");
	}
	return true;
}

