#include "include/scenario.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/in.h>
#include <linux/netfilter.h>


static int16_t sc_random(int16_t max) {
	struct timeval t;
	gettimeofday(&t,NULL);
	srandom(t.tv_usec+t.tv_sec);
	return ( ( random() % max ) + 1);
}

bool scenario_action_none(scenario_t * s, int seq, u_int32_t pkt_id){
	return true;
}

bool scenario_action_loss(scenario_t * s, int seq, uint32_t pkt_id){
	int16_t var_rand = 0;
	s->period_pkt_count++;
	var_rand = sc_random(100);
	if( var_rand <= s->init_random_occurence ){
		printf("random_scenario[loss]: dropping pkt_id[%d] seq[%d]\n", pkt_id, seq);
		nfq_set_verdict(s->qh, pkt_id, NF_DROP, 0, NULL);
		return false;
	}
	return true;
}

bool scenario_action_jitter(scenario_t * s, int seq, uint32_t pkt_id){
	int16_t var_rand = 0;
	s->period_pkt_count++;

	if(s->pb_state == PB_NONE) {
		var_rand = sc_random(s->init_random_occurence);
	}

	if ( (var_rand==1) && (s->pb_state == PB_NONE) ) {   // scenario random occurance
		s->pb_state = PB_INIT;
	}

	if(s->pb_state == PB_NONE) {
		printf("scenario_action[jitter]: no problem pkt_id[%d] seq[%d] period_cnt[%d]\n", pkt_id, seq , s->period_pkt_count);
	} else if(s->pb_state == PB_INIT) {
		s->pb_pkt_pos = 0;
		s->pb_pkt_start = s->period_pkt_count;
		s->pb_state = PB_ACTIVE;
		s->pb_pkt_max = sc_random(s->init_max_burst); // in this scenario this is a random amount of packet delayed emulate congestion
		printf("scenario_action[jitter]: problem initialized affecting[%d] packets \n",s->pb_pkt_max);
	}

	if(s->pb_state == PB_ACTIVE){ // pb is initialized, start queing packets
		s->queue_delay[s->pb_pkt_pos] = pkt_id;
		s->queue_seq[s->pb_pkt_pos] = seq;

		printf("scenario_action[jitter]: queueing[%d/%d] pkt_id[%d] seq[%d] period_cnt[%d]\n", s->pb_pkt_pos, s->pb_pkt_max, pkt_id, seq, s->period_pkt_count);
		if(s->pb_pkt_pos == s->pb_pkt_max){
			s->pb_state = PB_STOP;
		} else {
			s->pb_pkt_pos++;
		}
		return false;
	} else if(s->pb_state == PB_STOP) {  // release the packets
		uint32_t pkt_id;
		int i;
		for (i=0;i<=s->pb_pkt_pos;i++){
			pkt_id = s->queue_delay[i];
			printf("scenario_action[jitter]: release delayed packet[%d/%d] id[%d] seq[%d] period_cnt[%d]\n", i, s->pb_pkt_max, pkt_id, s->queue_seq[i], s->period_pkt_count);
			nfq_set_verdict(s->qh, pkt_id , NF_ACCEPT, 0, NULL);
		}
		s->pb_state = PB_NONE;
	}

	return true;
}
