#include "include/scenario.h"
#include "include/disruptor.h"
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

int scenario_action_none(struct scenario_s * s, struct disrupt_packet_s * p){
	return true;
}

int scenario_action_loss(struct scenario_s * s, struct disrupt_packet_s * p){
	int16_t var_rand = 0;
	var_rand = sc_random(100);
	if( var_rand <= s->init_random_occurence ){
		log_debug("random_scenario[loss]: dropping pkt_id[%d] seq[%d]", p->pkt_id, p->seq);
		s->period_pkt_loss++;
		nfq_set_verdict(s->qh, p->pkt_id, NF_DROP, 0, NULL);
		return false;
	}
	return true;
}

int scenario_action_loss_rtcp(struct scenario_s * s, struct disrupt_packet_s * p){
	int16_t var_rand = 0;
	if(!p->rtcp) {
		return true;
	}
	var_rand = sc_random(100);
	if( var_rand <= s->init_random_occurence ){
		log_debug("random_scenario[loss_rtcp]: dropping RTCP pkt_id[%d] ssrc[%#x]", p->pkt_id, p->ssrc);
		s->period_pkt_loss++;
		nfq_set_verdict(s->qh, p->pkt_id, NF_DROP, 0, NULL);
		return false;
	}
	return true;
}

int scenario_action_burst_loss(struct scenario_s * s, struct disrupt_packet_s * p){
	int16_t var_rand = 0;
	s->period_pkt_count++;

	if(s->pb_state == PB_NONE) {
		var_rand = sc_random(s->init_random_occurence);
	}

	if ( (var_rand==1) && (s->pb_state == PB_NONE) ) {   // scenario random occurance
		s->pb_state = PB_INIT;
	}

	if(s->pb_state == PB_NONE) {
		log_debug("stream[%d]scenario_action[burst_loss]: no problem pkt_id[%d] seq[%d] period_cnt[%d]", p->stream->id, p->pkt_id, p->seq , s->period_pkt_count);
	} else if(s->pb_state == PB_INIT) {
		s->pb_pkt_pos = 0;
		s->pb_pkt_start = s->period_pkt_count;
		s->pb_state = PB_ACTIVE;
		s->pb_pkt_max = sc_random(s->init_max_burst); // in this scenario this is a random amount of packet delayed emulate congestion
		log_notice("stream[%d]scenario_action[burst_loss]: problem initialized affecting[%d] packets", p->stream->id, s->pb_pkt_max);
	}

	if(s->pb_state == PB_ACTIVE){ // pb is initialized, start queing packets
		log_debug("scenario_action[burst_loss]: dropping[%d/%d] pkt_id[%d] seq[%d] period_cnt[%d]", s->pb_pkt_pos, s->pb_pkt_max, p->pkt_id, p->seq, s->period_pkt_count);
		s->period_pkt_loss++;
		nfq_set_verdict(s->qh, p->pkt_id, NF_DROP, 0, NULL);
		if(s->pb_pkt_pos == s->pb_pkt_max){
			s->pb_state = PB_STOP;
		} else {
			s->pb_pkt_pos++;
		}
		return false;
	} else if(s->pb_state == PB_STOP) {
		s->pb_state = PB_NONE;
	}

	return true;
}

int scenario_action_jitter(struct scenario_s * s, struct disrupt_packet_s * p){
	int16_t var_rand = 0;
	s->period_pkt_count++;

	if(s->pb_state == PB_NONE) {
		var_rand = sc_random(s->init_random_occurence);
	}

	if ( (var_rand==1) && (s->pb_state == PB_NONE) ) {   // scenario random occurance
		s->pb_state = PB_INIT;
	}

	if(s->pb_state == PB_NONE) {
		log_debug("scenario_action[jitter]: no problem pkt_id[%d] seq[%d] period_cnt[%d]", p->pkt_id, p->seq , s->period_pkt_count);
	} else if(s->pb_state == PB_INIT) {
		s->pb_pkt_pos = 0;
		s->pb_pkt_start = s->period_pkt_count;
		s->pb_state = PB_ACTIVE;
		s->pb_pkt_max = sc_random(s->init_max_burst); // in this scenario this is a random amount of packet delayed emulate congestion
		log_debug("scenario_action[jitter]: problem initialized affecting[%d] packets",s->pb_pkt_max);

	}

	if(s->pb_state == PB_ACTIVE){ // pb is initialized, start queing packets
		s->queue_delay[s->pb_pkt_pos] = p->pkt_id;
		s->queue_seq[s->pb_pkt_pos] = p->seq;
		s->period_pkt_delayed++;

		log_debug("scenario_action[jitter]: queueing[%d/%d] pkt_id[%d] seq[%d] period_cnt[%d]", s->pb_pkt_pos, s->pb_pkt_max, p->pkt_id, p->seq, s->period_pkt_count);
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
			log_debug("scenario_action[jitter]: release delayed packet[%d/%d] id[%d] seq[%d] period_cnt[%d]", i, s->pb_pkt_max, p->pkt_id, s->queue_seq[i], s->period_pkt_count);
			nfq_set_verdict(s->qh, p->pkt_id , NF_ACCEPT, 0, NULL);
		}
		s->pb_state = PB_NONE;
	}

	return true;
}
