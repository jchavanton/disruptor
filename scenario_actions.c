/*
 * Copyright (C) 2015-2016 Julien Chavanton
 *
 * This file is part of Disruptor, a network impairment server.
 *
 * Disruptor is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * Disruptor is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "include/scenario.h"
#include "include/disruptor.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
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
	if( var_rand <= s->init_interval_occurence ){
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
	if( var_rand <= s->init_interval_occurence ){
		log_debug("random_scenario[loss_rtcp]: dropping RTCP pkt_id[%d] ssrc[%#x]", p->pkt_id, p->ssrc);
		s->period_pkt_loss++;
		nfq_set_verdict(s->qh, p->pkt_id, NF_DROP, 0, NULL);
		return false;
	}
	return true;
}

int scenario_action_burst_loss(struct scenario_s * s, struct disrupt_packet_s * p) {
	int16_t var_rand = 0;

	if(s->pb_state == PB_NONE) {
		var_rand = sc_random(s->init_interval_occurence);
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
		log_debug("stream[%d]scenario_action[burst_loss]: dropping[%d/%d] pkt_id[%d] seq[%d] period_cnt[%d]", p->stream->id, s->pb_pkt_pos, s->pb_pkt_max, p->pkt_id, p->seq, s->period_pkt_count);
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

	if(s->pb_state == PB_NONE) {
		if(s->params & JITTER_FIXED_BURST_INTERVAL) {
			log_debug("stream[%d]scenario_action[jitter][%d]-[%d]>=[%d]: no problem pkt_id[%d] seq[%d] period_cnt[%d]",
                                   p->stream->id, s->period_pkt_count, s->pb_pkt_stop, s->init_interval_occurence, p->pkt_id, p->seq , s->period_pkt_count);
			if(s->period_pkt_count - s->pb_pkt_stop >= s->init_interval_occurence)
				var_rand = 1;
		} else {
			var_rand = sc_random(s->init_interval_occurence);
		}
	}

	if ( (var_rand==1) && (s->pb_state == PB_NONE) ) {   // scenario random occurance
		s->pb_state = PB_INIT;
	}

	if(s->pb_state == PB_NONE) {
		log_debug("stream[%d]scenario_action[jitter]: no problem pkt_id[%d] seq[%d] period_cnt[%d]", p->stream->id, p->pkt_id, p->seq , s->period_pkt_count);
	} else if(s->pb_state == PB_INIT) {
		s->pb_pkt_pos = 0;
		s->pb_pkt_start = s->period_pkt_count;
		s->pb_state = PB_ACTIVE;
		if(s->params & JITTER_FIXED_BURST_LEN) {
			s->pb_pkt_max = s->init_max_burst;
		} else {
			s->pb_pkt_max = sc_random(s->init_max_burst); // in this scenario this is a random amount of packet delayed emulate congestion
		}
		log_debug("stream[%d]scenario_action[jitter]: problem initialized affecting[%d] packets", p->stream->id, s->pb_pkt_max);
	}

	if(s->pb_state == PB_ACTIVE){ // pb is initialized, start queing packets
		s->queue_delay[s->pb_pkt_pos] = p->pkt_id;
		s->queue_seq[s->pb_pkt_pos] = p->seq;
		s->period_pkt_delayed++;

		log_debug("stream[%d]scenario_action[jitter]: queueing[%d/%d] pkt_id[%d] seq[%d] period_cnt[%d]", p->stream->id, s->pb_pkt_pos, s->pb_pkt_max, s->queue_delay[s->pb_pkt_pos], p->seq, s->period_pkt_count);
		if(s->pb_pkt_pos == s->pb_pkt_max){
			s->pb_pkt_stop = s->period_pkt_count;
			s->pb_state = PB_STOP;
		} else {
			s->pb_pkt_pos++;
		}
		return false;
	} else if(s->pb_state == PB_STOP) {  // release the packets
		uint32_t pkt_id;
		int i;
		log_debug("stream[%d]scenario_action[jitter]: delayed packets [%d]", p->stream, s->pb_pkt_pos);

		if(s->params & JITTER_OUT_OF_ORDER) {
			for (i=s->pb_pkt_pos;i>=0;i--){
				pkt_id = s->queue_delay[i];
				log_debug("stream[%d]scenario_action[jitter]: release(outoforder) delayed packet[%d/%d] id[%d] seq[%d] period_cnt[%d]",
                                                       p->stream->id, i, s->pb_pkt_max, pkt_id, s->queue_seq[i], s->period_pkt_count);
				nfq_set_verdict(s->qh, pkt_id , NF_ACCEPT, 0, NULL);
			}
		} else {
			for (i=0;i<=s->pb_pkt_pos;i++){
				pkt_id = s->queue_delay[i];
				log_debug("stream[%d]scenario_action[jitter]: release delayed packet[%d/%d] id[%d] seq[%d] period_cnt[%d]",
                                                       p->stream->id, i, s->pb_pkt_max, pkt_id, s->queue_seq[i], s->period_pkt_count);
				nfq_set_verdict(s->qh, pkt_id , NF_ACCEPT, 0, NULL);
			}
		}
		s->pb_state = PB_NONE;
	}

	return true;
}
