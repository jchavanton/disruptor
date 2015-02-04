#include "include/scenario.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include "ezxml/ezxml.h"

void scenario_init(struct scenario_s *s){
	if(!s->queue_seq){
		s->queue_seq = malloc(sizeof(unsigned int) *  q_max_pkt);
	}
	if(!s->queue_delay){
		s->queue_delay = malloc(sizeof(unsigned int) *  q_max_pkt);
	}
}

void scenario_period_init(struct scenario_s *s){
	s->pb_state = PB_NONE;              // starting without active problem
	s->pb_pkt_pos = 0;
	s->pb_pkt_start = 0;
	s->pb_pkt_max = 0;
	s->period_pkt_count = 0;
	srand ( time(NULL) );   // random seed
}

void scenario_set_action(struct scenario_s * s){
	switch(s->action){   /* set the function pointer to the action */
		case A_NONE:
			s->scenario_action = scenario_action_none;
			break;
		case A_JITTER:
 			s->scenario_action = scenario_action_jitter;
			break;
		case A_LOSS:
			s->scenario_action = scenario_action_loss;
			break;
		default :
			s->scenario_action = NULL;
			break;
	}
	return;
}

void scenario_init_xml(struct disrupt_stream_s *stream) {
	printf("scenario_init_xml\n");
	stream->scenario.scenario_xml = ezxml_parse_file("scenario.xml");
	stream->scenario.scenario_period_xml = ezxml_child(stream->scenario.scenario_xml, "period");
	scenario_init(&stream->scenario);
	scenario_read_period_xml(&stream->scenario,0);
}

bool scenario_read_period_xml(struct scenario_s * s, int32_t stream_duration) {
	ezxml_t action;
	const char *action_name;
	const char *period_duration;

	if(s->scenario_period_xml) {
		period_duration = ezxml_attr(s->scenario_period_xml, "duration");
		for (action = ezxml_child(s->scenario_period_xml, "action"); action; action = action->next) {
			action_name = ezxml_attr(action, "name");
			break;
		}
		s->period_start = stream_duration;
		s->period_duration = atoi(period_duration);
		s->period_packet_count =0;
		s->period_bandwidth=0;
		scenario_period_init(s);
		s->scenario_period_xml = s->scenario_period_xml->next;
	} else {
		printf("scenario_read_period_xml: no period found.\n");
		return false;
	}
	//ezxml_free(scenario_xml);

	printf("scenario_read_xml: period[%ss] action[%s]", period_duration, action_name);
	if(strcasecmp(action_name,"jitter") == 0){
		s->action = A_JITTER;
		s->init_max_burst = atoi(ezxml_attr(action, "max"));
		s->init_random_occurence = atoi(ezxml_attr(action, "rand"));
		printf(" max_burst[%d] random_occurence[%d]", s->init_max_burst, s->init_random_occurence);
	} else if(strcasecmp(action_name,"loss") == 0){
		s->action = A_LOSS;
		s->init_random_occurence = atoi(ezxml_attr(action, "rand"));
		printf(" percentage[%d]", s->init_random_occurence);
	} else {
		s->action = A_NONE;
	}
	printf("\n");
	scenario_set_action(s);
	return true;
}

bool scenario_check_pkt(struct scenario_s * s, struct disrupt_packet_s * packet, int32_t stream_duration){
	if(s == NULL || s->scenario_action == NULL)
		return true;
	s->period_packet_count++;
	s->period_bandwidth = s->period_bandwidth + packet->size;
	if( stream_duration - s->period_start >= s->period_duration){
		int32_t bps=0;
		//if(s->period_duration > 0){
		//	bps = s->period_bandwidth / s->period_duration;
		//}
		printf("scenario period completed...[%ds]to[%ds] pkt_rx[%d] bytes[%d]\n", s->period_start, stream_duration, s->period_packet_count, s->period_bandwidth);
		if(!scenario_read_period_xml(s, stream_duration)) {
			//s->action=NONE;
			//scenario_set_action(s);
			s->scenario_action = NULL;
		}
		return true;
	}
	return s->scenario_action(s, packet->seq, packet->pkt_id);
}





