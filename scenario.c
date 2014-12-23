#include "include/scenario.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include "ezxml/ezxml.h"

void scenario_init(scenario_t *s){
	const int qmax_pkt = Q_MAX_PKT;
	//s = (scenario_t *)malloc(sizeof(scenario_t));
	s->jitterized_seq_numbers_during_the_call = malloc(sizeof(unsigned int) * qmax_pkt);
	s->queue_packet_ids_delay = malloc(sizeof(unsigned int) * qmax_pkt);
	s->pb = 0;              // starting without active problem
	s->pb_seq_pos = 0;
	s->pb_seq_start = 0;
	s->scf_pkt_count = 0;
	s->counter1=0;
	s->counter2=0;
	srand ( time(NULL) );   // random seed
}

void scenario_set_action(scenario_t * s){
	switch(s->action){   /* set the function pointer to the action */
		case NONE:
			s->scenario_action = scenario_none;
			break;
		case JITTER:
 			s->scenario_action = scenario_random_jitter_experiment;
			break;
		default :
			s->scenario_action = NULL;
			break;
	}
	return;
}

void scenario_read_xml(scenario_t * s, disrupt_stream_t d_stream) {
	ezxml_t scenario_xml = ezxml_parse_file("scenario.xml"), period, action;
	const char *action_name;
	const char *period_duration;

	for (period = ezxml_child(scenario_xml, "period"); period; period = period->next) {
		period_duration = ezxml_attr(period, "duration");
		for (action = ezxml_child(period, "action"); action; action = action->next) {
			action_name = ezxml_attr(action, "name");
		}
	}
	//ezxml_free(scenario_xml);

	printf("scenario_read_xml: period[%s] action[%s]\n", period_duration, action_name);
	if(strcasecmp(action_name,"jitter") == 0){
		s->action = JITTER;
	} else {
		s->action = NONE;
	}
	s->duration = atoi(period_duration);
	printf("scenario_read_xml: period[%d] action[%d]\n", s->duration, s->action);
	s->d_stream=d_stream;
	scenario_init(s);
	scenario_set_action(s);
	return;
}

bool scenario_check_pkt(scenario_t * s, uint16_t seq, uint32_t pkt_id, int32_t stream_duration){
	if(s == NULL || s->scenario_action == NULL)
		return 0;
	return s->scenario_action(s,seq,pkt_id);
}





