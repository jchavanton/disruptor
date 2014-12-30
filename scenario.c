#include "include/scenario.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include "ezxml/ezxml.h"

void scenario_init(scenario_t *s){
	if(!s->queue_seq){
		s->queue_seq = malloc(sizeof(unsigned int) *  q_max_pkt);
	}
	if(!s->queue_delay){
		s->queue_delay = malloc(sizeof(unsigned int) *  q_max_pkt);
	}
	s->pb_state = PB_NONE;              // starting without active problem
	s->pb_pkt_pos = 0;
	s->pb_pkt_start = 0;
	s->pb_pkt_max = 0;
	s->period_pkt_count = 0;
	srand ( time(NULL) );   // random seed
}

void scenario_set_action(scenario_t * s){
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

void scenario_read_xml(scenario_t * s, disrupt_stream_t d_stream) {
	ezxml_t scenario_xml = ezxml_parse_file("scenario.xml"), period, action;
	const char *action_name;
	const char *period_duration;

	for (period = ezxml_child(scenario_xml, "period"); period; period = period->next) {
		period_duration = ezxml_attr(period, "duration");
		for (action = ezxml_child(period, "action"); action; action = action->next) {
			action_name = ezxml_attr(action, "name");
			break;
		}
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
	s->duration = atoi(period_duration);
	printf("\n");
	s->d_stream=d_stream;
	scenario_init(s);
	scenario_set_action(s);
	return;
}

bool scenario_check_pkt(scenario_t * s, uint16_t seq, uint32_t pkt_id, int32_t stream_duration){
	if(s == NULL || s->scenario_action == NULL)
		return true;
	if(s->duration <= stream_duration){ /* todo select next action ... */
		printf("scenario period completed...[%d][%d]\n", s->duration, stream_duration);
		//s->action=NONE;
		//scenario_set_action(s);
		s->scenario_action = NULL;
		return true;
	}
	return s->scenario_action(s,seq,pkt_id);
}





