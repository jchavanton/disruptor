all:
	gcc -o disruptor disruptor.c scenario.c scenario_actions.c ezxml/ezxml.c -lnetfilter_queue -ggdb
