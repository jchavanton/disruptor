all:
	gcc -o disruptor disruptor.c scenario.c scenario_functions.c -lnetfilter_queue -ggdb
