all:
	gcc -o disruptor disruptor.c -lnetfilter_queue -ggdb
