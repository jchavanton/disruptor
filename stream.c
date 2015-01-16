#include <inttypes.h>
#include "include/scenario.h"

struct disrupt_stream_s * stream_get(struct disrupt_stream_s * stream, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port){
	while(stream != NULL){
		if( stream->socket.src_ip==src_ip && stream->socket.src_port==src_port && stream->socket.src_ip==src_ip && stream->socket.dst_port==dst_port){
			return stream;
		}
		if(stream->next==NULL)
			return NULL;
		stream=stream->next;
	}
	return NULL;
}

struct disrupt_stream_s * stream_add(struct disrupt_stream_s * stream, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port){
	struct disrupt_stream_s * stream_new;
	stream_new = (struct disrupt_stream_s *) malloc(sizeof(struct disrupt_stream_s));
	if(!stream_new){
		printf("stream_add: can not allocate memory\n");
		return NULL;
	}
	/* initialize the stream */
	struct timeval t;
	gettimeofday(&t,NULL);
	stream_new->start = t;
	stream_new->socket.src_ip = src_ip;
	stream_new->socket.src_port = src_port;
	stream_new->socket.dst_ip = dst_ip;
	stream_new->socket.dst_port = dst_port;

	if(!stream)
		return stream_new;
	stream->previous=stream_new;
	stream_new->next=stream;
	return stream_new;
}

void stream_print(struct disrupt_stream_s * stream){
	while(stream != NULL){
		printf("active stream: src ip:port[%d.%d.%d.%d:%d] dest ip:port[%d.%d.%d.%d:%d] start[%"PRId64"]\n",
			(stream->socket.src_ip>>24)&0xFF,(stream->socket.src_ip>>16)&0xFF,(stream->socket.src_ip>>8)&0xFF,(stream->socket.src_ip)&0xFF,
			ntohs(stream->socket.src_port),
			(stream->socket.dst_ip>>24)&0xFF,(stream->socket.dst_ip>>16)&0xFF,(stream->socket.dst_ip>>8)&0xFF,(stream->socket.dst_ip)&0xFF,
			ntohs(stream->socket.dst_port),
			(int64_t)stream->start.tv_sec
		);
		if(stream->next==NULL)
			return;
		stream=stream->next;
	}
}
