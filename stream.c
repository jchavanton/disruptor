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

#include <inttypes.h>
#include <string.h>
#include "include/scenario.h"
#include "include/disruptor.h"
#include "include/stream.h"

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
	memset(stream_new, 0, sizeof(struct disrupt_stream_s));
	if(!stream_new){
		log_error("stream_add: can not allocate memory\n");
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

	if(!stream) {
		stream_new->id=1;
		return stream_new;
	}
	stream->previous=stream_new;
	stream_new->next=stream;
	stream_new->id=stream_new->next->id+1;
	return stream_new;
}

void stream_print(struct disrupt_stream_s * stream){
	while(stream != NULL){
		log_info("active stream[%d]: src ip:port[%d.%d.%d.%d:%d] dest ip:port[%d.%d.%d.%d:%d] start[%"PRId64"]", stream->id,
			(stream->socket.src_ip)&0xFF,(stream->socket.src_ip>>8)&0xFF,(stream->socket.src_ip>>16)&0xFF,(stream->socket.src_ip>>24)&0xFF,
			ntohs(stream->socket.src_port),
			(stream->socket.dst_ip)&0xFF,(stream->socket.dst_ip>>8)&0xFF,(stream->socket.dst_ip>>16)&0xFF,(stream->socket.dst_ip>>24)&0xFF,
			ntohs(stream->socket.dst_port),
			(int64_t)stream->start.tv_sec
		);
		if(stream->next==NULL)
			return;
		stream=stream->next;
	}
}
