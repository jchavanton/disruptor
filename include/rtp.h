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

#include <linux/udp.h>

#define RTP_MAX_BUF_LEN 16384

#if defined(__LITTLE_ENDIAN_BITFIELD)

typedef struct {
	unsigned cc:4;      /* CSRC count             */
	unsigned x:1;       /* header extension flag  */
	unsigned p:1;       /* padding flag           */
	unsigned version:2; /* protocol version       */
	unsigned pt:7;      /* payload type           */
	unsigned m:1;       /* marker bit             */
	unsigned seq:16;    /* sequence number        */
	unsigned ts:32;     /* timestamp              */
	uint32_t ssrc;      /* synchronization source */
} rtp_hdr_t;

typedef struct {
	unsigned rc:5;      /* reception report count */
	unsigned p:1;       /* padding flag           */
	unsigned version:2; /* protocol version       */
	unsigned pt:8;      /* packet type */
	unsigned length:8;  /* The length of this RTCP packet in 32-bit words minus one */
	uint32_t ssrc;      /* synchronization source */
} rtcp_hdr_t;

#else /*  BIG_ENDIAN */

typedef struct {
	unsigned version:2; /* protocol version       */
	unsigned p:1;       /* padding flag           */
	unsigned x:1;       /* header extension flag  */
	unsigned cc:4;      /* CSRC count             */
	unsigned m:1;       /* marker bit             */
	unsigned pt:7;      /* payload type           */
	unsigned seq:16;    /* sequence number        */
	unsigned ts:32;     /* timestamp              */
	uint32_t ssrc;      /* synchronization source */
} rtp_hdr_t;

typedef struct {
	unsigned version:2; /* protocol version       */
	unsigned p:1;       /* padding flag           */
	unsigned rc:5;      /* reception report count */
	unsigned pt:8;      /* packet type */
	unsigned length:8;  /* The length of this RTCP packet in 32-bit words minus one */
	uint32_t ssrc;      /* synchronization source */
} rtcp_hdr_t;

#endif

typedef struct {
	rtp_hdr_t header;
	char body[RTP_MAX_BUF_LEN];
} rtp_msg_t;

typedef struct {
	rtcp_hdr_t header;
	char body[RTP_MAX_BUF_LEN];
} rtcp_msg_t;

