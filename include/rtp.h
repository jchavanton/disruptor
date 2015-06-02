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

