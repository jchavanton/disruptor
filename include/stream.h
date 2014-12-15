
typedef struct disrupt_stream_s { /* UDP stream detected */
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t src_ip;
	uint32_t dst_ip;
	struct timeval start;
} disrupt_stream_t;

