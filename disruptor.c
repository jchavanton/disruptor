#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>
#include <time.h>

#include "include/disruptor.h"
#include "include/disruptor_config.h"
#include "include/rtp.h"
#include "include/scenario.h"

#define DATALINK_OVERHEAD 17
#define DISRUPTOR_MAX_Q_LEN 1000

/* packet, scenario and logging */

struct scenario_s *scenario;
struct disrupt_stream_s *stream_head;
struct disrupt_stream_s *stream;
char * scenario_filename = "scenario.xml";
int log_level = 2;
char time_str[20];

static const char *log_fn = "/tmp/disruptor.log";
static const char *pid_fn = "/tmp/disruptor.pid";
static FILE *log_output = NULL;
pid_t process_id = 0;
pid_t sid = 0;

typedef struct disrupt_nfq_s {
	struct nfq_q_handle *qh;	/* Netfilter Queue handle */
	struct nfq_handle *h;		/* Netfilter handle */
	int32_t fd;			/* Netfilter Queue file descriptor */
	int32_t recv_pkt_sz;		/* received packet size */
	int32_t qid;			/* Netfilter Queue ID */
	char buf[4096];
} disrupt_nfq_t;

disrupt_nfq_t d_nfq; /* Disruptor Netfilter */
disrupt_packet_t packet; /* current packet */

bool disrupt_tcp_packet_analysis(unsigned char * payload_transport, int32_t pkt_id){
	struct tcphdr * tcp_header = (struct tcphdr *) payload_transport;
	unsigned char * payload_app = payload_transport + (tcp_header->doff * 4); /* Data Offset: 4 bits, The number of 32 bit words in the TCP Header. */

	/* SIP DETECTION */
	if( strncmp( payload_app, "SIP/2.0 ", 8) == 0 ){
		log_notice("SIP RESPONSE[%c%c%c]", payload_app[8], payload_app[9], payload_app[10]);
		return 1;
	}

	char *sip_found = strstr(payload_app,"sip:");
	if(!sip_found) {
		log_debug("TCP unknown");
		return 1;
	}
	int16_t sip_method_len = (unsigned char *)sip_found-payload_app - 1;
	if(sip_method_len > 10){
		log_notice("TCP SIP method not found...");
		return 1;
	}
	char sip_method[128];
	strncpy(sip_method, payload_app, sip_method_len);
	sip_method[sip_method_len] ='\0';
	if( sip_method ){
		log_notice("SIP REQUEST[%s]", sip_method);
	}
	return true;
}

int disrupt_udp_packet_analysis(char * payload_transport, int32_t pkt_id){
	struct udphdr * udp_hdr = (struct udphdr *) payload_transport;
	unsigned char * payload_app = payload_transport + sizeof(struct udphdr);

	/* RTP DETECTION */

	if( (ntohs(udp_hdr->source) % 2) ){
		rtcp_msg_t * rtcp_msg = (rtcp_msg_t *) payload_app;
		if(rtcp_msg->header.pt == 200 || rtcp_msg->header.pt == 201){
			packet.rtcp = true;
			packet.rtp=false;
			packet.ssrc = rtcp_msg->header.ssrc;
			log_debug("RTCP packet [%d]", rtcp_msg->header.pt);
		} else {
			log_debug("non RTCP packet received [%d]", rtcp_msg->header.pt);
			return true;
		}
	} else {
		rtp_msg_t * rtp_msg = (rtp_msg_t *) payload_app;
		if(rtp_msg->header.version != 2){
			log_debug("non RTP packet received [%d]", rtp_msg->header.version);
			return true;
		}
		packet.pt = rtp_msg->header.pt;
		packet.seq = ntohs(rtp_msg->header.seq);
		packet.ssrc = ntohl(rtp_msg->header.ssrc);
		packet.ts = ntohl(rtp_msg->header.ts);
		packet.rtp = true;
		packet.rtcp = false;
		if(packet.seq%100 == 0){
		log_debug("RTP version[%d] pt[%d] seq[%d] ts[%d] ssrc[%#x] B[%d]",
                                  packet.pt, rtp_msg->header.version, packet.seq, packet.ts, packet.ssrc, packet.size);
		}
	}
	packet.pkt_id = pkt_id;

	struct timeval t;
	gettimeofday(&t,NULL);
	int32_t stream_duration = (int32_t)(t.tv_sec - stream->start.tv_sec);

	/* check scenario : if there is and active scenario is will decide what to do with the packet */
	return scenario_check_pkt(&stream->scenario, &packet, stream_duration, stream->id);
}

void disrupt_stream_detection(struct iphdr * ip_hdr, struct udphdr * udp_hdr){

		stream = stream_get(stream_head, ip_hdr->saddr, udp_hdr->source, ip_hdr->daddr, udp_hdr->dest);
		if( !stream ){
			stream = stream_head = stream_add(stream_head, ip_hdr->saddr, udp_hdr->source, ip_hdr->daddr, udp_hdr->dest);
			stream->scenario.qh = d_nfq.qh;
			struct timeval t;
			gettimeofday(&t,NULL);
			stream->start = t;
			stream->scenario.filename=scenario_filename;
			scenario_init_xml(stream);
			log_info("********** new stream detected *********");
			stream_print(stream_head);
			log_info("****************************************");
		}
		packet.stream = stream;
}

int disrupt_ip_packet_analysis(struct nfq_data *nfa, int32_t pkt_id) {
	#ifdef NFQ_V0
		char *payload_data;
	#else
		unsigned char *payload_data;
	#endif

	uint16_t payload_len = nfq_get_payload(nfa, &payload_data);
	struct iphdr * ip_hdr = (struct iphdr *)(payload_data);

	packet.size= payload_len + DATALINK_OVERHEAD;

	/* Detect transport protocol */
	if ( ip_hdr->protocol == IPPROTO_TCP ) {
		return disrupt_tcp_packet_analysis(payload_data + sizeof(struct iphdr), pkt_id);
	} else if ( ip_hdr->protocol == IPPROTO_UDP ) {
		disrupt_stream_detection(ip_hdr, (struct udphdr *) (payload_data + sizeof(struct iphdr)) );
		return disrupt_udp_packet_analysis(payload_data + sizeof(struct iphdr), pkt_id);
	}
}

/* Definition of callback function */
int disruptor_nfq_call_back(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	//struct disrupt_stream_s *stream = (struct disrupt_stream_s *) data;
	//struct scenario_s * scenario = &stream->scenario;
	int16_t verdict = true;
	int32_t pkt_id;
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
 		pkt_id = ntohl(ph->packet_id);
	}
	// NF_DROP 0
	// NF_ACCEPT 1
	// NF_STOLEN 2
	// NF_QUEUE 3
	// NF_REPEAT 4
	// NF_STOP 5
	verdict = disrupt_ip_packet_analysis(nfa, pkt_id);
	if(verdict){
		nfq_set_verdict(qh, pkt_id, verdict, 0, NULL); /* if scenario is not keeping the packet we release it immediatly */
	}
	return 1;
}

void disruptor_nfq_init() {
	/* Library initialisation */
	d_nfq.h = nfq_open();
	if (!d_nfq.h) {
		log_error("error during nfq_open()");
		exit(1);
	}
	log_debug("unbinding existing nf_queue handler for AF_INET (if any)");
	if (nfq_unbind_pf(d_nfq.h, AF_INET) < 0) {
		log_error("error during nfq_unbind_pf()");
		exit(1);
	}
	log_debug("binding nfnetlink_queue as nf_queue handler for AF_INET");
	if (nfq_bind_pf(d_nfq.h, AF_INET) < 0) {
		log_error("error during nfq_bind_pf()");
		exit(1);
	}
}

void disruptor_nfq_bind() {
	/* Bind the program to a specific queue */
	if(!d_nfq.qid){
		d_nfq.qid=10; /* Default queue id */
	}
	log_info("binding intercept socket to queue [%d]", d_nfq.qid);
	d_nfq.qh = nfq_create_queue(d_nfq.h, d_nfq.qid, &disruptor_nfq_call_back, (void *)stream);
	if (!d_nfq.qh) {
		log_error("error during nfq_create_queue()");
		exit(1);
	}

	log_debug("setting copy_packet mode");
	if (nfq_set_mode(d_nfq.qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		log_error("can't set packet_copy mode");
		exit(1);
	}

	if(nfq_set_queue_maxlen(d_nfq.qh, (uint32_t)DISRUPTOR_MAX_Q_LEN) < 0){
		log_error("error setting maximum queue size to [%d]", DISRUPTOR_MAX_Q_LEN);
		exit(1);
	}
}

void disruptor_nfq_handle_traffic() {
	/*handle the incoming packets*/

	d_nfq.fd = nfq_fd(d_nfq.h);
	while ((d_nfq.recv_pkt_sz = recv(d_nfq.fd, d_nfq.buf, sizeof(d_nfq.buf), 0)) >= 0) {
			nfq_handle_packet(d_nfq.h, d_nfq.buf, d_nfq.recv_pkt_sz); /* send packet to callback */
	}
}



void disruptor_command_line_options(int argc, char **argv){
	int opt;
	FILE *pid_fh=NULL;
	int pid;
	while ((opt = getopt(argc, argv, "hdl:q:f:")) != -1) {
		switch (opt) {
			case 'l':
				log_level =  atoi(optarg);
				break;
			case 'q':
				d_nfq.qid = atoi(optarg);
				log_info("disruptor_command_line_options: nfq queue id[%d]", d_nfq.qid);
				break;
			case 'h':
				log_info("-d daemonize\n-q nfq queue id\n-f scenario file name\n-l log level: 0=error, 1=info, 2=notice, 3=debug");
				exit(0);
				break;
			case 'f':
			case 's':
				scenario_filename = optarg;
				break;
			case 'd':
				if(pid_fh=fopen(pid_fn, "r")){
					log_error("can not deamonize [%s] found", pid_fn);
					exit(1);
				}
				process_id = fork();
				if (process_id > 0) {
					log_info("daemonizing ...");
					exit(0);
				} else if (process_id < 0){
					log_error("can not fork");
					exit(1);
				}
				log_info("logging to %s", log_fn);
				umask(0);
				sid = setsid();
				if (sid < 0)
					exit(1);
				//chdir("/");
				close(STDIN_FILENO);
				close(STDOUT_FILENO);
				close(STDERR_FILENO);
				pid_fh = fopen(pid_fn, "w");
				fprintf(pid_fh, "%d\n", getpid());
				fclose(pid_fh);
				log_output = fopen(log_fn, "w+");
				fflush(log_output);
			default:
				break;
		}
	}
	log_info("scenario file[%s] loglevel[%d]", scenario_filename, log_level);
}

static void signal_handler(int sig) {
	switch(sig) {
		case SIGINT:
		case SIGTERM:
			log_info("disruptor exiting...");
			unlink(pid_fn);
			exit(0);
	}
}

void init_signal_handling(void){
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
}

void init_logging(void){
	log_output=stdout;
	fflush(log_output);
}

void update_time_str(void) {
	time_t now = time (0);
	struct tm *gmt_tm = gmtime (&now);
	strftime (time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", gmt_tm);
}

void log_error( const char* format, ... ) {
	va_list args;
	update_time_str();
	fprintf( log_output, "\e[1;31m[%s] ", time_str);
	va_start( args, format );
	vfprintf( log_output, format, args );
	va_end( args );
	fprintf( log_output, "\e[0m\n" );
	fflush(log_output);
}

void log_info( const char* format, ... ) {
	if(log_level < 1)
		return;
	va_list args;
	update_time_str();
	fprintf( log_output, "\e[1;35m[%s] ", time_str);
	va_start( args, format );
	vfprintf( log_output, format, args );
	va_end( args );
	fprintf( log_output, "\e[0m\n" );
	fflush(log_output);
}

void log_notice( const char* format, ... ) {
	if(log_level < 2)
		return;
	va_list args;
	update_time_str();
	fprintf( log_output, "\e[1;34m[%s] ", time_str);
	va_start( args, format );
	vfprintf( log_output, format, args );
	va_end( args );
	fprintf( log_output, "\e[0m\n" );
	fflush(log_output);
}

void log_debug( const char* format, ... ) {
	if(log_level < 3)
		return;
	va_list args;
	update_time_str();
	fprintf( log_output, "\e[1;37m[%s] ", time_str);
	va_start( args, format );
	vfprintf( log_output, format, args );
	va_end( args );
	fprintf( log_output, "\e[0m\n" );
	fflush(log_output);
}


void main(int argc, char **argv){
	init_logging();
	disruptor_command_line_options(argc, argv);
	init_signal_handling();
	disruptor_nfq_init();
	disruptor_nfq_bind();
	//stream->scenario.qh = d_nfq.qh;
	disruptor_nfq_handle_traffic();
}
