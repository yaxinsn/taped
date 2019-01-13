
#ifndef SNIFFER_RTP_H_
#define SNIFFER_RTP_H_

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "log.h"
#include <arpa/inet.h>

#include <pthread.h>    

#include "sniffer_lib.h"  

//#include <linux/in.h>
#include "config.h"
#include "linux-utils.h"
#include "wake_utils.h"
#include "sniffer_sip.h"

#include "g722.h"
#include "mixer.h"


pthread_t setup_rtp_sniffer(struct session_info* ss);

void close_rtp_sniffer(struct session_info* ss);

void rtp_sniffer_init(void);
void update_rtp_session_number(struct session_info* ss);

#endif //SNIFFER_RTP_H_

