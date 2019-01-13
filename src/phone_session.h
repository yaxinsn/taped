/*
	file: 电话通话的会话信息。
	author: liudan
	time: 2018-4

*/

#ifndef _PHONE_SESSION_H
#define _PHONE_SESSION_H
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <linux/if_ether.h> //struct ethhdr

#include <netinet/in.h>
#include <netinet/ip.h> 

#include <linux/udp.h>//struct udphdr

#include <pthread.h>

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "types_.h"
#include "list.h"

struct session_ctx_t
{
    pthread_mutex_t head_lock;  //sync

    struct list_head si_head;

};
struct session_info* si_new_session();
void si_del_session(struct session_info* si);
struct session_info* si_find_session(char* call_id);

int session_init();



/* 从各种信令协议中，找出通话双方的信息，如IP，电话号码，通话时间等等。 */
struct  person
{
    struct in_addr  ip;
    u16             port;
    char           number[64];
    char           name[64];
};

#define SS_MODE_CALLING 1
#define  SS_MODE_CALLED 2

struct session_info //与信令协议 sip ,skinny无关。是更高一级的应用数据。把从信令中得到的信息保存于此。
{
    int mode; /* call direction   */ // 1是主叫，2是被叫。
    struct list_head node;
    struct tm ring_time;  //响玲的时间点。
	time_t comm_time; //接通的时间点 . ack 的时间，或是ACK的ok的时间。  strptime — date and time conversion
	//time_t hangup_time;//
	time_t start_time_stamp;
	time_t stop_time_stamp;
    //enum session_state state; /*从报文中同步过来。*/
    char* call_id; 
   // u32   callReference; //for skinny;
    /* 如何判断calling? 如何说INVATE的IP层srcIP == sdp.connection IP.  this ip 就
        是calling. */
    struct  person calling;
    struct  person called;
	
    char    called_group_number[64];
	
    pthread_t rtp_sniffer_tid;

    int skinny_state;
    
    int skinny_callstate_connected;
     
}; /* 用于记录本次通信的两者的ip, port, 电话号码，用户名等等。*/


#endif //_PHONE_SESSION_H

