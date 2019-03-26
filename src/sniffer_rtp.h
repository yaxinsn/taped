
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
struct linear_mix_list_st
{
    
    struct list_head* linear_buf_list;
    
    struct list_head* _mix_list;
    
    struct list_head  _list_a;
    struct list_head  _list_b;
    u32 _pkt_count;
    int mix_ready_flag;
    
};


typedef struct linear_buf_st
{    
    struct list_head node;
    int len;
    u8*  p_buf;
}linear_buf;

struct rtp_session_info
{
    
    struct list_head node;
    pthread_t   thread_id;
    pcap_t*     pd;
   
    int     call_dir; /// is same the ss mode.
 
    struct  person calling;  //sip msg header From
    struct  person called;   //sip msg header to
    FILE*   save_calling_fp;
    FILE*   save_called_fp;
    u8     rtp_type;

    time_t start_time_stamp;

    time_t stop_time_stamp;
    //struct session_info* session;
    struct tm ring_time; 
    struct tm end_time;

/* 2018-6-10 */
    struct mixer stMix;
    int mix_count;
    g722_decode_state_t* g722dst_calling;

    g722_decode_state_t* g722dst_called;
    FILE* save_mix_fp; 

    FILE* save_calling_linear_fp; 
    FILE* save_called_linear_fp; 
    
    char calling_name_linear[256];
    
    char called_name_linear[256];
    char mix_file_name[256];

     
     int calling_pkt_count;
     int called_pkt_count;
  #if 0   
     struct list_head* p_calling_linear_buf_list;
     struct list_head*  p_called_linear_buf_list;
     
     struct list_head  calling_linear_buf_list_a;
     struct list_head  called_linear_buf_list_a;
     struct list_head  calling_linear_buf_list_b;
     struct list_head  called_linear_buf_list_b;

     
     struct list_head* p_calling_linear_buf_mix_list;
     struct list_head*  p_called_linear_buf_mix_list;
#endif
     struct linear_mix_list_st calling_mix_list_st;

     struct linear_mix_list_st called_mix_list_st;

     int mix_file_frag_count;
     int mix_file_frag_info_caller;  //   0 is user hung up. the rtp is stop;   1 is session_talking_2
     int session_id;
     int exit_flag;
	 char called_group_number[64];
};

pthread_t setup_rtp_sniffer(struct session_info* ss);
/*
结束整个通话的会话。就是用户挂机时的处理。
不是RTP通信的结束。
*/
void close_dial_session_sniffer(unsigned long rtp_sniffer_tid);
/*
结一个rtp通信。
*/
void close_one_rtp_sniffer(unsigned long rtp_sniffer_tid);

void rtp_sniffer_init(void);
//void update_rtp_session_number(struct session_info* ss);
struct rtp_session_info* _rtp_find_session(pthread_t   thread_id);

#endif //SNIFFER_RTP_H_

