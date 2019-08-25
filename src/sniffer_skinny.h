#ifndef _SNIFFER_SKINNY_H
#define _SNIFFER_SKINNY_H

#include <pthread.h>
#include "sniffer_lib.h"
#include "list.h"
#include "phone_session.h"
#include <time.h>

/*skinny portorol  used Little-Endian */
/*skinny portorol  used Little-Endian */
/*skinny portorol  used Little-Endian */
/*skinny portorol  used Little-Endian */
/*skinny portorol  used Little-Endian */
/*skinny portorol  used Little-Endian */
/*skinny portorol  used Little-Endian */
/*skinny portorol  used Little-Endian */
/*skinny portorol  used Little-Endian */
/*skinny portorol  used Little-Endian */
/*skinny portorol  used Little-Endian */
/*skinny portorol  used Little-Endian */
/*skinny portorol  used Little-Endian */
/*skinny portorol  used Little-Endian */
/*skinny portorol  used Little-Endian */
/*skinny portorol  used Little-Endian */
/*skinny portorol  used Little-Endian */
extern FILE* skinny_log_fp;
#define SKINNY_LOG_FILE "/home/root/hzivy-skinny.log"
#if 0
#define skinny_log(fmt,...)  \
    _logger_file2(skinny_log_fp,SKINNY_LOG_FILE ,__func__,__LINE__,fmt,##__VA_ARGS__);  
#endif
#define skinny_log(fmt,...)  \
    _logger_file2(main_log_fp,MAIN_LOG_FILE,__func__,__LINE__,fmt,##__VA_ARGS__);

#define skinny_log_err(fmt,...)  \
            skinny_log("ERROR|"fmt,##__VA_ARGS__); 

enum skinny_session_state
{
        SESSION_K,
};


struct skinny_frame
{
  int from_server;// 1  yes (this is respo pkt), 0 no. 0 is to server. this is request pkt.
  char* line;
  char*  sip_msg_body;

  //struct sip_msg_header msg_hdr;
  u8 body_sdp;

  u16    rtp_port;//不知道是src dest.
  struct in_addr rtp_ip;
  //struct session_info* ss;

  enum skinny_session_state state;
};
typedef struct skinny_callReference_info
{


	struct list_head node;
    //char call_id[32]; 
    u32 			call_id;
   // u32   callReference; //for skinny;
    /* 如何判断calling? 如何说INVATE的IP层srcIP == sdp.
    connection IP.  this ip 就是calling. */
  //  struct  person calling;
  //  struct  person called;
    
    int 			mode; /* call direction   */ // 1是主叫，2是被叫。
    char    		called_group_number[64];
    
    char           	called_number[64];
    char           	calling_number[64];
   // pthread_t 		rtp_sniffer_tid;

    
    int 			skinny_state;//1 = ;2=onHOOK(挂机)
    int 			skinny_callstate_connected;
    u32 			skinny_serial_no;
    struct list_head skinny_media_list;
    int         skinny_media_list_num;
    int         bingxi_flag;

}skinny_callRefer;

typedef struct skinny_media_info_st //与信令协议 sip ,skinny无关。是更高一级的应用数据。把从信令中得到的信息保存于此。
{
    struct list_head 			node;


    //char passThruPartyID[32]; 
	u32 						passThruPartyID;


    skinny_callRefer* 			pfather;
     
	struct session_info      session_comm_info;
}skinny_media_info; /* 用于记录本次通信的两者的ip, port, 电话号码，用户名等等。*/

pthread_t sniffer_skinny_start(void);

#if 0
static const value_string DCallState[] = {
  { 0x00000, "Idle" },
  { 0x00001, "OffHook" },
  { 0x00002, "OnHook" },
  { 0x00003, "RingOut" },
  { 0x00004, "RingIn" },
  { 0x00005, "Connected" },
  { 0x00006, "Busy" },
  { 0x00007, "Congestion" },
  { 0x00008, "Hold" },
  { 0x00009, "CallWaiting" },
  { 0x0000a, "CallTransfer" },
  { 0x0000b, "CallPark" },
  { 0x0000c, "Proceed" },
  { 0x0000d, "CallRemoteMultiline" },
  { 0x0000e, "InvalidNumber" },
  { 0x0000f, "HoldRevert" },
  { 0x00010, "Whisper" },
  { 0x00011, "RemoteHold" },
  { 0x00012, "MaxState" },
  { 0x00000, NULL }
};
#endif
#define SKINNY_CALLSTATE_ONHOOK   0x02 //表示挂机。

#define SKINNY_CALLSTATE_RING_OUT  0x03
#define SKINNY_CALLSTATE_RING_IN  0x04
#define SKINNY_CALLSTATE_CONNECTED 0x05
#define SKINNY_CALLSTATE_Proceed   0x0c

#endif //_SNIFFER_SKINNY_H

