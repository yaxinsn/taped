
#ifndef SNIFFER_SIP_H

#define SNIFFER_SIP_H 
	
#include <pthread.h>
#include "sniffer_lib.h"
#include "list.h"
#include "phone_session.h"
#include <time.h>




struct sip_msg_header
{
	char* contant;
	char* expires;
	char* from; //from 是主叫的number
	char* to;  //被叫number
	char* call_id;
	char* via;
	
	char* cseq;
	char* user_agent;
	char* Max_forwards;
	char* allow;
	char* date;
	int content_length;
	char* from_number; //calling number;
	char* to_number;   //called number;

	
	char* remote_party_id;
	char* remote_party_id_phone_number;
};
enum sip_session_state
{
    SS_ERROR = 0,
    SS_INVATE = 1,
    SS_TRYING = 2,
    SS_RINGING = 3,
    SS_OK,
    SS_ACK,
    SS_BYE,

    
};

enum REQ_TYPE
{
	REQ_REG = 1,
	REQ_INVITE,
	REQ_ACK,
	REQ_BYE,
	REQ_OPTIONS,
	REQ_CANCEL,

	
};
enum RES_TYPE
{
    RES_TRYING = 1,
    RES_UNAUTH,
    RES_OK,
    RES_SERVER_UNAVAI,
    RES_RINGING,

};
//struct session_info;

struct sip_pkt
{
	int type;// 1 request 2 response
	//enum REQ_TYPE request_type; //  
	//enum RES_TYPE response_type;
	char* line;
	char*  sip_msg_body;
	
	struct sip_msg_header msg_hdr;
	u8 body_sdp;
	
	u16    rtp_port;//不知道是src dest.
    struct in_addr rtp_ip;
	//struct session_info* ss;
	
    enum sip_session_state state;
    int session_ok_cseq_register;
};



pthread_t sniffer_sip_start();

#endif

