/******************************************
*
* 本文件的程序主要是用来抓 SIP等报文。
* 本程序抓sip的报文，并解析出sip里的call-id,以此作为key,把pkt的过程放到
一个session中，session放到一个全局的链表中。
跟踪每个session的从生到死的过程。最后free session.

* 
*******************************************/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <arpa/inet.h>
#include "log.h"

#include <pthread.h>    

#include "sniffer_lib.h"  


#include "config.h"
#include "linux-utils.h"
#include "wake_utils.h"
#include "sniffer_sip.h"
#include "str_lib.h"
#include "upload.h"

#include "sniffer_rtp.h"

extern struct config_st g_config;

FILE* sip_log_fp = NULL;
#define SIP_LOG_FILE "/home/root/hzivy-sip.log"
#define sip_log(fmt,...)  \
    _logger_file2(sip_log_fp,SIP_LOG_FILE,__func__,__LINE__,fmt,##__VA_ARGS__);  


#define sip_log_err(fmt,...)  \
						sip_log("ERROR|"fmt,##__VA_ARGS__); 

/**************************session lib end ****************************/
/*
sniffer_handle_sip 一个包一个包地进行处理。
每抓一个包被调用一次。

struct pcap_pkthdr  
{  
    struct timeval ts; // 抓到包的时间  
    bpf_u_int32 caplen; // 表示抓到的数据长度  
    bpf_u_int32 len; // 表示数据包的实际长度  
}  


*/
/****************************************** check and parse **************************************/


// SIP包内容标记
#define SIPTAGANDVERSION1 "SIP/2.0"		// 回应, 在第一行开始位置
#define SIPTAGANDVERSION2 " SIP/2.0"	// 请求, 在第一行结束位置
// SIP包结束标记
#define SIPPACKENDTAG "\r\n\r\n"
#define SIPSDPPACKENDTAG "\r\n"

/* 在一行的最后加个\0,\r\n-->\0 然后返回下一行。 */
char* split_line_next(char* l)
{
	char* next = strstr(l,SIPSDPPACKENDTAG);
	if(next == NULL)
		return next;
	next[0] = 0;
	next+=2;
	return next;
}
char** parse_tokens(char* src,int* count)
{
    char* array[100] = {0};
    char** path = NULL;
    int i = 0;
    char* p = NULL;
    char* in = src;
    char seps[] = " ";
    do{
        p = strtok(in,seps);
        if(p)
        {
            array[i] = p;
            i++;
            if(i >=100)
                break;
        }
        in = NULL;
    }while(p);
    path = (char**)malloc(sizeof(char*)*(i+1));
    if(!path)
        return NULL;
    memset(path,0,sizeof(char*)*(i+1));
    memcpy(path,array,sizeof(char*)*i);
    *count = i;
    return path;
}
#if 0
int __parse_line(char* line,char**key,char** v)
{
	
	char *pKey = NULL;
	char *pV = NULL;
	char seps[] = ":";
	static char nullBuf[] = "";
	pKey = strtok(line, seps);
	if(pKey)
	{
    	pV = strtok(NULL, seps);
    	if(pV == NULL)
    	{
    		pV = nullBuf;
    	}
	}
	else
	{	
		return -1;
	}

	pKey = skip_space(pKey);
	pV = skip_space(pV);
	*v = pV;
	*key = pKey;
	return 0;
}
#endif
//从 SDP 报文里c=中找到 IP信息。
int parse_sdp_connection_info(char* p, struct sip_pkt* sp)
{
    int count;
    char** media_ele;

    media_ele = parse_tokens(p,&count);
    if(media_ele != NULL && count >= 3){
        sip_log("find the ip info from conection of sdp : %s %s %s \n",
        media_ele[0],media_ele[1],media_ele[2]);
       inet_aton(media_ele[2], &sp->rtp_ip );
    }
    else
    {
        sip_log_err("failed \n");
    }
    FREE(media_ele);

	return 0;
	
}
int parse_sdp_media_dest(char* p,struct sip_pkt* sp)
{
    //find port号
    // media_type Media_port Medai_protocol fromat format 
    int count;
    char** media_ele;
    media_ele = parse_tokens(p,&count);
    if(media_ele != NULL && count >= 2){
        sip_log("find the  port info from media of sdp : %s %s \n",media_ele[0],media_ele[1]);
        sp->rtp_port = atoi(media_ele[1]);
        if (strcmp(media_ele[0],"audio") != 0)
        {
            sip_log_err("media type : %s\n",media_ele[0]);
            FREE(media_ele);
            return 1;
        }
    }
    else
    {        
        FREE(media_ele);
        return -1;
    }
    FREE(media_ele);
    return 0;
}
char* __find_msg_body_key(const char* src,const char* key,int* v_len)
{
    return find_key_from_line(src,key,v_len,NULL);

}
/**
从src中找到key，然后把key后面的内容copy到dest中。
**dest 返回已经copy好的内容的地址。
**/
const char* __parse_msg_heade_body_str_element
(const char* src,const char* key,char** dest)
{
    int len=0;
    char* v;
    v = __find_msg_body_key(src,key,&len);
    if(v){
    
        *dest = strndup(v,len);
	    sip_log(" %s=%s \n",key,*dest);
    }
    else
    {
	    sip_log(" not find %s\n",key);
        
    }
    return v;
}
int parse_msg_body(struct sip_pkt* sp)
{
	int ret = 0;
	parse_msg_body_sdp_media_connect(sp);
}
/*
这个函数有问题，
SDP报文中有多组(media connect) 如audio和video。
还有通信两方的信息。

它只从sdp里解析出了第一组 audio （media和connect info）。
一般而言 第一组audio是我们最想要的。
*/
int parse_msg_body_sdp_media_connect(struct sip_pkt* sp)
{
    
    char* b = sp->sip_msg_body;
    char* media_line = NULL;
    const char* origin_media_line;
    char* connect_line = NULL;
    const char* origin_connect_line;
    int ret;
    int offset;
    int flag = 0;
    
	//printf("%s:%d \n",__func__,__LINE__);
    origin_media_line = __parse_msg_heade_body_str_element(b,"m=",&media_line);
	//printf("%s:%d \n",__func__,__LINE__);

start:
    if(media_line == NULL)
    {
        sip_log_err("not find media line\n");
        return -1;
    }
    ret = parse_sdp_media_dest(media_line,sp);
    if(ret == 0)
    {
        sip_log("find media line and the audio \n");
        goto end;
    }
    else if(ret == -1){
        sip_log_err("parse media element failed\n");
        FREE(media_line);
        return -1;
    }
    else if(ret == 1)
    {
        flag =1;
        sip_log_err("reparse next media line \n");
        offset = strlen(media_line);
        FREE(media_line);
        origin_media_line = __parse_msg_heade_body_str_element
            (origin_media_line+offset,"m=",&media_line);
        goto start;    
    }
end:
    if(flag == 1)
    {
        offset = strlen(media_line);
      //  printf("%s \n",origin_media_line+offset);
        origin_connect_line = __parse_msg_heade_body_str_element
            (origin_media_line+offset,"c=",&connect_line);
        ret = parse_sdp_connection_info(connect_line,sp);
        FREE(connect_line);
    }
    else
    {
        origin_connect_line = __parse_msg_heade_body_str_element
            (b,"c=",&connect_line);
        ret = parse_sdp_connection_info(connect_line,sp);
        FREE(connect_line);
    }
    return 0;
}
#if 0
int parse_msg_body(struct sip_pkt* sp)
{
    //SIP body, 也许可以包含各种协议数据，SDP是其中一种，我们主要是解析SDP.
    //find "m="
    /*
       m= audio 10028 RTP/AVP 112 98 9 8 0 18 97 101
       c= IN IP4 172.25.16.10
       m=一行10028是port, 
       c=行中IP是  RTP的ip.
       
        */
     sip_log("DEBUG here\n");
    char* b = sp->sip_msg_body;
    const char* key="m=";
    const char* key2="c=";
    char* p = strstr(b,key);
    if(p != NULL)
    {
        p+=2;
        parse_sdp_media_dest(p,sp);
    }
    
    p = strstr(b,key2);
    if(p != NULL)
    {
        p+=2;
        sip_log("DEBUG here\n");
        parse_sdp_connection_info(p,sp);
    }
    return 0;
}
#endif
//return value and length of value
char* __find_msg_hdr_key(const char* mh,const char* key,int* v_len)
{
    return find_key_from_line(mh,key,v_len,": ");

}
char* __parse_msg_header_str_element(const char* src,const char* key,char** dest)
{
    int len=0;
    char* v;
    v = __find_msg_hdr_key(src,key,&len);
    if(v){
    
        *dest = strndup(v,len);
	    sip_log(" %s=%s \n",key,*dest);
    }
    else
    {
	    sip_log(" not find %s\n",key);
        
    }
    return *dest;
}
int __parse_msg_header_element(char* src,char* key)
{

	char* v;
    int len;
    v = __find_msg_hdr_key(src,key,&len);
    if(v != NULL)
    {
        sip_log(" %s==<%d>\n",key,v);
    }
    else{
        sip_log_err("not find %s failed \n",key);
		return -1;
    }
	return 0;
}
int parse_sip_number(char* src,char** dest)
{
    char* p;
    char* e;
    if(*dest)
        return 0;
    p = strstr(src,"<sip:");
    if(p)
    {
        e = strchr(p,'@');
        if(e)
        {
            p+=strlen("<sip:");
            *e=0;
            *dest = strndup(p,e-p);
            *e='@';
        }
    }
    return 0;
}
int parse_msg_header(char* mh,struct sip_pkt* sp)
{
	const char* key = "Content-Length";
	const char* key_Content_Type = "Content-Type";
//	const char* call_id = "Call-ID";
	
	char* v;
	int len;

	if(sp->msg_hdr.call_id == NULL)
        v = __parse_msg_header_str_element(mh,"Call-ID",&sp->msg_hdr.call_id);
    
	if(sp->msg_hdr.from == NULL)
	{
        v = __parse_msg_header_str_element(mh,"From",&sp->msg_hdr.from);
        if(sp->msg_hdr.from != NULL)
        {
            parse_sip_number(sp->msg_hdr.from,&sp->msg_hdr.from_number);
            sip_log("calling number: <%s> \n",sp->msg_hdr.from_number);
        }
    }
	if(sp->msg_hdr.to == NULL){
        v = __parse_msg_header_str_element(mh,"To",&sp->msg_hdr.to);
        if(sp->msg_hdr.to)
        {
            parse_sip_number(sp->msg_hdr.to,&sp->msg_hdr.to_number);
            sip_log("called number: <%s> \n",sp->msg_hdr.to_number);
        }
	}
	if(sp->msg_hdr.date == NULL)
        v = __parse_msg_header_str_element(mh,"Date",&sp->msg_hdr.date);

	if(sp->msg_hdr.user_agent == NULL)
        v = __parse_msg_header_str_element(mh,"User-Agent",&sp->msg_hdr.user_agent);

	if(sp->msg_hdr.cseq == NULL){
        v = __parse_msg_header_str_element(mh,"CSeq",&sp->msg_hdr.cseq);
        if(sp->msg_hdr.cseq != NULL)
        {
            if(strstr(sp->msg_hdr.cseq,"REGISTER"))
                sp->session_ok_cseq_register = 1;
        }
    }
	if(sp->msg_hdr.remote_party_id == NULL){
			__parse_msg_header_str_element(mh,"Remote-Party-ID",&sp->msg_hdr.remote_party_id);
			if(sp->msg_hdr.remote_party_id != NULL)
			{
				parse_sip_number(sp->msg_hdr.remote_party_id,&sp->msg_hdr.remote_party_id_phone_number);
	            sip_log("Remote-Party-ID number: <%s> \n",sp->msg_hdr.remote_party_id_phone_number);
			}
		}


    v= __find_msg_hdr_key(mh,key,&len);
	if(v != NULL)
	{
	    sp->msg_hdr.content_length = atoi(v);
	    sip_log("%s== %d \n",key,sp->msg_hdr.content_length);
	}
	else
	    sip_log_err("not find %s failed \n",key);

    v= __find_msg_hdr_key(mh,key_Content_Type,&len);
    if(v!= NULL)
    {
	    if(!strncmp(v,"application/sdp",len))
        {
            sp->body_sdp = 1; //this pkt is SDP, I will parse this msgbody.and this body is SDP 
            sip_log("find the application/sdp, the sip body have sdp  \n");
        }
    }
    else
        sip_log_err("not find %s \n",key_Content_Type);

    return 0;
}

int parse_sip_start_line_request_state(char* l,struct sip_pkt* sp)
{
    const char* key2  = "INVITE ";
    char* p;
    sip_log("start line %s \n",l);
    p = strstr(l,key2);
    if(p)
    {
        sp->state = SS_INVATE;
        return 0;
    }
    p = strstr(l,"ACK ");
     if(p)
    {
        sp->state = SS_ACK;
        return 0;
    } 
    
    p = strstr(l,"BYE ");
     if(p)
    {
        sp->state = SS_BYE;
        return 0;
    }   
    return 0;
}
int parse_sip_start_line_response_state(char* l,struct sip_pkt* sp)
{
    const char* key2  = "100 Trying";
    char* p;
    sip_log("start line %s \n",l);
    p = strstr(l,key2);
    if(p)
    {
        sp->state = SS_TRYING;
        return 0;
    }
    p = strstr(l,"200 OK");
     if(p)
    {
        sp->state = SS_OK;
        return 0;
    } 
    p = strstr(l,"Ringing ");
     if(p)
    {
        sp->state = SS_RINGING;
        return 0;
    }   
    return 0;
}

int pase_sip_start_line(char* l,struct sip_pkt* sp)
{
	const char* sip_key = " SIP/2.0";
	const  char* sip_key1 = "SIP/2.0 ";
//	const char* key2  = "INVITE ";
	//struct session_info* ss = NULL;
	char* p = strstr(l,sip_key);
	if(p != NULL)
	{
	    sip_log("this pkt is request \n");
		sp->type = 1;  //request;
	}
	else if((p = strstr(l,sip_key1)) != NULL)
	{
	    sip_log("thsi pkt is response \n");
	    sp->type = 2;// response
	}
	else
	    return -1;
	    
    if(sp->type == 1 )
       parse_sip_start_line_request_state(l,sp);
   else if(sp->type == 2)
       parse_sip_start_line_response_state(l,sp);
	return 0;
}

void create_session(struct sip_pkt* spkt_p)
{
     struct session_info* ss = si_find_session(spkt_p->msg_hdr.call_id);
     if(!ss)
     {
        _create_session(spkt_p);
     }
     else
     {
        sip_log("INVATE this session (callid %s) is exist\n",spkt_p->msg_hdr.call_id);
     }
}
void _create_session(struct sip_pkt* spkt_p)
{
    struct session_info* ss = si_new_session();
    if(ss)
    {
    /*
    如果是一个INVITE报文，报文中还有body(SDP)，则这个报文来自主叫。
    rtp_ip是主叫的 ip.
    
    */
        if(spkt_p->state == SS_INVATE)
        {
            if(spkt_p->body_sdp)
                ss->mode = SS_MODE_CALLING;
            else
                ss->mode = SS_MODE_CALLED;
        }   
        ss->call_id = strdup(spkt_p->msg_hdr.call_id);
        if(ss->mode == SS_MODE_CALLING)
        {
            ss->calling.ip.s_addr = spkt_p->rtp_ip.s_addr;
            ss->calling.port= spkt_p->rtp_port;
            strncpy(ss->calling.number,spkt_p->msg_hdr.from_number,sizeof(ss->calling.number));
        }
        sip_log("I create new session !!!!!!!!! callid %s \n",ss->call_id);
    }
	else
	{
		sip_log_err("ss is not created!\n");
	}
}
int get_session_start_time(struct sip_pkt* spkt_p, struct session_info* ss)
{
    char* c =  spkt_p->msg_hdr.date;
    struct tm ttm;
    if(!c)
        return -1;
    strptime(c,"%a, %d %B %Y %T %Z",&ttm);
    sip_log(" I get time: acstime %s  \n",asctime(&ttm));
    memcpy(&ss->ring_time,&ttm,sizeof(ttm));
    return 0;
}

int __get_ok_pkt_cseq(struct sip_pkt* spkt_p)
{

    char* p=    spkt_p->msg_hdr.cseq;
    char* p1;
    int cseq_key;
    if(p != NULL)
        return 0;//unkown;
    p1 = strchr(p,' ');
    *p1 = 0;
    cseq_key = atoi(p);
    *p1 = ' ';
    sip_log("I get a ok's cseq %d\n",cseq_key);
    return cseq_key;
}


void _update_session_for_ok(struct sip_pkt* spkt_p)
{
    struct session_info* ss;
//    int ok_cseq;
    if(spkt_p->session_ok_cseq_register == 1)
        return;
        
    if(spkt_p->msg_hdr.call_id)
    {
       
        ss = si_find_session(spkt_p->msg_hdr.call_id);
       
        if(ss != NULL)
        {
        
            sip_log("I find the session (callid %s) \n",ss->call_id);
            if (ss->mode == SS_MODE_CALLED)
            {
                if(spkt_p->body_sdp)
                {
                    ss->called.ip.s_addr = spkt_p->rtp_ip.s_addr;
                    ss->called.port = spkt_p->rtp_port;
                    //ss->called.number =strdup(spkt_p->msg_hdr.to_number);
                    if(spkt_p->msg_hdr.remote_party_id_phone_number)
                    {
                    	strncpy(ss->called_group_number,ss->called.number,
							sizeof(ss->called_group_number));
                    	strncpy(ss->called.number,
							spkt_p->msg_hdr.remote_party_id_phone_number,
							sizeof(ss->called.number));
                    }
                    else
					{
                    	strncpy(ss->called.number,
                    		spkt_p->msg_hdr.to_number,
                    		sizeof(ss->called.number));
                    
                    }
                    //strncpy(ss->called.number,spkt_p->msg_hdr.to_number,sizeof(ss->called.number));
                }
            }
            else if  (ss->mode ==SS_MODE_CALLING)
            {
                get_session_start_time(spkt_p,ss);
                if(spkt_p->body_sdp)
                {
                    ss->called.ip.s_addr = spkt_p->rtp_ip.s_addr;
                    ss->called.port = spkt_p->rtp_port;
                    if(spkt_p->msg_hdr.remote_party_id_phone_number)
                    {
                    /* 把原来的called number放到called_group_number里，这是被叫的组号。 */
                    	strncpy(ss->called_group_number,ss->called.number,
							sizeof(ss->called_group_number));
                    	strncpy(ss->called.number,
							spkt_p->msg_hdr.remote_party_id_phone_number,
							sizeof(ss->called.number));
                    }
                    else
					{
                    	strncpy(ss->called.number,
                    		spkt_p->msg_hdr.to_number,
                    		sizeof(ss->called.number));
                    
                    }
					if(ss->rtp_sniffer_tid == 0){
                    
                        sip_log("this sip session (%s) 's rtp not exist, setup rtp pthread\n",
                                ss->call_id);
                        ss->rtp_sniffer_tid = setup_rtp_sniffer(ss);
                    }
                    else
                    {
                        sip_log("this sip session (%s) 's rtp is exist!\n",
                                ss->call_id);
                    }
                }
            }
            else
            {
                sip_log_err("session (callid %s)  not update any info!\n",spkt_p->msg_hdr.call_id);
                
            }
            
            
        }
        else
        {
            
            sip_log_err("I not find the session (callid %s) \n",spkt_p->msg_hdr.call_id);
        }
    }
}

void _update_session(struct sip_pkt* spkt_p)
{
    struct session_info* ss;
    if(spkt_p->msg_hdr.call_id)
    {
       
        ss = si_find_session(spkt_p->msg_hdr.call_id);
       
        if(ss != NULL)
        {
        
            sip_log("I find the session (callid %s) \n",ss->call_id);
            if (ss->mode == SS_MODE_CALLED && spkt_p->state == SS_ACK)
            {
  //              ss->state = spkt_p->state;
                get_session_start_time(spkt_p,ss);
                if(spkt_p->body_sdp)
                {
                    ss->calling.ip.s_addr = spkt_p->rtp_ip.s_addr;
                    ss->calling.port = spkt_p->rtp_port;
                   
                    
                    strncpy(ss->calling.number,spkt_p->msg_hdr.from_number,sizeof(ss->calling.number));
                    sip_log("I find the session (callid %s) calling number: %s \n",
                            ss->call_id,ss->calling.number);
                            
                     if(ss->rtp_sniffer_tid == 0)
                     {
                        sip_log("this sip session (%s) 's rtp not exist, setup rtp pthread\n",
                                ss->call_id);
                        ss->rtp_sniffer_tid = setup_rtp_sniffer(ss);
                    }
                    else
                    {
                        sip_log("this sip session (%s) 's rtp is exist!\n",
                                ss->call_id);
                    }
                }
                else
                {     
                    sip_log("I find the session (callid %s) no body \n",
                        ss->call_id);
      
                }
            }
         
            else
            {
                sip_log_err("session (callid %s)  not update any info!\n",spkt_p->msg_hdr.call_id);
                
            }
            
            
        }
        else
        {
            
            sip_log_err("I not find the session (callid %s) \n",spkt_p->msg_hdr.call_id);
        }
    }
}


void _close_session(struct sip_pkt* spkt_p)
{
    struct session_info* ss;
    if(spkt_p->msg_hdr.call_id)
    {
        ss = si_find_session(spkt_p->msg_hdr.call_id);
        if(ss != NULL)
        {
            sip_log("I find the session (callid %s),and close it. \n",ss->call_id);
 //           ss->state = spkt_p->state;
            
            close_rtp_sniffer(ss);
        }
        else
        {
            sip_log_err("not find the session (callid %s) \n",spkt_p->msg_hdr.call_id);
            return;
        }
        si_del_session(ss);
    }
    else
    {
        sip_log_err(" this spkt not callid ,so bad \n");
    }

}
void sync_session(struct sip_pkt* spkt_p)
{
    sip_log("pkt state %d \n",spkt_p->state);
    switch(spkt_p->state)
    {
        case SS_INVATE:
            create_session(spkt_p);
        break;
        case SS_ACK:
        _update_session(spkt_p);
        break;
        case SS_OK:
        _update_session_for_ok(spkt_p);
        break;
        case SS_BYE:
        _close_session(spkt_p);
        break;
        case SS_ERROR:
        case SS_TRYING:
        case SS_RINGING:
        default:
        break;
    }
}
/**********************************************************************/
void __free_sip_pkt(struct sip_pkt* spkt_p)
{
    struct sip_msg_header* msg_hdr = &spkt_p->msg_hdr;

    FREE(msg_hdr->contant);
    FREE(msg_hdr->expires);
    FREE(msg_hdr->to);
    FREE(msg_hdr->call_id);
    FREE(msg_hdr->via);
    FREE(msg_hdr->from);
    FREE(msg_hdr->cseq);
    FREE(msg_hdr->user_agent);
    FREE(msg_hdr->Max_forwards);
    FREE(msg_hdr->allow);
    FREE(msg_hdr->date);
    FREE(msg_hdr->from_number);
    FREE(msg_hdr->to_number);
	
    FREE(msg_hdr->remote_party_id);
    FREE(msg_hdr->remote_party_id_phone_number);    
}
//int handle_sip_pkt_content( struct udphdr* udph)
int handle_sip_pkt_content(void* sip_payload,int len)
{
	//char* sip = (u8*)(udph+1);
	
	struct sip_pkt spkt;
	struct sip_pkt* spkt_p = &spkt;
	char* mesg_header;
	char* mesg_body;
	//char* sip = malloc(htons(udph->len));
	char* sip = malloc((len));
	if(sip == NULL)
		return -1;
	memcpy(sip,(u8*)sip_payload,len);

	memset(&spkt,0,sizeof(spkt));

    mesg_header = split_line_next(sip);
    if(mesg_header == NULL)
        return -1;
#if 1
	mesg_body = strstr(mesg_header,SIPPACKENDTAG);
    if(mesg_body == NULL){
        sip_log("sip not messgae body \n");
        
    }
    else{
        mesg_body[2] = 0;
        mesg_body[3] = 0;
        spkt_p->sip_msg_body = mesg_body+strlen(SIPPACKENDTAG);
    }
#endif
    //三大块切分完成。
    //下面各处理各的。
    //1, start-line
	spkt_p->line = sip;
	
    sip_log("[%s:%d] spkt_p->line %s \n" ,__func__,__LINE__,spkt_p->line);
	pase_sip_start_line(spkt_p->line,spkt_p);
	
	//2, message header
	
	if((mesg_header[0] != '\r')&&(mesg_header[1] != '\n'))
	{
		parse_msg_header(mesg_header,spkt_p);
	}
	//3, message body.
	
	if ((spkt_p->body_sdp)&&(spkt_p->sip_msg_body))
	    parse_msg_body(spkt_p);


	sync_session(spkt_p);
	
	__free_sip_pkt(spkt_p);
	free(sip);//add it ,2017.11.12 --需要再仔细检查它。
	return 0;
	
}
#if 0

/*
send_sip_pkt:

把SIP报文也发给upload.
*/

static void send_sip_pkt(struct iphdr* iph,struct udphdr* udph)
{
    char buf[2000] = {0};

    u8* rtp_pkt = (u8*)(udph+1);
    int rtp_len = ntohs(udph->len);
    
    struct phone_msg* msg;
    
    struct talking_mesg* tm;
    int len;
    int ret;
    msg = ( struct phone_msg*)buf;
    msg->event = SIP_PKT;
    len = sizeof(struct phone_msg);

    len = rtp_len + sizeof(struct phone_msg) +sizeof( struct talking_mesg);
    if(len > sizeof(buf))
        sip_log_err("total len %d > 2000 \n",len);

    
    tm = (struct talking_mesg*)msg->data;

    tm->phone_sender_ip = iph->saddr; /* 本来就是网络序 */
    tm->phone_sender_port = udph->source;
    tm->phone_rcv_ip = iph->daddr;
    tm->phone_rcv_port = udph->dest;
    tm->lenth = rtp_len;
    
    memcpy(tm->data,rtp_pkt,rtp_len);
    
#if 0    
    ret = uploader_push_msg(msg, len);
    if(ret != 0)
        log_err("uploader_push_msg (SIP_PKT) failed,ret %d \n",ret);

#endif    
}
#endif
/***************************************
处理被抓到的SIP报文。
****************************************/
static void sniffer_handle_sip(u_char * user, const struct pcap_pkthdr * packet_header, const u_char * packet_content)
{
    int ret = 0;
    
	const struct pcap_pkthdr* phdr = packet_header;
	struct iphdr* iph = NULL;
	struct udphdr* udph = NULL;
	
	ret = check_iphdr(phdr,packet_content,&iph);
	if(ret != 0)
		goto error;
	if(iph->protocol == IPPROTO_UDP)
	{
	    if(0 != check_udp(iph,&udph))	
		    goto error;
	
        //send_sip_pkt(iph,udph);/* 把sip报文转给upload一份。 */
	    handle_sip_pkt_content((void*)(udph+1),htons(udph->len)-8);
	    return;
	}
	if(iph->protocol == IPPROTO_TCP)
	{
	    struct tcphdr* th = NULL;
	
	    if(0 != check_tcp(iph,&th))	{
            sip_log_err("check_tcp error\n");
		    goto error;
	    }
	    {
    	    u8* tcp_payload = ((u8*)th)+(th->doff * 4);
    	    int tcp_len = ntohs(iph->tot_len)- iph->ihl*4;
    	    int tcp_payload_len = tcp_len - (th->doff * 4);
    	    if(tcp_payload_len == 0)
    	    {
    		    sip_log("this frame no tcp payload\n\n");
    		    return;
    	    }
            //send_sip_pkt(iph,udph);/* 把sip报文转给upload一份。 */
	        handle_sip_pkt_content(tcp_payload,tcp_payload_len);
	    }
	    return;
	}
error:
	return;
}

/*
这里有两个抓包的过程，一是只抓 sip, 另一个抓RTP
这里就需要两个线程。一个线程是常驻，用于抓SIP 
另一个线程是动态的，用于抓RTP.

*/
int sniffer_loop_sip( pcap_t *p)
{
	 pcap_loop( p,-1,sniffer_handle_sip,(u_char*)NULL);
	 return 0;
}
/***********************************************
线程启动与执行体
************************************************/
/*
sniffer_sip_loop:
打开pcap_file,进入抓包执行体。

*/
void* sniffer_sip_loop(void* arg)
{

	char filter[200] = {0};
    //printf("%s:%d \n",__func__,__LINE__);
    pcap_t* pd=0;
    #if 1
	//pd = open_pcap_file("enp0s3",65535,1,0);
	pd = open_pcap_file("eth0",65535,1,0);
	if(pd == NULL)
	{

		sip_log_err("open_pcap_file failed ! \n");
		exit(1);
	}

	sprintf(filter," host %s and port %d ",
	inet_ntoa(g_config.call.ip),
	g_config.call.port);
	sniffer_setfilter(pd,filter);
	sip_log("filter: %s\n",filter);
#endif
    
    sip_log("sniffer_loop_sip  \n");

	while(1)
	{
		sniffer_loop_sip(pd);
	}
}


pthread_t __sniffer_sip_start(void)
{
	pthread_t tid;
	
   // printf("%s:%d \n",__func__,__LINE__);
	if(pthread_create(&tid,NULL,sniffer_sip_loop,NULL))
	{
		sip_log_err("create  sniffer_sip_loop failed\n");
		return -1;
	}

   // printf("%s:%d \n",__func__,__LINE__);

	return tid;

}




pthread_t sniffer_sip_start(void)
{
	pthread_t tid;

    sip_log_fp = fopen(SIP_LOG_FILE,"a+");
    if(sip_log_fp == NULL){
        printf("sip log file not open \n");
        exit(1);
    }
	tid = __sniffer_sip_start();
    sip_log("%s:%d tid %d\n",__func__,__LINE__,tid);
	return tid;

}

