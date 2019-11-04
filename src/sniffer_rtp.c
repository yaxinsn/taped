
/******************************************
说明:
本程序，会启动一个专用于抓RTP报文的线程。
由sniffer_sip来启动或是关闭线程。
把抓到的RTP报文按一定的要求，然后保存成文件。
***************************************/
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include "alaw.h"

#include "ulaw_codec.h"

#include "log.h"
#include "sniffer_rtp.h"
#include "upload.h"


#include "mixer.h"
#include "alaw_codec.h"

#include "curl_upload.h"

#include "phone_session.h"

extern struct config_st g_config;


struct rtp_ctx_t
{
    pthread_mutex_t head_lock;  //sync

    struct list_head rtp_head;
    u32     count;
    u32     increase;

};
struct rtp_ctx_t rtp_ctx;
int g_run_del_session_count = 0;

struct rtp_session_info* _rtp_new_session(void)
{
    struct rtp_session_info* rs = NULL;

    rs = (struct rtp_session_info*)malloc(sizeof(struct rtp_session_info));
    if ( rs == NULL)
        return NULL;
    bzero(rs,sizeof(struct rtp_session_info));
    rs->rtp_type = 1; ///  1 is reserved;
    pthread_mutex_lock(&rtp_ctx.head_lock);
    list_add(&rs->node,&rtp_ctx.rtp_head);
    pthread_mutex_unlock(&rtp_ctx.head_lock);
    rtp_ctx.count++;
    rtp_ctx.increase++;
    if(rtp_ctx.increase == 0)
    {
        rtp_ctx.increase = 1;
    }
    rs->my_thread_id =  rtp_ctx.increase;

    rs->exit_flag = 0;
    return rs;
}
static void _rtp_del_session(struct rtp_session_info* si)
{

    pthread_mutex_lock(&rtp_ctx.head_lock);
    g722_decode_release(si->g722dst_called);
    g722_decode_release(si->g722dst_calling);
    list_del(&si->node);
    rtp_ctx.count--;
    pthread_mutex_unlock(&rtp_ctx.head_lock);
    FREE(si);
    g_run_del_session_count++;
    if(g_run_del_session_count%20 == 0 )
    {
        log("### rtp_session count %d ###\n",rtp_ctx.count);
    }
    return;
}
struct rtp_session_info* rtp_find_session(void)
{
    struct rtp_session_info* p;
    struct rtp_session_info* n;
    struct list_head* rtp_head;
    pthread_t   thread_id = pthread_self();
    rtp_head = &rtp_ctx.rtp_head;

    list_for_each_entry_safe(p,n,rtp_head,node)
    {
        if(thread_id == p->thread_id)
        {
            return p;
        }
    }
    return NULL;
}
struct rtp_session_info* rtp_find_session_by_my_pthead_id(u32   my_thread_id)
{
    struct rtp_session_info* p;
    struct rtp_session_info* n;
    struct list_head* rtp_head;
    rtp_head = &rtp_ctx.rtp_head;

    list_for_each_entry_safe(p,n,rtp_head,node)
    {
        if(my_thread_id == p->my_thread_id)
        {
            return p;
        }
    }
    return NULL;
}

/****************************/

enum RTP_TYPE
{
    RTP_TYPE_PCMU = 0,//711u
    RTP_TYPE_PCMU_GSM = 3,
    RTP_TYPE_PCMU_G723,
    RTP_TYPE_PCMU_PCMA = 8, //711a
    RTP_TYPE_PCMU_G722 = 9,
    RTP_TYPE_PCMU_G729 = 18,

};

struct rtp_type_str
{
    enum RTP_TYPE type;
    const char* type_str;
};
struct rtp_type_str g_rtp_file_perfix[] =
{
    {RTP_TYPE_PCMU,"g711u"},
    {RTP_TYPE_PCMU_GSM,"gsm"},
    {RTP_TYPE_PCMU_G723,"g723"},
    {RTP_TYPE_PCMU_G722,"g722"},
    {RTP_TYPE_PCMU_G729,"g729"},
};

//#define RTP_TYPE_PCMU  0

#if defined(__LITTLE_ENDIAN_BITFIELD)
struct rttphdr{

    u8 source_id_count:4 ,
       extension:1 ,
       padding:1,
       version:2;
    u8 type:7,
       marker:1;
    u16 sequence_number;
    u32 timestamp;
    u32 synchronization_source_id;
}__attribute__  ((__packed__));

#elif defined (__BIG_ENDIAN_BITFIELD)
struct rttphdr{
    u8 version:2,
       padding:1,
       extension:1,
       source_id_count:4;

    u8 marker:1,
       type:7;
    u16 sequence_number;
    u32 timestamp;
    u32 synchronization_source_id;
}__attribute__  ((__packed__));

#else
#error  "Please fix <asm/byteorder.h>"
#endif

int upload_the_mix_file( struct rtp_session_info* n);
/**************************************************************/
u8* rtp_g722_decode(g722_decode_state_t* g722dst,char *src, int src_len, int* len)
{
	//*len = 0;


	if(NULL==src) return NULL;

	int samples = src_len;
	const uint8_t* uc_src=(const uint8_t*)src;


	*len = samples*2;
	u8* char_dst=malloc( sizeof(char)*(samples*2));
	if(char_dst == NULL)
	{
	    log_err("malloc err!\n");
	    return NULL;
	}
	memset(char_dst, 0, *len);
	int16_t *dst=(int16_t*)char_dst;


	*len = g722_decode((g722_decode_state_t*)g722dst, dst, uc_src, src_len);


	// g722_decode返回的长度应该是收int16_t类型计算的, 因此要*sizeof(int16_t) _ 相当于*2
	*len *= 2;

	return char_dst;
}
#if 0
static int session_talking_pkt_dec722
(struct rtp_session_info* rs,u8* payload, int payload_len,
   u8 rty_type,FILE* fp,g722_decode_state_t* g722_decode)
{
    int dest_g722_len;
    u8* dest_buf;
    //int mix_len;
//    bool ret;

    dest_buf = rtp_g722_decode(g722_decode,(char*)payload,payload_len,&dest_g722_len);
    if(dest_buf){
        fwrite(dest_buf,dest_g722_len,1,fp);
        free(dest_buf);

    }
    else
    {
        log_err("g722 decode error! \n");
        return -1;
    }


     return 0;
}

static int session_talking_pkt_dec711u
(struct rtp_session_info* rs,u8* payload, int payload_len,FILE* fp)
{
    int dest_g711u_len;
    u8* dest_buf;
//    int mix_len;
//    bool ret;

    dest_buf =  (u8*)ulawcodec_decode((char*)payload,  payload_len,&dest_g711u_len);

    if(dest_buf){
        fwrite(dest_buf,dest_g711u_len,1,fp);
        free(dest_buf);

    }
    else
    {
        log_err("g711u decode error! \n");
        return -1;
    }



     return 0;
}
static int session_talking_pkt_dec711a
(struct rtp_session_info* rs,u8* payload, int payload_len,FILE* fp)
{
    int dest_g711u_len;
    u8* dest_buf;
//    int mix_len;
//    bool ret;

    dest_buf =  (u8*)alawcodec_decode((char*)payload,  payload_len,&dest_g711u_len);

    if(dest_buf){
        fwrite(dest_buf,dest_g711u_len,1,fp);
        free(dest_buf);

    }
    else
    {
        log_err("g711a decode error! \n");
        return -1;
    }



     return 0;
}

static void session_talking(struct iphdr* iph,struct udphdr* udph,
    struct rtp_session_info* rs)
{
    u8* rtp_pkt = (u8*)(udph+1);
    int rtp_len = ntohs(udph->len)-8;
    u8* rtp_payload = NULL;
    struct rttphdr* rtp_hdr;
    rtp_hdr = (struct rttphdr*)rtp_pkt;

   // struct phone_msg* msg;
    rtp_payload = rtp_pkt+sizeof(struct rttphdr);
    if(rs->rtp_type == 1)
    {
        rs->rtp_type = rtp_hdr->type;

        log("get a rty_type firstly %d \n",rtp_hdr->type);
    }
    if(rs->rtp_type != rtp_hdr->type)
    {
        log_err("rtp pkt type %d , session rtp type %d\n",rtp_hdr->type,rs->rtp_type);

    }

    if(iph->saddr == rs->calling.ip.s_addr)
    {

        rs->calling_pkt_count++;
        if(rs->rtp_type == RTP_TYPE_PCMU_G722)
        session_talking_pkt_dec722(rs,rtp_payload,
            rtp_len-sizeof(struct rttphdr),rs->rtp_type,
            rs->save_calling_linear_fp,rs->g722dst_calling);
        else if(rs->rtp_type == RTP_TYPE_PCMU)
        {
            session_talking_pkt_dec711u(rs,rtp_payload,
            rtp_len-sizeof(struct rttphdr),
            rs->save_calling_linear_fp);

        }
        else if (rs->rtp_type == RTP_TYPE_PCMU_PCMA)
        {
            session_talking_pkt_dec711a(rs,rtp_payload,
            rtp_len-sizeof(struct rttphdr),
            rs->save_calling_linear_fp);

        }
        else
        {
            log_err("this pkt not a g722, g711u, I can't decode it \n");
            return;
        }
    }

    if(iph->saddr == rs->called.ip.s_addr)
    {

        rs->called_pkt_count++;
        if(rs->rtp_type == RTP_TYPE_PCMU_G722)
        {
            session_talking_pkt_dec722(rs,rtp_payload,
                rtp_len-sizeof(struct rttphdr),rs->rtp_type,
                rs->save_called_linear_fp,rs->g722dst_called);
        }
        else if(rs->rtp_type == RTP_TYPE_PCMU)
        {

            session_talking_pkt_dec711u(rs,rtp_payload,
            rtp_len-sizeof(struct rttphdr),
            rs->save_called_linear_fp);

        }
        else if(rs->rtp_type == RTP_TYPE_PCMU_PCMA)
        {

            session_talking_pkt_dec711a(rs,rtp_payload,
            rtp_len-sizeof(struct rttphdr),
            rs->save_called_linear_fp);

        }
        else
        {
            log_err("this pkt not a g722, g711u, I can't decode it \n");
            return;
        }
    }

}
#endif
//////////////////////////////////////////////////

static int session_talking_pkt_dec722_2
(struct rtp_session_info* rs,u8* payload, int payload_len,
   g722_decode_state_t* g722_decode, linear_buf* lb)
{
    int dest_g722_len;
    u8* dest_buf;
    //int mix_len;
//    bool ret;

    dest_buf = (u8*)rtp_g722_decode(g722_decode,(char*)payload,payload_len,&dest_g722_len);
    if(dest_buf){
        lb->len = dest_g722_len;
        lb->p_buf = dest_buf;
        //fwrite(dest_buf,dest_g722_len,1,fp);
        //free(dest_buf);

    }
    else
    {
        log_err("g722 decode error! \n");
        return -1;
    }


     return 0;
}

static int session_talking_pkt_dec711u_2
(struct rtp_session_info* rs,u8* payload, int payload_len,linear_buf* lb)
{
    int dest_g711u_len;
    u8* dest_buf;
 //   int mix_len;
//    bool ret;

    dest_buf =  (u8*)ulawcodec_decode((char*)payload,  payload_len,&dest_g711u_len);

    if(dest_buf){
        lb->len = dest_g711u_len;
        lb->p_buf = dest_buf;

    }
    else
    {
        log_err("g711u decode error! \n");
        return -1;
    }



     return 0;
}
static int session_talking_pkt_dec711a_2
(struct rtp_session_info* rs,u8* payload, int payload_len,linear_buf* lb)
{
    int dest_g711u_len;
    u8* dest_buf;
   // int mix_len;
   // bool ret;

    dest_buf =  (u8*)alawcodec_decode((char*)payload,  payload_len,&dest_g711u_len);

    if(dest_buf){
        lb->len = dest_g711u_len;
        lb->p_buf = dest_buf;

    }
    else
    {
        log_err("g711a decode error! \n");
        return -1;
    }



     return 0;
}

static linear_buf* session_talking_pkt_to_linear
(struct rtp_session_info* rs,u8* payload, int payload_len,
   u8 rty_type,g722_decode_state_t* g722_decode)
{
   // int dest_g722_len;
   // u8* dest_buf;
 //   int mix_len;
    int ret;
    linear_buf*   lb;
    lb = malloc(sizeof(linear_buf));
    if(lb == NULL)
    {
        log_err("malloc lb is failed \n");
        return NULL;
    }
    memset(lb,0,sizeof(linear_buf));
    if(rs->rtp_type == RTP_TYPE_PCMU_G722)
    {
        ret = session_talking_pkt_dec722_2(rs,payload,
            payload_len,g722_decode, lb);
    }
    else if(rs->rtp_type == RTP_TYPE_PCMU)
    {
        ret= session_talking_pkt_dec711u_2(rs,payload,
        payload_len,lb);

    }
    else if (rs->rtp_type == RTP_TYPE_PCMU_PCMA)
    {
        ret = session_talking_pkt_dec711a_2(rs,payload,
        payload_len,lb);

    }
    else
    {
        log_err("this pkt not a g722, g711u, I can't decode it \n");
        return NULL;
    }

    if(ret == -1)
    {
        FREE(lb);
        return NULL;
    }
    return lb;
}

//6000  pkt == 120s
#define   MIX_BUF_COUNT  6000 //
int linear_list_mix(struct rtp_session_info* rs)
{
    struct linear_mix_list_st* list_st_a = &rs->calling_mix_list_st;
    struct linear_mix_list_st* list_st_b = &rs->called_mix_list_st;
    struct list_head* _mix_list_a = list_st_a->_mix_list;
    struct list_head* _mix_list_b = list_st_b->_mix_list;
    struct mixer* mix_engine = &rs->stMix;
    linear_buf*   lb_a;
    linear_buf*   lb_b;
    size_t mix_len = 0;
    char save_file_name[256] = {0};
    char ring_time[256] = {0};
    FILE* dest_fp;
    int tttt = 0;

    char           *calling_number =  rs->calling.number;

    char           *called_number = rs->called.number;


    strftime(ring_time,256,"%Y-%m-%d-%H-%M-%S",&rs->ring_time);
    if(calling_number[0] == '*')
    {
        calling_number++;
    }
    if(called_number[0] == '*')
    {
         called_number++;
    }

    if(rs->call_dir == SS_MODE_CALLING)
    {
        sprintf(save_file_name,"/tmp/fromLocal_%s_to_%s_startTime_%s_No_%d_fragid_%d_thread_%lu_mythreadid_%u.mix",
                calling_number,called_number,ring_time,
                rs->session_id,rs->mix_file_frag_count,rs->thread_id,rs->my_thread_id);
    }
    else
    {
        sprintf(save_file_name,"/tmp/from_%s_toLocal_%s_startTime_%s_No_%d_fragid_%d_thread_%lu_mythreadid_%u.mix",
                 calling_number,called_number,ring_time,
                rs->session_id,rs->mix_file_frag_count,rs->thread_id,rs->my_thread_id);
    }

    log("save file name %s \n",save_file_name);
    sprintf(rs->mix_file_name,"%s",save_file_name);
    dest_fp = fopen(save_file_name,"w");

    do
    {
        if(!list_empty(_mix_list_a)){
            lb_a = list_first_entry(_mix_list_a, typeof(*lb_a), node);
            mix(mix_engine,(char*)lb_a->p_buf,lb_a->len,&mix_len);
            list_del(&lb_a->node);
            FREE(lb_a->p_buf);
            FREE(lb_a);
        }
        if(!list_empty(_mix_list_b)){
            lb_b = list_first_entry(_mix_list_b, typeof(*lb_b), node);
            mix(mix_engine,(char*)lb_b->p_buf,lb_b->len,&mix_len);
            list_del(&lb_b->node);
            FREE(lb_b->p_buf);
            FREE(lb_b);
        }
        tttt++;
        fwrite(rs->stMix.data,mix_len,1,dest_fp);
    } while((!list_empty(_mix_list_a))||(!list_empty(_mix_list_b)));

    fclose(dest_fp);
    return 0;
}
static  int linear_buf_save_to_list(
    linear_buf*   lb,
    struct linear_mix_list_st* list_st)
{

    list_st->_pkt_count++;
    if(lb != NULL)
    {
        list_add_tail(&lb->node,list_st->linear_buf_list);
    }
    if( (list_st->_pkt_count % MIX_BUF_COUNT) == 0)
    {

        list_st->_mix_list=
            list_st->linear_buf_list;

        if(list_st->linear_buf_list ==
            &list_st->_list_a)
            list_st->linear_buf_list = &list_st->_list_b;
        else
            list_st->linear_buf_list = &list_st->_list_a;

        list_st->mix_ready_flag = 1;
        return 1;
    }
    return 0;
}
static void session_talking_2(struct iphdr* iph,struct udphdr* udph,
    struct rtp_session_info* rs)
{
    u8* rtp_pkt = (u8*)(udph+1);
    int rtp_len = ntohs(udph->len)-8;
    u8* rtp_payload = NULL;
    struct rttphdr* rtp_hdr;
    rtp_hdr = (struct rttphdr*)rtp_pkt;
    linear_buf*   lb;
   // struct phone_msg* msg;
    rtp_payload = rtp_pkt+sizeof(struct rttphdr);
    if(rs->rtp_type == 1)
    {
        rs->rtp_type = rtp_hdr->type;

        log("get a rty_type firstly %d \n",rtp_hdr->type);
    }
    if(rs->rtp_type != rtp_hdr->type)
    {
        log_err("rtp pkt type %d , session rtp type %d\n",rtp_hdr->type,rs->rtp_type);

    }

    if(iph->saddr == rs->calling.ip.s_addr)
    {

        rs->calling_pkt_count++;
        lb = session_talking_pkt_to_linear(rs,rtp_payload,
            rtp_len-sizeof(struct rttphdr),
            rs->rtp_type,rs->g722dst_calling);

        linear_buf_save_to_list(lb,&rs->calling_mix_list_st);

    }
    else if(iph->saddr == rs->called.ip.s_addr)
    {

        rs->called_pkt_count++;

        lb = session_talking_pkt_to_linear(rs,rtp_payload,
            rtp_len-sizeof(struct rttphdr),
            rs->rtp_type,rs->g722dst_called);
        linear_buf_save_to_list(lb,&rs->called_mix_list_st);
    }

    if((rs->called_mix_list_st.mix_ready_flag == 1)
        &&(rs->calling_mix_list_st.mix_ready_flag == 1))
    {
 //////   printf("---%s:%d rs->mix_file_frag_count %d "
 //   "called_mix_list_st pkt count %d  calling _pkt_count %d \n",
//        __func__,__LINE__,rs->mix_file_frag_count,
//        rs->called_mix_list_st._pkt_count,
//        rs->calling_mix_list_st._pkt_count);

        linear_list_mix(rs);
        upload_the_mix_file(rs);

        rs->called_mix_list_st.mix_ready_flag = 0;
        rs->calling_mix_list_st.mix_ready_flag = 0;
    }

}

/****************************************************/
const char* get_rtp_type(u8 type)
{
    u32 i;
    for(i = 0;i<sizeof(g_rtp_file_perfix)/sizeof(struct rtp_type_str);i++)
    {
        if(type == g_rtp_file_perfix[i].type)
            return g_rtp_file_perfix[i].type_str;
    }
    return "NA";
}
#define READ_BUF_SIZE 1024
/* not use it*/
#if 0
int mix_the_linear_file(struct rtp_session_info* n)
{
    char save_file_name[256] = {0};
    int fp_calling;
    int fp_called;
    FILE* dest_fp;
    u8 calling_buf[READ_BUF_SIZE];
    u8 called_buf[READ_BUF_SIZE];
    int reta;
    int retb;
    size_t mix_len = 0;
    int break_flag = 0;

    char ring_time[64] =  {0};

    fp_calling = open(n->calling_name_linear,O_RDONLY);
    fp_called = open(n->called_name_linear,O_RDONLY);

    log("DEBUG fp_calling %d fp_called %d \n",fp_calling,fp_called);


    strftime(ring_time,256,"%Y-%m-%d-%H-%M-%S",&n->ring_time);
    if(n->call_dir == SS_MODE_CALLING)
    {

        sprintf(save_file_name,"/tmp/from_Local_%s_to_%s_startTime_%s.mix",
            n->calling.number,n->called.number,ring_time);
    }
    else
    {
        sprintf(save_file_name,"/tmp/from_%s_to_Local_%s_startTime_%s.mix",
            n->calling.number,n->called.number,ring_time);

    }

    log("save file name %s \n",save_file_name);
    sprintf(n->mix_file_name,"%s",save_file_name);
    dest_fp = fopen(save_file_name,"w");

    while(1)
    {
        memset(calling_buf,0,sizeof(calling_buf));
        memset(called_buf,0,sizeof(calling_buf));

        reta = read(fp_calling,calling_buf,READ_BUF_SIZE);
        retb = read(fp_called,called_buf,READ_BUF_SIZE);
        if(reta  <= 0 )//read end
        {
            log_err("calling file read errro , reta = %d \n",reta);
            break_flag |= 1;
        }
        else if(reta > 0)
        {
            mix(&n->stMix,calling_buf,reta,&mix_len);
           // log("mix_len %d \n", mix_len);
        }

        if(retb  <= 0 )//read end
        {
            break_flag |= 2;
            log_err("called file read errro , reta = %d \n",retb);
        }
        else if(reta > 0)
        {
            mix(&n->stMix,called_buf,retb,&mix_len);
            //log("mix_len %d \n", mix_len);
        }
        fwrite(n->stMix.data,mix_len,1,dest_fp);
        if(break_flag == 3){

             log("read file end and finish the mix  \n");
            break;
        }
    }
    fclose(dest_fp);
    close(fp_calling);
    close(fp_called);
    return 0;
}
#endif
int cul_rtp_end_time(struct rtp_session_info* n)
{

    u32 duration;

    time_t a;
    struct tm tt;
    a = mktime(&n->ring_time);

    duration = n->stop_time_stamp - n->start_time_stamp;

    a += duration;
    if(duration > 60*10)
    {

    	log("the ring time >10minites?  thread %lu \n",n->thread_id);
    }
    localtime_r(&a,&tt);
    memcpy(&n->end_time,&tt,sizeof(struct tm));
    return 0;
}
/*
caller_flag is 0 ,mean  the signal_handler
fiag is 1, mean is
*/

int upload_the_mix_file(struct rtp_session_info* n)
{
    int ret;
    struct upload_file_info ufi;
    char time_str[256]={0};
    struct config_st* c = &g_config;
//    char ring_time[256]={0};


    strncpy(ufi.call_caller_number,n->calling.number,sizeof(ufi.call_caller_number));

    strncpy(ufi.call_callee_number,n->called.number,sizeof(ufi.call_callee_number));

	strncpy(ufi.called_group_number,
		n->called_group_number,sizeof(ufi.called_group_number));
    if(n->call_dir == SS_MODE_CALLING){
        sprintf(ufi.call_direction,"%d",0);

        strncpy(ufi.call_local_number,n->calling.number,sizeof(ufi.call_local_number));
    }
    else
    {
        sprintf(ufi.call_direction,"%d",1);
        strncpy(ufi.call_local_number,n->called.number,sizeof(ufi.call_local_number));
    }

    strftime(time_str,256,"%Y-%m-%d %H:%M:%S",&n->ring_time);
    strncpy(ufi.call_begin_time,time_str,sizeof(ufi.call_begin_time));

    memset(time_str,0,sizeof(time_str));
    strftime(time_str,256,"%Y-%m-%d %H:%M:%S",&n->end_time);
    strncpy(ufi.call_end_time,time_str,sizeof(ufi.call_end_time));
#if 0
    strftime(ring_time,256,"%Y-%m-%d-%H-%M-%S",&n->ring_time);

    sprintf(ufi.file_name,"local_%s_from_%s_to_%s_startTime_%s_No_%d_fragid_%d.mix",
    ufi.call_local_number,
            n->calling.number,n->called.number,ring_time,
            n->session_id,n->mix_file_frag_count);
#else
    strncpy(ufi.file_name,n->mix_file_name,sizeof(ufi.file_name));
#endif
    n->mix_file_name[0] = '\0';//清空这个字段。这样下次不会再上传此文件了。--2019-8-19

    //  ufi.frag_flag  1表示第一个或是中间的一个。2表示一个明确的结束。--2019-8-19
    if ( n->exit_flag == RTP_EXIT_STOP_SNIFFER_EXIT_PTHREAD_SET_LAST_PACK_FLAG)
    {
        sprintf(ufi.frag_flag,"%d",2); //last frag
        //在此要判断ufi.file_name是不是已经被上传走了，上传走之后，则不需要再上传它了。
        if(ufi.file_name[0] == '\0')
        {
            log("this file (%s) has been uploaded --2019-8-20\n",(n->mix_file_name+1));
        }
    }
    else
    {
        sprintf(ufi.frag_flag,"%d",1);//first or
    }
#if 0
    if( n->mix_file_frag_info_caller == 0
        && n->mix_file_frag_count == 0)
    {
        sprintf(ufi.frag_flag,"%d",1);
    }
    else if ( n->mix_file_frag_info_caller == 1)
        sprintf(ufi.frag_flag,"%d",1);

    else if ( n->mix_file_frag_info_caller == 0)
    {
    	if(n->exit_flag == 2)
    	{
        	sprintf(ufi.frag_flag,"%d",2); //last frag
        }
        else
        {
        	sprintf(ufi.frag_flag,"%d",1); //last frag

        }
    }
#endif
    sprintf(ufi.frag_serial_no ,"%d",n->session_id);
  //  sprintf(ufi.file_name,"from_%s_to_%s_startTime_%s.mix",
  //          n->calling.number,n->called.number,ring_time);

    sprintf(ufi.box_id,"%02X:%02X:%02X:%02X:%02X:%02X",
        c->eth0_mac[0],c->eth0_mac[1],c->eth0_mac[2],
	    c->eth0_mac[3],c->eth0_mac[4],c->eth0_mac[5]);
#if 0
    ret = upload_mix_file(c->upload_http_url,&ufi);
#endif

    n->mix_file_frag_count++;
    /*  this function should be locked by curl_upload module
    */
    log("before upload_push_msg in rtp:\n");
    log("called_group_number %s \n",ufi.called_group_number);
    log("call_caller_number %s \n",ufi.call_caller_number);
    log("call_callee_number %s \n",ufi.call_callee_number);
    log("ufi.frag_flag %s  rtpsession exit_flag %d (1, not exit pthread, 2 exit this pthread but other pthread run, 3"\
    "all pthread exit, so ufi.frag_flag must 2)\n",ufi.frag_flag,n->exit_flag);

    ret = uploader_push_msg((struct upload_msg*)&ufi,sizeof(ufi));
    return ret;
}


void handler_last_linear_list(struct rtp_session_info* n)
{

    n->calling_mix_list_st._mix_list =
        n->calling_mix_list_st.linear_buf_list;

    n->called_mix_list_st._mix_list =
        n->called_mix_list_st.linear_buf_list;

     linear_list_mix(n);
#if 0
     if(n->exit_flag == 2)
     {

     	n->mix_file_frag_info_caller = 0;//last frag
     }
     else
     {

     	n->mix_file_frag_info_caller = 1;//not last frag
     }
#endif
     upload_the_mix_file(n);
}

///////////////////////////////////////////////////////////////////
static int finish_rtp_in_signal(struct rtp_session_info* n);

static int rtp_may_destory(struct rtp_session_info* n)
{
    int retval=3;
    if(n->exit_flag >= RTP_EXIT_STOP_SNIFFER_EXIT_PTHREAD)
    {

        pcap_close(n->pd);
        _rtp_del_session(n);
        log("I(%lu) and finish and quit  \n",pthread_self());
        pthread_exit(&retval);
    }
    log("I(%lu) not quit  \n",pthread_self());

    return 0;
}
static int finish_rtp(struct rtp_session_info* n)
{
    int retval=3;

    log("I(%lu)  enter finish_rtp \n",pthread_self());
#if 0
    time(&n->stop_time_stamp);
    cul_rtp_end_time(n);

    handler_last_linear_list(n);

    rtp_may_destory(n);
#endif
    //else
    {
        while(1)
	    {
	            sleep(10); //
            log("I(%lu) sleep and wait to kill me  \n",pthread_self());
            if(n->exit_flag >= RTP_EXIT_STOP_SNIFFER_EXIT_PTHREAD)
            {

                log("I(%lu) get exit_Flag is 2,so \n",pthread_self());
                finish_rtp_in_signal(n);

                rtp_may_destory(n);
                break;
            }
        }
    }
    return 0;
}
static int finish_rtp_in_signal(struct rtp_session_info* n)
{
    int retval=3;

    log("I(%lu)  enter finish_rtp_in_signal \n",pthread_self());
    time(&n->stop_time_stamp);
    cul_rtp_end_time(n);

    handler_last_linear_list(n);

    log("I(%lu)  exit finish_rtp_in_signal \n",pthread_self());

    return 0;
}

static void sighandler(int s)
{
    int retval = 3;
    struct rtp_session_info* n;

    log("I(%lu) recv a signal %d\n",pthread_self(),s);
    n = rtp_find_session();
    if(n)
    {
        log("I(%lu) find the session info and finish it,but not exit\n",pthread_self());
        if(n->exit_flag >= RTP_EXIT_STOP_SNIFFER_EXIT_PTHREAD)
        {
            finish_rtp_in_signal(n);
            rtp_may_destory(n);
        }
        else
        /* 在并席过程中，或是在skinny-session中有多个RTP时，
        我们只在skinny-session结束时，才把所有的rtp生成的mix文件上传上去。
        这是由于上传进程在工作时，有一些skinny的报文没有抓到。比较奇怪。*/
        {
            log("I(%lu) is the session info,not upload some mix file.\n",pthread_self());
        }

    }
    else
    {
        log_err("not find rtp session \n");
    }

    sem_post(&n->_kill_signal_event);
#if 0  //2019-8-22
    log(" %lu thread quit-------- \n", (unsigned long)pthread_self());
    if(n->exit_flag >= RTP_EXIT_STOP_SNIFFER_EXIT_PTHREAD)
    {
        pthread_exit(&retval);
    }
    else
    {
    	log("I(%lu) not exit! \n",pthread_self());
        n->no_send_mix_file = 1;
    }
#endif
}

#if 0
static void sighandler(int s)
{
        int retval = 3;
        char* file_perfix;
        struct rtp_session_info* n;
        char new_name[300];
        char ring_time[300];
        int t=0;
        u32 duration;
        char calledip_str[30]={0};
        char callingip_str[30]={0};

        n = rtp_find_session(pthread_self());
        if(n)
        {
        log("I  find rtp session -------n->rtp_typ %d-----\n",n->rtp_type);
            time(&n->stop_time_stamp);
            duration = n->stop_time_stamp - n->start_time_stamp;

                strftime(ring_time,256,"%Y-%m-%d_%H-%M-%S",&n->ring_time);
                sprintf(calledip_str, "%s",inet_ntoa(n->called.ip));
                sprintf(callingip_str, "%s",inet_ntoa(n->calling.ip));


            pcap_close(n->pd);
            if(n->save_called_fp)
                fclose(n->save_called_fp);
            if(n->save_calling_fp)
                fclose(n->save_calling_fp);
            file_perfix = get_rtp_type(n->rtp_type);

            if(n->save_mix_fp)
                fclose(n->save_mix_fp);

            if(n->save_calling_linear_fp)
                fclose(n->save_calling_linear_fp);

            if(n->save_called_linear_fp)
                fclose(n->save_called_linear_fp);

            mix_the_linear_file(n);
            memset(new_name,0,sizeof(new_name));
            sprintf(new_name,"/tmp/from_%s_startTime_%s_duration_%d.%s",
                callingip_str,ring_time,duration, file_perfix);
            rename(n->called_name,new_name);

            memset(new_name,0,sizeof(new_name));
            sprintf(new_name,"/tmp/to_%s_startTime_%s_duration_%d.%s",
                calledip_str,ring_time,duration, file_perfix);
            rename(n->calling_name,new_name);


            _rtp_del_session(n);
        }
        else
        {
            log_err("not find rtp session \n");
        }
        log(" %lu thread quit \n", (unsigned long)pthread_self());
        pthread_exit(&retval);

}
#endif
static int thread_kill(u32 my_thread_id)
{

    int kill_ret;
    int ret;
    struct rtp_session_info* n;
    struct rtp_session_info* rtp_check_again;
    struct timespec ts;
    n = rtp_find_session_by_my_pthead_id(my_thread_id);
    if(n)
    {
        log("I(%lu) will set (%lu)'s exit_flag before sem_timedwait _kill_signal_event \n",
                pthread_self(),my_thread_id);
        struct timeval tv;
        if(gettimeofday(&tv, NULL) == 0)
        {

            uint64_t nsec = (uint64_t )((tv.tv_usec)*1000);
            ts.tv_sec = tv.tv_sec + (nsec/1000000000LL);
            ts.tv_nsec = nsec%1000000000LL;
        }
        else
        {
	        time_t a;
	        time(&a);
            ts.tv_sec = a;
            ts.tv_nsec = a*1000000000LL;
        }
        ts.tv_sec += 5;//wait 5s


        ret =  sem_timedwait((&n->_kill_signal_event),&ts);
        if(ret != 0)
        {
            if(errno == ETIMEDOUT) //超时了。
            {
                log_err("sem_timedwait time out,so return from thread_kill\n");
                //在此不可以再使用thread_id进行查询，很有可能查到另一个新的线程的信息。
                rtp_check_again = rtp_find_session_by_my_pthead_id(my_thread_id);
                if(rtp_check_again == NULL)
                {
                    log("this rtp thread is destory! \n");
                }
                else
                {
                    log("this rtp thread has been exist! Why??? I must kill it right now \n");
                    goto kill;

                }
            }
        }
        else
        {
kill:
            log("I(%lu) set (%lu)'s exit_flag \n",pthread_self(),my_thread_id);

            kill_ret = pthread_kill(n->thread_id,SIGQUIT);
                //log("%s:%d ret %d \n",__func__,__LINE__,kill_ret);
            if(kill_ret == ESRCH)
            {
                    log("the tid is not exist\n");
            }
            else if(kill_ret == EINVAL)
            {
                    log("unvalide signal\n");
            }
            else
            {
                log("the tid is exist\n");
            }
        }
    }

    return 0;
}

void close_one_rtp_sniffer(unsigned long rtp_sniffer_tid)
{

	//session_down();

	//time(&ss->stop_time_stamp);
    struct rtp_session_info* n;
	unsigned long rtp_my_pthread_id = rtp_sniffer_tid;
	if(rtp_my_pthread_id)
	{

		log(" I (%lu) kill  No<%lu> thread(rtp) \n",(unsigned long)pthread_self()
				,(unsigned long)rtp_my_pthread_id);
#if 1
		n = rtp_find_session_by_my_pthead_id(rtp_my_pthread_id);
		if(n)
		{

			log("set rtp sniffer's exit_flag to 1( only close only one rtp ) \n");
			n->exit_flag = RTP_EXIT_STOP_SNIFFER_NOT_EXIT_PTHREAD;

		}
#endif

		thread_kill(rtp_my_pthread_id);
	}
}

void close_dial_session_sniffer_lastone(unsigned long rtp_sniffer_tid)
{

	//session_down();
    sleep(1);//2019-8-23,报文来得太快，上一次的handle_StopMediaTransmission时的rtp
        // 线程未完全处理完。

	//time(&ss->stop_time_stamp);
	struct rtp_session_info* n;

	unsigned long rtp_my_pthread_id = rtp_sniffer_tid;
	if(rtp_my_pthread_id)
	{

		log(" I (%lu) kill No<%lu> thread(rtp) \n",(unsigned long)pthread_self()
				,(unsigned long)rtp_my_pthread_id);
#if 1
		n = rtp_find_session_by_my_pthead_id(rtp_my_pthread_id);
		if(n)
		{

			log("set rtp sniffer's exit_flag to 3(all dial session close) \n");
			n->exit_flag = RTP_EXIT_STOP_SNIFFER_EXIT_PTHREAD_SET_LAST_PACK_FLAG;

		}
#endif

		thread_kill(rtp_my_pthread_id);
	}
}
void close_dial_session_sniffer(unsigned long rtp_sniffer_tid)
{

	//session_down();

	//time(&ss->stop_time_stamp);
	struct rtp_session_info* n;
	unsigned long rtp_my_pthread_id = rtp_sniffer_tid;
	if(rtp_my_pthread_id)
	{

		log(" I (%lu) kill  No<%lu> thread(rtp) \n",
		    (unsigned long)pthread_self(),(unsigned long)rtp_my_pthread_id);
#if 1
		n = rtp_find_session_by_my_pthead_id(rtp_my_pthread_id);
		if(n)
		{

			log("set rtp sniffer's exit_flag to 2 (all dial session close) \n");
			n->exit_flag = RTP_EXIT_STOP_SNIFFER_EXIT_PTHREAD;

		}
#endif

		thread_kill(rtp_my_pthread_id);
	}
}


void handle_rtp(struct iphdr* iph,struct udphdr* udph,void* arg)
{


	struct rtp_session_info* rs = arg;

  //  session_talking( iph,udph,rs);
  session_talking_2( iph,udph,rs);
}
static void sniffer_handle_rtp(u_char * user, const struct pcap_pkthdr * packet_header, const u_char * packet_content)
{

	int ret = 0;
	{
    	struct rtp_session_info* n;
        n = rtp_find_session();
        if(n)
        {
            if(n->exit_flag)
            {
                log("I(%lu) get my exit_flag ,finish it \n",pthread_self());
               // finish_rtp(n);
               finish_rtp(n);
            }
        }
    }
	const struct pcap_pkthdr* phdr = packet_header;
	struct iphdr* iph = NULL;
	struct udphdr* udph = NULL;


	ret = check_iphdr(phdr,packet_content,&iph);
	if(ret != 0){
	    log_err("ip header error\n");
		goto error;
    }

	if(0 != check_udp(iph,&udph))	{
	    log_err("udp error\n");
		goto error;
    }
	handle_rtp(iph,udph,(void*) user);
error:
	return;
}

static int sniffer_rtp_loop2( pcap_t *p,void* arg)
{
	 pcap_loop( p,-1,sniffer_handle_rtp,(u_char*)arg);
	 return 0;
}

static void* sniffer_rtp_loop1(void* arg)
{

	struct rtp_session_info* rs = arg;

    pcap_t *pd =rs->pd;

	while(1)
	{
	    if(rs->exit_flag != 0)
	    {
	        log("I(%lu) get exit flag , so I call finish_rtp rtp_session_info's tid (%lu) \n",pthread_self(),rs->thread_id);
	        finish_rtp(rs);
	    }
		sniffer_rtp_loop2(pd,arg);
	}
	return NULL;
}

static pcap_t* init_sniffer_rtp(struct session_info* ss)
{
	char filter[200] = {0};
	char callingip_str[32] = {0};
	char calledip_str[32] = {0};
    pcap_t* pd=0;
    signal(SIGQUIT, sighandler);
	//pd = open_pcap_file("enp0s3",65535,1,0);
	pd = open_pcap_file("eth0",65535,1,0);
	if(pd == NULL)
	{
		log("open_pcap_file failed ! \n");
		return NULL;
	}
	sprintf(callingip_str,"%s",inet_ntoa(ss->calling.ip));
	sprintf(calledip_str,"%s",inet_ntoa(ss->called.ip));

	sprintf(filter,"(udp and host %s and port %d) or (udp and host %s and port %d)",
	    callingip_str,
	    ss->calling.port,
	       calledip_str,
	    ss->called.port);

	if(sniffer_setfilter(pd,filter) <0){
	    log("rtp sniffer set filter failed!\n");
	    exit(1);
	}
    return pd;
}
u32 setup_rtp_sniffer(struct session_info* ss)
{
	pthread_t tid;
	pcap_t* pd;
	struct rtp_session_info* rs;

    time_t a;

	if (ss->mode == SS_MODE_CALLED){
	    log("this session is called (slave) \n");
	}
	else if(ss->mode == SS_MODE_CALLING){
	    log("this session is calling(master)\n");
    }
    else
    {
        log_err("this session is bad ession.!!!!");
    }
    if(ss->call_id)
    {
    	log("sniffer rtp info: callid <%s> \n",ss->call_id);
    }
    else
    {
    	log("sniffer rtp info: callid <NNAA> \n");
    }
	log("sniffer calling %s:%d phone_number %s \n",
	    inet_ntoa(ss->calling.ip),ss->calling.port,ss->calling.number);
	log("sniffer called  %s:%d phone_number %s \n",
	    inet_ntoa(ss->called.ip),ss->called.port,ss->called.number);
	log("Serial_No %d \n", ss->serial_no);

    pd =  init_sniffer_rtp(ss);
    if(pd == NULL)
    {
        return 0;//bad
    }
    rs = _rtp_new_session();
    if(rs == NULL)
    {
        log_err("rtp_new_session failed\n");

    }
    INIT_LIST_HEAD(&rs->calling_mix_list_st._list_a);
    INIT_LIST_HEAD(&rs->calling_mix_list_st._list_b);
    rs->calling_mix_list_st.linear_buf_list =
        &rs->calling_mix_list_st._list_a;


    INIT_LIST_HEAD(&rs->called_mix_list_st._list_a);
    INIT_LIST_HEAD(&rs->called_mix_list_st._list_b);

     rs->called_mix_list_st.linear_buf_list =
        &rs->called_mix_list_st._list_a;
/*get the ring time */
{

	struct tm t;
    time(&a);
    localtime_r(&a,&t);

    memcpy(&rs->ring_time,&t,sizeof(struct tm));
}
    rs->start_time_stamp = a;
    rs->call_dir = ss->mode;
    memcpy(&rs->called,&ss->called,sizeof(ss->called));
    memcpy(&rs->calling,&ss->calling,sizeof(ss->calling));
 //   log("DEBUG here\n");
    memcpy(&rs->called,&ss->called,sizeof(struct  person));
    memcpy(&rs->calling,&ss->calling,sizeof(struct  person));
	strncpy(rs->called_group_number,
		ss->called_group_number,
		sizeof(rs->called_group_number));
    rs->pd = pd;

    rs->g722dst_called = (void*)g722_decode_init((g722_decode_state_t*) rs->g722dst_called, G722BITSRATE, 1 /* 表明采用8000采样 */);
    rs->g722dst_calling= (void*)g722_decode_init((g722_decode_state_t*) rs->g722dst_calling, G722BITSRATE, 1 /* 表明采用8000采样 */);

    rs->session_id = ss->serial_no; //rs session_id表示的是服务器用于进行组文件的iD号。


 //   pthread_mutex_init(&rs->exit_flag_lock, NULL);
   // pthread_mutex_init(&rs->kill_signal_lock, NULL);

    sem_init(&rs->_kill_signal_event, 0, 0);
    sem_post(&rs->_kill_signal_event);

	//session_up();

	if(pthread_create(&tid,NULL,sniffer_rtp_loop1,rs))
	{
		log("create msg_engine_start sniffer_sip_loop failed\n");
		return -1;
	}
	rs->thread_id = tid;

	log("rs thread_id %lu my_thread_id %lu\n",rs->thread_id,rs->my_thread_id);

    pthread_detach(tid);//线程与sip线程分离。

	return rs->my_thread_id;

}

void rtp_sniffer_init(void)
{

    INIT_LIST_HEAD(&rtp_ctx.rtp_head);
    //rtp_ctx.serial_no = 0;
    ulawcodec_init();
    ast_alaw_init();

}
