

//
/* 
Modify 1：2019-1-26 BingXi（并席）功能，
    key: BingXi,
    不使用OpenReceiveChannel,CloseRecvChannel,OpenRecvChannelACK作为关键信息。
    使用   StartMediaTransmission, StopMediaTransmission, 
      StartMediaTransmissionACK三个关键。
      在以上6个passThruPartyID这个ID，用于标记这些报文是一个流程里的。

Modify 2: 一个Callreference 可以有多个以passThruPartyID为key的mdeia.
这些Media都要侦听，
所以我们要先以Callid为key，做一个callid的Callidsession的listHead.
在每一个CallidSession里，还以passThruPartyID为key的listHead.

Modify 3: Media的stop是stopMedia的报文。
          Callreference的stop则是以callstate报文里的OnHook
          或是以DefineTimeDate

          Callstate的conected表示CallReference的所有media全连接成功（一般只有一个）
          
*/  

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "log.h"

#include <pthread.h>    

#include "sniffer_lib.h"  


#include "config.h"
#include "linux-utils.h"
#include "wake_utils.h"
#include "sniffer_skinny.h"
#include "str_lib.h"
#include "upload.h"

#include "sniffer_rtp.h"

extern struct config_st g_config;



#define TCP_PORT_SKINNY 2000 /* Not IANA registered */

#define SSL_PORT_SKINNY 2443 /* IANA assigned to PowerClient Central Storage Facility */

#define BASIC_MSG_TYPE 0x00
#define V10_MSG_TYPE 0x0A
#define V11_MSG_TYPE 0x0B
#define V15_MSG_TYPE 0x0F
#define V16_MSG_TYPE 0x10
#define V17_MSG_TYPE 0x11
#define V18_MSG_TYPE 0x12
#define V19_MSG_TYPE 0x13
#define V20_MSG_TYPE 0x14
#define V21_MSG_TYPE 0x15
#define V22_MSG_TYPE 0x16

typedef struct _value_string {
    unsigned int      value;
    const char     *strptr;
} value_string;


static const value_string header_version[] = {
  { BASIC_MSG_TYPE, "Basic" },
  { V10_MSG_TYPE,   "V10" },
  { V11_MSG_TYPE,   "V11" },
  { V15_MSG_TYPE,   "V15" },
  { V16_MSG_TYPE,   "V16" },
  { V17_MSG_TYPE,   "V17" },
  { V18_MSG_TYPE,   "V18" },
  { V19_MSG_TYPE,   "V19" },
  { V20_MSG_TYPE,   "V20" },
  { V21_MSG_TYPE,   "V21" },
  { V22_MSG_TYPE,   "V22" },
  { 0             , NULL }
};

/* Declare MessageId */
static const value_string message_id[] = {
  { 0x0000, "KeepAliveReq" },
  { 0x0001, "RegisterReq" },
  { 0x0002, "IpPort" },
  { 0x0003, "KeypadButton" },
  { 0x0004, "EnblocCall" },
  { 0x0005, "Stimulus" },
  { 0x0006, "OffHook" },
  { 0x0007, "OnHook" },
  { 0x0008, "HookFlash" },
  { 0x0009, "ForwardStatReq" },
  { 0x000a, "SpeedDialStatReq" },
  { 0x000b, "LineStatReq" },
  { 0x000c, "ConfigStatReq" },
  { 0x000d, "TimeDateReq" },
  { 0x000e, "ButtonTemplateReq" },
  { 0x000f, "VersionReq" },
  { 0x0010, "CapabilitiesRes" },
  { 0x0012, "ServerReq" },
  { 0x0020, "Alarm" },
  { 0x0021, "MulticastMediaReceptionAck" },
  { 0x0022, "OpenReceiveChannelAck" },
  { 0x0023, "ConnectionStatisticsRes" },
  { 0x0024, "OffHookWithCalingPartyNumber" },
  { 0x0025, "SoftKeySetReq" },
  { 0x0026, "SoftKeyEvent" },
  { 0x0027, "UnregisterReq" },
  { 0x0028, "SoftKeyTemplateReq" },
  { 0x0029, "RegisterTokenReq" },
  { 0x002a, "MediaTransmissionFailure" },
  { 0x002b, "HeadsetStatus" },
  { 0x002c, "MediaResourceNotification" },
  { 0x002d, "RegisterAvailableLines" },
  { 0x002e, "DeviceToUserData" },
  { 0x002f, "DeviceToUserDataResponse" },
  { 0x0030, "UpdateCapabilities" },
  { 0x0031, "OpenMultiMediaReceiveChannelAck" },
  { 0x0032, "ClearConference" },
  { 0x0033, "ServiceURLStatReq" },
  { 0x0034, "FeatureStatReq" },
  { 0x0035, "CreateConferenceRes" },
  { 0x0036, "DeleteConferenceRes" },
  { 0x0037, "ModifyConferenceRes" },
  { 0x0038, "AddParticipantRes" },
  { 0x0039, "AuditConferenceRes" },
  { 0x0040, "AuditParticipantRes" },
  { 0x0041, "DeviceToUserDataVersion1" },
  { 0x0042, "DeviceToUserDataResponseVersion1" },
  { 0x0043, "CapabilitiesV2Res" },
  { 0x0044, "CapabilitiesV3Res" },
  { 0x0045, "PortRes" },
  { 0x0046, "QoSResvNotify" },
  { 0x0047, "QoSErrorNotify" },
  { 0x0048, "SubscriptionStatReq" },
  { 0x0049, "MediaPathEvent" },
  { 0x004a, "MediaPathCapability" },
  { 0x004c, "MwiNotification" },
  { 0x0081, "RegisterAck" },
  { 0x0082, "StartTone" },
  { 0x0083, "StopTone" },
  { 0x0085, "SetRinger" },
  { 0x0086, "SetLamp" },
  { 0x0087, "SetHookFlashDetect" },
  { 0x0088, "SetSpeakerMode" },
  { 0x0089, "SetMicroMode" },
  { 0x008a, "StartMediaTransmission" },
  { 0x008b, "StopMediaTransmission" },
  { 0x008f, "CallInfo" },
  { 0x0090, "ForwardStatRes" },
  { 0x0091, "SpeedDialStatRes" },
  { 0x0092, "LineStatRes" },
  { 0x0093, "ConfigStatRes" },
  { 0x0094, "TimeDateRes" },//---------liudan ??–??—?—?é—′?€?
  { 0x0095, "StartSessionTransmission" },
  { 0x0096, "StopSessionTransmission" },
  { 0x0097, "ButtonTemplateRes" },
  { 0x0098, "VersionRes" },
  { 0x0099, "DisplayText" },
  { 0x009a, "ClearDisplay" },
  { 0x009b, "CapabilitiesReq" },
  { 0x009d, "RegisterReject" },
  { 0x009e, "ServerRes" },
  { 0x009f, "Reset" },
  { 0x0100, "KeepAliveAck" },
  { 0x0101, "StartMulticastMediaReception" },
  { 0x0102, "StartMulticastMediaTransmission" },
  { 0x0103, "StopMulticastMediaReception" },
  { 0x0104, "StopMulticastMediaTransmission" },
  { 0x0105, "OpenReceiveChannel" },
  { 0x0106, "CloseReceiveChannel" },
  { 0x0107, "ConnectionStatisticsReq" },
  { 0x0108, "SoftKeyTemplateRes" },
  { 0x0109, "SoftKeySetRes" },
  { 0x0110, "SelectSoftKeys" },
  { 0x0111, "CallState" },
  { 0x0112, "DisplayPromptStatus" },
  { 0x0113, "ClearPromptStatus" },
  { 0x0114, "DisplayNotify" },
  { 0x0115, "ClearNotify" },
  { 0x0116, "ActivateCallPlane" },
  { 0x0117, "DeactivateCallPlane" },
  { 0x0118, "UnregisterAck" },
  { 0x0119, "BackSpaceRes" },
  { 0x011a, "RegisterTokenAck" },
  { 0x011b, "RegisterTokenReject" },
  { 0x011c, "StartMediaFailureDetection" },
  { 0x011d, "DialedNumber" },
  { 0x011e, "UserToDeviceData" },
  { 0x011f, "FeatureStatRes" },
  { 0x0120, "DisplayPriNotify" },
  { 0x0121, "ClearPriNotify" },
  { 0x0122, "StartAnnouncement" },
  { 0x0123, "StopAnnouncement" },
  { 0x0124, "AnnouncementFinish" },
  { 0x0127, "NotifyDtmfTone" },
  { 0x0128, "SendDtmfTone" },
  { 0x0129, "SubscribeDtmfPayloadReq" },
  { 0x012a, "SubscribeDtmfPayloadRes" },
  { 0x012b, "SubscribeDtmfPayloadErr" },
  { 0x012c, "UnSubscribeDtmfPayloadReq" },
  { 0x012d, "UnSubscribeDtmfPayloadRes" },
  { 0x012e, "UnSubscribeDtmfPayloadErr" },
  { 0x012f, "ServiceURLStatRes" },
  { 0x0130, "CallSelectStatRes" },
  { 0x0131, "OpenMultiMediaReceiveChannel" },
  { 0x0132, "StartMultiMediaTransmission" },
  { 0x0133, "StopMultiMediaTransmission" },
  { 0x0134, "MiscellaneousCommand" },
  { 0x0135, "FlowControlCommand" },
  { 0x0136, "CloseMultiMediaReceiveChannel" },
  { 0x0137, "CreateConferenceReq" },
  { 0x0138, "DeleteConferenceReq" },
  { 0x0139, "ModifyConferenceReq" },
  { 0x013a, "AddParticipantReq" },
  { 0x013b, "DropParticipantReq" },
  { 0x013c, "AuditConferenceReq" },
  { 0x013d, "AuditParticipantReq" },
  { 0x013e, "ChangeParticipantReq" },
  { 0x013f, "UserToDeviceDataVersion1" },
  { 0x0140, "VideoDisplayCommand" },
  { 0x0141, "FlowControlNotify" },
  { 0x0142, "ConfigStatV2Res" },
  { 0x0143, "DisplayNotifyV2" },
  { 0x0144, "DisplayPriNotifyV2" },
  { 0x0145, "DisplayPromptStatusV2" },
  { 0x0146, "FeatureStatV2Res" },
  { 0x0147, "LineStatV2Res" },
  { 0x0148, "ServiceURLStatV2Res" },
  { 0x0149, "SpeedDialStatV2Res" },
  { 0x014a, "CallInfoV2" },
  { 0x014b, "PortReq" },
  { 0x014c, "PortClose" },
  { 0x014d, "QoSListen" },
  { 0x014e, "QoSPath" },
  { 0x014f, "QoSTeardown" },
  { 0x0150, "UpdateDSCP" },
  { 0x0151, "QoSModify" },
  { 0x0152, "SubscriptionStatRes" },
  { 0x0153, "Notification" },
  { 0x0154, "StartMediaTransmissionAck" },
  { 0x0155, "StartMultiMediaTransmissionAck" },
  { 0x0156, "CallHistoryInfo" },
  { 0x0157, "LocationInfo" },
  { 0x0158, "MwiRes" },
  { 0x0159, "AddOnDeviceCapabilities" },
  { 0x015a, "EnhancedAlarm" },
  { 0x015e, "CallCountReq" },
  { 0x015f, "CallCountResp" },
  { 0x0160, "RecordingStatus" },
  { 0x8000, "SPCPRegisterTokenReq" },
  { 0x8100, "SPCPRegisterTokenAck" },
  { 0x8101, "SPCPRegisterTokenReject" },
  {0     , NULL}
};

typedef struct skinny_packet_info
{
    u32 callid;
    u32 callstate;
    
}skinny_info_t;

typedef struct _skinny_opcode_map_t skinny_opcode_map_t;

/* begin conversaton  info*/
typedef enum _skinny_message_type_t {
  SKINNY_MSGTYPE_EVENT    = 0,
  SKINNY_MSGTYPE_REQUEST  = 1,
  SKINNY_MSGTYPE_RESPONSE = 2,
} skinny_message_type_t;

  

typedef void (*message_handler) (skinny_opcode_map_t* skinny_op, 
                                    u8* msg,u32 len,skinny_info_t* skinny);

typedef struct _skinny_opcode_map_t {
  u32 opcode;
  message_handler handler;
  skinny_message_type_t type;
  const char *name;
} skinny_opcode_map_t;




/*******************************************************************************************************/


/******************************************
*
* ????–????????¨??o????è|???ˉ?”¨??￥??“ SKINNY ??￥?–??€?
* ????¨??o???“sip?????￥?–?????1?è§￡?????osipé?????call-id,??￥?-¤?????okey,???pkt???è???¨??”???°
??€??asession??-???session?”???°??€??a?…¨?±€???é“?è?¨??-?€?
è·?è?a?ˉ???asession???????”???°?-????è???¨??€???€???free session.

* 
*******************************************/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
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


extern struct config_st g_config;



struct skinny_frame_info {
  u32 callRef;//callid;
};


#include "sniffer_skinny.h"

typedef unsigned int UINT;
typedef unsigned short USHORT;

#define CW_LOAD_U8(ucValue, pucBuf)((ucValue) = (*(pucBuf)++));

#define CW_LOAD_U16(usValue, pucBuf)\
{\
    usValue  = (USHORT) ((*(pucBuf)++) );\
    usValue |= (USHORT) ((*(pucBuf)++)<< 8);\
}

#define CW_LOAD_U32(uiValue, pucBuf)\
{\
    uiValue  = (UINT) ((*(pucBuf)++));\
    uiValue |= (UINT) ((*(pucBuf)++) << 8);\
    uiValue |= (UINT) ((*(pucBuf)++) << 16);\
    uiValue |= (UINT) ((*(pucBuf)++) << 24);\
}


#define CW_LOAD_STR(pucDest, pucBuf, ulLen)\
{\
    memcpy((pucDest), (pucBuf), (ulLen));\
    ((pucBuf) += (ulLen));\
}

#define LOAD_STR_LINE(src,dest,dest_len,dlim) do{       \
        int t = 0;                                      \
        while(*(src) != (dlim)&& t<dest_len)            \
        {                                               \
                *(dest+t) = *(src);                     \
                (src)++;                                \
                t++;                                    \
        }                                               \
        (src)++;                                        \
}while(0);


char g_LineStatV2_lineDirNumber[128]={0};

//extern struct session_ctx_t sip_ctx;


struct session_ctx_t skinny_ctx;

void handle_default_function (skinny_opcode_map_t* skinny_op, u8* msg,u32 len,
    skinny_info_t* skinny_info);

static struct skinny_callReference_info* skinny_new_session(void)
{
    struct skinny_callReference_info* skinny_callRefer_info =NULL;
    skinny_callRefer_info = (struct skinny_callReference_info*)malloc(sizeof(struct skinny_callReference_info));
    if ( skinny_callRefer_info == NULL)
        return NULL;
    memset(skinny_callRefer_info,0,sizeof(struct skinny_callReference_info));
    INIT_LIST_HEAD(&skinny_callRefer_info->skinny_media_list);
    pthread_mutex_lock(&skinny_ctx.head_lock);
    list_add(&skinny_callRefer_info->node,&skinny_ctx.si_head);
    pthread_mutex_unlock(&skinny_ctx.head_lock);
    return skinny_callRefer_info;
}
void skinny_del_session(struct skinny_callReference_info* si)
{
    pthread_mutex_lock(&skinny_ctx.head_lock);
    //FREE(si->call_id);
    list_del(&si->node);
    pthread_mutex_unlock(&skinny_ctx.head_lock);
    FREE(si);
    return;
}
struct skinny_callReference_info* skinny_find_session(u32 call_id)
{
    struct skinny_callReference_info* p;
    struct skinny_callReference_info* n;
    struct list_head* si_head;
    si_head = &skinny_ctx.si_head;
    
    list_for_each_entry_safe(p,n,si_head,node)
    {

        //if(!strcmp(call_id,p->call_id))
        if(call_id == p->call_id)
        {
        
            //skinny_log("find callid %s\n",call_id);
            return p;
        }
    }
    
    skinny_log("ERROR: nofind callid %u\n",call_id);
    return NULL;
}



static skinny_media_info* __skinny_new_media(struct skinny_callReference_info* skinny_callRefer)
{
    skinny_media_info* sm =NULL;
    sm = (skinny_media_info*)malloc(sizeof(skinny_media_info));
    if ( sm == NULL)
        return NULL;
    memset(sm,0,sizeof(skinny_media_info));
   // pthread_mutex_lock(&sip_ctx.head_lock);
    list_add(&sm->node,&skinny_callRefer->skinny_media_list);
    //pthread_mutex_unlock(&sip_ctx.head_lock);
    return sm;
}
void __skinny_del_media(skinny_callRefer* skinny_call, skinny_media_info* sm)
{
   

    list_del(&sm->node);
    
    FREE(sm);
    return;
}
skinny_media_info* __skinny_find_media(skinny_callRefer* skinny_call, u32 passThruPartyID)
{
    skinny_media_info* p;
    skinny_media_info* n;
    struct list_head* si_head;
    si_head = &skinny_call->skinny_media_list;
    
    list_for_each_entry_safe(p,n,si_head,node)
    {

        //if(!strcmp(passThruPartyID,p->passThruPartyID))
        if(passThruPartyID ==p->passThruPartyID)
        {
        
            //skinny_log("find passThruPartyID %s\n",passThruPartyID);
            return p;
        }
    }
    
    skinny_log("ERROR: nofind callid %u at skinnyCallRefencee %u \n",passThruPartyID,skinny_call->call_id);
    return NULL;
}

void __skinny_foreach_media_list(struct skinny_callReference_info* skinny_callRefer_info,
	void(*func)( skinny_media_info* n,struct skinny_callReference_info* skinny_callRefer_info))
{
	skinny_media_info* p;
    skinny_media_info* n;
	struct list_head* si_head;
	si_head = &skinny_callRefer_info->skinny_media_list;

	list_for_each_entry_safe(p,n,si_head,node)
	{
		
		func(p,skinny_callRefer_info);
	}

}

struct skinny_callReference_info* skinny_get_session(u32 callid)
{
  struct skinny_callReference_info* skinny_callRefer_info=skinny_find_session(callid);
  if(skinny_callRefer_info == NULL)
  {
      return NULL;
  }
  return skinny_callRefer_info;
}
static  struct skinny_callReference_info* skinny_get_session_by_callRef(u32 callReference)
{
  
  struct skinny_callReference_info* skinny_callRefer_info;
  
  //sprintf(callid,"%d",callReference);
      
  skinny_callRefer_info = skinny_get_session(callReference);
  if(skinny_callRefer_info ==  NULL)
  {
    skinny_log_err("no this callid %u session\n",callReference);
  }
  return skinny_callRefer_info;
}
/*------------------------------------------------*/
typedef struct qualifierOut_st
{
    u32 percedenceValue;
    u32 ssValue;
    u32 maxFramesPerpacket;
    u32 any_compressionType;
}qualifierOut;

void close_skinny_media(skinny_media_info* sm,
	struct skinny_callReference_info* skinny_callRefer_info)
{
	
    skinny_log(" close this callid %u sm %p media %u \n",skinny_callRefer_info->call_id,
    sm,sm->passThruPartyID);

    close_rtp_sniffer(sm->session_comm_info.rtp_sniffer_tid);
        __skinny_del_media(skinny_callRefer_info,sm);
}
void close_skinny_session_by_Callid(u32 callid)
{

  struct skinny_callReference_info* skinny_callRefer_info;

    skinny_callRefer_info = skinny_get_session(callid);
    if(skinny_callRefer_info)
    {
    
        skinny_log(" close this callid %u  \n",skinny_callRefer_info->call_id);
        
    	__skinny_foreach_media_list(skinny_callRefer_info,close_skinny_media);
        
    }
    else
    {
        skinny_log_err("no this callid %u session\n",callid);
        //exit(0);
    }

}
void close_skinny_media_by_PartyID(struct skinny_callReference_info* skinny_callRefer_info,u32 passThruPartyID)
{

  
	skinny_media_info* sm;

    sm = __skinny_find_media(skinny_callRefer_info,passThruPartyID);
    if(sm)
    {
        close_rtp_sniffer(sm->passThruPartyID);
        __skinny_del_media(skinny_callRefer_info,sm);
        
    }
    else
    {
        skinny_log_err("no this passThruPartyID %u Media\n",passThruPartyID);
        //exit(0);
    }

}

/* all session 's end is clearPromptStatus 2018-5-6 */
void handle_clear_prompt_status(skinny_opcode_map_t* skinny_op, 
                    u8* msg,u32 len,
                    skinny_info_t* skinny_info)
{
    u8* p = msg;
    u32 lineInstance;
    u32 callRefer;
    
    CW_LOAD_U32(lineInstance,p);
    CW_LOAD_U32(callRefer,p);
    skinny_log("enter\n");
    skinny_info->callid = callRefer;
   

	close_skinny_session_by_Callid(callRefer);

}

void __start_media_rtp_sniffer(skinny_media_info* sm,
	struct skinny_callReference_info* skinny_callRefer_info)
{

	
    sm->session_comm_info.mode = skinny_callRefer_info->mode;
    strncpy(sm->session_comm_info.called.number, 
			skinny_callRefer_info->called_number,
			sizeof(sm->session_comm_info.called.number));
	
	strncpy(sm->session_comm_info.calling.number, 
		skinny_callRefer_info->calling_number,
		sizeof(sm->session_comm_info.calling.number));

				
    if(skinny_callRefer_info->called_group_number[0] != 0)
    {
    	strncpy(sm->session_comm_info.called_group_number,
    	skinny_callRefer_info->called_group_number,
    	sizeof(sm->session_comm_info.called_group_number));
    	skinny_log("start rtp sniffer and skinny find the group number <%s> \n",
    		sm->session_comm_info.called_group_number);
    }
    
	skinny_log("_-_-_-----\n");
    if((sm->session_comm_info.called.ip.s_addr !=0)
    	&&(sm->session_comm_info.calling.ip.s_addr !=0)
    	&&(skinny_callRefer_info->skinny_callstate_connected == 1))
	{
    	sm->session_comm_info.rtp_sniffer_tid = setup_rtp_sniffer(&sm->session_comm_info);

    	
	skinny_log("_-_-_----- sm->session_comm_info.rtp_sniffer_tid %u\n",sm->session_comm_info.rtp_sniffer_tid);
    }
}
void __start_rtp_sniffer(struct skinny_callReference_info* skinny_callRefer_info)
{

	skinny_log("_-_-_-----\n");

	__skinny_foreach_media_list(skinny_callRefer_info, __start_media_rtp_sniffer);

}

/* center nofity peer's ip+port to csico phone */

void handle_start_media_transmission(skinny_opcode_map_t* skinny_op, u8* msg,u32 len,
                    skinny_info_t* skinny_info)
{
    u8* p = msg;
    u32 conferenceID;
  //  u32 status;
    u32 ipv4orv6;
    u32 remoteIpv4Address;
    u32 remotePort;
    u32 millisecondPaccketSize;
    u32 passThruPartyID;
    u32 compressionType;
    u32 callRefer;
    qualifierOut qualifier_out;
//    u32 callRefer;
    
    struct skinny_callReference_info* skinny_callRefer_info;
    skinny_media_info* sm;
    skinny_log("enter\n");
    
    CW_LOAD_U32(conferenceID,p);
    CW_LOAD_U32(passThruPartyID,p);
    CW_LOAD_U32(ipv4orv6,p);
    CW_LOAD_U32(remoteIpv4Address,p);
    p+=12;
    CW_LOAD_U32(remotePort,p);
    CW_LOAD_U32(millisecondPaccketSize,p);
    
    CW_LOAD_U32(compressionType,p);

    CW_LOAD_U32(qualifier_out.percedenceValue,p);
    CW_LOAD_U32(qualifier_out.ssValue,p);
    CW_LOAD_U32(qualifier_out.maxFramesPerpacket,p);
    CW_LOAD_U32(qualifier_out.any_compressionType,p);
    
    CW_LOAD_U32(callRefer,p);
    skinny_log("_-_-_----------- callrefer %u , Port %d  remoteIP %x \n",
        callRefer,remotePort,remoteIpv4Address);

    skinny_info->callid = callRefer;

    skinny_callRefer_info = skinny_get_session_by_callRef(callRefer);
    if(skinny_callRefer_info)
    {
    	sm =  __skinny_new_media(skinny_callRefer_info);
    	if(!sm)
    	{
    		skinny_log_err("create new media failed\n");
    		goto END;
    	}
    	sm->passThruPartyID = passThruPartyID;
    	sm->pfather = skinny_callRefer_info;
    
      if(skinny_callRefer_info->mode == SS_MODE_CALLING)
      {
      
          skinny_log("_-_-_-----I am master ------ callrefer %d , Port %d  remoteIP beijiao %x \n",
            callRefer,remotePort,remoteIpv4Address);
          sm->session_comm_info.called.ip.s_addr = remoteIpv4Address;
          sm->session_comm_info.called.port = (remotePort);
      }
      else
      {     skinny_log("_-_-_-----I am slave, ------ callrefer %d , Port %d  remoteIP is zhujiao %x \n",
            callRefer,remotePort,remoteIpv4Address);
  
          sm->session_comm_info.calling.ip.s_addr = remoteIpv4Address;
          sm->session_comm_info.calling.port = (remotePort);
      }
     // __start_rtp_sniffer(ss);
    }
    else
    {
      skinny_log_err("not find this callid %u \n",callRefer);
    }
 END:
 	return;
}
  /* 2019-1-26 BingXi */      
void handle_startMediaTransmissionACK(
  skinny_opcode_map_t* skinny_op, 
  u8* msg,
  u32 len,
  skinny_info_t* skinny_info)
{
    u8* p = msg;
    u32 conferenceID;
    u32 passThruPartyID; //同个channel里的ID。
    u32 callReference;
    u32 Ipv4or6;
    u32 ipv4Address;
    u32 Port;//transmitPort
    u32 startMediaTransmissionStatus = 0;

    struct skinny_callReference_info* skinny_callRefer_info;
    skinny_media_info* sm;
    
    CW_LOAD_U32(conferenceID,p);
    CW_LOAD_U32(passThruPartyID,p);
    CW_LOAD_U32(callReference,p);
    CW_LOAD_U32(Ipv4or6,p);
  
    CW_LOAD_U32(ipv4Address,p);
    p += 12; // FOR IPV6'S SIZE'
    skinny_log("--enter \n");
    CW_LOAD_U32(Port,p);    
    CW_LOAD_U32(startMediaTransmissionStatus,p);
    skinny_callRefer_info = skinny_get_session_by_callRef(callReference);
    if(skinny_callRefer_info)
    {   	
    	sm =  __skinny_find_media(skinny_callRefer_info,passThruPartyID);
    	if(!sm)
    	{
    		skinny_log_err("find the media  media failed!@@@\n");
    		goto END;
    	}
    	
    		skinny_log("find the media  media successfully!@@@ sm %p, passThruPartyID %u\n",
    		sm,passThruPartyID);
    	//sm->passThruPartyID = passThruPartyID;
    	sm->pfather = skinny_callRefer_info;
    	
      if(skinny_callRefer_info->mode == SS_MODE_CALLING){
      
        skinny_log("_-_-_-----I am master ------ callrefer %d , Port %d zhijiao ipv4Address %x \n",
                    callReference,Port,ipv4Address);
          sm->session_comm_info.calling.ip.s_addr = ipv4Address;
          sm->session_comm_info.calling.port = (Port);
      }
      else
      {
      
            skinny_log("_-_-_-----I am slave ------ callrefer %d , Port %d beijiao ipv4Address %x \n",
            callReference,Port,ipv4Address);

          sm->session_comm_info.called.ip.s_addr = ipv4Address;
          sm->session_comm_info.called.port = (Port);
      }
      sm->session_comm_info.mode = skinny_callRefer_info->mode;
      __start_rtp_sniffer(skinny_callRefer_info);
    } 
    else
    {
      skinny_log_err("not find this callid %u \n",callReference);
    }

 END:
 	return;
 }
 void handle_StopMediaTransmission(
  skinny_opcode_map_t* skinny_op, 
  u8* msg,
  u32 len,
  skinny_info_t* skinny_info)
 {
    u8* p = msg;
    u32 conferenceID;
    u32 passThruPartyID; //同个channel里的ID。
    u32 callReference;
    u32 portHandingFlag;

   // char callid[32] = {0};
    //struct skinny_callReference_info* skinny_callRefer_info;
        
    skinny_log("close the callid \n");
    CW_LOAD_U32(conferenceID,p);
    CW_LOAD_U32(passThruPartyID,p);
    CW_LOAD_U32(callReference,p);
    CW_LOAD_U32(portHandingFlag,p);
    
  //  sprintf(callid,"%u",callReference);


    skinny_log("close the callid(%u) \n",callReference);
    close_skinny_session_by_Callid(callReference);
 }

void handle_open_receive_channel_ack(
	skinny_opcode_map_t* skinny_op, 
		u8* msg,
		u32 len,
        skinny_info_t* skinny_info)
{

  handle_default_function(skinny_op,msg,len,skinny_info);
}

#if 1
#if 0
/* 当时由于taped没有ntp服务，只好从报文里取出时钟时间，再计算出通话的开始时间。 */
void cul_skinny_start_time(struct skinny_callReference_info* ss, struct tm* t)
{
    time_t a;
    time_t now;
    struct tm* tt;
    time(&now);
    a = mktime(t);
    a -= now - ss->start_time_stamp;

    tt = localtime(&a);
    memcpy(&ss->ring_time,tt,sizeof(struct tm));
    skinny_log(" I get time: acstime %s  \n",asctime(tt));
}
#endif
void check_all_session_is_callstate_onhook(struct tm* t)
{
    struct skinny_callReference_info* p;
    struct skinny_callReference_info* n;
    struct list_head* si_head;
    si_head = &skinny_ctx.si_head;
    
    list_for_each_entry_safe(p,n,si_head,node)
    {

        if(p->skinny_state == SKINNY_CALLSTATE_ONHOOK)
        {
            //cul_skinny_start_time(p,t);
            skinny_log("this callid %u session is onhook, I will close it.\n",p->call_id);
            close_skinny_session_by_Callid(p->call_id);

        }
    }
    
}

void handle_default_TimeDate(
    skinny_opcode_map_t* skinny_op, 
    u8* msg,
    u32 len,
    skinny_info_t* skinny_info)
{

  struct tm t;
  char ring_time[256]={0};
  int wMilliseconds;
  time_t system_time;
  u8* p = msg;
  //char callid[32]={0};
  struct skinny_callReference_info* skinny_callRefer_info ;
  
    skinny_log("enter and return doNothing \n");
   return; //2019-1-26
   
   memset(&t,0,sizeof(struct tm));
   CW_LOAD_U32(t.tm_year,p);
   CW_LOAD_U32(t.tm_mon,p);
   CW_LOAD_U32(t.tm_wday,p);
   CW_LOAD_U32(t.tm_mday,p);
   CW_LOAD_U32(t.tm_hour,p);
   CW_LOAD_U32(t.tm_min,p);
   CW_LOAD_U32(t.tm_sec,p);
   CW_LOAD_U32(wMilliseconds,p);
   CW_LOAD_U32(wMilliseconds,p);
   CW_LOAD_U32(system_time,p);
   skinny_log("time : %d-%d-%d, %d:%d:%d\n",
   t.tm_year,t.tm_mon,t.tm_mday,
       t.tm_hour,t.tm_min,t.tm_sec);
       
   t.tm_year = t.tm_year - 1900;
   t.tm_mon = t.tm_mon - 1;
   t.tm_mday = t.tm_mday;
   t.tm_wday = t.tm_wday;
   t.tm_hour = t.tm_hour;
   t.tm_min = t.tm_min;
   t.tm_sec = t.tm_sec;
   
   strftime(ring_time,256,"time_%Y-%m-%d_%H-%M-%S",&t);
       skinny_log("time : %s \n",ring_time);
               
    if(skinny_info->callid == 0)
    {
        skinny_log("callid is 0\n");
        check_all_session_is_callstate_onhook(&t);
        return;
    }
    else
    {
  
  
      skinny_callRefer_info = skinny_get_session_by_callRef(skinny_info->callid);
      if(skinny_callRefer_info)
      {
         // cul_skinny_start_time(ss,&t);
          
          skinny_log("I will close this skinny %u \n",skinny_info->callid);
          ///  sprintf(callid,"%d",skinny_info->callid);
          close_skinny_session_by_Callid(skinny_info->callid);
          
      }
      else
      {
        skinny_log_err("no this callid %u session\n",skinny_info->callid);
          //exit(0);
      }
        
  }
}
#endif
#if 0
handle_prompt_status_v2(skinny_opcode_map_t* skinny_op, u8* msg,u32 len,
                            skinny_info_t* skinny_info)
{
  u8* p = msg;
  u32 timeOutValue;
  u32 lineInstance;
  u32 callReference;
  char* prompt_status;
    int prompt_status_len;
    int msessag_id_len = 4;
  
  struct skinny_callReference_info* ss;
  
  char callid[64]={0};
  
    skinny_log("enter\n");
  CW_LOAD_U32(timeOutValue,p);
  CW_LOAD_U32(lineInstance,p);
  CW_LOAD_U32(callReference,p);

  prompt_status_len = len - msessag_id_len - 3*4;
  

}
#endif
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

void handle_CallState(skinny_opcode_map_t* skinny_op, u8* msg,u32 len,
                            skinny_info_t* skinny_info)
{

    
  u8* p = msg;
  u32 callState;
  u32 lineInstance;
  u32 callReference;

  
  skinny_callRefer* skinny_callRefer_info;
  
  
    skinny_log("enter\n");
  CW_LOAD_U32(callState,p);
  CW_LOAD_U32(lineInstance,p);
  CW_LOAD_U32(callReference,p);

  
    skinny_info->callid = callReference;

    skinny_callRefer_info=skinny_find_session(callReference);
    if(skinny_callRefer_info == NULL)
    {
        skinny_callRefer_info = skinny_new_session();
        if(skinny_callRefer_info ==NULL)
            return;
   		skinny_callRefer_info->call_id = callReference;
    }

    skinny_log("enter callid %u\n",callReference);

  if(skinny_callRefer_info ==  NULL)
  {
    skinny_log_err("no this callid %u session\n",callReference);
    return;
  }
  skinny_callRefer_info->skinny_state = callState;
  if(callState == SKINNY_CALLSTATE_RING_IN)//ring in;
  {
  
      skinny_callRefer_info->mode = SS_MODE_CALLED;
      skinny_log(" I am ringin callstate ,so I am called. \n");
      
  }
    else if(callState == SKINNY_CALLSTATE_Proceed)//Proceed
    {
      skinny_callRefer_info->mode = SS_MODE_CALLING;
      skinny_log(" I am process callstate ,so I am calling. callReference %d \n",callReference);
      
        
    }
    else if(callState == SKINNY_CALLSTATE_RING_OUT)//calling.
    {
      skinny_callRefer_info->mode = SS_MODE_CALLING;
      skinny_log(" I am ring out callstate ,so I am calling. callReference %d \n",callReference);
      
        
    }
    else if(callState == SKINNY_CALLSTATE_CONNECTED) //connected.
    {
      skinny_callRefer_info->skinny_callstate_connected = 1;
      skinny_log(" process callstate Connected , I start the rtp sinnfer. callReference %d \n",callReference);
      __start_rtp_sniffer(skinny_callRefer_info);
    }
    else
    {
      
      skinny_log(" I callstate %d . \n",callState);
    }
  	skinny_info->callstate = callState;
  	skinny_callRefer_info->skinny_state = callState;
  
    skinny_log("exit callid \n");
} 

void __update_rtp_session_number (
    skinny_media_info* media_info,
	struct skinny_callReference_info* skinny_callRefer_info)
{
	struct rtp_session_info* n;
	
	if(media_info->session_comm_info.rtp_sniffer_tid)
	{
		n = _rtp_find_session(media_info->session_comm_info.rtp_sniffer_tid);
		if(n)
		{
			skinny_log("I(%u) update (%u)'s calling and called number \n",
				pthread_self(),
				media_info->session_comm_info.rtp_sniffer_tid);
			strncpy(n->called.number, 
			skinny_callRefer_info->called_number,
			sizeof(n->called.number));
			
			strncpy(n->calling.number, 
				skinny_callRefer_info->calling_number,
				sizeof(n->calling.number));
				
			strncpy(n->called_group_number, 
				skinny_callRefer_info->called_group_number,
				sizeof(n->called_group_number));
		}
	}
}

/* 在这个函数执行时，rtp应该还没有建立起来。 */
void update_rtp_session_number(struct skinny_callReference_info* skinny_callRefer_info)
{

	__skinny_foreach_media_list(skinny_callRefer_info,__update_rtp_session_number);
}




void handle_callinfo2_function(skinny_opcode_map_t* skinny_op, u8* msg,u32 len,
    skinny_info_t* skinny_info)
{
    
  u8* p = msg;
  u32 lineInstance;
  u32 callReference;
  u32 callType;
  u32 originalCdpnRedirectReason;
  u32 lastRedirect;
  u32 callInstance;
  u32 callSecurityStatus;
  u32 partyPiRestrictionBits;
  
  char callingParty[33] = {0};
  char AlternateCallingParty[33] = {0}; 
  char calledParty[33] = {0};
  char originalCalledParty[33] = {0};
  char lastRedirectingParty[33] = {0};

  char cgpnVoiceMailbox[128] = {0};
  char cdpnVoiceMailbox[128] = {0};
  char originalCdpnVoiceMailbox[128] = {0};
  char lastRedirectingVoiceMailbox[128] = {0};
  char callingPartyName[128] = {0};
  char calledPartyName[128] = {0};
  char originalCalledPartyName[128] = {0};
  char lastRedirectingPartyName[128] = {0};
  
  char HuntPilotNumber[33] = {0};

  //char* calling_number = NULL;
  //char* called_number = NULL;
  //char* AlternateCalling_number = NULL;

  
  struct skinny_callReference_info* skinny_callRefer_info;
  
//  char callid[64]={0};

    skinny_log("enter\n");
  CW_LOAD_U32(lineInstance,p);
  CW_LOAD_U32(callReference,p);
  CW_LOAD_U32(callType,p);
  
  CW_LOAD_U32(originalCdpnRedirectReason,p);
  CW_LOAD_U32(lastRedirect,p);
  CW_LOAD_U32(callInstance,p);
  CW_LOAD_U32(callSecurityStatus,p);
  CW_LOAD_U32(partyPiRestrictionBits,p);
  

  skinny_callRefer_info = skinny_get_session_by_callRef(callReference);
    if(skinny_callRefer_info)
    {


    }
    else
    {
        skinny_log_err("not find this callid %u \n",callReference);
        return;
    }
  LOAD_STR_LINE(p, callingParty, 32, 0);
  LOAD_STR_LINE(p, AlternateCallingParty, 32, 0); 
  LOAD_STR_LINE(p, calledParty, 32, 0); 
  LOAD_STR_LINE(p, originalCalledParty, 32, 0);
  LOAD_STR_LINE(p, lastRedirectingParty, 32, 0);
  skinny_log("callingParty:<%s>\n",callingParty);
  skinny_log("AlternateCallingParty:<%s>\n",AlternateCallingParty);
  skinny_log("calledParty:<%s>\n",calledParty);
  skinny_log("originalCalledParty:<%s>\n",originalCalledParty);
  skinny_log("lastRedirectingParty:<%s>\n",lastRedirectingParty);

  if(skinny_callRefer_info->called_number[0] == 0)
  {
    strncpy(skinny_callRefer_info->called_number,calledParty,sizeof(skinny_callRefer_info->called_number));
  }
  else
  {
    if(0 ==strncmp(skinny_callRefer_info->called_number,calledParty,strlen(calledParty)))
    {
    
    }
    else
    {
      skinny_log("calledParty is changed from <%s> to <%s> \n",skinny_callRefer_info->called_number,calledParty);
      if(skinny_callRefer_info->skinny_callstate_connected == 1)
      {
        skinny_log("callstate is connected, update the called number\n");
        strncpy(skinny_callRefer_info->called_group_number,
          skinny_callRefer_info->called_number,sizeof(skinny_callRefer_info->called_group_number));
        /* update the new called number ....2018-12-3 */
        strncpy(skinny_callRefer_info->called_number,calledParty,sizeof(skinny_callRefer_info->called_number));
        
      }
    }
  }
  strncpy(skinny_callRefer_info->calling_number,callingParty,sizeof(skinny_callRefer_info->calling_number));
  skinny_log("I get called number %s,calling number %s \n",
      skinny_callRefer_info->called_number,skinny_callRefer_info->calling_number);
  
  LOAD_STR_LINE(p, cgpnVoiceMailbox, 127, 0);
  skinny_log("cgpnVoiceMailbox:<%s>\n",cgpnVoiceMailbox);
  LOAD_STR_LINE(p, cdpnVoiceMailbox, 127, 0);
  skinny_log("cdpnVoiceMailbox:<%s>\n",cdpnVoiceMailbox);
  
  LOAD_STR_LINE(p, originalCdpnVoiceMailbox, 127, 0);
  skinny_log("originalCdpnVoiceMailbox:<%s>\n",originalCdpnVoiceMailbox);
  
  LOAD_STR_LINE(p, lastRedirectingVoiceMailbox, 127, 0);
  skinny_log("lastRedirectingVoiceMailbox:<%s>\n",lastRedirectingVoiceMailbox);
  
  LOAD_STR_LINE(p, callingPartyName, 127, 0);
  skinny_log("callingPartyName:<%s>\n",callingPartyName);
  
  LOAD_STR_LINE(p, calledPartyName, 127, 0);
  skinny_log("calledPartyName:<%s>\n",calledPartyName);
  
  LOAD_STR_LINE(p, originalCalledPartyName, 127, 0);
  skinny_log("originalCalledPartyName:<%s>\n",originalCalledPartyName);
  LOAD_STR_LINE(p, lastRedirectingPartyName, 127, 0);
  skinny_log("lastRedirectingPartyName:<%s>\n",lastRedirectingPartyName);
  LOAD_STR_LINE(p, HuntPilotNumber, 127, 0);
  skinny_log("HuntPilotNumber:<%s>\n",HuntPilotNumber);
  
/* sccp当被叫时，会有HuntPilotNumber，则把电话自己的号码放到called里。 */
/* SCCP为主叫时，callinfov2里不会有HuntPilotNumber，
但 前后callinfoV2的报文里 calledParty 会变化，由'组号' 变成 '组员的号码'。*/  
  if(HuntPilotNumber[0] !=0)
  {
    skinny_log("Bingo, I get a huntPilotNumber, "
      "and change the called number to phone number(%s)",g_LineStatV2_lineDirNumber);
    if(g_LineStatV2_lineDirNumber[0] != 0)
    {
      strncpy(skinny_callRefer_info->called_number,g_LineStatV2_lineDirNumber,sizeof(skinny_callRefer_info->called_number));
    }
/* 把HuntPilotNumber放到called_group_number里，这是新增加的字体，会上报到平台。2018-12-3 */    
    strncpy(skinny_callRefer_info->called_group_number,HuntPilotNumber,sizeof(skinny_callRefer_info->called_group_number));
  }
  update_rtp_session_number(skinny_callRefer_info);
  return;

}

void handle_DialedNumber(skinny_opcode_map_t* skinny_op, u8* msg,u32 len,
                            skinny_info_t* skinny_info)
{
	u8* p = msg;
	struct skinny_callReference_info* skinny_callRefer_info;
	char dailed_num[26]={0};
	u32 line_instance=0;

	u32 callReference=0;


	skinny_log("enter\n");

	CW_LOAD_STR(dailed_num,p,25);

	CW_LOAD_U32(line_instance,p);
	CW_LOAD_U32(callReference,p);

	skinny_info->callid = callReference;

	skinny_callRefer_info = skinny_new_session();
	if(skinny_callRefer_info ==NULL)
	    return;

	skinny_callRefer_info->call_id = callReference;
	if(skinny_callRefer_info ==  NULL)
	{
		skinny_log_err("no this callid %u session\n",callReference);
		return;
	}
	skinny_callRefer_info->mode = SS_MODE_CALLING;
	skinny_log("callid %u dailed number %u \n",callReference,dailed_num);

	return;
}
/* 在电话注册时，得到电话的号码。 */
void handle_LineStateV2 (
    skinny_opcode_map_t* skinny_op, 
    u8* msg,u32 len,
    skinny_info_t* skinny_info)
{


  u8* p = msg;

  u32 lineNumber;
  u32 lineType;
  char lineDirNumber[33]={0};
  char lineFullyQualifiedDisplayName[33]={0};
  char lineTextLabel[33] = {0};
  
  CW_LOAD_U32(lineNumber,p);
  CW_LOAD_U32(lineType,p);
  
  LOAD_STR_LINE(p, lineDirNumber, 32, 0);
  LOAD_STR_LINE(p, lineFullyQualifiedDisplayName, 32, 0);
  LOAD_STR_LINE(p, lineTextLabel, 32, 0);
  skinny_log("lineNumber:%u\n",lineNumber);
  skinny_log("lineType:%u\n",lineType);
  skinny_log("lineDirNumber:%s\n",lineDirNumber);
  skinny_log("lineFullyQualifiedDisplayName:%s\n",lineFullyQualifiedDisplayName);

  skinny_log("lineTextLabel:%s\n",lineTextLabel);
  if(lineDirNumber[0] != 0)
  {
    if(g_LineStatV2_lineDirNumber[0] == 0)
    {
      skinny_log("init set  g_LineStatV2_lineDirNumber \n");
      strncpy(g_LineStatV2_lineDirNumber,lineDirNumber,
      sizeof(g_LineStatV2_lineDirNumber)-1);
      
    }
    else
    {
      skinny_log(" g_LineStatV2_lineDirNumber's value <%s> \n",
        g_LineStatV2_lineDirNumber);
      if(!strncmp(g_LineStatV2_lineDirNumber,lineDirNumber,
        strlen(g_LineStatV2_lineDirNumber)))  
      {
        skinny_log("g_LineStatV2_lineDirNumber == lineDirNumber, not update it \n");
      }
      else
      {
        skinny_log("g_LineStatV2_lineDirNumber != lineDirNumber, must update it \n");
        
        strncpy(g_LineStatV2_lineDirNumber,lineDirNumber,
        sizeof(g_LineStatV2_lineDirNumber)-1);
      }
    }
  }
  else
  {
    skinny_log("not get lineDirNumber \n");
  }
}
              


void handle_default_function (skinny_opcode_map_t* skinny_op, u8* msg,u32 len,
    skinny_info_t* skinny_info)
{
  skinny_log("%s and msg len %d  \n",skinny_op->name,len);
  
}

/* Messages Handler Array */
static  skinny_opcode_map_t skinny_opcode_map[] = {
  {0x0000, handle_default_function                                           , SKINNY_MSGTYPE_REQUEST  , "KeepAliveReqMessage"},
#if 1
  {0x0001, handle_default_function                      , SKINNY_MSGTYPE_REQUEST  , "RegisterReqMessage"},
  {0x0002, handle_default_function                           , SKINNY_MSGTYPE_EVENT    , "IpPortMessage"},
  {0x0003, handle_default_function                     , SKINNY_MSGTYPE_EVENT    , "KeypadButtonMessage"},
  {0x0004, handle_default_function                       , SKINNY_MSGTYPE_EVENT    , "EnblocCallMessage"},
  {0x0005, handle_default_function                         , SKINNY_MSGTYPE_EVENT    , "StimulusMessage"},
  {0x0006, handle_default_function                          , SKINNY_MSGTYPE_EVENT    , "OffHookMessage"},
  {0x0007, handle_default_function                           , SKINNY_MSGTYPE_EVENT    , "OnHookMessage"},
  {0x0008, handle_default_function                        , SKINNY_MSGTYPE_EVENT    , "HookFlashMessage"},
  {0x0009, handle_default_function                   , SKINNY_MSGTYPE_REQUEST  , "ForwardStatReqMessage"},
  {0x000a, handle_default_function                 , SKINNY_MSGTYPE_REQUEST  , "SpeedDialStatReqMessage"},
  {0x000b, handle_default_function                      , SKINNY_MSGTYPE_REQUEST  , "LineStatReqMessage"},
  {0x000c, handle_default_function                                           , SKINNY_MSGTYPE_REQUEST  , "ConfigStatReqMessage"},
  {0x000d, handle_default_function                                           , SKINNY_MSGTYPE_REQUEST  , "TimeDateReqMessage"},
  {0x000e, handle_default_function                                           , SKINNY_MSGTYPE_REQUEST  , "ButtonTemplateReqMessage"},
  {0x000f, handle_default_function                                           , SKINNY_MSGTYPE_REQUEST  , "VersionReqMessage"},
  {0x0010, handle_default_function                  , SKINNY_MSGTYPE_RESPONSE , "CapabilitiesResMessage"},
  {0x0012, handle_default_function                                           , SKINNY_MSGTYPE_REQUEST  , "ServerReqMessage"},
  {0x0020, handle_default_function                            , SKINNY_MSGTYPE_EVENT    , "AlarmMessage"},
  {0x0021, handle_default_function       , SKINNY_MSGTYPE_RESPONSE , "MulticastMediaReceptionAckMessage"},
  {0x0022, handle_open_receive_channel_ack            , SKINNY_MSGTYPE_RESPONSE , "OpenReceiveChannelAckMessage"},
  {0x0023, handle_default_function          , SKINNY_MSGTYPE_RESPONSE , "ConnectionStatisticsResMessage"},
  {0x0024, handle_default_function     , SKINNY_MSGTYPE_EVENT    , "OffHookWithCalingPartyNumberMessage"},
  {0x0025, handle_default_function                                           , SKINNY_MSGTYPE_REQUEST  , "SoftKeySetReqMessage"},
  {0x0026, handle_default_function                     , SKINNY_MSGTYPE_EVENT    , "SoftKeyEventMessage"},
  {0x0027, handle_default_function                    , SKINNY_MSGTYPE_REQUEST  , "UnregisterReqMessage"},
  {0x0028, handle_default_function                                           , SKINNY_MSGTYPE_REQUEST  , "SoftKeyTemplateReqMessage"},
  {0x0029, handle_default_function                        , SKINNY_MSGTYPE_REQUEST  , "RegisterTokenReq"},
  {0x002a, handle_default_function         , SKINNY_MSGTYPE_RESPONSE , "MediaTransmissionFailureMessage"},
  {0x002b, handle_default_function                    , SKINNY_MSGTYPE_EVENT    , "HeadsetStatusMessage"},
  {0x002c, handle_default_function        , SKINNY_MSGTYPE_EVENT    , "MediaResourceNotificationMessage"},
  {0x002d, handle_default_function           , SKINNY_MSGTYPE_EVENT    , "RegisterAvailableLinesMessage"},
  {0x002e, handle_default_function                 , SKINNY_MSGTYPE_REQUEST  , "DeviceToUserDataMessage"},
  {0x002f, handle_default_function         , SKINNY_MSGTYPE_RESPONSE , "DeviceToUserDataResponseMessage"},
  {0x0030, handle_default_function               , SKINNY_MSGTYPE_EVENT    , "UpdateCapabilitiesMessage"},
  {0x0031, handle_default_function  , SKINNY_MSGTYPE_RESPONSE , "OpenMultiMediaReceiveChannelAckMessage"},
  {0x0032, handle_default_function                  , SKINNY_MSGTYPE_EVENT    , "ClearConferenceMessage"},
  {0x0033, handle_default_function                , SKINNY_MSGTYPE_REQUEST  , "ServiceURLStatReqMessage"},
  {0x0034, handle_default_function                   , SKINNY_MSGTYPE_REQUEST  , "FeatureStatReqMessage"},
  {0x0035, handle_default_function              , SKINNY_MSGTYPE_RESPONSE , "CreateConferenceResMessage"},
  {0x0036, handle_default_function              , SKINNY_MSGTYPE_RESPONSE , "DeleteConferenceResMessage"},
  {0x0037, handle_default_function              , SKINNY_MSGTYPE_RESPONSE , "ModifyConferenceResMessage"},
  {0x0038, handle_default_function                , SKINNY_MSGTYPE_RESPONSE , "AddParticipantResMessage"},
  {0x0039, handle_default_function               , SKINNY_MSGTYPE_RESPONSE , "AuditConferenceResMessage"},
  {0x0040, handle_default_function              , SKINNY_MSGTYPE_RESPONSE , "AuditParticipantResMessage"},
  {0x0041, handle_default_function         , SKINNY_MSGTYPE_REQUEST  , "DeviceToUserDataMessageVersion1"},
  {0x0042, handle_default_function , SKINNY_MSGTYPE_RESPONSE , "DeviceToUserDataResponseMessageVersion1"},
  {0x0043, handle_default_function                , SKINNY_MSGTYPE_RESPONSE , "CapabilitiesV2ResMessage"},
  {0x0044, handle_default_function                , SKINNY_MSGTYPE_RESPONSE , "CapabilitiesV3ResMessage"},
  {0x0045, handle_default_function                          , SKINNY_MSGTYPE_RESPONSE , "PortResMessage"},
  {0x0046, handle_default_function                    , SKINNY_MSGTYPE_EVENT    , "QoSResvNotifyMessage"},
  {0x0047, handle_default_function                   , SKINNY_MSGTYPE_EVENT    , "QoSErrorNotifyMessage"},
  {0x0048, handle_default_function              , SKINNY_MSGTYPE_REQUEST  , "SubscriptionStatReqMessage"},
  {0x0049, handle_default_function                   , SKINNY_MSGTYPE_EVENT    , "MediaPathEventMessage"},
  {0x004a, handle_default_function              , SKINNY_MSGTYPE_EVENT    , "MediaPathCapabilityMessage"},
  {0x004c, handle_default_function                  , SKINNY_MSGTYPE_REQUEST  , "MwiNotificationMessage"},
  {0x0081, handle_default_function                      , SKINNY_MSGTYPE_RESPONSE , "RegisterAckMessage"},
  {0x0082, handle_default_function                        , SKINNY_MSGTYPE_EVENT    , "StartToneMessage"},
  {0x0083, handle_default_function                         , SKINNY_MSGTYPE_EVENT    , "StopToneMessage"},
  {0x0085, handle_default_function                        , SKINNY_MSGTYPE_EVENT    , "SetRingerMessage"},
  {0x0086, handle_default_function                          , SKINNY_MSGTYPE_EVENT    , "SetLampMessage"},
  {0x0087, handle_default_function                                           , SKINNY_MSGTYPE_EVENT    , "SetHookFlashDetectMessage"},
  {0x0088, handle_default_function                   , SKINNY_MSGTYPE_EVENT    , "SetSpeakerModeMessage"},
  {0x0089, handle_default_function                     , SKINNY_MSGTYPE_EVENT    , "SetMicroModeMessage"},
  {0x008a, handle_start_media_transmission           , SKINNY_MSGTYPE_REQUEST  , "StartMediaTransmissionMessage"},
  {0x008b, handle_StopMediaTransmission   , SKINNY_MSGTYPE_EVENT    , "StopMediaTransmissionMessage"},
  {0x008f, handle_default_function                         , SKINNY_MSGTYPE_EVENT    , "CallInfoMessage"},
  {0x0090, handle_default_function                   , SKINNY_MSGTYPE_RESPONSE , "ForwardStatResMessage"},
  {0x0091, handle_default_function                 , SKINNY_MSGTYPE_RESPONSE , "SpeedDialStatResMessage"},
  {0x0092, handle_default_function                      , SKINNY_MSGTYPE_RESPONSE , "LineStatResMessage"},
  {0x0093, handle_default_function                    , SKINNY_MSGTYPE_RESPONSE , "ConfigStatResMessage"},
  //???TimeDateResMessageé????–?—?é—′?€?
  {0x0094, handle_default_function                      , SKINNY_MSGTYPE_RESPONSE , "TimeDateResMessage"},//---liudan
  {0x0095, handle_default_function         , SKINNY_MSGTYPE_EVENT    , "StartSessionTransmissionMessage"},
  {0x0096, handle_default_function          , SKINNY_MSGTYPE_EVENT    , "StopSessionTransmissionMessage"},
  {0x0097, handle_default_function                , SKINNY_MSGTYPE_RESPONSE , "ButtonTemplateResMessage"},
  {0x0098, handle_default_function                       , SKINNY_MSGTYPE_RESPONSE , "VersionResMessage"},
  {0x0099, handle_default_function                      , SKINNY_MSGTYPE_EVENT    , "DisplayTextMessage"},
  {0x009a, handle_default_function                                           , SKINNY_MSGTYPE_EVENT    , "ClearDisplay"},
  {0x009b, handle_default_function                                           , SKINNY_MSGTYPE_EVENT    , "CapabilitiesReq"},
  {0x009d, handle_default_function                   , SKINNY_MSGTYPE_EVENT    , "RegisterRejectMessage"},
  {0x009e, handle_default_function                        , SKINNY_MSGTYPE_RESPONSE , "ServerResMessage"},
  {0x009f, handle_default_function                                   , SKINNY_MSGTYPE_EVENT    , "Reset"},
  {0x0100, handle_default_function                                           , SKINNY_MSGTYPE_RESPONSE , "KeepAliveAckMessage"},
  {0x0101, handle_default_function     , SKINNY_MSGTYPE_REQUEST  , "StartMulticastMediaReceptionMessage"},
  {0x0102, handle_default_function  , SKINNY_MSGTYPE_REQUEST  , "StartMulticastMediaTransmissionMessage"},
  {0x0103, handle_default_function      , SKINNY_MSGTYPE_EVENT    , "StopMulticastMediaReceptionMessage"},
  {0x0104, handle_default_function   , SKINNY_MSGTYPE_EVENT    , "StopMulticastMediaTransmissionMessage"},
  {0x0105, handle_default_function               , SKINNY_MSGTYPE_REQUEST  , "OpenReceiveChannelMessage"},
  {0x0106, handle_default_function              , SKINNY_MSGTYPE_EVENT    , "CloseReceiveChannelMessage"},
  {0x0107, handle_default_function          , SKINNY_MSGTYPE_REQUEST  , "ConnectionStatisticsReqMessage"},
  {0x0108, handle_default_function               , SKINNY_MSGTYPE_RESPONSE , "SoftKeyTemplateResMessage"},
  {0x0109, handle_default_function                    , SKINNY_MSGTYPE_RESPONSE , "SoftKeySetResMessage"},
  {0x0110, handle_default_function                   , SKINNY_MSGTYPE_EVENT    , "SelectSoftKeysMessage"},
  {0x0111, handle_CallState                        , SKINNY_MSGTYPE_EVENT    , "CallStateMessage"},
  {0x0112, handle_default_function              , SKINNY_MSGTYPE_EVENT    , "DisplayPromptStatusMessage"},
  {0x0113, handle_clear_prompt_status                , SKINNY_MSGTYPE_EVENT    ,"ClearPromptStatusMessage"},
  {0x0114, handle_default_function                    , SKINNY_MSGTYPE_EVENT    , "DisplayNotifyMessage"},
  {0x0115, handle_default_function                                           , SKINNY_MSGTYPE_EVENT    , "ClearNotifyMessage"},
  {0x0116, handle_default_function                , SKINNY_MSGTYPE_EVENT    , "ActivateCallPlaneMessage"},
  {0x0117, handle_default_function                                           , SKINNY_MSGTYPE_EVENT    , "DeactivateCallPlaneMessage"},
  {0x0118, handle_default_function                    , SKINNY_MSGTYPE_RESPONSE , "UnregisterAckMessage"},
  {0x0119, handle_default_function                     , SKINNY_MSGTYPE_EVENT    , "BackSpaceResMessage"},
  {0x011a, handle_default_function                                           , SKINNY_MSGTYPE_RESPONSE , "RegisterTokenAck"},
  {0x011b, handle_default_function                     , SKINNY_MSGTYPE_RESPONSE , "RegisterTokenReject"},
  {0x011c, handle_default_function       , SKINNY_MSGTYPE_EVENT    , "StartMediaFailureDetectionMessage"},
  {0x011d, handle_DialedNumber                     , SKINNY_MSGTYPE_EVENT    , "DialedNumberMessage"}, //?????°?”¨??·è?“?…￥?????·????€?
  {0x011e, handle_default_function                 , SKINNY_MSGTYPE_EVENT    , "UserToDeviceDataMessage"},
  {0x011f, handle_default_function                   , SKINNY_MSGTYPE_RESPONSE , "FeatureStatResMessage"},
  {0x0120, handle_default_function                 , SKINNY_MSGTYPE_EVENT    , "DisplayPriNotifyMessage"},
  {0x0121, handle_default_function                   , SKINNY_MSGTYPE_EVENT    , "ClearPriNotifyMessage"},
  {0x0122, handle_default_function                , SKINNY_MSGTYPE_EVENT    , "StartAnnouncementMessage"},
  {0x0123, handle_default_function                 , SKINNY_MSGTYPE_EVENT    , "StopAnnouncementMessage"},
  {0x0124, handle_default_function               , SKINNY_MSGTYPE_EVENT    , "AnnouncementFinishMessage"},
  {0x0127, handle_default_function                   , SKINNY_MSGTYPE_EVENT    , "NotifyDtmfToneMessage"},
  {0x0128, handle_default_function                     , SKINNY_MSGTYPE_EVENT    , "SendDtmfToneMessage"},
  {0x0129, handle_default_function          , SKINNY_MSGTYPE_REQUEST  , "SubscribeDtmfPayloadReqMessage"},
  {0x012a, handle_default_function          , SKINNY_MSGTYPE_RESPONSE , "SubscribeDtmfPayloadResMessage"},
  {0x012b, handle_default_function          , SKINNY_MSGTYPE_RESPONSE , "SubscribeDtmfPayloadErrMessage"},
  {0x012c, handle_default_function        , SKINNY_MSGTYPE_REQUEST  , "UnSubscribeDtmfPayloadReqMessage"},
  {0x012d, handle_default_function        , SKINNY_MSGTYPE_RESPONSE , "UnSubscribeDtmfPayloadResMessage"},
  {0x012e, handle_default_function        , SKINNY_MSGTYPE_RESPONSE , "UnSubscribeDtmfPayloadErrMessage"},
  {0x012f, handle_default_function                , SKINNY_MSGTYPE_RESPONSE , "ServiceURLStatResMessage"},
  {0x0130, handle_default_function                , SKINNY_MSGTYPE_EVENT    , "CallSelectStatResMessage"},
  {0x0131, handle_default_function     , SKINNY_MSGTYPE_REQUEST  , "OpenMultiMediaReceiveChannelMessage"},
  {0x0132, handle_default_function      , SKINNY_MSGTYPE_REQUEST  , "StartMultiMediaTransmissionMessage"},
  {0x0133, handle_default_function       , SKINNY_MSGTYPE_EVENT    , "StopMultiMediaTransmissionMessage"},
  {0x0134, handle_default_function             , SKINNY_MSGTYPE_EVENT    , "MiscellaneousCommandMessage"},
  {0x0135, handle_default_function               , SKINNY_MSGTYPE_EVENT    , "FlowControlCommandMessage"},
  {0x0136, handle_default_function    , SKINNY_MSGTYPE_EVENT    , "CloseMultiMediaReceiveChannelMessage"},
  {0x0137, handle_default_function              , SKINNY_MSGTYPE_REQUEST  , "CreateConferenceReqMessage"},
  {0x0138, handle_default_function              , SKINNY_MSGTYPE_REQUEST  , "DeleteConferenceReqMessage"},
  {0x0139, handle_default_function              , SKINNY_MSGTYPE_REQUEST  , "ModifyConferenceReqMessage"},
  {0x013a, handle_default_function                , SKINNY_MSGTYPE_REQUEST  , "AddParticipantReqMessage"},
  {0x013b, handle_default_function               , SKINNY_MSGTYPE_REQUEST  , "DropParticipantReqMessage"},
  {0x013c, handle_default_function                                           , SKINNY_MSGTYPE_REQUEST  , "AuditConferenceReqMessage"},
  {0x013d, handle_default_function              , SKINNY_MSGTYPE_REQUEST  , "AuditParticipantReqMessage"},
  {0x013e, handle_default_function             , SKINNY_MSGTYPE_REQUEST  , "ChangeParticipantReqMessage"},
  {0x013f, handle_default_function         , SKINNY_MSGTYPE_EVENT    , "UserToDeviceDataMessageVersion1"},
  {0x0140, handle_default_function              , SKINNY_MSGTYPE_EVENT    , "VideoDisplayCommandMessage"},
  {0x0141, handle_default_function                , SKINNY_MSGTYPE_EVENT    , "FlowControlNotifyMessage"},
  {0x0142, handle_default_function                  , SKINNY_MSGTYPE_RESPONSE , "ConfigStatV2ResMessage"},
  {0x0143, handle_default_function                  , SKINNY_MSGTYPE_EVENT    , "DisplayNotifyV2Message"},
  {0x0144, handle_default_function               , SKINNY_MSGTYPE_EVENT    , "DisplayPriNotifyV2Message"},
  {0x0145, handle_default_function            , SKINNY_MSGTYPE_EVENT    , "DisplayPromptStatusV2Message"},
  {0x0146, handle_default_function                 , SKINNY_MSGTYPE_RESPONSE , "FeatureStatV2ResMessage"},
  {0x0147, handle_LineStateV2                    , SKINNY_MSGTYPE_RESPONSE , "LineStatV2ResMessage"},
  {0x0148, handle_default_function              , SKINNY_MSGTYPE_RESPONSE , "ServiceURLStatV2ResMessage"},
  {0x0149, handle_default_function               , SKINNY_MSGTYPE_RESPONSE , "SpeedDialStatV2ResMessage"},
  {0x014a, handle_callinfo2_function                       , SKINNY_MSGTYPE_EVENT    , "CallInfoV2Message"},
  {0x014b, handle_default_function                          , SKINNY_MSGTYPE_REQUEST  , "PortReqMessage"},
  {0x014c, handle_default_function                        , SKINNY_MSGTYPE_EVENT    , "PortCloseMessage"},
  {0x014d, handle_default_function                        , SKINNY_MSGTYPE_EVENT    , "QoSListenMessage"},
  {0x014e, handle_default_function                          , SKINNY_MSGTYPE_EVENT    , "QoSPathMessage"},
  {0x014f, handle_default_function                      , SKINNY_MSGTYPE_EVENT    , "QoSTeardownMessage"},
  {0x0150, handle_default_function                       , SKINNY_MSGTYPE_EVENT    , "UpdateDSCPMessage"},
  {0x0151, handle_default_function                        , SKINNY_MSGTYPE_EVENT    , "QoSModifyMessage"},
  {0x0152, handle_default_function              , SKINNY_MSGTYPE_RESPONSE , "SubscriptionStatResMessage"},
  {0x0153, handle_default_function                     , SKINNY_MSGTYPE_EVENT    , "NotificationMessage"},
  {0x0154, handle_startMediaTransmissionACK        , SKINNY_MSGTYPE_RESPONSE , "StartMediaTransmissionAckMessage"},
  {0x0155, handle_default_function   , SKINNY_MSGTYPE_RESPONSE , "StartMultiMediaTransmissionAckMessage"},
  {0x0156, handle_default_function                  , SKINNY_MSGTYPE_EVENT    , "CallHistoryInfoMessage"},
  {0x0157, handle_default_function                     , SKINNY_MSGTYPE_EVENT    , "LocationInfoMessage"},
  {0x0158, handle_default_function                           , SKINNY_MSGTYPE_RESPONSE , "MwiResMessage"},
  {0x0159, handle_default_function          , SKINNY_MSGTYPE_EVENT    , "AddOnDeviceCapabilitiesMessage"},
  {0x015a, handle_default_function                    , SKINNY_MSGTYPE_EVENT    , "EnhancedAlarmMessage"},
  {0x015e, handle_default_function                                           , SKINNY_MSGTYPE_REQUEST  , "CallCountReqMessage"},
  {0x015f, handle_default_function                    , SKINNY_MSGTYPE_RESPONSE , "CallCountRespMessage"},
  {0x0160, handle_default_function                  , SKINNY_MSGTYPE_EVENT    , "RecordingStatusMessage"},
  {0x8000, handle_default_function                    , SKINNY_MSGTYPE_REQUEST  , "SPCPRegisterTokenReq"},
  {0x8100, handle_default_function                    , SKINNY_MSGTYPE_RESPONSE , "SPCPRegisterTokenAck"},
  {0x8101, handle_default_function                 , SKINNY_MSGTYPE_RESPONSE , "SPCPRegisterTokenReject"},
#endif
};

#define CW_IsMsgOutBound(pucCurPos, pucEndPos, usLen) ((pucCurPos + usLen) > pucEndPos)

void handler_skinny_elements(u8* msg,int msg_size)
{
  u32 len;
  u32 hdr_opcode;
  u32 hdr_ver;
  u8* p = msg;
  u32 i;
  u32 message_len = 0;
    skinny_opcode_map_t* opcode_entry;

  skinny_info_t skinny_info;
  memset(&skinny_info,0,sizeof(skinny_info_t));
  
  while(p+12 < msg+msg_size)
  {
    CW_LOAD_U32(len,p);
    CW_LOAD_U32(hdr_ver,p);

    CW_LOAD_U32(hdr_opcode,p);
    message_len = len -4;
    skinny_log("len %x (%x) ver %x opcode %x\n",len,htonl(len),hdr_ver,hdr_opcode);
    if(p+message_len <= msg+msg_size)
    {
      for (i = 0; i < sizeof(skinny_opcode_map)/sizeof(skinny_opcode_map_t) ; i++) 
      {
          if (skinny_opcode_map[i].opcode == hdr_opcode) 
        {
             opcode_entry = &skinny_opcode_map[i];
           opcode_entry->handler(opcode_entry,p,len,&skinny_info);
           p+=message_len;
           break;
          }
        }
      
    }
    else
      skinny_log_err("opcode %u msg broken!\n",hdr_opcode);
      
  }
}
void show_tcp_info(struct tcphdr* th )
{
  
  skinny_log("tcp info :\n"
        "source port %u, dest port %u\n "
        "Sequence Number %u,Acknowledgement Number %u\n "
        "head len %d byte (%d)\n"
        "flags %s %s %s %s %s %s %s %s \n",
      htons(th->source),htons(th->dest),ntohl(th->seq),          ntohl(th->ack_seq),
        th->doff*4, th->doff,
        th->fin?"Finish":"NoFinish",
        th->syn?"Syn":"NoSyn",
        th->rst?"Reset":"NoReset",
        th->psh?"Push":"NoPush",
        th->ack?"Ack":"NoAck",
        th->urg?"Urgent":"NoUrgent",
        th->ece?"ECN-ECHO":"NoECH-ECHO",
        th->cwr?"Congestion_Window_Reduced":"NoCWR");
}

void dump_hex(u8* src,int len)
{
    char buffer[8000]={0};
    int i;
    int t;
    char* p = buffer;
    for(i=0;i<len;i++){
        t = sprintf(p,"%02X ",src[i]);
        p+=t;
    }
    skinny_log("%s\n",buffer);
}
static void sniffer_handle_skinny(u_char * user, const struct pcap_pkthdr * packet_header, const u_char * packet_content)
{
    int ret = 0;
    
  const struct pcap_pkthdr* phdr = packet_header;
  struct iphdr* iph = NULL;
  struct tcphdr* th = NULL;
  u8* tcp_payload;
  int tcp_payload_len;
  int tcp_len;
  
  
  skinny_log("\n\n");
  ret = check_iphdr(phdr,packet_content,&iph);
  if(ret != 0){
    
    skinny_log_err("check_iphdr error\n");
    goto error;
    }
  if(0 != check_tcp(iph,&th)) {
    
    skinny_log_err("check_tcp error\n");
    goto error;
  }
  
    //send_sip_pkt(iph,udph);/* ???sip??￥?–?è?????upload??€????€? */

  tcp_payload = ((u8*)th)+(th->doff * 4);
  tcp_len = ntohs(iph->tot_len)- iph->ihl*4;
  tcp_payload_len = tcp_len - (th->doff * 4);
  show_tcp_info(th);
  if(tcp_payload_len == 0)
  {
    skinny_log("this frame no tcp payload\n\n");
    return;
  }
  
  skinny_log("tcp_payload %p, tcp_payload_len  %d th %p \n",tcp_payload,
      tcp_payload_len,th);
  //dump_hex(tcp_payload,tcp_payload_len);
  handler_skinny_elements(tcp_payload,tcp_payload_len);
  
error:
  return;
}

int sniffer_loop_skinny( pcap_t *p)
{
   pcap_loop( p,-1,sniffer_handle_skinny,(u_char*)NULL);
   return 0;
}

/***********************************************
?o??¨???ˉ??¨????‰§è????“
************************************************/
/*
sniffer_sip_loop:
?‰“??€pcap_file,è???…￥??“??…?‰§è????“?€?

*/
void* sniffer_skinny_loop(void* arg)
{

  char filter[200] = {0};
    pcap_t* pd=0;

  //pd = open_pcap_file("enp0s3",65535,1,0);
  pd = open_pcap_file("eth0",65535,1,0);
  if(pd == NULL)
  {

    skinny_log_err("open_pcap_file failed ! <%s> and exit\n",strerror(errno));
    exit(1);
  }

  sprintf(filter,"tcp and host %s and port %d ",
    inet_ntoa(g_config.skinny_call.ip),
    g_config.skinny_call.port);
  sniffer_setfilter(pd,filter);
  skinny_log("filter: %s\n",filter);
    skinny_log("sniffer_skinny_loop ok  \n");

  while(1)
  {
    sniffer_loop_skinny(pd);
  }
}


pthread_t __sniffer_skinny_start(void)
{
  pthread_t tid;
  
  INIT_LIST_HEAD(&skinny_ctx.si_head);
  if(pthread_create(&tid,NULL,sniffer_skinny_loop,NULL))
  {
    skinny_log_err("create  sniffer_skinny_loop failed\n");
    return -1;
  }

  return tid;

}


FILE* skinny_log_fp;

pthread_t sniffer_skinny_start(void)
{
  pthread_t tid;

    
    skinny_log_fp = fopen(SKINNY_LOG_FILE,"a+");
    if(skinny_log_fp == NULL){
        printf("skinny log file not open \n");
        
        exit(1);
    }

  tid = __sniffer_skinny_start();
    skinny_log("%s:%d tid %d\n",__func__,__LINE__,tid);
  return tid;

}

