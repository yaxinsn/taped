/*****************************************************************

2017/9/24 10:04:09 liudan 
config

*****************************************************************/

#include <stdlib.h>
#include <sys/types.h>
#include <stdlib.h>

#include <time.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>
#include <netdb.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <arpa/inet.h> 
#include <stdarg.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <stdio.h>
#include "log.h"
#include "json.h"
#include "config.h"
/*

          
           struct in_addr {
               uint32_t       s_addr; 
           };
*/

#define CONF_ "/home/root/rundir/etc/base.config"

char buf[65536];

void read_file(void)
{
	FILE *fp;
	char* p = buf;
    int ch;

    if((fp=fopen(CONF_,"r")) == NULL) 
    {
      printf("Cannot open file.\n");
      exit(1);
    }

    while( !(EOF == (ch=fgetc(fp)))) 
    {
    	if((ch != '\n')&& (p - buf) < 65535 )
    	{
    		*p=ch;
    		p++;
     	}
    }
    *p = 0;
    
}
int get_config_hostip(json_object* j_cfg,struct config_st* c )
{	
	const char* str = NULL;
	//struct json_object *o;
	//enum json_type o_type;
	int ret;
	struct hostip_st* hostip = &c->hostip;
	
	json_object* j_ = json_object_object_get(j_cfg, "HOSTIP");
	if(j_ ==NULL){
		log("no HOSTIP");
		return -1;
	}


	str = json_common_get_string(j_, "IP");
	if(str != NULL)
	{
		ret = inet_pton(AF_INET, str, &hostip->ip);        
		if(ret !=1)
		{
			log("GET hostip IP failed!");
		}
	}
	str = json_common_get_string(j_,"NETMASK");
	if(str != NULL)
	{
		ret = inet_pton(AF_INET, str, &hostip->netmask);        
		if(ret !=1)
		{
			log("GET hostip NETMASK failed!");
		}
	}
	str = json_common_get_string(j_,"GATEWAY");
	if(str != NULL)
	{
		ret = inet_pton(AF_INET, str, &hostip->gateway);        
		if(ret !=1)
		{
			log("GET hostip GATEWAY failed!");
		}
	}	
	return 0;
}
int get_config_ntp_server(json_object* j_cfg,struct config_st* c )
{	
	const char* str;
	struct json_object *o;
	enum json_type o_type;
	//int ret;
	struct ntp_st* p_ntp = &c->ntp;
	
	json_object* j_ = json_object_object_get(j_cfg, "NTPSERVER");
	if(j_ ==NULL){
		log("no NTPSERVER");
		return -1;
	}


	str = json_common_get_string(j_,"NTPSERVER");
	if(str != NULL)
		strcpy(p_ntp->ntp_server,str);
	else
		return -1;
	
	return 0;
}

int get_config_heart_ser(json_object* j_cfg,struct config_st* c )
{	
	const char* str;
	struct json_object *o;
	enum json_type o_type;
	//int ret;
	struct heart_server_st* heart = &c->heart_ser;
	
	json_object* j_ = json_object_object_get(j_cfg, "HEART");
	if(j_ ==NULL){
		log("no HEART");
		return -1;
	}
	o = json_object_object_get(j_, "INTERVAL");
	
	o_type = json_object_get_type(o);
	
	
	if(json_type_int == o_type)
	{
		heart->interval = json_object_get_int(o);
		log("intval %d",heart->interval);
	}
	else if (json_type_string == o_type)
	{
		heart->interval = atoi(convert_json_to_str(o));
	}
	log("intval %d",heart->interval);

	str = json_common_get_string(j_,"URL");
	if(str != NULL)
		strcpy(heart->url,str);
	else
		return -1;
	
	return 0;
}

int get_config_callcenter(json_object* j_cfg,struct config_st* c )
{	
	const char* str;
	struct json_object *o;
	enum json_type o_type;
	int ret;
	struct callcenter_st* call = &c->call;
	
	json_object* j_ = json_object_object_get(j_cfg, "CALLCENTER");
	if(j_ ==NULL){
		log("no CALLCENTER");
		return -1;
	}
	//str = json_common_get_string(j_,"PORT");
	o = json_object_object_get(j_, "PORT");
	o_type = json_object_get_type(o);
	if(json_type_int == o_type)
	{
		call->port = json_object_get_int(o);
	}
	else if (json_type_string == o_type)
	{
		call->port = atoi(convert_json_to_str(o));
	}
	

	str = json_common_get_string(j_,"IP");
	if(str != NULL)
	{
		ret = inet_pton(AF_INET, str, &call->ip);        
		if(ret !=1)
		{
			log("GET Call center ip failed!");
		}
	}
	
	return 0;
}
int get_config_callcenter_skinny(json_object* j_cfg,struct config_st* c )
{	
	const char* str;
	struct json_object *o;
	enum json_type o_type;
	int ret;
	struct callcenter_st* call = &c->skinny_call;
	
	json_object* j_ = json_object_object_get(j_cfg, "CALLCENTER_SKINNY");
	if(j_ ==NULL){
		log("no CALLCENTER");
		return -1;
	}
	//str = json_common_get_string(j_,"PORT");
	o = json_object_object_get(j_, "PORT");
	o_type = json_object_get_type(o);
	if(json_type_int == o_type)
	{
		call->port = json_object_get_int(o);
	}
	else if (json_type_string == o_type)
	{
		call->port = atoi(convert_json_to_str(o));
	}
	

	str = json_common_get_string(j_,"IP");
	if(str != NULL)
	{
		ret = inet_pton(AF_INET, str, &call->ip);        
		if(ret !=1)
		{
			log("GET Call center ip failed!");
		}
	}
	
	return 0;
}

int get_config_pwd(json_object* j_cfg,struct config_st* c )
{
	
	const char* str;
	json_object* j_pwd = json_object_object_get(j_cfg, "PASSWORD");
	if(j_pwd ==NULL){
		log("no PASSWORD");
		return -1;
	}
	str = json_common_get_string(j_pwd,"PASSWORD");
	if(str)
		memcpy(c->pwd.password,str,32);
	return 0;
}



int get_config_tape(json_object* j_cfg,struct config_st* c )
{	
	const char* str;
	struct json_object *o;
	enum json_type o_type;
	
	struct tapeserver_st* tape = &c->tape;
	
	json_object* j_ = json_object_object_get(j_cfg, "TAPESERVER");
	if(j_ ==NULL){
		log("no TAPESERVER");
		return -1;
	}
	o = json_object_object_get(j_, "SPAREPORT");
	o_type = json_object_get_type(o);
	if(json_type_int == o_type)
	{
		tape->spareport = json_object_get_int(o);
	}
	else if (json_type_string == o_type)
	{
		tape->spareport = atoi(convert_json_to_str(o));
	}
	
	o = json_object_object_get(j_, "MAINPORT");
	o_type = json_object_get_type(o);
	if(json_type_int == o_type)
	{
		tape->mainport = json_object_get_int(o);
	}
	else if (json_type_string == o_type)
	{
		tape->mainport = atoi(convert_json_to_str(o));
	}
	
	str = json_common_get_string(j_,"MAINIP");
	if(str != NULL)
		inet_pton(AF_INET, str, &tape->mainip);    
	
	
	str = json_common_get_string(j_,"SPAREIP");
	if(str != NULL)
		inet_pton(AF_INET, str, &tape->spareip);
    
	return 0;
}

int get_eth0_mac(u8* mac)
{
    int fd                     = -1;
    struct ifreq stIfreq            = {0};

    fd = socket(AF_INET,SOCK_DGRAM,0);
	if(fd < 0)
	{
		printf("get_eth0_mac::Create Socket Err(%s)!\n",strerror(errno));
		return -1;
	}
	strcpy(stIfreq.ifr_name,"eth0");

	
	if (ioctl(fd, SIOCGIFHWADDR, &stIfreq) < 0)
	{
		printf("get_eth0_mac::Could not get hwaddr!\n");
		close(fd);
		return -1;
	}
	memcpy(mac, stIfreq.ifr_hwaddr.sa_data, 6);
    close(fd);
    
	return 0;
}

int get_config(struct config_st* c)
{
	read_file();
	json_object* j_cfg = convert_json_data(buf);
	
	if(j_cfg == NULL)
	{
		log("cfg to json failed!");
		return -1;
	}	
	get_config_pwd(j_cfg,c);
	get_config_tape(j_cfg,c);
	get_config_callcenter(j_cfg,c);
	get_config_callcenter_skinny(j_cfg,c);
	get_config_heart_ser(j_cfg,c);
	get_config_ntp_server(j_cfg,c);
	get_config_hostip(j_cfg,c);
	json_object_put(j_cfg);

	sprintf(c->upload_http_url, "http://%s:%d/record/box/reportOneRecord",
	inet_ntoa(c->tape.mainip),c->tape.mainport);

	get_eth0_mac(c->eth0_mac);

	if(c->skinny_call.ip.s_addr == 0)
	{
	    c->skinny_call.ip.s_addr = c->call.ip.s_addr;
	    c->skinny_call.port = 2000;
	}
	return 0;
	
}

int show_config(struct config_st* c)
{
	log("hostip:\n");
	log("IP %x\n",c->hostip.ip);
	log("netmask %x\n",c->hostip.netmask);	
	log("gateway %x\n",c->hostip.gateway);	
	
	log("heart server:\n");
	log("URL %s\n",c->heart_ser.url);
	log("intval %d\n",c->heart_ser.interval);
	
	log("ntpd server:\n");
	log("\tserver %s\n",c->ntp.ntp_server);
	
	log("callcenter sip server:\n");
	log("ip %x\n",c->call.ip);
	log("port %d\n",c->call.port);

	log("callcenter skinny server:\n");
	log("ip %x\n",c->skinny_call.ip);
	log("port %d\n",c->skinny_call.port);
	
	log("tape server:\n");
	log("main ip %x\n",c->tape.mainip);
	log("main port %d\n",c->tape.mainport);
	log("SPARE IP  %x\n",c->tape.spareip);
	log("SPARE PORT  %d\n",c->tape.spareport);	
	log("tape upload server url %s\n",c->upload_http_url);
	
	log("boxid  %02x:%02x:%02x:%02x:%02x:%02x\n",
	    c->eth0_mac[0],c->eth0_mac[1],c->eth0_mac[2],
	    c->eth0_mac[3],c->eth0_mac[4],c->eth0_mac[5]);
	log("password :\n");
	
	log("pawd %s\n",c->pwd.password);
	log("\n\n");
	return 0;
}

