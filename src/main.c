/*****************************************************************

2017/9/24 10:04:09 liudan 
读取整个文件，转成字符串，并完成config的定义。

文件分类：

main.c


*****************************************************************/
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
#include <arpa/inet.h> 
#include <stdarg.h>

#include "log.h"
#include "config.h"
#include "upload.h"
#include "sniffer_sip.h"
#include "sniffer_rtp.h"

int main_log(char* s)
{
    char log[1000]={0};
    sprintf(log,"echo %s >> /home/root/core/main.log");
    system(log);
    return 0;
}
struct config_st g_config;
int init_device_hostip(void)
{
    struct config_st* c = &g_config;
    char cmd[1024]={0};
    char ip_str[32]={0};
    char netmask_str[32]={0};
    char gw_str[32]={0};
    sprintf(ip_str,"%s",inet_ntoa(c->hostip.ip));
    sprintf(netmask_str,"%s",inet_ntoa(c->hostip.netmask));
    
    sprintf(gw_str,"%s",inet_ntoa(c->hostip.gateway));
    if(c->hostip.ip.s_addr !=0 
        && c->hostip.netmask.s_addr != 0 
        && c->hostip.netmask.s_addr != 0)
    {
        
        sprintf(cmd,"/home/root/rundir/init_network.sh %s %s %s",ip_str,netmask_str,gw_str);
        system(cmd);
        sleep(5);
    }
    else
    {
        log_err("not set device hostip \n");
    }
    return 0;
}
int init_ntpd()
{
    
    char* ntp_server = g_config.ntp.ntp_server;
    char cmd[1024]={0};
    sprintf(cmd,"ntpd -p %s",ntp_server);
    system(cmd);
    return 0;
}
void main_get_config()
{
	
	memset(&g_config,0,sizeof(g_config));
	get_config(&g_config);
	show_config(&g_config);
}
FILE* main_log_fp;
int main(int argc,char* argv[])
{
	pthread_t uploader;
	pthread_t heart;
	pthread_t sniffer;
	pthread_t sniffer_skinny;


	main_log_fp = fopen(MAIN_LOG_FILE,"a+");
    if(main_log_fp == NULL){
        printf("main log file not open \n");
        main_log("main log file not open");
        exit(1);
    }
    
	log("test get config and upload \n");
	main_get_config();
	log("get config and upload \n");

	init_device_hostip();
	
	init_ntpd();
	session_init();
	rtp_sniffer_init();
#if 1	
	uploader = uploader_start();
	if(uploader == 0)
	{
		log("uploader start error, exit\n");
        main_log("uploader start error, exit");
		exit(1);
	}


		heart = heart_start();
	if(heart == 0)
	{
		log("heart start error, exit\n");
        main_log("heart start error, exit");
		exit(1);
	}
	
#endif	
    sniffer = sniffer_sip_start();
    sleep(1);
	sniffer_skinny = sniffer_skinny_start();
 //   printf("%s:%d \n",__func__,__LINE__);

    
	pthread_join(sniffer,NULL);
	pthread_join(sniffer_skinny,NULL);
	pthread_join(uploader,NULL);
	pthread_join(heart,NULL);
	
   // printf("%s:%d \n",__func__,__LINE__);
	return 0;
}