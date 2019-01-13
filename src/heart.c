#include <stdio.h>
#include <unistd.h>
#include <sys/un.h> 
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <pthread.h>
#include "types_.h"


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
#include <assert.h>

#include "log.h"
#include "types_.h"
#include "list.h"

#include "upload.h"
#include "thread_msg_engine.h"
#include "config.h"

extern struct config_st g_config;
char cmd[1024]={0};
char param[128]={0};


void* heart_loop(void* arg)
{
    struct config_st* c = &g_config;

    int interval = c->heart_ser.interval;

    if(interval <30)
        interval = 30;

    if(interval > 60*5)
        interval = 60*5;

    while(1)
    {
        sleep(interval);
        system(cmd);
    }
	

}
pthread_t heart_start(void)
{
	pthread_t tid;
    struct config_st* c = &g_config;
    char max_str[32]={0};

    sprintf(max_str,"%02x:%02x:%02x:%02x:%02x:%02x",
	    c->eth0_mac[0],c->eth0_mac[1],c->eth0_mac[2],
	    c->eth0_mac[3],c->eth0_mac[4],c->eth0_mac[5]);
    sprintf(param,"MAC=%s&IP=%s",max_str,inet_ntoa(c->hostip.ip));
    
    sprintf(cmd,"curl -l -H \"Content-type: application/x-www-form-urlencoded\" "
                "-X POST -d '%s' %s",param,c->heart_ser.url);
     log("cmd:<%s>\n",cmd);
    if(c->heart_ser.url[0] == 0)
    {
        printf("ERROR: heart_server url is null\n");
        exit(1);
    }
   
    if(pthread_create(&tid,NULL,heart_loop,NULL))
    {
        log_err("create  heart_loop failed\n");
        return -1;
    }
    return tid;
}

