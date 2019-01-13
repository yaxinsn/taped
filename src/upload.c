/**********************************************

???????????
??????upload???
???????????????

upload????????
?????skb????

**********************************************/

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>

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
#include "linux-utils.h"
#include "wake_utils.h"




struct msg_head
{
	u8 type;
	u8 resv[3];
};



typedef struct upload_ctx_st
{
	struct msg_engine_ctx msg_eng;
	int main_fd; /*main server fd */
	int bak_fd; /* back server fd */
	int warn_event;// 1  main server????? 2 back server ?????
	char* server_url;
}upload_ctx_t;


extern struct config_st g_config;

upload_ctx_t  upload_ctx;
#define PERROR log

 

static int __upload_msg_handle(void* msg,int len,struct msg_engine_ctx* me)
{
	struct upload_msg* pm = msg;
    upload_ctx_t* upload_s;
    char file_name[300]={0};
    int ret;
	upload_s = container_of(me, upload_ctx_t, msg_eng);
	ret = upload_mix_file(upload_s->server_url,&pm->upload_file_info);
	if(ret == 0){
	    sprintf(file_name,"%s",pm->upload_file_info.file_name);
	    remove(file_name);
	}
	else
	{
	    log(" upload by curl failed ,so push the msg into msgpool, and upload again! \n");

	    return -1;

	    //uploader_push_msg(pm,sizeof(*pm));
	}
	return 0;
}


int upload_init(void)
{
    struct config_st* c = &g_config;
    upload_ctx.server_url = c->upload_http_url;
	upload_ctx.msg_eng.cb_func = __upload_msg_handle;
	return 0;
}


pthread_t uploader_start(void)
{
	pthread_t tid;
	unsigned long ttid = 0;
	upload_init();
	tid = msg_engine_start(&upload_ctx.msg_eng,"upload");
	ttid = (long)tid;
	log("tid %u, ttid %u \n",tid,ttid);
	if(ttid == 0)
		return 0;
	
	return tid;

}

int uploader_push_msg(struct upload_msg* msg,int len)
{

	return msg_engine_push_entry(&upload_ctx.msg_eng,msg,len);
	
	return 0; 
}


