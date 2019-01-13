#ifndef THREAD_MSG_ENGINE_H_
#define THREAD_MSG_ENGINE_H_

#include <stdio.h>
#include <unistd.h>
#include <sys/un.h> 
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <pthread.h>


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
#include "wake_utils.h"


#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var,head,field,tvar)           \
    for((var) = TAILQ_FIRST((head));                    \
        (var) &&((tvar) = TAILQ_NEXT((var),field),1);   \
        (var) = (tvar))
#endif

struct msg_engine_ctx;

typedef int (*msg_engine_handle)(void* msg,int len,struct msg_engine_ctx* me);

typedef struct _entry
{
	TAILQ_ENTRY(_entry) node;
	long 				stamp;
	int 				type;
	int 				len;
	char				msg[0];
}_entry_st;

typedef TAILQ_HEAD(__list, _entry)  entry_head_t;

struct msg_engine_ctx
{
	char name[32];
	int msg_num;
	pthread_mutex_t mutex;  //sync
	_wake_ wake;
	pthread_t tid;
	
	entry_head_t msg_head;
	msg_engine_handle cb_func;
};


int msg_engine_push_entry(struct msg_engine_ctx* me,void* msg,int len);
pthread_t msg_engine_start(struct msg_engine_ctx* me,const char* name);

#endif   //THREAD_MSG_ENGINE_H_


