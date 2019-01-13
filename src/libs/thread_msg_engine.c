/*
一个线程，专门用于处理 TAILQ 消息队列的。
线程最后会调用回调函数，来完成上层的功能。
*/



#include "thread_msg_engine.h"

static int msg_engine_init(struct msg_engine_ctx* me)
{

  	wake_init(&me->wake);
	TAILQ_INIT(&me->msg_head);
	return 0;
}

static int msg_engine_handler(struct msg_engine_ctx* _ctx )
{
	
	_entry_st* entry = NULL;
	_entry_st* entry_next = NULL;
	int ret;
	pthread_mutex_lock(&_ctx->mutex);
	TAILQ_FOREACH_SAFE(entry,&_ctx->msg_head,node,entry_next)
	{

		ret = _ctx->cb_func(entry->msg,entry->len,_ctx);
	    if(ret == 0)
	    {
	    	TAILQ_REMOVE(&_ctx->msg_head,entry,node);
		    free(entry);
		}
	}
	
	pthread_mutex_unlock(&_ctx->mutex);
	return 0;
}

void* msg_engine_loop(void* arg)
{
	struct msg_engine_ctx* me = arg;

	while(1)
	{
		msg_engine_handler(me);
		sleep_down(&me->wake);
	}
}

pthread_t msg_engine_start(struct msg_engine_ctx* me,const char* name)
{
	pthread_t tid;
	msg_engine_init(me);
	if(pthread_create(&tid,NULL,msg_engine_loop,me))
	{
		log("create msg_engine_start %s failed\n",name);
		return -1;
	}
	strncpy(me->name,name,sizeof(me->name));
	me->tid = tid;
	return tid;

}

int msg_engine_push_entry(struct msg_engine_ctx* me,void* msg,int len)
{
	    _entry_st* entry = NULL;
    entry = malloc(sizeof(_entry_st)+len);
    if(entry == NULL){
        log("malloc __msg_entry_t is failed!\n");
        return -1;
    }

    memset(entry,0,sizeof(_entry_st)+len);
    
    entry->len = len;
    //_u_log("push msg type is %d len %d",type,len);
    memcpy(entry->msg,msg,len);
    pthread_mutex_lock(&me->mutex);
    TAILQ_INSERT_TAIL(&me->msg_head, entry, node);
    pthread_mutex_unlock(&me->mutex);
    wake_up(&me->wake);
	return 0;
}


