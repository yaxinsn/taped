

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

#include "phone_session.h"



struct session_ctx_t sip_ctx;


struct session_info* si_new_session()
{
    struct session_info* ss =NULL;
    ss = (struct session_info*)malloc(sizeof(struct session_info));
    if ( ss == NULL)
        return NULL;
    memset(ss,0,sizeof(struct session_info));
    pthread_mutex_lock(&sip_ctx.head_lock);
    list_add(&ss->node,&sip_ctx.si_head);
    pthread_mutex_unlock(&sip_ctx.head_lock);
    return ss;
}
void si_del_session(struct session_info* si)
{
    FREE(si->call_id);
    pthread_mutex_lock(&sip_ctx.head_lock);

    list_del(&si->node);
    
        pthread_mutex_unlock(&sip_ctx.head_lock);
    FREE(si);
    return;
}
struct session_info* si_find_session(char* call_id)
{
    struct session_info* p;
    struct session_info* n;
    struct list_head* si_head;
    si_head = &sip_ctx.si_head;
    
    list_for_each_entry_safe(p,n,si_head,node)
    {

        if(!strcmp(call_id,p->call_id))
        {
        
            log("find callid %s\n",call_id);
            return p;
        }
    }
    
    log("nofind callid %s\n",call_id);
    return NULL;
}


int session_init()
{
    INIT_LIST_HEAD(&sip_ctx.si_head);
	return 0;
}


