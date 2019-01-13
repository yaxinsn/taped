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

#define	G722PAYLOADTYPE		"9"
#define G722BITSRATE	64000
#define	G722RATE		8000
#define G722PTIME		20
//#include "wangji-722/g722.h"
#include "g722.h"


#define debug(fmt,...)  \
						printf("[%s:%d] |"fmt"\n",__func__,__LINE__,##__VA_ARGS__); 

char* de_g722_decode(g722_decode_state_t* g722dst,char *src, int src_len, int* len) 
{
	//*len = 0;

	
	if(NULL==src) return NULL;

	int samples = src_len; 
	const uint8_t* uc_src=(const uint8_t*)src;

	debug("here\n");

	*len = samples*2;
	debug("here\n");
	char* char_dst=malloc( sizeof(char)*(samples*2));
	if(char_dst == NULL)
	{
	    printf("malloc err!\n");
	    return NULL;
	}
	debug("here\n");
	memset(char_dst, 0, *len);
	int16_t *dst=(int16_t*)char_dst;

	debug("here\n");

	*len = g722_decode((g722_decode_state_t*)g722dst, dst, uc_src, src_len);

	debug("here *len %d\n",*len);

	// g722_decode返回的长度应该是收int16_t类型计算的, 因此要*sizeof(int16_t) _ 相当于*2
	*len *= 2;

	return char_dst;
}



unsigned long get_file_size(const char *filename) 
{ 
    struct stat buf; 
    if(stat(filename, &buf)<0) 
    { 
        return 0; 
    } 
    return (unsigned long)buf.st_size; 
}

de_g722_file(char* src_file,char* dest_file)
{
    g722_decode_state_t* g722dst;
    int fd = 0;
    int dest_fd=0;
    char* src_buf;
    int fsize;
    int s;
    int dest_len;
    char* dest_buf;
    g722dst = (void*)g722_decode_init((g722_decode_state_t*)g722dst, G722BITSRATE, 1 /* 表明采用8000采样 */);

    fd=open(src_file,O_RDONLY);
    if(fd < 0)
    {
        printf("open error!");
        return -1;
    }
    

    fsize = get_file_size(src_file);
    src_buf = malloc(fsize);
    s = read(fd,src_buf,fsize);
    if(s == fsize)
    {
        printf("de_g722_file read ok\n");
    }
    else
    {
        printf("fsize %d  read %d\n", fsize,s);
    }
    close(fd);
    
    debug("eeeee");
    dest_buf = de_g722_decode(g722dst,src_buf,s,&dest_len);
    
    debug("eeeee : dest_file %s dest_buf %p\n",dest_file,dest_buf);
    if(dest_buf)
    {
    debug("eeeee");
        dest_fd=open(dest_file,O_WRONLY);
        
    debug("eeeee dest_fd %d",dest_fd);
        if(dest_fd < 0)
        {
            debug("dest_fd open error!");
            return -1;
        }
        
    debug("eeeee");
        int ret;
        ret = write(dest_fd,dest_buf,dest_len);
        
        debug("eeeee,ret %d",ret);
        close(dest_fd);
    }
    else
    {
        debug("-------");
    }
    
        debug("-------");
    free(dest_buf);
    g722_decode_release(g722dst);
    return 0;
}


int main(int argc,char* argv[])
{
    if(argc <2)
    {
        printf("argc != 2,exit\n");
        exit(1);
    }

    debug("eeeee %s",argv[2]);
    de_g722_file(argv[1],argv[2]);
    return 0;
    
}
