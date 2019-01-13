

#if 0
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
#endif

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>

#include "log.h"



void __local_time_str(char* time_str,int len)
{


	time_t a;
	struct tm* t;
	
	time(&a);
	t = localtime(&a);
	strftime(time_str,len,"%Y-%m-%d_%H-%M-%S",t);
//printf("%s	\n",time_str);

}

void _logger_file(const char* file_name, const char* func, int line, const char* fmt,...)
{
    int fd;
    va_list args;
    FILE* log_fp=NULL;
   // static int log_line = 0;
    char buf_time[128]={0};
    
    struct stat st_a;
   
    if (log_fp == NULL) {
        if ((log_fp = fopen(file_name, "a+")) == NULL)
          return;
    }
   // time_t a;
    //time(&a);
	__local_time_str(buf_time,sizeof(buf_time)-1);
	
    fprintf(log_fp,"%-20s",buf_time);

    fprintf(log_fp," |%-20s|%-5d| ",func,line);
    va_start(args,fmt);
    vfprintf(log_fp,fmt,args);
    va_end(args);
   // log_line++;
    fflush(log_fp);
    if(!stat(file_name,&st_a))
    {
    	if(st_a.st_size >= 4096*100)
    	{
	        fd = fileno(log_fp);
	        ftruncate(fd, 0);
	        lseek(fd, 0, SEEK_SET);
    	}
    }
#if 0    
    if(log_line >= 400)
    {
        fd = fileno(log_fp);
        ftruncate(fd, 0);
        lseek(fd, 0, SEEK_SET);
        log_line = 0;
    }
#endif    
    fclose(log_fp);
    return;
}

void _logger_file2(FILE* log_fp,const char* file_name, const char* func, int line, const char* fmt,...)
{
    int fd;
    va_list args;
  //  FILE* log_fp=NULL;
   // static int log_line = 0;
    char buf_time[128]={0};
    
    struct stat st_a;
   
    if (log_fp == NULL) {
          return;
    }
   // time_t a;
    //time(&a);
	__local_time_str(buf_time,sizeof(buf_time)-1);
	
    fprintf(log_fp,"%-20s",buf_time);

    fprintf(log_fp," |%-20s|%-5d| ",func,line);
    va_start(args,fmt);
    vfprintf(log_fp,fmt,args);
    va_end(args);
   // log_line++;
    fflush(log_fp);
    if(!stat(file_name,&st_a))
    {
    	if(st_a.st_size >= 4096*100)
    	{
	        fd = fileno(log_fp);
	        ftruncate(fd, 0);
	        lseek(fd, 0, SEEK_SET);
    	}
    }
#if 0    
    if(log_line >= 400)
    {
        fd = fileno(log_fp);
        ftruncate(fd, 0);
        lseek(fd, 0, SEEK_SET);
        log_line = 0;
    }
#endif    
    return;
}

