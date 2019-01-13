
#ifndef __LOG_H
#define __LOG_H
#include "types_.h"
#include <string.h>

#include <sys/errno.h>

void _logger_file(const char* file_name, const char* func, int line, const char* fmt,...);


void _logger_file2
(FILE* log_fp,const char* file_name, const char* func, int line, const char* fmt,...);



extern FILE* main_log_fp;
#define MAIN_LOG_FILE "/home/root/hzivy-main.log"

#define log(fmt,...)  \
    _logger_file2(main_log_fp,MAIN_LOG_FILE,__func__,__LINE__,fmt,##__VA_ARGS__);  
    
#define log_err(fmt,...)  \
    _logger_file2(main_log_fp,MAIN_LOG_FILE,__func__,__LINE__,"ERROR| "fmt,##__VA_ARGS__); 


#define log_errno(fmt,...)  \
    _logger_file2(main_log_fp,MAIN_LOG_FILE,__func__,__LINE__,"ERROR| errnoinfo <%s> | "fmt,strerror(errno),##__VA_ARGS__); 


	

#define FREE(x)  do { if(x != NULL) free(x); x=NULL;} while(0);     

#endif //__LOG_H