#ifndef _CURL_UPLOAD_H
#define _CURL_UPLOAD_H

#include "log.h"

struct upload_file_info
{
    char  call_local_number[64];
    char  call_caller_number[64];
    char  call_callee_number[64];
    char  call_direction[2];
    char  box_id[32];
    char  call_begin_time[32];   
    char  call_end_time[32];
    char  file_name[128];
    char  frag_serial_no[32];
    
    char  frag_flag[3]; //0 no,1 yes, 2 the last frag.
    
    char  called_group_number[64];
};



int upload_mix_file(char* server_url,struct upload_file_info* file_info);




#endif
