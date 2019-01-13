

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

#include "mixer.h"


typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

typedef unsigned char   uint8_t;
typedef unsigned int    uint32_t;

typedef short SHORT;
bool mix2(struct mixer* mix,char* data, size_t len, char* data2, 
    size_t len2, size_t* mixed_len) 
{
	if(NULL == data || 0 == len) 
	    return false;
    int t32;
	// 计数
	mix->mixcount++;
	size_t i;
    size_t samples = 2000;
    if(samples <=len)
        return false;
        
	size_t mixed_sample = (samples*sizeof(SHORT)<=len)?samples:(size_t)(((double)len)/((double)sizeof(SHORT)));

	// 保存数据
	SHORT* int64data = (SHORT*)(mix->data);
	// 输入的数据为int16的
	SHORT* inputdata = (SHORT*)data;

	for(i=0; i<mixed_sample; i++) {
	    t32 = (int)int64data[i];
	    
		t32 += (int)(inputdata[i]);
		//t32 = t32/2;
		
		if(t32 < -32768)
		    t32 = -32768;
		else if(t32 > 32767)
		    t32 = 32767;

	    
		    
	    int64data[i] = (short)t32;
	}
	*mixed_len = mixed_sample*sizeof(SHORT);
	return true;
}


bool mix(struct mixer* mix,char* data, size_t len, size_t* mixed_len) 
{
	if(NULL == data || 0 == len) 
	    return false;
    int t32;
	// 计数
	mix->mixcount++;
	size_t i;
    size_t samples = 2000;
    if(samples <=len)
        return false;
        
	size_t mixed_sample = (samples*sizeof(SHORT)<=len)?samples:(size_t)(((double)len)/((double)sizeof(SHORT)));

	// 保存数据
	SHORT* int64data = (SHORT*)(mix->data);
	// 输入的数据为int16的
	SHORT* inputdata = (SHORT*)data;

    if(mix->mixcount%2 == 1)
    {
        for(i=0; i<mixed_sample; i++) {
            int64data[i] = inputdata[i];
        }
    }
    else{
	for(i=0; i<mixed_sample; i++) {
	    t32 = (int)int64data[i];
	    
		t32 += (int)(inputdata[i]);
		///t32 = t32/2;
		
		if(t32 < -32768)
		    t32 = -32768;
		else if(t32 > 32767)
		    t32 = 32767;
		    
	    int64data[i] = (short)t32;
	}
	}
	*mixed_len = mixed_sample*sizeof(SHORT);
	return true;
}


#if 0
bool mix(struct mixer* mix,char* data, size_t len, size_t* mixed_len) 
{
	if(NULL == data || 0 == len) 
	    return false;
    int t32;
	// 计数
	mix->mixcount ++;
	int i;
    size_t samples = 2000;
    if(samples <=len)
        return false;
        
	size_t mixed_sample = (samples*sizeof(SHORT)<=len)?samples:(size_t)(((double)len)/((double)sizeof(SHORT)));

	// 保存数据
	SHORT* int64data = (SHORT*)(mix->data);
	// 输入的数据为int16的
	u16* inputdata = (u16*)data;

	for(i=0; i<mixed_sample; i++) {
	    t32 = int64data[i];
	    
		t32 += (int)(inputdata[i]);
	    int64data[i] = t32;
	}
	*mixed_len = mixed_sample*sizeof(SHORT);
	return true;
}


bool mix(struct mixer* mix,char* data, size_t len, size_t* mixed_len) 
{
	if(NULL == data || 0 == len) 
	    return false;
    short t;
    short t2;
    short tmix;
	// 计数
	mix->mixcount ++;
	int i;
    size_t samples = 2000;
    if(samples <=len)
        return false;
        
	size_t mixed_sample = (samples*sizeof(SHORT)<=len)?samples:(size_t)(((double)len)/((double)sizeof(SHORT)));

	// 保存数据
	char* int64data = (char*)(mix->data);
	// 输入的数据为int16的
	char* inputdata = (char*)data;

	for(i=0; i<mixed_sample; i++) {
	    t = int64data[i];
	    t2 = inputdata[i];
	    if(t< 0 && t2 < 0)
	        tmix = t+t2 -(t*t2 /(-(32768 -1)));
	    else
	        tmix = t+t2 -(t*t2 /((32768 -1)));
	    int64data[i] = tmix;
	}
	*mixed_len = mixed_sample*sizeof(char);
	return true;

}

#endif

