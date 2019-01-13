
#include <linux/if_ether.h> //struct ethhdr
//#include <linux/ip.h> //struct iphdr
#include <linux/udp.h>//struct udphdr
//#include <linux/in.h>

#include <string.h>
#include "str_lib.h"


//return value and length of value
char* find_key_from_line(const char* line,const char* key,int* v_len,const char* delim)
{
    //Content-Length: 504\r\n
    //return 504  point
    char* p ;
	char* v;
	int a;
	p = strstr(line,key);
    if(p != NULL)
    {
        p+=strlen(key);
        if(delim != NULL)
	        v =p+strlen(delim);
	    else
	        v=p;
	    p = strstr(v,"\r\n");
	    if(p != NULL)
	    {
	        a = p-v;
	        *v_len = a;
	        return v;
	    }
	    else
	        return NULL;
	    
    }
    return NULL;
}
char* setup_value_by_key_from_line(const char* line,const char* key,char** dest)
{
    int len=0;
    char* v;
    v = find_key_from_line(line,key,&len,": ");
    if(v)
        *dest = strndup(v,len);
    return *dest;
}






