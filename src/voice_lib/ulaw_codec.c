
#include "ulaw.h"
#include "ulaw_codec.h"



#include <stdio.h>
#include <stdlib.h>


#include "ulaw_codec.h"

void ulawcodec_init()
{
	ast_ulaw_init();
}


char* ulawcodec_encode(char *src, int src_len, int* len) {

	int samples = (src_len)/2;
	if(NULL==src) 
	    return NULL;
	int16_t* int16_src=(int16_t*)src;
	*len = samples;
	
	char* char_dst = malloc(*len);
	if(char_dst == NULL)
	    return NULL;
	char* dst=(char*)char_dst;

	while (samples --)
		*dst++ = AST_LIN2MU(*int16_src++);
	return char_dst;

}


char* ulawcodec_decode(char *src, int src_len, int* len) {
	
	int samples = src_len;
	if(NULL==src) 
	    return NULL;
	unsigned char* uc_src=(unsigned char*)src;
	*len = 2 * samples;
	char* char_dst = malloc(*len);
	if(char_dst == NULL)
	    return NULL;
	int16_t* dst=(int16_t*)char_dst;

	while (samples --)
		*dst++ = AST_MULAW(*uc_src++);

	return char_dst;
}
