#ifndef _ALAW_CODEC_H
#define _ALAW_CODEC_H
#include <stdio.h>




void alawcodec_init();
char* alawcodec_encode(char *src, int src_len, int* len);
char* alawcodec_decode(char *src, int src_len, int* len);

#endif
