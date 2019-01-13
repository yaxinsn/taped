#ifndef _ULAW_CODEC_H
#define _ULAW_CODEC_H
#include <stdio.h>




void ulawcodec_init();
char* ulawcodec_encode(char *src, int src_len, int* len);
char* ulawcodec_decode(char *src, int src_len, int* len);

#endif
