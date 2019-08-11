
#ifndef _MIXER_H_
#define _MIXER_H_

struct mixer{
    int data[2000];
    int mixcount;
    
};
bool mix(struct mixer* mix,char* data, size_t len, size_t* mixed_len);

void build_wav_header(long pcm_size, unsigned char* header);
#endif
