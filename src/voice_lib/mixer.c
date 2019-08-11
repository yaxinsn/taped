

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


typedef unsigned char byte;


void _writeWavHeader( long totalAudioLen, long totalDataLen,
                       long longSampleRate,int channels, long byteRate,u8* header)
{
      //  byte[] header = new byte[44];
        //RIFF WAVE Chunk
        // RIFF标记占据四个字节
        header[0] = 'R';
        header[1] = 'I';
        header[2] = 'F';
        header[3] = 'F';
        //数据大小表示，由于原始数据为long型，通过四次计算得到长度
        header[4] = (byte) (totalDataLen & 0xff);
        header[5] = (byte) ((totalDataLen >> 8) & 0xff);
        header[6] = (byte) ((totalDataLen >> 16) & 0xff);
        header[7] = (byte) ((totalDataLen >> 24) & 0xff);
        //WAVE标记占据四个字节
        header[8] = 'W';
        header[9] = 'A';
        header[10] = 'V';
        header[11] = 'E';
        //FMT Chunk
        header[12] = 'f';
        // 'fmt '标记符占据四个字节
        header[13] = 'm';
        header[14] = 't';
        header[15] = ' ';//过渡字节
        //数据大小
        header[16] = 16; // 4 bytes: size of 'fmt ' chunk
        header[17] = 0;
        header[18] = 0;
        header[19] = 0;
        //编码方式 10H为PCM编码格式
        header[20] = 1; // format = 1
        header[21] = 0;
        //通道数
        header[22] = (byte) channels;
        header[23] = 0;
        //采样率，每个通道的播放速度
        header[24] = (byte) (longSampleRate & 0xff);
        header[25] = (byte) ((longSampleRate >> 8) & 0xff);
        header[26] = (byte) ((longSampleRate >> 16) & 0xff);
        header[27] = (byte) ((longSampleRate >> 24) & 0xff);
        //音频数据传送速率,采样率*通道数*采样深度/8
        header[28] = (byte) (byteRate & 0xff);
        header[29] = (byte) ((byteRate >> 8) & 0xff);
        header[30] = (byte) ((byteRate >> 16) & 0xff);
        header[31] = (byte) ((byteRate >> 24) & 0xff);
        // 确定系统一次要处理多少个这样字节的数据，确定缓冲区，通道数*采样位数
        header[32] = (byte) (1 * 16 / 8);
        header[33] = 0;
        //每个样本的数据位数
        header[34] = 16;
        header[35] = 0;
        //Data chunk
        header[36] = 'd';//data标记符
        header[37] = 'a';
        header[38] = 't';
        header[39] = 'a';
        //数据长度
        header[40] = (byte) (totalAudioLen & 0xff);
        header[41] = (byte) ((totalAudioLen >> 8) & 0xff);
        header[42] = (byte) ((totalAudioLen >> 16) & 0xff);
        header[43] = (byte) ((totalAudioLen >> 24) & 0xff);

       // return header;
    }

void build_wav_header( long pcm_size, unsigned char* header)
{
    long totalDataLen;
    long longSampleRate = 8000;
    int channels = 1;
    totalDataLen = pcm_size+36;
    long byteRate = (16*longSampleRate*channels) / 8;
    _writeWavHeader(pcm_size,totalDataLen,longSampleRate,channels,byteRate,(u8* )header);
}


