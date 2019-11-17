

#include "time_.h"
#include <stdio.h>

#include <time.h>

#include <sys/syscall.h>
#if 0
struct timespec {
    time_t   tv_sec;        /* seconds */
    long     tv_nsec;       /* nanoseconds */
};
#endif
/* 开机到现在的秒数。 */
int  get_time_stamp(time_t* stamp)
{
   struct timespec tp;
    int ret;
    ret = syscall(SYS_clock_gettime,CLOCK_MONOTONIC,&tp);
	*stamp = tp.tv_sec;
    return ret;
}
#if 0
int  get_time_stamp1(time_t* stamp)
{
   struct timespec tp;
    int ret;
    ret = clock_gettime(CLOCK_MONOTONIC, &tp);
	*stamp = tp.tv_sec;
    return ret;
}
#endif



