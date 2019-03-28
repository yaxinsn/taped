


CC=/opt/gcc-linaro-arm-linux-gnueabihf-4.7-2013.03-20130313_linux/bin/arm-linux-gnueabihf-gcc

TARGET_DIR=../rundir
STAGING_DIR=../staging_dir/staging_dir
TOOLCHAIN_DIR=/opt/gcc-linaro-arm-linux-gnueabihf-4.7-2013.03-20130313_linux/arm-linux-gnueabihf/libc/
progam_src =   main.c  sniffer_sip.c upload.c heart.c config.c sniffer_rtp.c phone_session.c sniffer_skinny.c curl_upload.c
progam_obj =  $(progam_src:.c=.o)
lib_src =  linux-utils.c  log.c  sniffer_lib.c  thread_msg_engine.c  wake_utils.c json.c str_lib.c 
voice_lib_src = g722_encode.c g722_decode.c mixer.c ulaw.c ulaw_codec.c
voice_lib_src+=alaw.c alaw_codec.c
 
lib_obj =  $(lib_src:.c=.o)
voice_lib_obj =  $(voice_lib_src:.c=.o)

all_src = $(progam_src) $(lib_src) $(voice_lib_src)
CFLAGS += -Wall #-Werror
#CFLAGS += -Wno-unused-result -Wno-discarded-qualifiers
CFLAGS +=  -Wno-deprecated-declarations 
#-Wextra -Wwrite-strings -Wno-unused-parameter 
CFLAGS += -Wno-unused-function -Wno-implicit-function-declaration -Wno-unused-variable
CFLAGS += -g -O2
#CFLAGS += -Werror=parentheses
#-std=gnu99 -D_GNU_SOURCE -D_REEN^CANT -g -O2
CFLAGS +=-I$(STAGING_DIR)/usr/include  -I./
CFLAGS += -I./ -I./libs/ -I./voice_lib/ -I$(TOOLCHAIN_DIR)/usr/include



LDFLAGS = -L$(STAGING_DIR)/usr/lib/ -ljson-c -lpcap -lpthread -lcurl
vpath %.c ./libs ./voice_lib
vpath %.c  ./voice_lib
vpath %.h ./libs ./voice_lib
vpath %.h  ./voice_lib

HFILE=$(shell ls *.h)

all: taped
LIB=$(STAGING_DIR)/usr/lib/libjson-c.so


$(all_src:.c=.o): %.o : %.c $(HFILE)
	$(CC) $(CFLAGS)  $< -c -o $@


taped: $(progam_obj) $(lib_obj) $(voice_lib_obj)
#	$(CC) $(LDFLAGS) -Wl,-rpath=./  -L./json-c/.libs  -ljson-c $^ $(LIB) -o $@ 
	$(CC) $(LDFLAGS) -Wl,-rpath=./  $(CFLAGS) $^ $(LIB) -o $@ 
#	$(CC) $(LDFLAGS) -Wl,-rpath=./  $^ -o $@ -L./ ./json-c/.libs/libjson-c.so

install:taped
	cp taped $(TARGET_DIR)/home/root/rundir/usr/sbin/ -rf

tar:install
	cd $(TARGET_DIR)/  &&  tar czf rootfsVXXX.tar.gz etc/ home/ && mv rootfsVXXX.tar.gz ../


clean:
	rm taped *.o -f
