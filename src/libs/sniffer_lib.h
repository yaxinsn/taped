
#ifndef SNIFFER_LIB_H
#define SNIFFER_LIB_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <linux/if_ether.h> //struct ethhdr

#include <netinet/in.h>
#include <netinet/ip.h> 

#include <linux/udp.h>//struct udphdr
#include <linux/tcp.h>//struct udphdr
    

#include "log.h"
#include "types_.h"

int get_device_info(char* device);
pcap_t* open_pcap_file(const char* device,int snaplen,int promise,int to_ms);
int sniffer_setfilter(pcap_t * pd,const char* bpf_str);

int check_iphdr( const struct pcap_pkthdr * phdr, const u_char * pkt,
    struct iphdr** iphdr_p );

int check_udp( struct iphdr* iph,struct udphdr** udph_p);
int check_tcp( struct iphdr* iph,struct tcphdr** tcph_p);








#endif

