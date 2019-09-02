#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include "log.h"
#include "sniffer_lib.h"

#define CAP_LEN 1024

void handle(u_char * user, const struct pcap_pkthdr * h, const u_char * p) ;

#define HAVE_PCAP_CREATE
#define warning printf
int Bflag=20*1024*1024;
static pcap_t *
open_interface(const char *device, int snaplen,int to_ms, int Bflag,char *ebuf)
{
	pcap_t *pc;
#ifdef HAVE_PCAP_CREATE
	int status;
	char *cp;
#endif

#ifdef HAVE_PCAP_CREATE
	pc = pcap_create(device, ebuf);
	if (pc == NULL) {
		/*
		 * If this failed with "No such device", that means
		 * the interface doesn't exist; return NULL, so that
		 * the caller can see whether the device name is
		 * actually an interface index.
		 */
		if (strstr(ebuf, "No such device") != NULL)
			return (NULL);
		error("%s", ebuf);
	}
#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
	if (Jflag)
		show_tstamp_types_and_exit(pc, device);
#endif
#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
	status = pcap_set_tstamp_precision(pc, ndo->ndo_tstamp_precision);
	if (status != 0)
		error("%s: Can't set %ssecond time stamp precision: %s",
			device,
			tstamp_precision_to_string(ndo->ndo_tstamp_precision),
			pcap_statustostr(status));
#endif

#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
	if (immediate_mode) {
		status = pcap_set_immediate_mode(pc, 1);
		if (status != 0)
			error("%s: Can't set immediate mode: %s",
			device,
			pcap_statustostr(status));
	}
#endif
#if 0
	/*
	 * Is this an interface that supports monitor mode?
	 */
	if (pcap_can_set_rfmon(pc) == 1)
		supports_monitor_mode = 1;
	else
		supports_monitor_mode = 0;
#endif
	status = pcap_set_snaplen(pc, snaplen);
	if (status != 0)
		error("%s: Can't set snapshot length: %s",
		    device, pcap_statustostr(status));
	status = pcap_set_promisc(pc, 1);
	if (status != 0)
		error("%s: Can't set promiscuous mode: %s",
		    device, pcap_statustostr(status));
#if 0
	if (Iflag) {
		status = pcap_set_rfmon(pc, 1);
		if (status != 0)
			error("%s: Can't set monitor mode: %s",
			    device, pcap_statustostr(status));
	}
#endif

	status = pcap_set_timeout(pc, to_ms);
	if (status != 0)
		error("%s: pcap_set_timeout failed: %s",
		    device, pcap_statustostr(status));



	if (Bflag != 0) {
		status = pcap_set_buffer_size(pc, Bflag);
		if (status != 0)
			error("%s: Can't set buffer size: %s",
			    device, pcap_statustostr(status));
	}
#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
	if (jflag != -1) {
		status = pcap_set_tstamp_type(pc, jflag);
		if (status < 0)
			error("%s: Can't set time stamp type: %s",
		              device, pcap_statustostr(status));
	}
#endif
	status = pcap_activate(pc);
	if (status < 0) {
		/*
		 * pcap_activate() failed.
		 */
		cp = pcap_geterr(pc);
		if (status == PCAP_ERROR)
			error("%s", cp);
		else if (status == PCAP_ERROR_NO_SUCH_DEVICE) {
			/*
			 * Return an error for our caller to handle.
			 */
			pcap_close(pc);
			snprintf(ebuf, PCAP_ERRBUF_SIZE, "%s: %s\n(%s)",
			    device, pcap_statustostr(status), cp);
			return (NULL);
		} else if (status == PCAP_ERROR_PERM_DENIED && *cp != '\0')
			error("%s: %s\n(%s)", device,
			    pcap_statustostr(status), cp);
		else
			error("%s: %s", device,
			    pcap_statustostr(status));
	} else if (status > 0) {
		/*
		 * pcap_activate() succeeded, but it's warning us
		 * of a problem it had.
		 */
		cp = pcap_geterr(pc);
		if (status == PCAP_WARNING)
			warning("%s", cp);
		else if (status == PCAP_WARNING_PROMISC_NOTSUP &&
		         *cp != '\0')
			warning("%s: %s\n(%s)", device,
			    pcap_statustostr(status), cp);
		else
			warning("%s: %s", device,
			    pcap_statustostr(status));
	}
#ifdef HAVE_PCAP_SETDIRECTION
	if (Qflag != -1) {
		status = pcap_setdirection(pc, Qflag);
		if (status != 0)
			error("%s: pcap_setdirection() failed: %s",
			      device,  pcap_geterr(pc));
		}
#endif /* HAVE_PCAP_SETDIRECTION */
#else /* HAVE_PCAP_CREATE */
	*ebuf = '\0';
	pc = pcap_open_live(device, ndo->ndo_snaplen, !pflag, 1000, ebuf);
	if (pc == NULL) {
		/*
		 * If this failed with "No such device", that means
		 * the interface doesn't exist; return NULL, so that
		 * the caller can see whether the device name is
		 * actually an interface index.
		 */
		if (strstr(ebuf, "No such device") != NULL)
			return (NULL);
		error("%s", ebuf);
	}
	if (*ebuf)
		warning("%s", ebuf);
#endif /* HAVE_PCAP_CREATE */

	return (pc);
}
//捕获的数据包内容由这个函数处理，这个回调函数的格式必须是下面的形式
void handle(u_char * user, const struct pcap_pkthdr * packet_header, const u_char * packet_content)
{
    pcap_dump(user, packet_header,packet_content);    //输出数据到文件,输出过后的文件就是pcap格式的，可以用wireshark打开
    printf("I get one packet! \n");
}

	
int get_device_info(char* device)
{
	
	char ebuf[PCAP_ERRBUF_SIZE];   //错放错误信息
	bpf_u_int32 netmaskp;//存放掩码   需要先转换为 in_addr格式的，然后再进行inet_ntoa()转换
    bpf_u_int32 netp;  //存放网络号  需要先转换为 in_addr格式的，然后再进行inet_ntoa()转换
    char *netmask;    //存放转换后的掩码
    char *net;  //存放转换后的网络号
    struct in_addr addr;   //作为转换的过度
    int ret;
    ret = pcap_lookupnet(device, &netp,&netmaskp,ebuf);
    if(-1 == (ret))
        printf("pcap_net error\n");

    addr.s_addr = netp; //先赋值给addr
    net = inet_ntoa(addr);//将addr进行转换，成点分十进制
    printf("net is:%s %x\n",net,netp);

    addr.s_addr = netmaskp; //先赋值给addr
    netmask = inet_ntoa(addr);//将addr进行转换，成点分十进制
    printf("netmask is:%s %x\n",netmask,netmaskp);
	return 0;
}
static int __set_nonblock(pcap_t* pd)
{

	char errbuf[PCAP_ERRBUF_SIZE];
	int ret;
	ret = pcap_setnonblock(pd,1,errbuf);
	if(ret)
	{
	    printf("pcap_setnonblock: error %s \n",errbuf);
	    return -1;
	}
	return 0;
	

}
#if 0
/*
open_pcap_file 
device :指定网卡
snaplen ：捕获数据包的长度。
promise : 1表示是混杂模式，其它非混杂模式
to_ms   ：此句柄的等待时间。
*/
pcap_t* open_pcap_file(const char* device,int snaplen,int promise,int to_ms)
{
	char ebuf[1024];
	pcap_t *pd = NULL;    //存放数据包捕获描述字
	int  pcap_link;  //用于返回数据链路层类型
	struct bpf_program fcode;
	//获得捕获描述字
    pd = pcap_open_live(device, snaplen,promise,to_ms,ebuf);
    if(NULL == pd){
        printf("pcap_open_live error %d %s\n",errno,strerror(errno));
        exit(-1);
	}
//返回链路层类型，每一种都有一个代号
    pcap_link = pcap_datalink(pd);
    printf("now the datalink is:%d\n",pcap_link);

    //返回实际抓取的字符
    int real_cap_len = pcap_snapshot(pd);
    printf("the real cap :%d \n",real_cap_len);
	    //设置过滤规则
	
#if 0
    pcap_compile(pd, &fcode, "arp",1, 0);
    printf("pcap_compile error %d %s\n",errno,strerror(errno));
//printf("--------------\n");
    //设置过滤器
    if (pcap_setfilter(pd, &fcode) < 0){
        printf("pcap_setfilter error %d %s\n",errno,strerror(errno));
    }
	printf("---------%s:%d---pd %p-\n",__func__,__LINE__,pd);
	__set_nonblock(pd);
#endif    
	return   pd;
}
#else
pcap_t* open_pcap_file(const char* device,int snaplen,int promise,int to_ms)
{
    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t* pd;
    pd = open_interface(device,snaplen,1000,Bflag,ebuf);
    if(NULL ==  pd)
    {
        printf("open_interface error %d error(%s)\n",errno,ebuf);
    }
    return pd;

}




#endif

int sniffer_setfilter(pcap_t * pd,const char* bpf_str)
{
	//设置过滤规则
	struct bpf_program fcode;

	printf("---------%s:%d---pd %p--bpf_str %s\n",__func__,__LINE__,pd,bpf_str);
    if(pcap_compile(pd, &fcode, bpf_str,1, 0) <0)
    	printf("pcap_compile error %d %s\n",errno,strerror(errno));

//	log("---------%s:%d-----\n",__func__,__LINE__);
    //设置过滤器
    if(pcap_setfilter(pd, &fcode) < 0)
        printf("pcap_setfilter error %d %s\n",errno,strerror(errno));
    
    __set_nonblock(pd);
    return 0;
}
#if 0

void sniff_handle(u_char * user, const struct pcap_pkthdr * packet_header, const u_char * packet_content)
{
    pcap_dump(user, packet_header,packet_content);
    printf("I get one packet! \n");
}

int sniff_loop_test( pcap_t *p)
{
	//打开用于捕获数据包的文件
	 const char* fname = "./icmp.pcap";
	 pcap_dumper_t *pd_t;  //打开用于保存捕获数据包的文件， 函数返回值
	 
	
    if( NULL == (pd_t = pcap_dump_open(p, fname) ) )
   	{
        printf("pcap_dump_open error %d %s\n",errno,strerror(errno));
    }
   
	 pcap_loop( p,10,sniff_handle,(u_char*)pd_t);
	
	 pcap_dump_flush(pd_t);
	
	 pcap_dump_close(pd_t);	 
	 return 0;
}

#endif


int check_iphdr( const struct pcap_pkthdr * phdr, const u_char * pkt,
    struct iphdr** iphdr_p )
{

	const struct ethhdr* ethh = NULL;
	struct iphdr* iph;
	const u8*   data = pkt;
	const u16* vlan_proto = 0;
	if (phdr->len != phdr->caplen)
	{
		log_err(" phdr->len %d != phdr->caplen %d \n",phdr->len,phdr->caplen);
		return -1;
	}
	ethh =(struct ethhdr*) data;
	if(ethh->h_proto != htons(ETH_P_IP))
	{
		if(ethh->h_proto == htons(ETH_P_8021Q))
		{
			vlan_proto = &(ethh->h_proto);
			vlan_proto += 2;// shift 4 byte;
			if(*vlan_proto != htons(ETH_P_IP)){
				log_err(" pkt is vlan pkt,but not a vlanip pkt; vlan_proto %x \n",htons(*vlan_proto));
				return -1;
			}
			else
			{
				iph = (struct iphdr*)(vlan_proto+1);
			}
		}
		else
		{
			log_err(" pkt is not ip or vlan pkt; ethh->h_proto %x \n",htons(ethh->h_proto));
			return -1;
		}
	}
	else
	{
		iph = (struct iphdr*)(ethh+1);
	}
	/* ip hdr is corrent */
	if(iph->ihl <5 || iph->version != 4){
	
		log_err("ip header error\n");
		goto inhdr_error;
	}
	if((int)iph->ihl*4 >  (int)(phdr->caplen -((u8*)iph - data))){
		log_err("ip header len is beyond the caplen!\n");
		goto inhdr_error;
	}
	if(ntohs(iph->tot_len) > phdr->caplen -((u8*)iph - data))
	{
		log_err(" ip tot len is beyond the caplen! \n");
		goto inhdr_error;
	}

	*iphdr_p = iph;
	
	return 0;
inhdr_error:
	
	return -2;
}

int check_udp( struct iphdr* iph,struct udphdr** udph_p)
{
	struct udphdr* udph;
    uint32_t ip_payload_len = ntohs(iph->tot_len)- iph->ihl*4;
	if(iph->protocol == IPPROTO_UDP)
	{
		udph = (struct udphdr*)((u8*)iph + iph->ihl*4);
		*udph_p = udph;
		if(htons(udph->len) > ip_payload_len){
		    log_err(" udph->len %d ip_payload_len %d \n",htons(udph->len),ip_payload_len);
			return -1;
		}
		return 0;
	}
	return -1;
}


int check_tcp( struct iphdr* iph,struct tcphdr** tcph_p)
{
	struct tcphdr* h;
	if(iph->protocol == IPPROTO_TCP)
	{
		h = (struct tcphdr*)((u8*)iph + iph->ihl*4);
		*tcph_p = h;
		return 0;
	}
	return -1;
}

