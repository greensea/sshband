#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <time.h>
#include "pcap.h"
#include "sshband.h"
#include "userinfo.h"

extern char config_net_device[1024];
extern char server_addr[19];
extern u_short ssh_port;
static int link_type = 0;
static int link_header_length = 0;


char* get_if_ip(const char* ifname)
{
	char* ip = NULL;
	int inet_sock;
	struct ifreq ifr;    
		
	if (ifname == NULL) {
		return NULL;
	}
	
	inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (inet_sock < 0) {
		SSHBAND_LOGE("%s: socket() fail: %s\n", __func__, strerror(errno));
		return NULL;
	}
	
	strcpy(ifr.ifr_name, ifname);
	
	if (ioctl(inet_sock, SIOCGIFADDR, &ifr) < 0) {
		SSHBAND_LOGE("%s: ioctl() fail: %s\n", __func__, strerror(errno));
		close(inet_sock);
		
		return NULL;
	}
	
	ip = inet_ntoa(((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr);
	
	close(inet_sock);
	return ip;
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	//const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	//const char *payload; /* Packet payload */
	hdl_pak_t pak;

	u_int size_ip;
	u_int size_tcp;

	//ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + link_header_length );
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		SSHBAND_LOGD("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	tcp = (struct sniff_tcp*)(packet + link_header_length + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		SSHBAND_LOGD("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	//payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	//printf("%4x, %4x, %4x\n", tcp->th_sport, tcp->th_sport >> 8, (tcp->th_sport & 0x00FF)<< 8);
	pak.sport = (tcp->th_sport >> 8) | ((tcp->th_sport & 0x00FF) << 8);
	pak.dport = (tcp->th_dport >> 8) | ((tcp->th_dport & 0x00FF) << 8);
	pak.flags = tcp->th_flags;
	pak.len = header->len;
	pak.ip_src = ip->ip_src;
	pak.ip_dst = ip->ip_dst;
	//printf("ip size %d, ", size_ip);
	//printf("%5u-->%5u, %dB, (%.2x) ", pak.sport, pak.dport, pak.len, tcp->th_flags);
	//printf("%s-->%s\n", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
	//printf("got %d, %d\n", header->caplen, header->len - SIZE_ETHERNET - size_ip - size_tcp);
	sshband_handler(pak);
}

int pcap_main() {
	pcap_t *handle;		/* Session handle */
	char* sip = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[128] = {0};	/* The filter expression, like "port 22" */
	bpf_u_int32 mask;		/* The netmask of our sniffing device */
	bpf_u_int32 net;		/* The IP of our sniffing device */
	const char* link_type_name = NULL;
	
	snprintf(filter_exp, sizeof(filter_exp) - 1, "port %d", ssh_port);

	if (pcap_lookupnet(config_net_device, &net, &mask, errbuf) == -1) {
		SSHBAND_LOGW("Can't get netmask on interface %s\n", config_net_device);
		net = 0;
		mask = 0;
	}
    else {
        SSHBAND_LOGD("Network address obtained by libpcap is %u.%u.%u.%u\n", ((unsigned char*)&net)[0], ((unsigned char*)&net)[1], ((unsigned char*)&net)[2], ((unsigned char*)&net)[3]);
    }

	sip = get_if_ip(config_net_device);
	if (sip == NULL) {
		SSHBAND_LOGW("Can't get IP address on interface %s: %s\n", config_net_device, errbuf);
		strncpy(server_addr, "0.0.0.0", sizeof(server_addr) - 1);
	}
	else {
		strncpy(server_addr, sip, sizeof(server_addr) - 1);
	}
	SSHBAND_LOGI("Server IP address is %s\n", server_addr);

	errbuf[0] = 0x00;
	handle = pcap_open_live(config_net_device, 1500, 0, 1000, errbuf);
	if (handle == NULL) {
		SSHBAND_LOGE("Couldn't open device %s: %s\n", config_net_device, errbuf);
		return(2);
	}
	
	link_type = pcap_datalink(handle);
	link_type_name = pcap_datalink_val_to_name(link_type);
	if (link_type_name == NULL) {
		link_type_name = "unknown";
	}
	
	SSHBAND_LOGI("Data link type is %s(%d)   ",  link_type_name, link_type);
	
	switch (link_type) {
		case DLT_EN10MB:
			link_header_length = SIZE_ETHERNET;
			break;
			
		case DLT_LINUX_SLL:
			link_header_length = SIZE_LINUXSLL;
			break;
			
		default:	
			SSHBAND_LOGE("Not support link type %s(%d) ",  link_type_name, link_type);
			return(2);	
	}
	
	
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		SSHBAND_LOGE("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	if (pcap_setfilter(handle, &fp) == -1) {
		SSHBAND_LOGE("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	
    SSHBAND_LOGI("sshband started\n");
    
	while (1) {
		pcap_loop(handle, -1, got_packet, NULL);
	}
	
	return 0;
}





