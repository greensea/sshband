#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "pcap.h"
#include "sshband.h"
#include "userinfo.h"

extern char config_net_device[1024];
static  int  link_type = 0;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	//const char *payload; /* Packet payload */
	hdl_pak_t pak;

	u_int size_ip;
	u_int size_tcp;

	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET );
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
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
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[] = "port 22";	/* The filter expression */
	bpf_u_int32 mask;		/* The netmask of our sniffing device */
	bpf_u_int32 net;		/* The IP of our sniffing device */
	
	if (pcap_lookupnet(config_net_device, &net, &mask, errbuf) == -1) {
		SSHBAND_LOGW("Can't get netmask for device %s\n", config_net_device);
		net = 0;
		mask = 0;
	}
	
	handle = pcap_open_live(config_net_device, 1500, 1, 1000, errbuf);
	if (handle == NULL) {
		SSHBAND_LOGE("Couldn't open device %s: %s\n", config_net_device, errbuf);
		return(2);
	}
	
	link_type = pcap_datalink(handle);
	SSHBAND_LOGI("pcap_datalink :  %d   ",  link_type);
	if (link_type != 1  &&  link_type != 113) {	
		SSHBAND_LOGE("Not support link type %d ",  link_type);
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
	
	while (1) {
		pcap_loop(handle, -1, got_packet, NULL);
	}
	
	return 0;
}





