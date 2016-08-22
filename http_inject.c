/*
[리포트]
HTTP 트래픽이 탐지되는 경우 차단 메세지를 inject하라.
[1단계 - forward fin]
HTTP 트래픽("GET "로 시작하는)이 탐지되는 경우 같은 방향(forward)으로 서버에게 "blocked" 메세지를 보낸다. NetClient, NetServer로 테스트하면 쉽게 디버깅할 수 있음.
[2단계 - bacward fin]
HTTP 트래픽("GET "로 시작하는)이 탐지되는 경우 같은 반대 방향(backward)으로 클라이언트에게 "blocked" 메세지를 보낸다. NetClient, NetServer로 테스트하면 쉽게 디버깅할 수 있음.
[3단계 - change block message]
"blocked"를 302 redirect message(https://en.wikipedia.org/wiki/HTTP_302)로 대체하여 victim(웹브라우저)에서 해당 웹페이지로 redirect되는지 확인한다.
[프로그램 실행 형식]
http_inject

*/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <strings.h>

#define ETHHDR_TYPE_IPv4 0x0800

#define IPHDR_PROTOCOL_TCP 0x06

#define INJECT_PACKET_BUFSIZE 128

typedef struct {
	unsigned char 	DstAddr[6];
	unsigned char  	SrcAddr[6];
	unsigned short 	type;
} ETHHDR;

typedef struct {
    unsigned char  	HdrLength:4;
    unsigned char  	Version:4;
    unsigned char  	TOS;
    unsigned short 	Length;
    unsigned short 	Id;
    unsigned short 	Flag:3;
    unsigned short	FragmentOffset:13;
    unsigned char  	TTL;
    unsigned char  	Protocol;
    unsigned short 	Checksum;
    unsigned int 	SrcAddr;
    unsigned int 	DstAddr;	
} IPHDR; 

typedef struct {
    unsigned short 	SrcPort;
    unsigned short 	DstPort;
    unsigned int 	SeqNum;
    unsigned int 	AckNum;
    unsigned short 	Reserved1:4;
    unsigned short 	HdrLength:4;
    unsigned short 	Fin:1;
    unsigned short 	Syn:1;
    unsigned short 	Rst:1;
    unsigned short 	Psh:1;
    unsigned short 	Ack:1;
    unsigned short 	Urg:1;
    unsigned short 	Reserved2:2;
    unsigned short 	Window;
    unsigned short 	Checksum;
    unsigned short 	UrgPtr;
} TCPHDR;

typedef struct {
    unsigned int 	SrcAddr;
    unsigned int 	DstAddr;
    unsigned char	Reserved;
    unsigned char 	Protocol;
    unsigned short	TCPSegLength;
    char 			TCP[128];
} PTCPHDR;


int BackwardInject () {

	return 0;
}

int GetIPHdrChksum (IPHDR * piphdr) {
	unsigned int		checksum = 0;
	unsigned short *	pshortdata = piphdr;
	int i = 0;

	for (i = 0; i < (piphdr->HdrLength * 4)/2; i++) {
		checksum += *pshortdata;
		pshortdata++;
	}
	
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);

	checksum = ~checksum & 0xffff;

	piphdr->Checksum = checksum;

	return 0;
}

int GetTCPHdrChksum (TCPHDR * ptcphdr, PTCPHDR * pseudohdr) {
	unsigned int 		checksum = 0;
	unsigned short *	pshortdata = pseudohdr;
	int i = 0;

	for (i = 0; i < (ntohs(pseudohdr->TCPSegLength) + 12)/2; i++) {
		checksum += *pshortdata;
		pshortdata++;
	}

	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);

	checksum = ~checksum & 0xffff;

	ptcphdr->Checksum = checksum;


	return 0;
}

int ForwardInject (pcap_t * pcd, const u_char * packet, int hsize) {
	ETHHDR * 		pethhdr;
	IPHDR * 		piphdr;
	TCPHDR *		ptcphdr;	
	char *			ptcpdata;
	unsigned char 	injectpacket[INJECT_PACKET_BUFSIZE] = {0, };
	char 			msg[] = "blocked";
	PTCPHDR 		pseudohdr;
	int i = 0;


	memcpy((char *)injectpacket, (char *)packet, hsize);

	pethhdr = (ETHHDR *)injectpacket;

	piphdr = (unsigned char *)pethhdr + sizeof(ETHHDR);
	
	piphdr->Checksum = 0;

	ptcphdr = (unsigned char *)piphdr + (int)(piphdr->HdrLength * 4);
	ptcpdata = (unsigned char *)ptcphdr + (int)(ptcphdr->HdrLength * 4);
	
	ptcphdr->Checksum = 0;	

	// Get Seq Num
	printf("ntohs iphdr Length : %d\n", ntohs(piphdr->Length));
	ptcphdr->SeqNum = htonl(ntohl(ptcphdr->SeqNum) + ntohs(piphdr->Length) - ((unsigned long)piphdr->HdrLength * 4 + (unsigned long)ptcphdr->HdrLength * 4));


	// Manipulate Total Length in IP header with msg "blocked"
	piphdr->Length = htons((unsigned short)(piphdr->HdrLength * 4) + (unsigned short)(ptcphdr->HdrLength * 4) + sizeof(msg));
	printf("Length : %d\n", sizeof(msg));
	memcpy(ptcpdata, msg, 8);
	
	// Set Fin Flag
	ptcphdr->Fin = 1;
	
	// Get Checksum of IP Header
	GetIPHdrChksum(piphdr);
	
	ptcphdr->Checksum = 0;

	pseudohdr.SrcAddr = piphdr->SrcAddr;
	pseudohdr.DstAddr = piphdr->DstAddr;
	pseudohdr.Reserved = 0x00;
	pseudohdr.Protocol = IPHDR_PROTOCOL_TCP;


	pseudohdr.TCPSegLength = ptcphdr->HdrLength * 4 + sizeof(msg);
	pseudohdr.TCPSegLength = htons(pseudohdr.TCPSegLength);

	memcpy((char *)(&pseudohdr.TCP), (char *)ptcphdr, ptcphdr->HdrLength * 4);
	memcpy((char *)pseudohdr.TCP + ptcphdr->HdrLength * 4, ptcpdata, sizeof(msg));


	GetTCPHdrChksum(ptcphdr, &pseudohdr);

	pcap_sendpacket(pcd, injectpacket, sizeof(ETHHDR) + piphdr->HdrLength * 4 + ptcphdr->HdrLength * 4 + sizeof(msg));

	return 0;
}

int PrintPacket(const unsigned char * packet, int len) {
	int i = 0;
	
	for (i = 0; i < len; i++) {
		if (i == 0)				printf("%02X ",		packet[0]);
		else if ((i % 16) == 0) printf("\n%02X ",	packet[i]);
		else if ((i % 8) == 0)	printf(" %02X ",	packet[i]);
		else					printf("%02X ",		packet[i]);
	}

	printf("\n");

	return 0;
}

int main (int argc, char * argv[]) {
	char * 			dev;
	int 			i = 0;
	char 			errbuf[PCAP_ERRBUF_SIZE];
	pcap_t * 		pcd;		/*packet capture descriptor*/
	bpf_u_int32 	mask;		/*netmask of device*/
	bpf_u_int32 	net;		/*IP of device*/
	const u_char * 	packet;
	struct 			pcap_pkthdr header;
	struct 			bpf_program fp;
	ETHHDR * 		pethhdr;
	IPHDR * 		piphdr;
	TCPHDR *		ptcphdr;
	unsigned char * phttp;
	int 			hsize;

	if (argc > 1) {
		dev = argv[1];		
	}

	else {
		printf("Find a device automatically...\n");
		dev = pcap_lookupdev(errbuf);
		
		if(dev == NULL) {
			fprintf(stderr, "Couldn't find device : %s\n", errbuf);
			return 2;
		}
	}
	
	printf("Device : %s\n", dev);	
	
	pcd = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	
	if (pcd == NULL) {
		fprintf(stderr, "Cannot open device(%s) : %s\n", dev, errbuf);
		return 2;
	}
	
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Cannot get netmask for device(%s) : %s\n", dev, errbuf);
	}

	//examine data link Layer
	
	if ((pcap_datalink(pcd)) != DLT_EN10MB) {	//Capture ethernet packet only.
		fprintf(stderr, "Device %s does not provide Ethernet header", dev);
		return 2;
	}
	
	printf("Data-link Layer check completed...(type : Ethernet)\n");	


	
	while(1) {
		packet 	= pcap_next(pcd, &header);

		if (packet == NULL)
			continue;

		pethhdr = (ETHHDR *)packet;

		if (ntohs(pethhdr->type) != ETHHDR_TYPE_IPv4)
			continue;
		
		//printf("IPv4 Header\n");
		piphdr = (unsigned char *)pethhdr + sizeof(ETHHDR);

		//printf("Protocol : %02X\n", piphdr->Protocol);
		if (piphdr->Protocol != IPHDR_PROTOCOL_TCP)
			continue;
		 

		ptcphdr = (unsigned char *)piphdr + (int)(piphdr->HdrLength * 4);
		//printf("ip HDRlen : %d tcp HDRlen : %d\n", piphdr->HdrLength, ptcphdr->HdrLength);
		phttp 	= (unsigned char *)ptcphdr + (int)(ptcphdr->HdrLength * 4);

		//printf("%p, %p\n", ptcphdr, phttp);

		//printf("%c %c\n", ((unsigned char *)phttp)[0], ((unsigned char *)phttp)[1]);
		hsize = sizeof(ETHHDR) + (piphdr->HdrLength * 4) + (ptcphdr->HdrLength * 4);
		
		if (!memcmp((char *)phttp, "GET", 3)) {
			printf("headerlen : %d\n", header.len);
			printf("hsize : %d\n", hsize);
			ForwardInject(pcd, packet, hsize);
		}

		//PrintPacket(packet, header.len);

	}

	return 0;
}


























