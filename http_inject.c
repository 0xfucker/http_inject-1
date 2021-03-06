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


int GetIPHdrChksum (IPHDR * piphdr) {	//Get IP Header Checksum..
	unsigned int		checksum = 0;
	unsigned short *	pshortdata = piphdr;	// 2byte header data
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
	unsigned char 	injectpacket[INJECT_PACKET_BUFSIZE] = {0, };	// packet to be transferred for blocking.
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
	ptcphdr->SeqNum = htonl(ntohl(ptcphdr->SeqNum) + ntohs(piphdr->Length) - ((unsigned long)piphdr->HdrLength * 4 + (unsigned long)ptcphdr->HdrLength * 4));


	// Manipulate Total Length in IP header with msg "blocked"
	piphdr->Length = htons((unsigned short)(piphdr->HdrLength * 4) + (unsigned short)(ptcphdr->HdrLength * 4) + sizeof(msg));
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

	printf("[HTTP BLOCKED]\n");
	return 0;
}

int BackwardInject (pcap_t * pcd, const u_char * packet, int hsize) {

	ETHHDR * 		pethhdr;
	IPHDR * 		piphdr;
	TCPHDR *		ptcphdr;	
	char *			ptcpdata;
	unsigned char 	injectpacket[INJECT_PACKET_BUFSIZE] = {0, };	
	char 			msg[] = "blocked";
	PTCPHDR 		pseudohdr;										//Pseudo Header for calculating tcp checksum
	int i = 0;

	unsigned char  	tempmac[6];
    unsigned int 	tempipaddr;
    unsigned short 	temptcpport;

    unsigned int 	tempnum;

    /* exchange src information and dest information */

	memcpy((char *)injectpacket, (char *)packet, hsize);

	pethhdr = (ETHHDR *)injectpacket;
	piphdr = (unsigned char *)pethhdr + sizeof(ETHHDR);
	piphdr->Checksum = 0;

	ptcphdr = (unsigned char *)piphdr + (int)(piphdr->HdrLength * 4);
	ptcpdata = (unsigned char *)ptcphdr + (int)(ptcphdr->HdrLength * 4);
	
	ptcphdr->Checksum = 0;	

	// change mac address
	memcpy(tempmac, pethhdr->DstAddr, 6);
	memcpy(pethhdr->DstAddr, pethhdr->SrcAddr, 6);
	memcpy(pethhdr->SrcAddr, tempmac, 6);
	
	// change ip address
	//printf("srcip : %x dstip : %x\n", piphdr->SrcAddr, piphdr->DstAddr);
	tempipaddr = piphdr->SrcAddr;
	piphdr->SrcAddr = piphdr->DstAddr;
	piphdr->DstAddr = tempipaddr;
	//printf("srcip : %x dstip : %x\n", piphdr->SrcAddr, piphdr->DstAddr);
	// change port

	temptcpport = ptcphdr->SrcPort;
	ptcphdr->SrcPort = ptcphdr->DstPort;
	ptcphdr->DstPort = temptcpport;

	// Get Seq, ACK Num

	tempnum = ptcphdr->AckNum;
	ptcphdr->AckNum = htonl(ntohl(ptcphdr->SeqNum) + ntohs(piphdr->Length) - ((unsigned long)piphdr->HdrLength * 4 + (unsigned long)ptcphdr->HdrLength * 4));
	ptcphdr->SeqNum = tempnum;

	// Manipulate Total Length in IP header with msg "blocked"
	piphdr->Length = htons((unsigned short)(piphdr->HdrLength * 4) + (unsigned short)(ptcphdr->HdrLength * 4) + sizeof(msg));
	
	//printf("Length : %d\n", sizeof(msg));
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
	
	printf("[HTTP BLOCKED]\n");
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
	ETHHDR * 		pethhdr;	// pointer of Ethernet Header
	IPHDR * 		piphdr;		// pointer of IP Header
	TCPHDR *		ptcphdr;	// pointer of TCP Header
	unsigned char * phttp;		// pointer of http Header
	int 			hsize;		// Whole size of packet

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
	
	pcd = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	
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
		
		piphdr = (unsigned char *)pethhdr + sizeof(ETHHDR);

		if (piphdr->Protocol != IPHDR_PROTOCOL_TCP)
			continue;
		 
		ptcphdr = (unsigned char *)piphdr + (int)(piphdr->HdrLength * 4);
		phttp 	= (unsigned char *)ptcphdr + (int)(ptcphdr->HdrLength * 4);
		hsize = sizeof(ETHHDR) + (piphdr->HdrLength * 4) + (ptcphdr->HdrLength * 4);
		
		if (!memcmp((char *)phttp, "GET", 3)) {
			//ForwardInject(pcd, packet, hsize);	// If activate this function, Blocking will be done by forward FIN method
			BackwardInject(pcd, packet, hsize);		// If activate this function, Blocking will be done by backward FIN method
		}
	}

	return 0;
}