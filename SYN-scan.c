#define HAVE_REMOTE
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "libnet.lib")
#include <stdio.h>
#include <pcap.h>
#include <libnet.h>
#include "network.h"
#include <Windows.h>

BOOL decode_tcp(const u_char *, int );
BOOL decode_ip(const u_char *, u_int);
void print_ip(u_int);
DWORD WINAPI SnifferThread(void *);
const int sniff(pcap_t*, unsigned short);
pcap_t* init_pcap(pcap_if_t *, pcap_if_t *);
libnet_ptag_t init_tcp(libnet_t *);
libnet_ptag_t init_ipv4(libnet_t *, uint32_t, uint32_t);
libnet_ptag_t init_ethernet(libnet_t *, uint8_t [], uint8_t []);
int rebuild_send_TCP(libnet_t *, libnet_ptag_t, int);


int port = -1;
int uchoice;
HANDLE port_mutex;
static pcap_t *adhandle;
struct libnet_ethernet_hdr ethernet_header;
struct libnet_ipv4_hdr ipv4_header;
struct libnet_tcp_hdr tcp_header;


void usage(char *argv[]){
	printf("Usage: %s [local address] [target mac address] [target address] [port range]\n\n", argv[0]);
	printf("local address\t- the IPV4 address of the local machine\n");								//argv[1]
	printf("target mac address\t- the mac address of the target, separated with ':'\n");			//argv[2]
	printf("target address\t- the IPV4 address of the target\n");									//argv[3]
	printf("port range\t- the range of ports to scan, e.g '50-100'");								//argv[4]
}

int main(int argc, char *argv[]){
	libnet_t *l;
	pcap_if_t *alldevs, *device;
	char errbuf[PCAP_ERRBUF_SIZE];

	char *new_device, *mac_destination;
	int i = 0, c1, c2, c3, c4;
	struct libnet_ether_addr *eh_addr;
	uint32_t IP_address, target_IP_address, packet_s;
	uint8_t enet_dst[6], enet_src[6], *packet;
	int values[6];
	libnet_ptag_t tag_ether, tag_ipv4, tag_tcp;
	int port_end, port_start;
	static struct thread_parameters params;			// port, source ip, destination ip
	HANDLE thread;


	if(argc != 5){
		usage(argv);
		return 1;
	}

		printf("\n");
		if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
			printf("Error finding devices!: %s\n", errbuf);
			return -1;
		}

	// Print out the devices available
	for(device = alldevs; device; device = device->next){
		printf("%d. %s\n", ++i, device->name);
		if(device->description)
			printf(" (%s)\n\n", device->description);
		else
			printf(" (No description)\n\n");
		if(i == 0){
			printf("No devices found!\n");
			return -1;
		}
	}

	// Scan which device the user chooses
	printf("Enter the device you want to use, 1-%d: ", i);
	scanf_s("%d", &uchoice);

	if(uchoice < 1 || uchoice > i){
		printf("\nInvalid device!\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the device to listen on
	for(device = alldevs, i = 0; i < uchoice-1; device = device->next, i++);
	
	// Remove rpcap from the name for use with libnet
	new_device = device->name +8;
	l = libnet_init(LIBNET_LINK_ADV, new_device, errbuf);
	if(l == NULL){
		printf("Error initializing libnet: %s\n", libnet_geterror(l));
		return -1;
	}

	// Get the MAC address of the device
	eh_addr = libnet_get_hwaddr(l);

	ethernet_header.ether_type = ETHERTYPE_IP;

	// Scan the 1st argument as the local IPV4 address (not in network byte order)
	sscanf_s(argv[1], "%d.%d.%d.%d", &c1, &c2, &c3, &c4);
	IP_address = (uint32_t)c1 + c2*256 + c3*256*256 + c4*256*256*256;

	// Scan the 3rd argument as the target IPV4 address (not in network byte order)
	sscanf_s(argv[3], "%d.%d.%d.%d", &c1, &c2, &c3, &c4);
	target_IP_address = (uint32_t)c1 + c2*256 + c3*256*256 + c4*256*256*256;
	
	// Put the local MAC address in a variable for use in the ethernet header
	printf("\nFrom device: ");
	for(i = 0; i < 6; i++){															// Fill and print enet_src with the mac address
	enet_src[i] = eh_addr->ether_addr_octet[i];
	printf("%02x", enet_src[i]);
	if(i != 5)
		printf(":");
	}
	printf("\n");

	// Get port range to scan
	sscanf_s(argv[4], "%d-%d", &port_start, &port_end);

	// So we can use the same adhandle in all functions
	adhandle = init_pcap(alldevs, device);

	if(adhandle == NULL){
		printf("Error getting adhandle\n");
		return -1;
	}

	// Initiate the TCP header
	tag_tcp = init_tcp(l);

	// Initiate the IPV4 header
	tag_ipv4 = init_ipv4(l, IP_address, target_IP_address);

	// Setup the arguments needed for the ethernet header
	mac_destination = argv[2];
	printf("Target: ");

	// Set the target mac address
	// %c is for removing text that doesn't belong
	if( 6 == sscanf_s(mac_destination, "%x:%x:%x:%x:%x:%x%c", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5])){
		for(i = 0; i < 6; ++i){					// Fill enet_dst with the mac address the user provided and print it
			enet_dst[i] = (uint8_t) values[i];
			printf("%02x", enet_dst[i]);
			if(i != 5)
				printf(":");
		}
	}else{
			printf("\nInvalid mac address format");
			return -1;
	}
	printf("\n\n");

	printf("Starting SYN-scan at port %d, stopping at %d\n\n", port_start, port_end);
	Sleep(1000);

	// Initiate eternet header
	tag_ether = init_ethernet(l, enet_dst, enet_src);


	// All headers are done at this point
	//printf("DEBUGGING: Created all headers successfully\n");									// All headers are done at this point

	// Build the packet
	if(libnet_adv_cull_packet(l, &packet, &packet_s) == -1){
		printf("Error creating packet: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		return -1;
	}


	params.dst_ip = target_IP_address;												// Initialize the struct that will be used in the sniff function
	params.src_ip = IP_address;

	thread = CreateThread(0, 0, &SnifferThread, &params, 0, 0);

	if(SetThreadPriority(thread, THREAD_PRIORITY_HIGHEST) == 0){
		printf("Error setting thread priority: %d\n", GetLastError());
		return -1;
	}

	// Check ports from port_start to port_end

	for(port = port_start; port < port_end; port++){
		if(!SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN)){
			printf("Error setting thread to background mode: %d\n", GetLastError());
			return -1;
		}

		//Sleep(500);																// Give the listener time to start
		rebuild_send_TCP(l, tag_tcp, port);
		//printf("DEBUGGING: Sent packet testing port %d\n", port);
		Sleep(500);															// The amount of time we will give to the function listening for answers
		SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_END);
	}

	libnet_destroy(l);
	return 0;
}


// Function so we can use the same adhandle without re-making it every time
// Only call this after deciding on a device
pcap_t* init_pcap(pcap_if_t *alldevs, pcap_if_t *device){
	pcap_t *adhandle_tmp;
	char errbuf[PCAP_ERRBUF_SIZE];

	if((adhandle_tmp = pcap_open(
			device->name,														// The device passed to this function
			LIBNET_TCP_H + LIBNET_IPV4_H + LIBNET_ETH_H + 50,					// Amount of data to capture (+50 just to be safe)
			PCAP_OPENFLAG_PROMISCUOUS,											// Open flag
			5000,																// Timeout
			NULL,																// No authentication
			errbuf																// An error buffer if an error occurs
			)) == NULL){
				printf("Error starting capture: %s\n", errbuf);
				pcap_freealldevs(alldevs);
				return NULL;
			}

	//printf("DEBUGGING: Successfully initiated adhandle\n");
	pcap_freealldevs(alldevs);
	return adhandle_tmp;
}

// This is the sniffer thread that checks if select ports respond
DWORD WINAPI SnifferThread(void *struct_in){
	pcap_t *thread_adhandle;
	pcap_if_t *thread_alldevs;
	pcap_if_t *thread_device;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i;

	struct thread_parameters *in_params;
	const u_char *packet;
	struct pcap_pkthdr *pcap_header;
	int packet_count = 0, result;
	const struct ether_hdr *ethernet_header;
	const struct ip_hdr *ip_header;
	const struct tcp_hdr *tcp_header;

	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &thread_alldevs, errbuf) == -1){
		printf("Error finding devices!: %s\n", errbuf);
		return -1;
	}

	// This is the device the user chose at the start so we use that one to listen aswell
	for(thread_device = thread_alldevs, i = 0; i < uchoice-1; thread_device = thread_device->next, i++);

	if((thread_adhandle = pcap_open(thread_device->name, 65535, 0, 1000, NULL, errbuf)) == NULL){
		printf("Error assigning device!: %s", errbuf);
		return -1;
	}

	pcap_freealldevs(thread_alldevs);

	in_params = (struct thread_parameters *)struct_in;
	//printf("DEBUGGING: Sniffer function starting\n");

	// Start the actual sniffing
	while(result = pcap_next_ex(thread_adhandle, &pcap_header, &packet) >= 0){
		//decode_ethernet(pkt_data);
		ethernet_header = (const struct ether_hdr *)packet;
		ip_header = (const struct ip_hdr *)packet + my_ETHER_HDR_LEN;
		tcp_header = (const struct tcp_hdr *)packet + my_ETHER_HDR_LEN + sizeof(struct ip_hdr);

		if(decode_ip(packet + my_ETHER_HDR_LEN, in_params->dst_ip) == TRUE)
			if(decode_tcp(packet + my_ETHER_HDR_LEN + sizeof(struct ip_hdr), port) == TRUE){

			}
		
	}
	printf("Sniffer function returned (This is not good)\n");
	return 0xBAD;
}

libnet_ptag_t init_tcp(libnet_t *l){
	libnet_ptag_t tag_tcp;

	tcp_header.th_sport = 5001;										// Random port
	tcp_header.th_dport = port;										// TODO: implement the incremental port here
	tcp_header.th_seq = 0;											// Sequence number
	tcp_header.th_ack = 0;											// ack nr is 0
	tcp_header.th_off = 5;											// Minimum size of offset is 5 dwords
	tcp_header.th_win = 32767;										// I have no clue why this is set to this
	tcp_header.th_seq = 1;

	tag_tcp = libnet_build_tcp(
	tcp_header.th_sport,											// Source port (doesn't matter)
	tcp_header.th_dport,											// The port we want to check
	tcp_header.th_seq,												// Seq number (could be anything)
	0,																// No ACK number for SYN
	TH_SYN,															// Set the SYN flag
	tcp_header.th_win,												// The window size
	0,																// Checksum will be generated later
	0,																// Not urgent
	LIBNET_TCP_H,													// Size of the packet is size of tcp header
	NULL,															// The payload we want to send
	0,																// The length of the payload
	l,																// The libnet handle
	0																// The libnet ptag (we want to create a new one so 0)
	);

	if(tag_tcp == -1){
		printf("Error creating tcp header: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(1);
	}

	return tag_tcp;
}

libnet_ptag_t init_ipv4(libnet_t *l, uint32_t src_ip, uint32_t dst_ip){
	libnet_ptag_t tag_ipv4;

	ipv4_header.ip_id = 242;										// ID field, no clue why this is 242
	ipv4_header.ip_tos = 0;											// Type of service 0
	ipv4_header.ip_ttl = 64;										// Time to live

	tag_ipv4 = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_TCP_H,
		0,															// Type of service
		ipv4_header.ip_id,											// ID number
		0,															// Frag offset
		ipv4_header.ip_ttl,											// Time to live of packet
		IPPROTO_TCP,												// Protocol
		0,															// Checksum (0 and libnet generates it automatically)
		src_ip,														// Source IP
		dst_ip,														// Destination IP
		NULL,														// No payload
		0,															// Size of payload is 0
		l,															// The handle to use
		0															// 0 to create a new tag
		);

	if(tag_ipv4 == -1){
		printf("Error creating ipv4 header: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(1);
	}

	return tag_ipv4;
}

libnet_ptag_t init_ethernet(libnet_t *l, uint8_t ether_dst[], uint8_t ether_src[]){
	libnet_ptag_t tag_ether;

	tag_ether = libnet_build_ethernet(
		ether_dst,
		ether_src,
		ETHERTYPE_IP,
		NULL,
		0,
		l,
		0);

	if(tag_ether == -1){
		printf("Error making ethernet header: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(1);
	}

	return tag_ether;
}

int rebuild_send_TCP(libnet_t *l, libnet_ptag_t tag_tcp, int port_in){
	uint8_t *packet;
	uint32_t packet_s;

	// Rebuild using the same parameters, only changing the destination port
	tag_tcp = libnet_build_tcp(
		tcp_header.th_sport,											// Source port (doesn't matter)
		port_in,														// The port we want to check
		tcp_header.th_seq,												// Seq number (could be anything)
		0,																// No ACK number for SYN
		TH_SYN,															// Set the SYN flag
		tcp_header.th_win,												// The window size
		0,																// Checksum will be generated later
		0,																// Not urgent
		LIBNET_TCP_H,													// Size of the packet is size of tcp header
		NULL,															// The payload we want to send
		0,																// The length of the payload
		l,																// The libnet handle
		tag_tcp															// The libnet ptag (we want to update the tcp part so we use the tcp tag)
		);

	if(tag_tcp == -1){
		printf("Error updating tcp header: %s", libnet_geterror(l));
		libnet_destroy(l);
		exit(1);
	}


	if(libnet_adv_cull_packet(l, &packet, &packet_s) == -1){
		printf("Error creating packet: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(1);
	}

	if(libnet_adv_write_link(l, packet, packet_s) == -1){
		printf("Error writing packet: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(1);
	}

	//printf("Successfully wrote a %d byte packet\n", packet_s);

	return 1;
}

void print_ip(u_int ip){ // Only works on little-endian
	int i;
	unsigned int ipAddress = ip;
    unsigned char octet[4] = {0,0,0,0};
    for (i=0; i<4; i++){
    octet[i] = ( ipAddress >> (i*8) ) & 0xFF;
    }
    printf("%d.%d.%d.%d",octet[0],octet[1],octet[2],octet[3]);
}

BOOL decode_ip(const u_char *header_in, u_int IP_addr){
	const struct ip_hdr *ip_header;

	ip_header = (struct ip_hdr *)header_in;

	/*printf("[IP Layer]\n");
	print_ip(ip_header->ip_src_addr);
	printf("  -->  ");
	print_ip(ip_header->ip_dest_addr);
	printf("\n");
	*/
	
	if(IP_addr == ip_header->ip_src_addr){
		return TRUE;
	}
	return FALSE;
}

BOOL decode_tcp(const u_char *header_in, int correct_port){
	const struct tcp_hdr *tcp_header;

	tcp_header = (const struct tcp_hdr *)header_in;

	/*
	printf("\t[TCP layer]\n");
	printf("\tPort: %hu  -->  %hu\n", ntohs(tcp_header->tcp_src_port), ntohs(tcp_header->tcp_dest_port));
	printf("\tAck #%u  Flags: ", ntohl(tcp_header->tcp_ack));
	if(tcp_header->tcp_flags & TCP_FIN)
		printf("FIN ");
	if(tcp_header->tcp_flags & TCP_SYN)
		printf("SYN ");
	if(tcp_header->tcp_flags & TCP_RST)
		printf("RST ");
	if(tcp_header->tcp_flags & TCP_PUSH)
		printf("PUSH ");
	if(tcp_header->tcp_flags & TCP_ACK)
		printf("ACK ");
	if(tcp_header->tcp_flags & TCP_URG)
		printf("URG");

		printf("\n");
	*/

		if(ntohs(tcp_header->tcp_src_port) == correct_port){
			printf("Port %d is open\n", correct_port);
			return TRUE;
		}

	return FALSE;
}