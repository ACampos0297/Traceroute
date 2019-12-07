#include <iostream>
#include "pch.h"

#define IP_HDR_SIZE  20  /* RFC 791 */ 
#define ICMP_HDR_SIZE  8  /* RFC 792 */ 
/* max payload size of an ICMP message originated in the program */
#define MAX_SIZE   65200 
#define MAX_NAME   255
/* max size of an IP datagram */
#define MAX_ICMP_SIZE    (MAX_SIZE + ICMP_HDR_SIZE) 
/* the returned ICMP message will most likely include only 8 bytes
* of the original message plus the IP header (as per RFC 792); however,
* longer replies (e.g., 68 bytes) are possible */
#define MAX_REPLY_SIZE    (IP_HDR_SIZE + ICMP_HDR_SIZE + MAX_ICMP_SIZE) 
#define DEFAULT_TIMEOUT 500

/* ICMP packet types */
#define ICMP_ECHO_REPLY  0 
#define ICMP_DEST_UNREACH 3 
#define ICMP_TTL_EXPIRE  11 
#define ICMP_ECHO_REQUEST 8 

/* remember the current packing state */
#pragma pack (push) 
#pragma pack (1) 

/* define the IP header (20 bytes) */
class IPHeader {
public:
	u_char h_len : 4;   /* 4 bits: length of the header in dwords */
	u_char version : 4;  /* 4 bits: version of IP, i.e., 4 */
	u_char tos;   /* type of service (TOS), ignore */
	u_short len;   /* length of packet */
	u_short ident;   /* unique identifier */
	u_short flags;   /* flags together with fragment offset - 16 bits */
	u_char ttl;   /* time to live */
	u_char proto;   /* protocol number (6=TCP, 17=UDP, etc.) */
	u_short checksum;  /* IP header checksum */
	u_long source_ip;
	u_long dest_ip;
};

/* define the ICMP header (8 bytes) */
class ICMPHeader {
public:
	unsigned char type;    /* ICMP packet type */
	unsigned char code;    /* type subcode */
	u_short checksum;   /* checksum of the ICMP */
	u_short id;    /* application-specific ID */
	u_short seq;    /* application-specific sequence */
};

/* now restore the previous packing state */
#pragma pack (pop) 



/*
* ======================================================================
* ip_checksum: compute Internet checksums
*
* Returns the checksum. No errors possible.
*
* ======================================================================
*/
u_short ip_checksum(u_short* buffer, int size) {
	u_long cksum = 0;

	/* sum all the words together, adding the final byte if size is odd */
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(u_short);
	}

	if (size)
		cksum += *(u_char*)buffer;

	/* add carry bits to lower u_short word */
	cksum = (cksum >> 16) + (cksum & 0xffff);

	/* return the bitwise complement of the resulting mishmash */
	return (u_short)(~cksum);
}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		printf("Usage: %s [IP or Host]", argv[0]);
		return -1;
	}

	string host = string(argv[1]);

	//Initialize WinSock; once per program run
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		printf("Main:\tWSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		return -1;
	}

	//perform DNS lookup
	// structure used in DNS lookups
	struct hostent* remote;
	// structure for connecting to server
	struct sockaddr_in server;
	// first assume that the string is an IP address
	DWORD IP = inet_addr(host.c_str());

	if (IP == INADDR_NONE)
	{
		// if not a valid IP, then do a DNS lookup
		if ((remote = gethostbyname(host.c_str())) == NULL)
		{
			printf("Invalid string: neither FQDN, nor IP address");
			return -1;
		}
		else // take the first IP address and copy into sin_addr
		{
			memcpy((char*) & (server.sin_addr), remote->h_addr, remote->h_length);
			string ip = inet_ntoa(server.sin_addr);
		}
	}
	else
	{
		// if a valid IP, directly drop its binary version into sin_addr
		server.sin_addr.S_un.S_addr = IP;
	}
	printf("Tracerouting to %s...\n", inet_ntoa(server.sin_addr));

	//OPEN TCP Socket
	SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == INVALID_SOCKET)
	{
		printf("socket() generated error %d\n", WSAGetLastError());
		WSACleanup();
		return -1;
	}
	else
	{
		// setup the port # and protocol type
		server.sin_family = AF_INET;
	}

	//Send 30 ICMP requests
	for (int i = 1; i <= 30; i++)
	{
		int ttl = i;
		// buffer for the ICMP header 
		u_char send_buf[MAX_ICMP_SIZE];  /* IP header is not present here */

		ICMPHeader* icmp = (ICMPHeader*)send_buf;

		// set up the echo request 
		// no need to flip the byte order since fields are 1 byte each 
		icmp->type = ICMP_ECHO_REQUEST;
		icmp->code = 0;

		// set up ID/SEQ fields as needed 
		icmp->id = (u_short)GetCurrentProcessId();
		icmp->seq = ttl;
		// initialize checksum to zero 
		icmp->checksum = 0;

		/* calculate the checksum */
		int packet_size = sizeof(ICMPHeader);   // 8 bytes 
		icmp->checksum = ip_checksum((u_short*)send_buf, packet_size);

		// set our TTL
		if (setsockopt(sock, IPPROTO_IP, IP_TTL, (const char*)& ttl, sizeof(ttl)) == SOCKET_ERROR) {
			closesocket(sock);
			printf("Unable to set TTL\n");
			return -1;
		}

		//send packet
		int ret;
		ret = sendto(sock, (char*)send_buf, packet_size, 0, (SOCKADDR*)& server, sizeof(server));
		if (ret == SOCKET_ERROR) {
			printf("send function failed with error %d\n", WSAGetLastError());
		}
	}

	//receive ICMP responses
	int ret;
	u_char rec_buf[MAX_REPLY_SIZE];/* this buffer starts with an IP header */
	IPHeader* router_ip_hdr = (IPHeader*)rec_buf;
	ICMPHeader* router_icmp_hdr = (ICMPHeader*)(router_ip_hdr + 1);
	IPHeader* orig_ip_hdr = (IPHeader*)(router_icmp_hdr + 1);
	ICMPHeader* orig_icmp_hdr = (ICMPHeader*)(orig_ip_hdr + 1);

	sockaddr_in response;
	int addrSize = sizeof(response);

	HANDLE handle = new HANDLE;
	WSAEVENT ICMPRecv = CreateEvent(NULL, false, false, NULL);
	handle = ICMPRecv;

	//receive
	ret=WSAEventSelect(sock, ICMPRecv, FD_READ);
	if (ret == SOCKET_ERROR) {
		printf("WSAEventSelect failed with error %d\n", WSAGetLastError());
		return -1;
	}
	
	while (1)
	{
		ret = WaitForSingleObject(handle, 500);

		if((ret = recvfrom(sock, (char*)rec_buf, MAX_REPLY_SIZE, 0, (SOCKADDR*)&response, &addrSize))<0)
		{
			printf("recv failed with error %d\n", WSAGetLastError());
			WSACleanup();
			return -1;
		}


		//make sure packet size >= 56 bytes
		if (ret >= 56)
		{
			// check if this is TTL_expired or is an echo reply
			if ((router_icmp_hdr->type == ICMP_TTL_EXPIRE || router_icmp_hdr->type == ICMP_ECHO_REPLY)
				&& router_icmp_hdr->code == 0)
			{
				// check if process ID matches
				if (orig_icmp_hdr->id == GetCurrentProcessId())
				{
					if (router_icmp_hdr->type == ICMP_ECHO_REPLY)
					{
						cout << "host reached" << endl;
						return 0;
					}

					int rec_ttl = orig_icmp_hdr->seq;
					long ip;
					sockaddr_in service;
					ip = router_ip_hdr->source_ip;
					service.sin_addr.s_addr = ip;
					char* ip_string = inet_ntoa(service.sin_addr);
					cout << "TTL = " << rec_ttl << " IP " << ip_string<<endl;
				}
			}
		}
	}
	closesocket(sock);
	WSACleanup;
	return 0;
}