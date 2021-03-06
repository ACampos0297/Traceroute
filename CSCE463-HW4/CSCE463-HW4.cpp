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

//keep track of pings that have received replies
class Pings
{
public:
	int hop; //1 to 30
	int rtt; //starts at 500
	int ttl;
	int count; //starts at 1
	int time_sent;
	int timeout;
	string routerIP= "<no DNS info>"; //filled in when reply comes back
	bool host = false;
	string routerName; //filled in when performing DNS reverse lookup
	Pings(int hop, int timeout, int ttl, int time_sent)
	{
		this->hop = hop;
		rtt = -1;
		count = 1;
		this->time_sent = time_sent;
		this->ttl = ttl;
		this->timeout = timeout;
	}
};

//thread
UINT WINAPI dnsThread(LPVOID params)
{
	Pings* p = (Pings*)params;

	struct hostent* reverse;
	// IPv4 demo of inet_ntop() and inet_pton()

	struct sockaddr_in sa;
	char str[INET_ADDRSTRLEN];

	// store this IP address in sa:
	inet_pton(AF_INET, p->routerIP.c_str(), &(sa.sin_addr));

	reverse = gethostbyaddr((char*)&sa.sin_addr, 4, AF_INET);	

	if (reverse == NULL)
	{
		p->routerName = "<no DNS info>";
	}
	else
	{
		p->routerName = string(reverse->h_name);
	}


	return 0;
}

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

	//create vector to keep track of sent pings
	vector<Pings> sentPings;
	vector<Pings> completedPings;
	vector<Pings> completedDNS;

	int run_time = timeGetTime();

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
		//add current hop to sentPings
		Pings hop = Pings(i, timeGetTime() + DEFAULT_TIMEOUT, i, timeGetTime());
		sentPings.push_back(hop);
	}

	//receive ICMP responses
	int ret;
	u_char rec_buf[MAX_REPLY_SIZE];/* this buffer starts with an IP header */
	IPHeader* router_ip_hdr = (IPHeader*)rec_buf;
	ICMPHeader* router_icmp_hdr = (ICMPHeader*)(router_ip_hdr + 1);
	IPHeader* orig_ip_hdr = (IPHeader*)(router_icmp_hdr + 1);
	ICMPHeader* orig_icmp_hdr = (ICMPHeader*)(orig_ip_hdr + 1);


	HANDLE handle = new HANDLE;
	WSAEVENT ICMPRecv = CreateEvent(NULL, false, false, NULL);
	handle = ICMPRecv;

	//receive
	ret=WSAEventSelect(sock, ICMPRecv, FD_READ);
	if (ret == SOCKET_ERROR) {
		printf("WSAEventSelect failed with error %d\n", WSAGetLastError());
		return -1;
	}
	int timeout;
	while (!sentPings.empty())
	{
		timeout = sentPings.at(0).timeout - timeGetTime();
		if (timeout < 0)
			timeout = 0;

		//wait for timeout	
		ret = WaitForSingleObject(handle, timeout);
  
		if(ret==0)
		{
			if ((ret = recvfrom(sock, (char*)rec_buf, MAX_REPLY_SIZE, 0, NULL, NULL)) < 0)
			{
				printf("recv failed with error %d\n", WSAGetLastError());
				WSACleanup();
				return -1;
			}
			// check if process ID matches
			if (orig_icmp_hdr->id == GetCurrentProcessId())
			{
				// check if this is TTL_expired or is an echo reply
				if ((router_icmp_hdr->type == ICMP_TTL_EXPIRE || router_icmp_hdr->type == ICMP_ECHO_REPLY)
					&& router_icmp_hdr->code == 0)
				{
					if (ret == 28 && router_icmp_hdr->type == ICMP_ECHO_REPLY)
					{
						int rec_ttl = router_icmp_hdr->seq;
						//erase from sent pings
						for (int i = 0; i < sentPings.size(); i++)
						{
							if (sentPings.at(i).ttl == rec_ttl)
							{
								//time received
								sentPings.at(i).rtt = timeGetTime() - sentPings.at(i).time_sent;
								//host
								sentPings.at(i).host = true;
								//save IP
								//get received IP
								long ip;
								sockaddr_in service;
								ip = router_ip_hdr->source_ip;
								service.sin_addr.s_addr = ip;
								char* ip_string = inet_ntoa(service.sin_addr);
								sentPings.at(i).routerIP = ip_string;
								//pop out of sent pings and into completed pings
								completedPings.push_back(sentPings.at(i));
								sentPings.erase(sentPings.begin() + i);
							}
						}

					}
					else
					{
						int rec_ttl = orig_icmp_hdr->seq;
						//erase from sent pings
						for (int i = 0; i < sentPings.size(); i++)
						{
							if (sentPings.at(i).ttl == rec_ttl)
							{
								//time received
								sentPings.at(i).rtt = timeGetTime() - sentPings.at(i).time_sent;
								//save IP
								//get received IP
								long ip;
								sockaddr_in service;
								ip = router_ip_hdr->source_ip;
								service.sin_addr.s_addr = ip;
								char* ip_string = inet_ntoa(service.sin_addr);
								sentPings.at(i).routerIP = ip_string;

								//pop out of sent pings and into completed pings
								completedPings.push_back(sentPings[i]);
								sentPings.erase(sentPings.begin() + i);

								/*
								cout << "Created thread for " << completedPings[completedPings.size() - 1].hop << endl;
								//start thread to look up DNS record
								HANDLE  thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dnsThread, &completedPings[completedPings.size() - 1], 0, NULL);
								DNSHandles.push_back(thread);
								*/
							}
						}
					}

				}
			}
		}
		else
		{
			if (sentPings.at(0).count == 3)
			{
				//pop out of sent pings and into completed pings
				completedPings.push_back(sentPings.at(0));
				sentPings.erase(sentPings.begin());
			}
			else {
				//we timed out
				int timedoutTTL = sentPings.at(0).ttl;
				Pings* previous = NULL;
				Pings* next = NULL;
				for (int i = 0; i < completedPings.size(); i++)
				{
					if (completedPings.at(i).ttl == (timedoutTTL - 1))
					{
						previous = &completedPings.at(i);
					}
					else if (completedPings.at(i).ttl == (timedoutTTL + 1))
					{
						next = &completedPings.at(i);
					}
				}
				if (previous != NULL && next != NULL) //we have previous RTT and next RTT
				{
					sentPings.at(0).timeout = 2 * ((int)(previous->rtt) + (int)(next->rtt) / 2.0);
				}
				else if (previous != NULL) //we have previous RTT so double that
				{
					sentPings.at(0).timeout = 2 * ((int)(previous->rtt));
				}
				else if (next != NULL) //we have next RTT so 150% that
					sentPings.at(0).timeout = (int)(next->rtt) * 1.5;
				else
					sentPings.at(0).timeout = DEFAULT_TIMEOUT;


				//send packet
				int ttl = timedoutTTL;
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
				ret = sendto(sock, (char*)send_buf, packet_size, 0, (SOCKADDR*)& server, sizeof(server));
				if (ret == SOCKET_ERROR) {
					printf("send function failed with error %d\n", WSAGetLastError());
				}

				//add current hop to sentPings
				sentPings.at(0).count++;
				sentPings.push_back(sentPings.at(0));
				sentPings.erase(sentPings.begin());
			}
		}	
	}
	
	
	vector<HANDLE> DNSHandles;

	for (int i = 0; i < completedPings.size(); i++)
	{
		bool foundHost = false;
		for (int j = 0; j < completedPings.size(); j++)
		{
			if (completedPings.at(j).ttl == i + 1)
			{
				//DNS threasd
				HANDLE handle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dnsThread, &completedPings[j], 0, NULL);
				DNSHandles.push_back(handle);
				
				if (completedPings.at(j).host)
					foundHost = true;
			}
		}
		if (foundHost)
			break;
	}

	for (int i = 0; i < DNSHandles.size(); i++)
	{
		WaitForSingleObject(DNSHandles[i], 500);
		CloseHandle(DNSHandles[i]);
	}
	int end_time = timeGetTime() - run_time;
	printf("Tracerouting to %s aka %s... \n", inet_ntoa(server.sin_addr), argv[1]);
	for (int i = 0; i < completedPings.size(); i++)
	{
		bool foundHost = false;
		for (int j = 0; j < completedPings.size(); j++)
		{
			if (completedPings.at(j).ttl == i + 1)
			{
				if (completedPings.at(j).rtt == -1)
				{
					cout << completedPings[j].hop << " *" << endl;
					break;
				}
				cout <<completedPings.at(j).hop;
				cout << " " << completedPings[j].routerName;
				cout << " (" << completedPings.at(j).routerIP<<") ";
				cout <<(double)(completedPings.at(j).rtt /1000.0) << " ms ";
				cout << "(" << completedPings.at(j).count << ")" << endl;
				if (completedPings.at(j).host)
					foundHost = true;
			}
		}
		if (foundHost)
			break;
	}

	
	cout << "\nExecution time: " << end_time << "ms" << endl;

	closesocket(sock);
	WSACleanup();
	return 0;
}