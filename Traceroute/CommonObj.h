#pragma once
#include "common.h"

#define SEND_ICMP_SENDTO_SOCKERROR -5
#define SEND_ICMP_SENDTO_ALL_FINE 5
#define IP_HDR_SIZE 20 /* RFC 791 */
#define ICMP_HDR_SIZE 8 /* RFC 792 */

/* max payload size of an ICMP message originated in the program */
#define MAX_SIZE 65200

/* max size of an IP datagram */
#define MAX_ICMP_SIZE (MAX_SIZE + ICMP_HDR_SIZE)

/* the returned ICMP message will most likely include only 8 bytes
* of the original message plus the IP header (as per RFC 792); however,
* longer replies (e.g., 68 bytes) are possible */
#define MAX_REPLY_SIZE (IP_HDR_SIZE + ICMP_HDR_SIZE + MAX_ICMP_SIZE)

/* ICMP packet types */
#define ICMP_ECHO_REPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_TTL_EXPIRED 11
#define ICMP_ECHO_REQUEST 8 

#define DEFAULT_TIMEOUT_DUR 500 //500 ms
#define MAX_HOP 30

#define EXTRA_BUFFER_TIMEOUT 10
#define MINIMUM_BUFFER_TIMEOUT 30
#define ALPHA 0.25

map <int, int> MAP_AVG_HOP_RTT =
{
	std::pair <int, int>(1, 1),
	std::pair <int, int>(2, 1),
	std::pair <int, int>(3, 1),
	std::pair <int, int>(4, 1),
	std::pair <int, int>(5, 1),
	std::pair <int, int>(6, 1),
	std::pair <int, int>(7, 2),
	std::pair <int, int>(8, 2),
	std::pair <int, int>(9, 3),
	std::pair <int, int>(10, 3),
	std::pair <int, int>(11, 4),
	std::pair <int, int>(12, 4),
	std::pair <int, int>(13, 5),
	std::pair <int, int>(14, 5),
	std::pair <int, int>(15, 5),
	std::pair <int, int>(16, 6),
	std::pair <int, int>(17, 8),
	std::pair <int, int>(18, 8),
	std::pair <int, int>(19, 9),
	std::pair <int, int>(20, 26),
	std::pair <int, int>(21, 26),
	std::pair <int, int>(22, 26),
	std::pair <int, int>(23, 60),
	std::pair <int, int>(24, 60),
	std::pair <int, int>(25, 100),
	std::pair <int, int>(26, 100),
	std::pair <int, int>(27, 120),
	std::pair <int, int>(28, 120),
	std::pair <int, int>(29, 150),
	std::pair <int, int>(30, 150),
};

/* remember the current packing state */
#pragma pack (push)
#pragma pack (1) 

/* define the IP header (20 bytes) */
class IPHeader {
public:
	u_char h_len : 4; /* lower 4 bits: length of the header in dwords */
	u_char version : 4; /* upper 4 bits: version of IP, i.e., 4 */
	u_char tos; /* type of service (TOS), ignore */
	u_short len; /* length of packet */
	u_short ident; /* unique identifier */
	u_short flags; /* flags together with fragment offset - 16 bits */
	u_char ttl; /* time to live */
	u_char proto; /* protocol number (6=TCP, 17=UDP, etc.) */
	u_short checksum; /* IP header checksum */
	u_long source_ip;
	u_long dest_ip;
};

/* define the ICMP header (8 bytes) */
class ICMPHeader {
public:
	u_char type; /* ICMP packet type */
	u_char code; /* type subcode */
	u_short checksum; /* checksum of the ICMP */
	u_short id; /* application-specific ID */
	u_short seq; /* application-specific sequence */
};

/* now restore the previous packing state */
#pragma pack (pop) 


class ICMPResponseModel {
public:
	DWORD IP;
	bool isLast; //true for success and false for nothing or failure
	int attemptCount;
	LARGE_INTEGER startTime;
	double RTT;
	DWORD packetSendTime;
	//DWORD RTT;
	bool gotResponse;
	bool isEcho;
	string char_ip, hostname;
};

/*
Object for each TTL router
*/
class HeapHopObj {
public:
	int ttl;
	long timeout;
	HeapHopObj(int i, long time_out) { ttl = i; timeout = time_out; }
};

class TimeoutComparator
{
public:
	bool operator()(const HeapHopObj& obj1, const HeapHopObj& obj2)
	{
		return obj1.timeout > obj2.timeout;
	}
};
