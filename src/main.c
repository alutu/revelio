#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>
#include <math.h>
#include <assert.h>
#include <signal.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <time.h>

#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/miniwget.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnperrors.h>


#include "tests.h"

char *stunserver = STUN_SERVER;
int stunport = STUN_PORT;
int debug = 0;
int icmp_packet_to_read = NO_ICMP_PACKET_TO_READ;
struct timeval timeout = { TIMEOUT, 0 };

/*--------------------------------------------------------------------
 * -------------------- UPnP get external IP -------------------------
 -------------------------------------------------------------------*/

static void DisplayIP(struct UPNPUrls * urls, struct IGDdatas * data) {
	char externalIPAddress[40];
	int r;

	r = UPNP_GetExternalIPAddress(urls->controlURL, data->first.servicetype,
			externalIPAddress);
	if (r != UPNPCOMMAND_SUCCESS) {
		if (debug)
			fprintf(stderr, "GetExternalIPAddress failed. (errorcode=%d);", r);
		fprintf(stdout, "noIGD;");
	} else {
		if (debug) {
			fprintf(stderr, "UPnP EXTERNAL IP: %s\n", externalIPAddress);
		}
		fprintf(stdout, "upnp %s;", externalIPAddress);
	}
}

/*-------------------------------------------------------------------------------
 * -------------------------STUN client to get the MAPPED ADDRESS----------------
 ------------------------------------------------------------------------------*/

/* helper function to print message names */
static const char *stun_msg2str(int msg) {
	switch (msg) {
	case STUN_BINDREQ:
		return "Binding Request";
	case STUN_BINDRESP:
		return "Binding Response";
	case STUN_BINDERR:
		return "Binding Error Response";
	case STUN_SECREQ:
		return "Shared Secret Request";
	case STUN_SECRESP:
		return "Shared Secret Response";
	case STUN_SECERR:
		return "Shared Secret Error Response";
	}
	return "Non-RFC3489 Message";
}

/* wrapper to send a STUN message*/
static int stun_send(int s, struct sockaddr_in *dst, struct stun_header *resp) 
//must modify this to send all the message
{
	return sendto(s, resp, ntohs(resp->msglen) + sizeof(*resp), 0,
			(struct sockaddr *) dst, sizeof(*dst));
}

/* helper function to generate a random request id */
static void stun_req_id(struct stun_header *req) {
	int x;
	srandom(time(0));
	for (x = 0; x < 4; x++)
		req->id.id[x] = random();
}

/* callback type to be invoked on stun responses. */
typedef int (stun_cb_f)(struct stun_attr *attr, void *arg);

/* handle an incoming STUN message.
 *  int type, code;
 * Do some basic sanity checks on packet size and content,
 * try to extract a bit of information, and possibly reply.
 * At the moment this only processes BIND requests, and returns
 * the externally visible address of the request.
 * If a callback is specified, invoke it with the attribute.
 *
 * check for the Message type of the STUN packet as well
 */
static int stun_handle_packet(int s, struct sockaddr_in *src,
		unsigned char *data, size_t len, stun_cb_f *stun_cb, void *arg) {

	struct stun_header *hdr = (struct stun_header *) data;
	struct stun_attr *attr;
	//unsigned short stun_type;
	int ret = STUN_IGNORE;
	int x;

	/* On entry, 'len' is the length of the udp payload. After the
	 * initial checks it becomes the size of unprocessed options,
	 * while 'data' is advanced accordingly.
	 */
	if (len < sizeof(struct stun_header)) {
		if (debug)
			fprintf(stderr, "Runt STUN packet (only %d, wanting at least %d);",
					(int) len, (int) sizeof(struct stun_header));
		return -1;
	}
	len -= sizeof(struct stun_header);
	data += sizeof(struct stun_header);
	x = ntohs(hdr->msglen); /* len as advertised in the message */

	if (debug) {
		fprintf(stderr, " Received STUN %s (%04x) ;",
				stun_msg2str(ntohs(hdr->msgtype)), ntohs(hdr->msgtype));
	}
	if (x > len) {
		if (debug) {
			fprintf(stderr,
					"Scrambled STUN packet length (got %d, expecting %d);", x,
					(int) len);
		}
	} else {
		len = x;
	}
	while (len) {
		if (len < sizeof(struct stun_attr)) {
			if (debug) {
				fprintf(stderr, "Runt Attribute (got %d, expecting %d);",
						(int) len, (int) sizeof(struct stun_attr));
			}
			break;
		}
		attr = (struct stun_attr *) data;
		/* compute total attribute length */
		x = ntohs(attr->len) + sizeof(struct stun_attr);
		if (x > len) {
			if (debug)
				fprintf(stderr,
						"Inconsistent Attribute (length %d exceeds remaining msg len %d);",
						x, (int) len);
			break;
		}
		if (stun_cb)
			stun_cb(attr, arg);

		/* Clear attribute id: in case previous entry was a string,
		 * this will act as the terminator for the string.
		 */
		attr->attr = 0;
		data += x;

		len -= x;
	}
	/* Null terminate any string.
	 * NOTE, we write past the size of the buffer passed by the
	 * caller, so this is potentially dangerous. The only thing that
	 * saves us is that usually we read the incoming message in a
	 * much larger buffer
	 */
	*data = '\0';
	return ret;
}

//should add something like stun_get_type -- request/response -- if request -- get the source

/* Extract the STUN_MAPPED_ADDRESS from the stun response.
 * This is used as a callback for stun_handle_response
 * when called from stun_request.
 */
static int stun_get_mapped(struct stun_attr *attr, void *arg) {
	struct stun_addr *addr = (struct stun_addr *) (attr + 1);
	struct sockaddr_in *sa = (struct sockaddr_in *) arg;

	if (ntohs(attr->attr) != STUN_MAPPED_ADDRESS || ntohs(attr->len) != 8) {
		return 1;
	}
	sa->sin_port = addr->port;
	sa->sin_addr.s_addr = addr->addr;
	return 0;
}

/* Generic STUN request
 * return 0 on success, other values on error.
 */
int stun_request(int s, struct sockaddr_in *dst, struct sockaddr_in *answer) {

	struct stun_header *req; //this is all we're sending
	unsigned char reqdata[1024] = { 0 };
	int reqlen;
	int res = 0;

	req = (struct stun_header *) (reqdata);
	stun_req_id(req);
	reqlen = 0;
	req->msgtype = 0;
	req->msglen = 0;
	req->msglen = htons(reqlen);
	req->msgtype = htons(STUN_BINDREQ);
	unsigned char reply_buf[1024];

	struct timeval to = { TIMEOUT, 0 };
	struct sockaddr_in src;
	socklen_t srclen;

	res = stun_send(s, dst, req); //SEND the STUN Binding Request to the STUN server

	if (res < 0) {
		if (debug)
			fprintf(stderr, "STUN Bind failed: %d;", res);
		return -1;
	}
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(s, &rfds);
	res = select(s + 1, &rfds, NULL, NULL, &to);
	if (res <= 0) { /* timeout or error */
		if (debug)
			fprintf(stderr, "STUN Request Response timeout, failed error %d;",
					res); //no response came
		return -1;
	}
	bzero(&src, sizeof(src));
	srclen = sizeof(src);
	/* pass -1 in the size, because stun_handle_packet might
	 * write past the end of the buffer.
	 */
	res = recvfrom(s, reply_buf, sizeof(reply_buf) - 1, 0,
			(struct sockaddr *) &src, &srclen);
	if (res <= 0) {
		if (debug)
			fprintf(stderr, "Response read failed error %d;", res);
		return -1;
	}

	bzero(answer, sizeof(struct sockaddr_in));

	stun_handle_packet(s, &src, reply_buf, res, stun_get_mapped, answer);
	return 0;
}

char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen) {
	switch (sa->sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &(((struct sockaddr_in *) sa)->sin_addr), s, maxlen);
		break;

	case AF_INET6:
		inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) sa)->sin6_addr), s,
				maxlen);
		break;

	default:
		strncpy(s, "Unknown AF", maxlen);
		return NULL;
	}

	return s;
}

/*------------------------------------------------------------------------------------------
 * ---------------------------MAIN----------------------------------------------------------
 -----------------------------------------------------------------------------------------*/

int main(int argc, char ** argv) {
	char oldTests[4096];
	char tests[4096];
	setvbuf(stdout, tests, _IOFBF, 4096);
	//test description
	fprintf(stdout, "%s-%s;", PACKAGE, VERSION);

	// add unix timestamp
	fprintf(stdout, "%d;", (int) time(NULL));

	//check for the "debug" parameter
	int opt;
	for (opt = 1; opt < argc; opt++) {
		if (argv[opt][0] == '-') {
			if (argv[opt][1] == 'd') {
				debug = 1;
			}
		}
	}
	/*--------------------------------------------------------------------------------------------------
	 * ---------------------------------------Local IP address-------------------------------------------------
	 --------------------------------------------------------------------------------------------------*/

	char buff[1024] = { 0 };
	struct ifconf ifc = { 0 };
	struct ifreq *ifr = NULL;
	int sck = 0;
	int nInterfaces = 0;
	int i = 0;

	sck = socket(AF_INET, SOCK_DGRAM, 0);
	if (sck < 0) {
		if (debug) {
			fprintf(stderr, "Error creating socket");
		}
		return -1;
	}

	/* Query available interfaces. */
	ifc.ifc_len = sizeof(buff);
	ifc.ifc_buf = buff;
	if (ioctl(sck, SIOCGIFCONF, &ifc) < 0) {
		if (debug)
			fprintf(stderr, "ioctl(SIOCGIFCONF)");
		return -1;
	}

	/* Iterate through the list of interfaces. */
	ifr = ifc.ifc_req;
	nInterfaces = ifc.ifc_len / sizeof(struct ifreq);
	for (i = 0; i < nInterfaces; i++) {
		struct ifreq *item = &ifr[i];
		/* Show the device name and IP address */
		struct sockaddr *addr = &(item->ifr_addr);
		char ip[INET6_ADDRSTRLEN];
		fprintf(stdout, "%s:%s,", item->ifr_name,
				get_ip_str(addr, ip, INET6_ADDRSTRLEN));
	}
	fprintf(stdout, ";");

	/*--------------------------------------------------------------------------------------------------
	 * ---------------------------------------UPnP detection-------------------------------------------------
	 --------------------------------------------------------------------------------------------------*/
//libminiupnpc needed!!!
	struct UPNPDev * devlist = 0;
	char lanaddr[64]; /* my ip address on the LAN */
	const char * rootdescurl = 0;
	const char * multicastif = 0;
	const char * minissdpdpath = 0;
	int error = 0;
	int ipv6 = 0;
	if (rootdescurl
			|| (devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0,
					ipv6, &error))) {
		struct UPNPUrls urls;
		struct IGDdatas data;

		if (!devlist) {
			if (debug)
				fprintf(stderr, "upnpDiscover()error_code=%d;", error);
		}

		i = 1;
		if ((rootdescurl
				&& UPNP_GetIGDFromUrl(rootdescurl, &urls, &data, lanaddr,
						sizeof(lanaddr)))
				|| (i = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr,
						sizeof(lanaddr)))) {
			DisplayIP(&urls, &data);//prints upnp data
			FreeUPNPUrls(&urls);
		} else {
			fprintf(stdout, "noIGD;");//otherwise noIGD device remark is printed
		}
		freeUPNPDevlist(devlist);
		devlist = 0;
	} else {
		fprintf(stdout, "noIGD;");
	}
	//fflush(stdout);

	/*--------------------------------------------------------------------------------------------------
	 * ---------------------------------------STUN mapped address-------------------------------------------------
	 --------------------------------------------------------------------------------------------------*/
//ministun -- classic stun
	int sock, res, sock2, sock_raw;
	struct sockaddr_in server, client, mapped, reply_mapped, client2, server2;
	struct hostent *hostinfo;
	int numbytes;
	struct sockaddr_in their_addr;

	socklen_t addr_len;
	addr_len = sizeof their_addr;

	// STEP1: get MAPPED ADDRESS from a STUN server
	hostinfo = gethostbyname(stunserver);
	if (!hostinfo) {
		if (debug) {
			fprintf(stderr, "Error resolving host %s\n", stunserver);
		}
		return -1;
	}
	bzero(&server, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr = *(struct in_addr*) hostinfo->h_addr;
	server.sin_port = htons(stunport); //3478

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		if (debug) {
			fprintf(stderr, "Error creating socket\n");
		}
		return -1;
	}

	bzero(&client, sizeof(client));
	client.sin_family = AF_INET;
	client.sin_addr.s_addr = htonl(INADDR_ANY);
	//client.sin_port = 0;


	if (bind(sock, (struct sockaddr*) &client, sizeof(client)) < 0) {
		if (debug) {
			fprintf(stderr, "Error bind to socket for STUN request\n");
		}
		close(sock);
		return -1;
	}

	if (debug) {
		printf(stderr, "Client IP address is: %s\n", inet_ntoa(client.sin_addr));
		printf(stderr, "Client port is: %d\n", (int) ntohs(client.sin_port));
	}

	res = stun_request(sock, &server, &mapped);
	if (res >= 0) {
		if (debug) {
			fprintf(stderr, "STUN MAPPED ADDRESS: %s:%i;\n",
					inet_ntoa(mapped.sin_addr), ntohs(mapped.sin_port));
		}
		fprintf(stdout, "stun %s:%i;", inet_ntoa(mapped.sin_addr),
				ntohs(mapped.sin_port));
	} else {
		fprintf(stdout, "\n");//exit from here
		exit(0);
	}

	/* --------------------------------------------------------------------------------------------------
	 * ---------------------------------------HAIRPIN TEST-----------------------------------------------
	 * -------------------------------------------------------------------------------------------------*/

	//Send a STUN Binding Request to the MAPPED ADDRESS using a different socket <sockfd>
	//to do: use libpcap
	bzero(&server2, sizeof(listen));
	server2.sin_family = AF_INET;
	server2.sin_addr.s_addr = mapped.sin_addr.s_addr;
	server2.sin_port = mapped.sin_port;

	sock2 = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock2 < 0) {
		if (debug) {
			fprintf(stderr, "Error creating socket\n");
		}
		return -1;
	}
	bzero(&client2, sizeof(listen));
	client2.sin_family = AF_INET;
	client2.sin_addr.s_addr = htonl(INADDR_ANY);
	//client2.sin_port = 0;

	//socket used to send a STUN BR to the mapped address
	if (bind(sock2, (struct sockaddr*) &client2, sizeof(client2)) < 0) { //open sockfd for a random port to send a new request
		if (debug) {
			fprintf(stderr, "Error bind to socket\n");
		}
		close(sock2);
		return -1;
	}

	fd_set rfds;
	struct timeval to = { TIMEOUT, 0 };
	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);

	sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_UDP); //listen for incoming STUN BIND REQUESTS
	// error with IPPROTO_UDP --> change to 0
	if (sock_raw < 0) {
		if (debug) {
			fprintf(stderr, "Error creating socket hairpin test\n");
		}
		return -1;
	}

	if (bind(sock_raw, (struct sockaddr*) &client, sizeof(client)) < 0) { //open sock for client -- 34780
		if (debug) {
			fprintf(stderr, "Error bind to socket hairpin test\n");
		}
		close(sock);
		return -1;
	}
	res = stun_request(sock2, &server, &reply_mapped);
	res = stun_request(sock2, &mapped, &reply_mapped); // replaced server2 with mapped

	res = select(sock + 1, &rfds, NULL, NULL, &to);
	unsigned char *buf = (unsigned char *) malloc(MAXBUFLEN);
	//if no events are detected on the socket "sock", then close the raw socket
	if (res <= 0) {
		fprintf(stdout, "no hairpin;");//something feeds line break at this place
		close(sock_raw);
	} else {
		if (debug) {
			fprintf(stderr, "will hairpin:");
		}
		int loopback = 0;
		while (loopback == 0) {
			if ((numbytes = recvfrom(sock_raw, buf, MAXBUFLEN - 1, 0,
					(struct sockaddr *) &their_addr, &addr_len)) < 0) {
				if (debug) {
					fprintf(stderr, "Error for recvfrom");
				}
			}
			struct stun_header *hdr = (struct stun_header *) (buf
					+ sizeof(struct udphdr) + sizeof(struct iphdr));
			if (ntohs(hdr->msgtype) == STUN_BINDREQ) {
				loopback = 1;
				//fprintf(stdout, "%s(%04x)-", stun_msg2str(ntohs(hdr->msgtype)),
				//		ntohs(hdr->msgtype));
				struct iphdr *iph = (struct iphdr*) (buf);
				fprintf(stdout, "TTL:%d;", (unsigned int) iph->ttl);
				if (debug) {
					fprintf(stderr, "  |-STUN %s (%04x) \n",
							stun_msg2str(ntohs(hdr->msgtype)),
							ntohs(hdr->msgtype));
					fprintf(stderr, "   |-TTL      : %d\n",
							(unsigned int) iph->ttl);
					fprintf(stderr, "   |-Protocol : %d\n",
							(unsigned int) iph->protocol);
					fprintf(stderr,
							"   |-IP Header Length  : %d DWORDS or %d Bytes\n",
							(unsigned int) iph->ihl,
							((unsigned int) (iph->ihl)) * 4);
				}

			}
		}
		free(buf);
	}
	/*
	close(sock2);
	close(sock);
	close(res);
	close(sock_raw);
    */
	strncpy(oldTests, tests, 4096);
//because both arrays were empty initially the line is broken by one of the zeros inserted during initialization.

	/*-------------------------------------------------------------------------------------------------------------------------
	 * TRACEROUTE
	 ------------------------------------------------------------------------------------------------------------------------*/
// traceroute to mapped address
	int iter = 0;
	int packet_len = 100;
	char trace[512];
	char path[1035];
	memset(trace, '\0', sizeof(512));
	FILE * f;
	char * split;
	//fflush(stdout);
	fprintf(stdout, "%d;", packet_len);
	//fprintf(stdout, "%s", oldTests);
	sprintf(trace, "traceroute -n -q 1 -m 16 %s %d", inet_ntoa(mapped.sin_addr),
			packet_len);
	f = popen(trace, "r");
	if (f == NULL) {
		fprintf(stdout, ";\n");
		fprintf(stderr, "Failed to run traceroute command\n");
		exit(0);
	}
	/* Read the output a line at a time - output it. */
	while (fgets(path, sizeof(path) - 1, f) != NULL) {
		split = strtok(path, "\n");
		fprintf(stdout, "%s|", split);
	}
	fprintf(stdout, ";\n");

	/* close */
	pclose(f);

	fflush(stdout);


	// pathchar to GRA

	while (iter < 21) {
		packet_len = 120 + 64 * iter;
		iter++;
		fprintf(stdout, "%s", oldTests);
		fprintf(stdout, "%d;", packet_len);
		//4.69.158.197 samknows1.lon1.level3.net
		sprintf(trace, "traceroute -n -q 1 -m 16 %s %d", inet_ntoa(mapped.sin_addr), packet_len);
		f = popen(trace, "r");
		if (f == NULL) {
			fprintf(stdout, ";\n");
			fprintf(stderr, "Failed to run traceroute command\n");
			exit(0);
		}

		/* Read the output a line at a time - output it. */
		while (fgets(path, sizeof(path) - 1, f) != NULL) {
			split = strtok(path, "\n");
			fprintf(stdout, "%s|", split);
		}
		fprintf(stdout, ";\n");
		fflush(stdout);
	}


	// traceroute to fixed address -- pathchar
    iter = 0;
	while (iter < 21) {
		packet_len = 120 + 64 * iter;
		iter++;
		fprintf(stdout, "%s", oldTests);
		fprintf(stdout, "%d;", packet_len);
		//4.69.158.197 samknows1.lon1.level3.net
		sprintf(trace, "traceroute -n -q 1 -m 16 4.69.202.89 %d", packet_len);
		f = popen(trace, "r");
		if (f == NULL) {
			fprintf(stdout, ";\n");
			fprintf(stderr, "Failed to run traceroute command\n");
			exit(0);
		}

		/* Read the output a line at a time - output it. */
		while (fgets(path, sizeof(path) - 1, f) != NULL) {
			split = strtok(path, "\n");
			fprintf(stdout, "%s|", split);
		}
		fprintf(stdout, ";\n");
		fflush(stdout);
	}

	return 1;
}
