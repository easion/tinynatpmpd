/*
 *   TinyNATPMPd: simple nat-pmp daemon for openwrt
 *
 *   Copyright 2015 Fu Hai Technology Co., Ltd
 *     Author: easion,<easion@gmail.com>
 *     Website: http://www.envcat.com/
 */

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/ioctl.h>

#include "natpmp.h"

#define NATPMP_MAX_VERSION	0
#define NATPMP_MAX_RETRIES	10
#define NATPMP_MAX_DELETES	3
#define NATPMP_WORK_PORT	5351
#define NATPMP_NOTIFI_PORT	5350
#define NATPMP_MAX_PACKET_SIZE	16
#define NATPMP_NOTIF_ADDR	("224.0.0.1")

#define NATPMP_COMMAND_PROBE	0

void	 natpmp_recv_client_msg(int, short, void *);
void	 route_recvmsg(int, short, void *);
void	 natpmp_probe(int, short, void *);
int	 default_gateway(in_addr_t *);

int		 mcast_fd;
int		 ctrl_fd;
in_addr_t	 gateway;
int		 probe_count;
struct event	 probe_ev;


typedef enum {
	NATPMP_UNKNOWN = 0,
	NATPMP_DISABLED,
	NATPMP_ENABLED,
} natpmp_status_t;

//natpmp_status_t status = NATPMP_UNKNOWN;

#define INLINE static inline

INLINE uint32_t readnu32(const uint8_t * p)
{
	return (p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]);
}
#define READNU32(p) readnu32(p)
INLINE uint16_t readnu16(const uint8_t * p)
{
	return (p[0] << 8 | p[1]);
}
#define READNU16(p) readnu16(p)
INLINE void writenu32(uint8_t * p, uint32_t n)
{
	p[0] = (n & 0xff000000) >> 24;
	p[1] = (n & 0xff0000) >> 16;
	p[2] = (n & 0xff00) >> 8;
	p[3] = n & 0xff;
}
#define WRITENU32(p, n) writenu32(p, n)
INLINE void writenu16(uint8_t * p, uint16_t n)
{
	p[0] = (n & 0xff00) >> 8;
	p[1] = n & 0xff;
}
#define WRITENU16(p, n) writenu16(p, n)


ssize_t
sendto_or_schedule(int sockfd, const void *buf, size_t len, int flags,
                   const struct sockaddr *dest_addr, socklen_t addrlen)
{
	return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

static void FillPublicAddressResponse(unsigned char * resp, in_addr_t senderaddr)
{
	char tmp[16];
	
	if(!ext_if_name || ext_if_name[0]=='\0') {
		resp[3] = 3;	/* Network Failure (e.g. NAT box itself
						 * has not obtained a DHCP lease) */
	} else if(getifaddr(ext_if_name, tmp, INET_ADDRSTRLEN, NULL, NULL) < 0) {
		LOG_ERROR( "Failed to get IP for interface %s", ext_if_name);
		resp[3] = 3;	/* Network Failure (e.g. NAT box itself
						 * has not obtained a DHCP lease) */
	} else {
		inet_pton(AF_INET, tmp, resp+8); /* ok */
	}

}

static void process_incoming_packet(int s, unsigned char *msg_buff, int len,
		struct sockaddr_in *senderaddr)
{
	unsigned char *req=msg_buff;	/* request udp packet */
	unsigned char resp[32];	/* response udp packet */
	int resplen;
	int n = len;
	char senderaddrstr[16];

	update_boot_time();

	if(!inet_ntop(AF_INET, &senderaddr->sin_addr,
			senderaddrstr, sizeof(senderaddrstr))) {
		LOG_ERROR( "inet_ntop(natpmp): %m");
	}

	LOG_INFO( "NAT-PMP request received from %s:%hu %dbytes",
	       senderaddrstr, ntohs(senderaddr->sin_port), n);

	if(n<2 || ((((req[1]-1)&~1)==0) && n<12)) {
		LOG_ERROR( "discarding NAT-PMP request (too short) %dBytes",
		       n);
		return;
	}
	if(req[1] & 128) {
		/* discarding NAT-PMP responses silently */
		return;
	}
	memset(resp, 0, sizeof(resp));
	resplen = 8;
	resp[1] = 128 + req[1];	/* response OPCODE is request OPCODE + 128 */
	/* setting response TIME STAMP :
	 * time elapsed since its port mapping table was initialized on
	 * startup or reset for any other reason */
	WRITENU32(resp+4, time(NULL) - startup_time);
	if(req[0] > 0) {
		/* invalid version */
		LOG_ERROR( "unsupported NAT-PMP version : %u",
		       (unsigned)req[0]);
		resp[3] = 1;	/* unsupported version */
	} else switch(req[1]) {
	case 0:	/* Public address request */
		LOG_INFO( "NAT-PMP public address request");
		FillPublicAddressResponse(resp, senderaddr->sin_addr.s_addr);
		resplen = 12;
		break;
	case 1:	/* UDP port mapping request */
	case 2:	/* TCP port mapping request */
		{
			unsigned short iport;	/* private port */
			unsigned short eport;	/* public port */
			uint32_t lifetime; 		/* lifetime=0 => remove port mapping */
			int r;
			int proto;
			char iaddr_old[16];
			unsigned short iport_old;
			unsigned int timestamp;

			iport = READNU16(req+4);
			eport = READNU16(req+6);
			lifetime = READNU32(req+8);
			proto = (req[1]==1)?IPPROTO_UDP:IPPROTO_TCP;
			LOG_INFO( "NAT-PMP port mapping request : "
			                 "%hu->%s:%hu %s lifetime=%us",
			                 eport, senderaddrstr, iport,
			                 (req[1]==1)?"udp":"tcp", lifetime);
			
			if(lifetime == 0) {
				LOG_INFO( " REMOVE MAPPING\n");
				int index = 0;
				unsigned short eport2, iport2;
				char iaddr2[16];
				int proto2;
				char desc[64];
				eport = 0; /* to indicate correct removing of port mapping */
				#if 0
				while(get_redirect_rule_by_index(index, 0,
				          &eport2, iaddr2, sizeof(iaddr2),
						  &iport2, &proto2,
						  desc, sizeof(desc),
				          0, 0, &timestamp, 0, 0) >= 0) {
					LOG_DBG( "%d %d %hu->'%s':%hu '%s'",
					       index, proto2, eport2, iaddr2, iport2, desc);
					if(0 == strcmp(iaddr2, senderaddrstr)
					  && 0 == memcmp(desc, "NAT-PMP", 7)) {
						/* (iport == 0) => remove all the mappings for this client */
						if((iport == 0) || ((iport == iport2) && (proto == proto2))) {
							r = _fw_delete_redir(eport2, proto2);
							if(r < 0) {
								LOG_ERROR( "Failed to remove NAT-PMP mapping eport %hu, protocol %s",
								       eport2, (proto2==IPPROTO_TCP)?"TCP":"UDP");
								resp[3] = 2;	/* Not Authorized/Refused */
								break;
							} else {
								LOG_INFO( "NAT-PMP %s port %hu mapping removed",
								       proto2==IPPROTO_TCP?"TCP":"UDP", eport2);
								index--;
							}
						}
					}
					
					index++;
				}
				#endif
			} else if(iport==0) {
				resp[3] = 2;	/* Not Authorized/Refused */
			} else { /* iport > 0 && lifetime > 0 */
				unsigned short eport_first = 0;
				int any_eport_allowed = 0;
				char desc[64];
				if(eport==0)	/* if no suggested external port, use same a internal port */
					eport = iport;
				while(resp[3] == 0) {
					if(eport_first == 0) { /* first time in loop */
						eport_first = eport;
					} else if(eport == eport_first) { /* no eport available */
						if(any_eport_allowed == 0) { /* all eports rejected by permissions */
							LOG_ERROR( "No allowed eport for NAT-PMP %hu %s->%s:%hu",
							       eport, (proto==IPPROTO_TCP)?"tcp":"udp", senderaddrstr, iport);
							resp[3] = 2;	/* Not Authorized/Refused */
						} else { /* at least one eport allowed (but none available) */
							LOG_ERROR( "Failed to find available eport for NAT-PMP %hu %s->%s:%hu",
							       eport, (proto==IPPROTO_TCP)?"tcp":"udp", senderaddrstr, iport);
							resp[3] = 4;	/* Out of resources */
						}
						break;
					}
					#if 0
					if(!check_fw_rule_against_permissions(upnppermlist, num_upnpperm, eport, senderaddr->sin_addr, iport)) {
						eport++;
						if(eport == 0) eport++; /* skip port zero */
						continue;
					}
					#endif
					any_eport_allowed = 1;	/* at lease one eport is allowed */
#ifdef CHECK_PORTINUSE
					if (port_in_use(ext_if_name, eport, proto, senderaddrstr, iport) > 0) {
						LOG_INFO( "port %hu protocol %s already in use",
						       eport, (proto==IPPROTO_TCP)?"tcp":"udp");
						eport++;
						if(eport == 0) eport++; /* skip port zero */
						continue;
					}
#endif
					#if 0
					r = get_redirect_rule(ext_if_name, eport, proto,
					                      iaddr_old, sizeof(iaddr_old),
					                      &iport_old, 0, 0, 0, 0,
					                      &timestamp, 0, 0);
					if(r==0) {
						if(strcmp(senderaddrstr, iaddr_old)==0
						    && iport==iport_old) {
							/* redirection allready existing */
							LOG_INFO( "port %hu %s already redirected to %s:%hu, replacing",
							       eport, (proto==IPPROTO_TCP)?"tcp":"udp", iaddr_old, iport_old);
							/* remove and then add again */
							if(_fw_delete_redir(eport, proto) < 0) {
								LOG_ERROR( "failed to remove port mapping");
								break;
							}
						} else {
							eport++;
							if(eport == 0) eport++; /* skip port zero */
							continue;
						}
					}
					#endif
					/* do the redirection */

					timestamp = time(NULL) + lifetime;
					snprintf(desc, sizeof(desc), "NAT-PMP %hu %s",
					         eport, (proto==IPPROTO_TCP)?"tcp":"udp");

					
					/* TODO : check return code */
					if(fw_redirect_internal(NULL, eport, senderaddrstr,
					                          iport, proto, desc,
					                          timestamp) < 0) {
						LOG_ERROR( "Failed to add NAT-PMP %hu %s->%s:%hu '%s'",
						       eport, (proto==IPPROTO_TCP)?"tcp":"udp", senderaddrstr, iport, desc);
						resp[3] = 3;  /* Failure */
					}					
					break;
				}
			}
			WRITENU16(resp+8, iport);	/* private port */
			WRITENU16(resp+10, eport);	/* public port */
			WRITENU32(resp+12, lifetime);	/* Port Mapping lifetime */
		}
		resplen = 16;
		break;
	default:
		resp[3] = 5;	/* Unsupported OPCODE */
	}
	n = sendto_or_schedule(s, resp, resplen, 0,
	           (struct sockaddr *)senderaddr, sizeof(*senderaddr));
	if(n<0) {
		LOG_ERROR( "sendto(natpmp): %m");
	} else if(n<resplen) {
		LOG_ERROR( "sendto(natpmp): sent only %d bytes out of %d",
		       n, resplen);
	}
}

static void natpmp_recv_server_msg(evutil_socket_t s, short event, void *arg)
{
	int n;
	unsigned char msg_buff[32];
	struct sockaddr_in senderaddr;
	socklen_t senderaddrlen;
	int len;

	memset(msg_buff, 0, 32);
	senderaddrlen = sizeof(senderaddr);

	n = recvfrom(s, msg_buff, 32, 0,
	             &senderaddr, &senderaddrlen);

	if(n < 0) {		
		if(errno != EAGAIN &&
		   errno != EWOULDBLOCK &&
		   errno != EINTR) {
			LOG_ERROR( "recvfrom(natpmp): %s",strerror(errno));
		}
		else{
			LOG_INFO("PROCESS FAILED %s!!",strerror(errno));
		}
		return ;
	}
	LOG_INFO("PROCESS REQUEST %d!!",n);
	process_incoming_packet(s,msg_buff,n,&senderaddr);
}

static int pmp_server_init(struct event_base *base, in_addr_t addr)
{
	struct sockaddr_in	 sock;
	int i = 1;

	memset(&sock, 0, sizeof(sock));
	sock.sin_family = AF_INET;
	sock.sin_port = htons(NATPMP_WORK_PORT);
	sock.sin_addr.s_addr = addr;

	if ((ctrl_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		// fatal("socket");
		return (-1);
	if(setsockopt(ctrl_fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) < 0)
	{
		LOG_ERROR( "%s: setsockopt(SO_REUSEADDR): %m",
		       "OpenAndConfNATPMPSocket");
		return -1;
	}

	if (fcntl(ctrl_fd, F_SETFL, O_NONBLOCK) == -1)
		// fatal("fcntl");
		return (-1);

	if (bind(ctrl_fd, (struct sockaddr *)&sock,
		sizeof(sock)) < 0)
		// fatal("connect");
		return (-1);

	printf("UPNP SOCKET AS %d\n", ctrl_fd);
	static struct event	 ctrl_ev;
	event_set(&ctrl_ev, ctrl_fd, EV_READ|EV_PERSIST,
		natpmp_recv_server_msg, NULL);
	if (base)
		event_base_set(base, &ctrl_ev);
	event_add(&ctrl_ev, NULL);
	return 0;
}


static int mcast_init(struct event_base *base)
{
	struct sockaddr_in	 sock;
	struct ip_mreq		 mreq;
	static struct event	 mcast_ev;
	int			 reuse = 1;
	unsigned char		 loop = 0;

	/* Listening on 224.0.0.1:5350 */
	memset(&sock, 0, sizeof(sock));
	sock.sin_family = AF_INET;
	sock.sin_addr.s_addr = htonl(INADDR_ALLHOSTS_GROUP);
	sock.sin_port = htons(NATPMP_NOTIFI_PORT );

	if ((mcast_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		// fatal("socket");
		return (-1);

	if (fcntl(mcast_fd, F_SETFL, O_NONBLOCK) == -1)
		// fatal("fcntl");
		return (-1);

	/* SO_REUSEADDR and/or SO_REUSEPORT? */
	if (setsockopt(mcast_fd, SOL_SOCKET, SO_REUSEADDR,
	    &reuse, sizeof(reuse)) == -1)
		// fatal("setsockopt: SO_REUSEADDR");
		return (-1);

	if (bind(mcast_fd, (struct sockaddr *)&sock, sizeof(sock)) == -1)
		// fatalx("");
		return (-1);

	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_multiaddr = sock.sin_addr;
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);

	if (setsockopt(mcast_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
	    &mreq, sizeof(mreq)) == -1)
		// fatal("");
		return (-1);

	if (setsockopt(mcast_fd, IPPROTO_IP, IP_MULTICAST_LOOP,
	    &loop, sizeof(loop)) == -1)
		// fatal("");
		return (-1);	
	return 0;
}


int
natpmp_init(struct event_base *base)
{
	int ret;
	ret = mcast_init(base);
	//route_init(base);
	if (ret < 0)
	{
		LOG_ERROR("mcast_init failed\n");	
	}

	if (default_gateway(&gateway) == 0) {
		ret = pmp_server_init(base,lan_ip_addr.s_addr);	
		if (ret < 0)
		{
			LOG_ERROR("pmp_server_init failed\n");	
		}
	}
	return (ret);
}

void send_public_address_change_notification(int * sockets, int n_sockets)
{
	struct sockaddr_in sockname;
	unsigned char notif[12];
	int j, n;
	int mysockets[2];

	if (n_sockets == 0 || !sockets)
	{
		mysockets[0] = mcast_fd;
		mysockets[1] = ctrl_fd;
		n_sockets = 2;
		sockets = mysockets;
	}

	notif[0] = 0;	/* vers */
	notif[1] = 128;	/* OP code */
	notif[2] = 0;	/* result code */
	notif[3] = 0;	/* result code */
	
	WRITENU32(notif+4, time(NULL) - startup_time);

	FillPublicAddressResponse(notif, 0);
	if(notif[3])
	{
		LOG_ERROR( "%s: cannot get public IP address, stopping",
		       "send_public_address_change_notification");
		return;
	}

	memset(&sockname, 0, sizeof(struct sockaddr_in));
    sockname.sin_family = AF_INET;
    sockname.sin_addr.s_addr = inet_addr(NATPMP_NOTIF_ADDR);

	for(j=0; j<n_sockets; j++)
	{
		if(sockets[j] < 0)
			continue;
    	sockname.sin_port = htons(NATPMP_NOTIFI_PORT);
		n = sendto_or_schedule(sockets[j], notif, 12, 0,
		           (struct sockaddr *)&sockname, sizeof(struct sockaddr_in));
		if(n < 0)
		{
			LOG_ERROR( "%s: sendto(s_udp=%d): %m",
			       "send_public_address_change_notification", sockets[j]);
			return;
		}
    	sockname.sin_port = htons(NATPMP_WORK_PORT);
		n = sendto_or_schedule(sockets[j], notif, 12, 0,
		           (struct sockaddr *)&sockname, sizeof(struct sockaddr_in));
		if(n < 0)
		{
			LOG_ERROR( "%s: sendto(s_udp=%d): %m",
			       "send_public_address_change_notification", sockets[j]);
			return;
		}
	}
}

int default_gateway(in_addr_t * addr)
{
	unsigned long d, g;
	char buf[256];
	int line = 0;
	FILE * f;
	char * p;
	f = fopen("/proc/net/route", "r");
	if(!f)
		return -1;
	while(fgets(buf, sizeof(buf), f)) {
		if(line > 0) {	/* skip the first line */
			p = buf;
			/* skip the interface name */
			while(*p && !isspace(*p))
				p++;
			while(*p && isspace(*p))
				p++;
			if(sscanf(p, "%lx%lx", &d, &g)==2) {
				if(d == 0 && g != 0) { /* default */
					*addr = g;
					fclose(f);
					return 0;
				}
			}
		}
		line++;
	}
	/* default route not found ! */
	if(f)
		fclose(f);
	return -1;
}

int
getifaddr(const char * ifname, char * buf, int len,
          struct in_addr * addr, struct in_addr * mask)
{
	/* use ioctl SIOCGIFADDR. Works only for ip v4 */
	/* SIOCGIFADDR struct ifreq *  */
	int s;
	struct ifreq ifr;
	int ifrlen;
	struct sockaddr_in * ifaddr;
	ifrlen = sizeof(ifr);

	if(!ifname || ifname[0]=='\0')
		return -1;
	s = socket(PF_INET, SOCK_DGRAM, 0);
	if(s < 0)
	{
		LOG_ERROR( "socket(PF_INET, SOCK_DGRAM): %m");
		return -1;
	}
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if(ioctl(s, SIOCGIFFLAGS, &ifr, &ifrlen) < 0)
	{
		LOG_DBG( "ioctl(s, SIOCGIFFLAGS, ...): %m");
		close(s);
		return -1;
	}
	if ((ifr.ifr_flags & IFF_UP) == 0)
	{
		LOG_DBG( "network interface %s is down", ifname);
		close(s);
		return -1;
	}
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if(ioctl(s, SIOCGIFADDR, &ifr, &ifrlen) < 0)
	{
		LOG_ERROR( "ioctl(s, SIOCGIFADDR, ...): %m");
		close(s);
		return -1;
	}
	ifaddr = (struct sockaddr_in *)&ifr.ifr_addr;
	if(addr) *addr = ifaddr->sin_addr;
	if(buf)
	{
		if(!inet_ntop(AF_INET, &ifaddr->sin_addr, buf, len))
		{
			LOG_ERROR( "inet_ntop(): %m");
			close(s);
			return -1;
		}
	}
	if(mask)
	{
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
		if(ioctl(s, SIOCGIFNETMASK, &ifr, &ifrlen) < 0)
		{
			LOG_ERROR( "ioctl(s, SIOCGIFNETMASK, ...): %m");
			close(s);
			return -1;
		}
#ifdef ifr_netmask
		*mask = ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr;
#else
		*mask = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
#endif
	}
	close(s);

	return 0;
}

