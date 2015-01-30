/*
 *   TinyNATPMPd: simple nat-pmp daemon for openwrt
 *
 *   Copyright 2015 Fu Hai Technology Co., Ltd
 *     Author: easion,<easion@gmail.com>
 *     Website: http://www.envcat.com/
 */

#ifndef _NATPMP_H
#define _NATPMP_H
#include <event.h>


#define LOG_INFO( ...) do{ \
		printf(__VA_ARGS__); \
		printf("\n"); \
	} \
	while (0)

#define LOG_DBG LOG_INFO
#define LOG_ERROR LOG_INFO

struct natpmpd {
	u_int8_t		 sc_flags;
#define NATPMPD_F_VERBOSE	 0x01;

	const char		*sc_confpath;
	struct in_addr		 sc_address;
#if 0
	TAILQ_HEAD(listen_addrs, listen_addr)		 listen_addrs;
	u_int8_t					 listen_all;
	char		 	 sc_interface[IF_NAMESIZE];
	struct timeval		 sc_starttime;
	int			 sc_delay;
#endif
	struct event		 sc_announce_ev;
	struct event		 sc_expire_ev;
};


int	 natpmp_init(struct event_base *);

extern char *ext_if_name;

extern struct in_addr if_ip_addr;
extern struct in_addr if_ip_mask;
extern time_t startup_time;

struct in_addr lan_ip_addr;
struct in_addr lan_ip_mask;
extern char ifstrlanaddr[64];
extern char ifstrwanaddr[64];

int getifaddr(const char * ifname, char * buf, int len,
          struct in_addr * addr, struct in_addr * mask);

int upnp_redirect_internal(const char * rhost, unsigned short eport,
                       const char * iaddr, unsigned short iport,
                       int proto, const char * desc,
                       unsigned int timestamp);

int _upnp_delete_redir(unsigned short eport, int proto);

#endif
