/*
 *   TinyNATPMPd: simple nat-pmp daemon for openwrt
 *
 *   Copyright 2015 Fu Hai Technology Co., Ltd
 *     Author: easion,<easion@gmail.com>
 *     Website: http://www.envcat.com/
 */
 /* MiniUPnP project
 * (c) 2007-2014 Thomas Bernard
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

#include <fcntl.h>
#include <unistd.h>
#include <event.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

#include "natpmp.h"

extern volatile sig_atomic_t should_send_public_address_change_notif;


static int open_router_watch_socket(void)
{
	int s;
	struct sockaddr_nl addr;

	s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (s == -1)
	{
		LOG_ERROR( "socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE): %m");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		LOG_ERROR( "bind(netlink): %m");
		close(s);
		return -1;
	}
	return s;
}


static void process_watch_notify(int s)
{
	char buffer[4096];
	struct iovec iov;
	struct msghdr hdr;
	struct nlmsghdr *nlhdr;
	struct ifinfomsg *ifi;
	struct ifaddrmsg *ifa;
	int len;

	struct rtattr *rth;
	int rtl;

	unsigned int ext_if_name_index = 0;

	iov.iov_base = buffer;
	iov.iov_len = sizeof(buffer);

	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_iov = &iov;
	hdr.msg_iovlen = 1;

	len = recvmsg(s, &hdr, 0);
	if (len < 0)
	{
		LOG_ERROR( "recvmsg(s, &hdr, 0): %m");
		return;
	}

	if(ext_if_name) {
		ext_if_name_index = if_nametoindex(ext_if_name);
	}

	for (nlhdr = (struct nlmsghdr *) buffer;
	     NLMSG_OK (nlhdr, (unsigned int)len);
	     nlhdr = NLMSG_NEXT (nlhdr, len))
	{
		int is_del = 0;
		char address[48];
		char ifname[IFNAMSIZ];
		address[0] = '\0';
		ifname[0] = '\0';
		if (nlhdr->nlmsg_type == NLMSG_DONE)
			break;
		switch(nlhdr->nlmsg_type) {
		case RTM_DELLINK:
			is_del = 1;
		case RTM_NEWLINK:
			ifi = (struct ifinfomsg *) NLMSG_DATA(nlhdr);
#if 0
			if(is_del) {
				if(ProcessInterfaceDown(ifi) < 0)
					LOG_ERROR( "ProcessInterfaceDown(ifi) failed");
			} else {
				if(ProcessInterfaceUp(ifi) < 0)
					LOG_ERROR( "ProcessInterfaceUp(ifi) failed");
			}
#endif
			break;
		case RTM_DELADDR:
			is_del = 1;
		case RTM_NEWADDR:
			/* see /usr/include/linux/netlink.h
			 * and /usr/include/linux/rtnetlink.h */
			ifa = (struct ifaddrmsg *) NLMSG_DATA(nlhdr);
			LOG_DBG( "%s %s index=%d fam=%d", "ProcessInterfaceWatchNotify",
			       is_del ? "RTM_DELADDR" : "RTM_NEWADDR",
			       ifa->ifa_index, ifa->ifa_family);
			for(rth = IFA_RTA(ifa), rtl = IFA_PAYLOAD(nlhdr);
			    rtl && RTA_OK(rth, rtl);
			    rth = RTA_NEXT(rth, rtl)) {
				char tmp[128];
				memset(tmp, 0, sizeof(tmp));
				switch(rth->rta_type) {
				case IFA_ADDRESS:
				case IFA_LOCAL:
				case IFA_BROADCAST:
				case IFA_ANYCAST:
					inet_ntop(ifa->ifa_family, RTA_DATA(rth), tmp, sizeof(tmp));
					if(rth->rta_type == IFA_ADDRESS)
						strncpy(address, tmp, sizeof(address));
					break;
				case IFA_LABEL:
					strncpy(tmp, RTA_DATA(rth), sizeof(tmp));
					strncpy(ifname, tmp, sizeof(ifname));
					break;
				case IFA_CACHEINFO:
					{
						struct ifa_cacheinfo *cache_info;
						cache_info = RTA_DATA(rth);
						snprintf(tmp, sizeof(tmp), "valid=%u prefered=%u",
						         cache_info->ifa_valid, cache_info->ifa_prefered);
					}
					break;
				default:
					strncpy(tmp, "*unknown*", sizeof(tmp));
				}
				LOG_DBG( " - %u - %s type=%d",
				       ifa->ifa_index, tmp,
				       rth->rta_type);
			}
			if(ifa->ifa_index == ext_if_name_index) {
				should_send_public_address_change_notif = 1;
			}
			break;
		default:
			LOG_DBG( "%s type %d ignored",
			       "ProcessInterfaceWatchNotify", nlhdr->nlmsg_type);
		}
	}

}

static void iface_recvmsg(int fd, short event, void *arg)
{
	process_watch_notify(fd);
	if (should_send_public_address_change_notif)
	{
		send_public_address_change_notification(NULL,0);
		should_send_public_address_change_notif = 0;
	}
}

int iface_init(struct event_base *base)
{
	int fd;
	static struct event	 ctrl_ev;

	fd = open_router_watch_socket();
	if (fd < 0)
	{
		LOG_ERROR("iface_init failed\n");
		return -1;
	}
	event_set(&ctrl_ev, fd, EV_READ|EV_PERSIST,
		iface_recvmsg, NULL);
	if (base)
		event_base_set(base, &ctrl_ev);
	event_add(&ctrl_ev, NULL);
	return 0;
}
