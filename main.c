/*
 *   TinyNATPMPd: simple nat-pmp daemon for openwrt
 *
 *   Copyright 2015 Fu Hai Technology Co., Ltd
 *     Author: easion,<easion@gmail.com>
 *     Website: http://www.envcat.com/
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <event.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>

#include "natpmp.h"

volatile sig_atomic_t should_send_public_address_change_notif;
char *ext_if_name;
char *lan_if_name;
char ifstrwanaddr[64];
struct in_addr if_ip_addr;
struct in_addr if_ip_mask;

char ifstrlanaddr[64];
struct in_addr lan_ip_addr;
struct in_addr lan_ip_mask;
time_t startup_time = 0;

static void
handle_signal(int sig, short event, void *arg)
{
	fw_destroy();
	exit(144);
}

void update_boot_time()
{
	char buff[64];
	int uptime = 0, fd;

	startup_time = time(NULL);

	fd = open("/proc/uptime", O_RDONLY);
	if(fd < 0)
	{
		LOG_ERROR( "open(\"/proc/uptime\" : %m");
	}
	else
	{
		memset(buff, 0, sizeof(buff));
		if(read(fd, buff, sizeof(buff) - 1) < 0)
		{
			LOG_ERROR( "read(\"/proc/uptime\" : %m");
		}
		else
		{
			uptime = atoi(buff);
			LOG_ERROR("system uptime is %d seconds", uptime);
		}
		close(fd);
		startup_time -= uptime;
	}
}

int main(int argc, char *argv[])
{
	int ret = 0;
	int debug = 0;
	struct event		 ev_sighup;
	struct event		 ev_sigint;
	struct event		 ev_sigterm;
	int			 c;
	struct event_base *base = NULL;
	struct natpmpd		*env = NULL;

	ext_if_name = "pppoe-wan"; //"eth0.2";
	lan_if_name = "br-lan";
	while ((c = getopt(argc, argv, "de:f:v")) != -1) {
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case 'e':
			lan_if_name = strdup(optarg);
			break;
		case 'f':
			ext_if_name = strdup(optarg);
			break;		
		case 'v':
			break;
		default:
			break;
		}
	}

	ret = geteuid();
	update_boot_time();
	base = event_init();
	//base = event_base_new();
	
	//if ((pw = getpwnam(NATPMPD_USER)) == NULL)
	//	errx(1, "unknown user %s", NATPMPD_USER);	

	if (getifaddr(ext_if_name, ifstrwanaddr, 64, &if_ip_addr, &if_ip_mask) < 0)
	{
		LOG_ERROR("getifaddr(%s, ifaddr, 16) failed", ext_if_name);
		//return 1;
	}

	if (getifaddr(lan_if_name, ifstrlanaddr, 64, &lan_ip_addr, &lan_ip_mask) < 0)
	{
		LOG_ERROR("getifaddr(%s, ifaddr, 16) failed", lan_if_name);
		return 1;
	}

	LOG_INFO("LAN At %s - %s\n", lan_if_name, ifstrlanaddr);
	LOG_INFO("WAN At %s - %s\n", ext_if_name, ifstrwanaddr);

	signal(SIGPIPE, SIG_IGN);


	should_send_public_address_change_notif = 0;

	ret = iface_init(base);
	if (ret < 0)
	{
		LOG_ERROR("iface_init failed");
	}
	ret = natpmp_init(base);
	if (ret < 0)
	{
		LOG_ERROR("natpmp_init failed");
		return 1;
	}
	send_public_address_change_notification(NULL,0);
	fw_init();
	LOG_ERROR("natpmp RUNNING");
	if (debug == 0)
	{
		signal_set(&ev_sighup, SIGHUP, handle_signal, env);
		signal_set(&ev_sigint, SIGINT, handle_signal, env);
		signal_set(&ev_sigterm, SIGTERM, handle_signal, env);
		signal_add(&ev_sighup, NULL);
		signal_add(&ev_sigint, NULL);
		signal_add(&ev_sigterm, NULL);
		if (daemon(1, 0) == -1){
				printf("failed to daemonize");
				exit(1);
		}
	}

	if (base && 0)
	{
		event_base_dispatch(base);
		event_base_free(base);	
	}
	else
		event_dispatch();
	fw_destroy();
	return 0;
}

