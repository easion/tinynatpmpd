

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <event.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdarg.h>

#include "natpmp.h"
#define FUHAI_NATPMP_SNAT_CHAIN "FUHAI_SNATPMP"
#define FUHAI_NATPMP_DNAT_CHAIN "FUHAI_DNATPMP"
#define TABLE_FUHAI_WIFI_TO_ROUTER "WIFI2Router"

static int execute(char *cmd_line, int quiet)
{
	int pid,
	status,
	rc;

	const char *new_argv[4];
	new_argv[0] = "/bin/sh";
	new_argv[1] = "-c";
	new_argv[2] = cmd_line;
	new_argv[3] = NULL;

	//printf("Exec [%s]\n", cmd_line);

	pid = fork();
	if (pid == 0) {    /* for the child process:         */
		/* We don't want to see any errors if quiet flag is on */
		if (quiet) close(2);
		if (execvp("/bin/sh", (char *const *)new_argv) == -1) {    /* execute the command  */
				LOG_ERROR( "execvp(): %s", strerror(errno));
		} else {
				LOG_ERROR( "execvp() failed");
		}
		exit(21);
	}

	/* for the parent:      */
	//LOG_DBG( "Waiting for PID %d to exit", pid);
	rc = waitpid(pid, &status, 0);
	//LOG_DBG( "Process PID %d exited", rc);

	return (WEXITSTATUS(status));
}


int safe_asprintf(char **strp, const char *fmt, ...) {
	va_list ap;
	int retval;

	va_start(ap, fmt);
	retval = safe_vasprintf(strp, fmt, ap);
	va_end(ap);

	return (retval);
}

int safe_vasprintf(char **strp, const char *fmt, va_list ap) {
	int retval;

	retval = vasprintf(strp, fmt, ap);

	if (retval == -1) {
		LOG_ERROR( "Failed to vasprintf: %s.  Bailing out", strerror(errno));
		exit (16);
	}
	return (retval);
}

static int iptables_do_command(const char *format, ...)
{
	va_list vlist;
	char *fmt_cmd;
	char *cmd;
	int rc;

	va_start(vlist, format);
	safe_vasprintf(&fmt_cmd, format, vlist);
	va_end(vlist);

	safe_asprintf(&cmd, "iptables %s", fmt_cmd);
	free(fmt_cmd);

	LOG_DBG( "Executing command: [%s]", cmd);

	rc = execute(cmd, 0);
	if (rc!=0) {
		// If quiet, do not display the error
			LOG_ERROR( "iptables command failed(%d): %s", rc, cmd);
	}
	free(cmd);
	return rc;
}

/*
delete_redirect_and_filter_rules
*/
int _fw_delete_redir(unsigned short eport, int proto)
{
	char tmpbuf[128];
	char* netproto = (proto == IPPROTO_UDP ? "udp" : "tcp");
	//清理旧的转发规则
	snprintf(tmpbuf,sizeof(tmpbuf),"%s dpt:%d",netproto, eport); // tcp dpt:26633 to:192.168.16.226:51832
	iptables_fw_destroy_mention("nat", "PREROUTING", tmpbuf);
	
	//iptables -t nat -D chain myindex
	//iptables -t nat -F chain
	
	printf("redirect remove eport %d\n", eport);
	printf("redirect remove proto %s\n", proto == IPPROTO_UDP ? "UDP" : "TCP");
	return 0;
}


/*
*/
int fw_redirect_internal(const char * rhost, unsigned short eport,
                       const char * iaddr, unsigned short iport,
                       int proto, const char * desc,
                       unsigned int timestamp)
{
	char snat_cmd[256];
	char dnat_cmd[256];
	char *netproto;

	netproto = (proto == IPPROTO_UDP ? "udp" : "tcp");
	if (rhost != NULL)
	{
		printf("redirect rhost %s\n", rhost);
	}

	printf("redirect iaddr %s\n", iaddr);
	printf("redirect desc %s\n", desc);

	printf("redirect eport %d\n", eport);
	printf("redirect iport %d\n", iport);
	printf("redirect proto %s\n", netproto);
	
	char tmpbuf[128];
	//清理旧的转发规则
	snprintf(tmpbuf,sizeof(tmpbuf),"%s", iaddr); // tcp dpt:26633 to:192.168.16.226:51832
	iptables_fw_destroy_mention("nat", "PREROUTING", tmpbuf);
	iptables_fw_destroy_mention("nat", "POSTROUTING", tmpbuf);

	/*dnat*/
	snprintf(dnat_cmd,sizeof(dnat_cmd), 
		"-t nat -A PREROUTING -p %s --dport %d -j DNAT --to-destination %s:%d",
		netproto, eport, iaddr, iport);
	iptables_do_command(dnat_cmd);

	/*snat*/
	snprintf(snat_cmd,sizeof(snat_cmd), 
		"-t nat -A POSTROUTING -d %s -p %s --dport %d -j SNAT --to %s",
		iaddr,netproto,  iport, ifstrlanaddr);
	iptables_do_command(snat_cmd);	
	return 0;
}

int iptables_fw_destroy_mention(
		const char * table,
		const char * chain,
		const char * mention ) {
	FILE *p = NULL;
	char *command = NULL;
	char *command2 = NULL;
	char line[4096];
	char rulenum[10];
	char *victim = strdup(mention);
	int deleted = 0;

	safe_asprintf(&command, "iptables -t %s -L %s -n --line-numbers -v",
		table, chain);

	if ((p = popen(command, "r"))) {
		while (!feof(p) && fgetc(p) != '\n');
		while (!feof(p) && fgetc(p) != '\n');
		while (fgets(line, sizeof(line), p)) {
			if (strstr(line, victim)) {
				if (sscanf(line, "%9[0-9]", rulenum) == 1) {
					LOG_DBG( "Deleting rule %s from %s.%s because it mentions %s", rulenum, table, chain, victim);
					safe_asprintf(&command2, "-t %s -D %s %s", table, chain, rulenum);
					iptables_do_command(command2);
					free(command2);
					deleted = 1;
					break;
				}
			}
		}
		pclose(p);
	}

	free(command);
	free(victim);

	if (deleted) {
		/* Recurse just in case there are more in the same table+chain */
		iptables_fw_destroy_mention(table, chain, mention);
	}

	return (deleted);
}

void fw_init()
{
#if 1
	iptables_do_command("-t nat -N " FUHAI_NATPMP_DNAT_CHAIN);

	/* Assign links and rules to these new chains */
	iptables_do_command("-t nat -A PREROUTING -i %s -j "FUHAI_NATPMP_DNAT_CHAIN, ext_if_name);
#endif

#if 0
	iptables_do_command("-t nat -A " FUHAI_NATPMP_DNAT_CHAIN " -d %s -j " TABLE_FUHAI_WIFI_TO_ROUTER, ifstrwanaddr);
	iptables_do_command("-t nat -A " TABLE_FUHAI_WIFI_TO_ROUTER " -j ACCEPT");
#endif

}

void fw_destroy()
{
	iptables_fw_destroy_mention("nat", "PREROUTING", FUHAI_NATPMP_DNAT_CHAIN);

	iptables_do_command("-t nat -F " FUHAI_NATPMP_DNAT_CHAIN);
	iptables_do_command("-t nat -X " FUHAI_NATPMP_DNAT_CHAIN);

	iptables_do_command("-t nat -F " TABLE_FUHAI_WIFI_TO_ROUTER);
	iptables_do_command("-t nat -X " TABLE_FUHAI_WIFI_TO_ROUTER);
}

