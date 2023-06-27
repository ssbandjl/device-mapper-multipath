#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <errno.h>
#include <debug.h>
#include <mpath_cmd.h>
#include <uxsock.h>
#include "memory.h"
#include <libudev.h>
#include <mpath_persist.h>

unsigned long mem_allocated;    /* Total memory used in Bytes */

static int do_update_pr(char * mapname, char * arg)
{
	int fd;
	char str[256];
	char *reply;
	int ret = 0;

	fd = mpath_connect();
	if (fd == -1) {
		condlog (0, "ux socket connect error");
		return 1 ;
	}

	snprintf(str,sizeof(str),"map %s %s", mapname, arg);
	condlog (2, "%s: pr message=%s", mapname, arg);
	send_packet(fd, str);
	ret = recv_packet(fd, &reply);
	if (ret < 0) {
		condlog(2, "%s: message=%s recv error=%d", mapname, str, errno);
		ret = -2;
	} else {
		condlog (2, "%s: message=%s reply=%s", mapname, str, reply);
		if (!reply || strncmp(reply,"ok", 2) == 0)
			ret = 0;
		else ret = -1;
	}

	free(reply);
	mpath_disconnect(fd);
	return ret;
}

int update_prflag(char *mapname, int set) {
	return do_update_pr(mapname, (set)? "setprstatus" : "unsetprstatus");
}

int update_prkey_flags(char *mapname, uint64_t prkey, uint8_t sa_flags) {
	char str[256];
	char *flagstr = "";

	if (sa_flags & MPATH_F_APTPL_MASK)
		flagstr = ":aptpl";
	if (prkey)
		snprintf(str, sizeof(str), "setprkey key %" PRIx64 "%s", prkey,
			 flagstr);
	else
		snprintf(str, sizeof(str), "unsetprkey");
	return do_update_pr(mapname, str);
}
