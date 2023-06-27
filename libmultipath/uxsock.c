/*
 * Original author : tridge@samba.org, January 2002
 *
 * Copyright (c) 2005 Christophe Varoqui
 * Copyright (c) 2005 Alasdair Kergon, Redhat
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <signal.h>
#include <errno.h>
#include <mpath_cmd.h>

#include "memory.h"
#include "uxsock.h"

/*
 * Code is similar with mpath_recv_reply() with data size limitation
 * and debug-able malloc.
 * When limit == 0, it means no limit on data size, used for socket client
 * to receiving data from multipathd.
 */
static int _recv_packet(int fd, char **buf, ssize_t limit);

/*
 * create a unix domain socket and start listening on it
 * return a file descriptor open on the socket
 */
int ux_socket_listen(const char *name)
{
	int fd, len;
	struct sockaddr_un addr;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd == -1) return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	addr.sun_path[0] = '\0';
	len = strlen(name) + 1 + sizeof(sa_family_t);
	strncpy(&addr.sun_path[1], name, len);

	if (bind(fd, (struct sockaddr *)&addr, len) == -1) {
		close(fd);
		return -1;
	}

	if (listen(fd, 10) == -1) {
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * keep writing until it's all sent
 */
size_t write_all(int fd, const void *buf, size_t len)
{
	size_t total = 0;

	while (len) {
		ssize_t n = write(fd, buf, len);
		if (n < 0) {
			if ((errno == EINTR) || (errno == EAGAIN))
				continue;
			return total;
		}
		if (!n)
			return total;
		buf = n + (char *)buf;
		len -= n;
		total += n;
	}
	return total;
}

/*
 * send a packet in length prefix format
 */
int send_packet(int fd, const char *buf)
{
	int ret = 0;
	sigset_t set, old;

	/* Block SIGPIPE */
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &set, &old);

	ret = mpath_send_cmd(fd, buf);

	/* And unblock it again */
	pthread_sigmask(SIG_SETMASK, &old, NULL);

	return ret;
}

static int _recv_packet(int fd, char **buf, ssize_t limit)
{
	int err = 0;
	ssize_t len = 0;
	unsigned int timeout = DEFAULT_REPLY_TIMEOUT;

	*buf = NULL;
	len = mpath_recv_reply_len(fd, timeout);
	if (len <= 0)
		return len;
	if ((limit > 0) && (len > limit))
		return -EINVAL;
	(*buf) = MALLOC(len);
	if (!*buf)
		return -ENOMEM;
	err = mpath_recv_reply_data(fd, *buf, len, timeout);
	if (err != 0) {
		FREE(*buf);
		(*buf) = NULL;
	}
	return err;
}

/*
 * receive a packet in length prefix format
 */
int recv_packet(int fd, char **buf)
{
	return _recv_packet(fd, buf, 0 /* no limit */);
}

int recv_packet_from_client(int fd, char **buf)
{
	return _recv_packet(fd, buf, _MAX_CMD_LEN);
}
