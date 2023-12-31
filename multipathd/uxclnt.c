/*
 * Original author : tridge@samba.org, January 2002
 *
 * Copyright (c) 2005 Christophe Varoqui
 * Copyright (c) 2005 Benjamin Marzinski, Redhat
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
#include <readline/readline.h>
#include <readline/history.h>

#include <mpath_cmd.h>
#include <uxsock.h>
#include <memory.h>
#include <defaults.h>

#include <vector.h>
#include "cli.h"

static void print_reply(char *s)
{
	if (isatty(1)) {
		printf("%s", s);
		return;
	}
	/* strip ANSI color markers */
	while (*s != '\0') {
		if ((*s == 0x1b) && (*(s+1) == '['))
			while ((*s++ != 'm') && (*s != '\0')) {};
		putchar(*s++);
	}
}
/*
 * process the client
 */
static void process(int fd)
{
	char *line;
	char *reply;

	cli_init();
	rl_readline_name = "multipathd";
	rl_completion_entry_function = key_generator;
	while ((line = readline("multipathd> "))) {
		size_t llen = strlen(line);

		if (!llen) {
			free(line);
			continue;
		}
		if (!strncmp(line, "exit", 4) && llen == 4)
			break;
		if (!strncmp(line, "quit", 4) && llen == 4)
			break;

		if (send_packet(fd, line) != 0) break;
		if (recv_packet(fd, &reply) != 0) break;

		print_reply(reply);

		if (line && *line)
			add_history(line);

		free(line);
		FREE(reply);
	}
}

static int process_req(int fd, char * inbuf)
{
	char *reply;
	int ret;

	if (send_packet(fd, inbuf) != 0) {
		printf("cannot send packet\n");
		return 1;
	}
	if (recv_packet(fd, &reply) != 0) {
		printf("error receiving packet\n");
		return 1;
	}
	printf("%s", reply);
	ret = (strcmp(reply, "fail\n") == 0);
	FREE(reply);
	/* Need to do better about getting return value */
	return ret;
}

/*
 * entry point
 */
int uxclnt(char * inbuf)
{
	int fd, ret = 0;

	fd = mpath_connect();
	if (fd == -1) {
		perror("ux_socket_connect");
		exit(1);
	}

	if (inbuf)
		ret = process_req(fd, inbuf);
	else
		process(fd);

	return ret;
}
