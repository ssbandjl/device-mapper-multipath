/*
 * Original author : tridge@samba.org, January 2002
 *
 * Copyright (c) 2005 Christophe Varoqui
 * Copyright (c) 2005 Benjamin Marzinski, Redhat
 */

/*
 * A simple domain socket listener
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <signal.h>
#include <stdbool.h>
#include <checkers.h>
#include <memory.h>
#include <debug.h>
#include <vector.h>
#include <structs.h>
#include <structs_vec.h>
#include <uxsock.h>
#include <defaults.h>
#include <mpath_cmd.h>

#include "main.h"
#include "cli.h"
#include "uxlsnr.h"

struct timespec sleep_time = {5, 0};

struct client {
	int fd;
	struct client *next, *prev;
};

static struct client *clients;
static unsigned num_clients;
struct pollfd *polls;
volatile sig_atomic_t reconfig_sig = 0;
volatile sig_atomic_t log_reset_sig = 0;

static bool _socket_client_is_root(int fd);

static bool _socket_client_is_root(int fd)
{
	socklen_t len = 0;
	struct ucred uc;

	len = sizeof(struct ucred);
	if ((fd >= 0) &&
	    (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) == 0) &&
	    (uc.uid == 0))
			return true;

	/* Treat error as not root client */
	return false;
}

/*
 * handle a new client joining
 */
static void new_client(int ux_sock)
{
	struct client *c;
	struct sockaddr addr;
	socklen_t len = sizeof(addr);
	int fd;

	fd = accept(ux_sock, &addr, &len);

	if (fd == -1)
		return;

	/* put it in our linked list */
	c = (struct client *)MALLOC(sizeof(*c));
	if (!c) {
		close(fd);
		return;
	}
	memset(c, 0, sizeof(*c));
	c->fd = fd;
	c->next = clients;
	if (c->next) c->next->prev = c;
	clients = c;
	num_clients++;
}

/*
 * kill off a dead client
 */
static void dead_client(struct client *c)
{
	close(c->fd);
	if (c->prev) c->prev->next = c->next;
	if (c->next) c->next->prev = c->prev;
	if (c == clients) clients = c->next;
	FREE(c);
	num_clients--;
}

void free_polls (void)
{
	if (polls)
		FREE(polls);
}

void uxsock_cleanup(void *arg)
{
	cli_exit();
	free_polls();
}

/*
 * entry point
 */
void * uxsock_listen(uxsock_trigger_fn uxsock_trigger, void * trigger_data)
{
	int ux_sock;
	int rlen;
	char *inbuf;
	char *reply;
	sigset_t mask;

	ux_sock = ux_socket_listen(DEFAULT_SOCKET);

	if (ux_sock == -1) {
		condlog(0, "ux_socket_listen error");
		exit(1);
	}

	pthread_cleanup_push(uxsock_cleanup, NULL);

	polls = (struct pollfd *)MALLOC(0);
	pthread_sigmask(SIG_SETMASK, NULL, &mask);
	sigdelset(&mask, SIGHUP);
	sigdelset(&mask, SIGUSR1);
	while (1) {
		struct pollfd *tmp;
		struct client *c;
		int i, poll_count;

		/* setup for a poll */
		tmp = REALLOC(polls, (1+num_clients) * sizeof(*polls));
		/* If we can't allocate poliing space for the new client,
		 * close it */
		if (!tmp)
			dead_client(clients);
		else
			polls = tmp;
		polls[0].fd = ux_sock;
		polls[0].events = POLLIN;

		/* setup the clients */
		for (i=1, c = clients; c; i++, c = c->next) {
			polls[i].fd = c->fd;
			polls[i].events = POLLIN;
		}

		/* most of our life is spent in this call */
		poll_count = ppoll(polls, i, &sleep_time, &mask);

		if (poll_count == -1) {
			if (errno == EINTR) {
				handle_signals();
				continue;
			}

			/* something went badly wrong! */
			condlog(0, "poll");
			pthread_exit(NULL);
		}

		if (poll_count == 0)
			continue;

		/* see if a client wants to speak to us */
		for (i=1, c = clients; c; i++) {
			struct client *next = c->next;

			if (polls[i].revents & POLLIN) {
				if (recv_packet_from_client(c->fd,
							    &inbuf) != 0) {
					dead_client(c);
				} else if (!inbuf) {
					condlog(4, "recv_packet_from_client "
						"get null request");
					continue;
				} else {
					condlog(4, "Got request [%s]", inbuf);
					uxsock_trigger(inbuf, &reply, &rlen, _socket_client_is_root(c->fd), trigger_data);
					if (reply) {
						if (send_packet(c->fd,
								reply) != 0) {
							dead_client(c);
						}
						condlog(4, "Reply [%d bytes]",
							rlen);
						FREE(reply);
						reply = NULL;
					}
					FREE(inbuf);
				}
			}
			c = next;
		}

		/* see if we got a new client */
		if (polls[0].revents & POLLIN) {
			new_client(ux_sock);
		}
	}

	pthread_cleanup_pop(1);
	close(ux_sock);
	return NULL;
}
