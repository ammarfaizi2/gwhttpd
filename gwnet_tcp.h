// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWNET_TCP_H
#define GWNET_TCP_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "gwbuf.h"

struct gwsockaddr {
	union {
		struct sockaddr		sa;
		struct sockaddr_in	in;
		struct sockaddr_in6	in6;
	};
};

struct gwbuf;

struct gwnet_tcp_srv;

struct gwnet_tcp_cli;

enum {
	GWNET_TCP_BUF_DEFAULT = 0,
	GWNET_TCP_BUF_CUSTOM  = 1,
};

struct gwnet_tcp_buf_cust {
	void		*udata;
	void		*buf;
	size_t		len;
	void (*free_fn)(void *udata);
};

struct gwnet_tcp_buf {
	uint8_t type;
	union {
		struct gwbuf buf;
		struct gwnet_tcp_buf_cust cust;
	};
};

struct gwnet_tcp_srv_cfg {
	char			bind_addr[255];
	uint16_t		port;
	uint16_t		nr_workers;
	uint8_t			reuse_addr;
	uint8_t			reuse_port;
	int			tcp_backlog;
};

typedef struct gwnet_tcp_srv gwnet_tcp_srv_t;
typedef struct gwnet_tcp_cli gwnet_tcp_cli_t;

typedef int (*gwnet_tcp_cli_pre_recv_t)(void *data, gwnet_tcp_srv_t *s,
					gwnet_tcp_cli_t *c);

typedef int (*gwnet_tcp_cli_post_recv_t)(void *data, gwnet_tcp_srv_t *s,
					 gwnet_tcp_cli_t *c, ssize_t recv_ret);

typedef int (*gwnet_tcp_cli_pre_send_t)(void *data, gwnet_tcp_srv_t *s,
					gwnet_tcp_cli_t *c);

typedef int (*gwnet_tcp_cli_post_send_t)(void *data, gwnet_tcp_srv_t *s,
					 gwnet_tcp_cli_t *c, ssize_t send_ret);

typedef void (*gwnet_tcp_cli_free_t)(void *data, gwnet_tcp_cli_t *c);

typedef int (*gwnet_tcp_srv_accept_t)(void *data, gwnet_tcp_srv_t *s,
				      gwnet_tcp_cli_t *c);

gwnet_tcp_srv_t *gwnet_tcp_srv_init(const struct gwnet_tcp_srv_cfg *cfg);
void gwnet_tcp_srv_free(gwnet_tcp_srv_t *s);
void gwnet_tcp_srv_stop(gwnet_tcp_srv_t *s);
int gwnet_tcp_srv_run(gwnet_tcp_srv_t *srv);

void gwnet_tcp_srv_cli_set_pre_recv_cb(gwnet_tcp_cli_t *c,
				       gwnet_tcp_cli_pre_recv_t cb);
void gwnet_tcp_srv_cli_set_post_recv_cb(gwnet_tcp_cli_t *c,
					gwnet_tcp_cli_post_recv_t cb);

void gwnet_tcp_srv_cli_set_pre_send_cb(gwnet_tcp_cli_t *c,
				       gwnet_tcp_cli_pre_send_t cb);
void gwnet_tcp_srv_cli_set_post_send_cb(gwnet_tcp_cli_t *c,
					gwnet_tcp_cli_post_send_t cb);

void gwnet_tcp_srv_cli_set_free_cb(gwnet_tcp_cli_t *c, gwnet_tcp_cli_free_t cb);

void gwnet_tcp_srv_cli_set_data(gwnet_tcp_cli_t *c, void *data);

void gwnet_tcp_srv_set_accept_cb(gwnet_tcp_srv_t *s, gwnet_tcp_srv_accept_t cb,
				 void *data);

void gwnet_tcp_srv_set_tcp_buf_rx(gwnet_tcp_cli_t *c,
				  const struct gwnet_tcp_buf *buf);

void gwnet_tcp_srv_set_tcp_buf_tx(gwnet_tcp_cli_t *c,
				  const struct gwnet_tcp_buf *buf);

struct gwnet_tcp_buf *gwnet_tcp_srv_cli_get_tx_buf(gwnet_tcp_cli_t *c);
struct gwnet_tcp_buf *gwnet_tcp_srv_cli_get_rx_buf(gwnet_tcp_cli_t *c);

#endif /* #ifndef GWNET_TCP_H */
