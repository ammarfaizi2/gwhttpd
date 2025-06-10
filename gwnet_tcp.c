// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>

#include <sys/eventfd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>

#include "common.h"

#include "gwnet_tcp.h"
#include "gwbuf.h"

enum {
	GWNET_EPL_EV_ACCEPT	= (1ull << 48ull),
	GWNET_EPL_EV_EVENTFD	= (2ull << 48ull),
	GWNET_EPL_EV_CLIENT	= (3ull << 48ull),
};

#define GWNET_EPL_EV_ALL	(GWNET_EPL_EV_ACCEPT | GWNET_EPL_EV_EVENTFD \
			 	 | GWNET_EPL_EV_CLIENT)

#define GWNET_EPL_EV_GET_EV(ev)		((ev) & GWNET_EPL_EV_ALL)
#define GWNET_EPL_EV_GET_PTR(ev)	((void *)((ev) & ~GWNET_EPL_EV_ALL))

struct gwnet_tcp_cli {
	int				fd;
	struct gwsockaddr		addr;
	struct gwnet_tcp_buf		tx_buf;
	struct gwnet_tcp_buf		rx_buf;
	uint64_t			conn_id;
	uint32_t			ep_mask;
	uint32_t			idx;

	gwnet_tcp_cli_pre_recv_t	pre_recv_cb;
	gwnet_tcp_cli_post_recv_t	post_recv_cb;
	gwnet_tcp_cli_pre_send_t	pre_send_cb;
	gwnet_tcp_cli_post_send_t	post_send_cb;
	gwnet_tcp_cli_free_t		free_cb;
	void				*udata;
	struct gwnet_tcp_srv		*ctx;
};

struct gwstack32 {
	uint32_t		sp;
	uint32_t		bp;
	uint32_t		*arr;
	pthread_mutex_t		lock;
};

struct gwnet_tcp_cli_bucket {
	struct gwstack32		stack;
	struct gwnet_tcp_cli		*arr;
	struct gwnet_tcp_cli_bucket	*next;
};

#define GWTCP_SRV_NR_EVENTS_EPOLL 512

struct gwnet_tcp_srv_wrk {
	int			ep_fd;
	int			ev_fd;
	struct gwnet_tcp_srv	*ctx;
	uint16_t		id;
	bool			epl_need_rearm;
	atomic_uint_fast32_t	nr_on_clients;
	pthread_t		thread;
	uint16_t		nr_events;
	struct epoll_event	events[GWTCP_SRV_NR_EVENTS_EPOLL];
};

struct gwnet_tcp_srv {
	volatile bool			should_stop;
	bool				accept_stopped;
	int				fd;
	socklen_t			addr_len;
	struct gwnet_tcp_cli_bucket	clients;

	uint16_t			nr_workers;
	struct gwnet_tcp_srv_wrk	*workers;

	atomic_uint_fast64_t		conn_id_gen;
	struct gwnet_tcp_srv_cfg	cfg;

	gwnet_tcp_srv_accept_t		accept_cb;
	void				*accept_cb_data;
};

__cold
static int gwstack32_init(struct gwstack32 *s, size_t cap)
{
	int ret;

	if (!s || !cap)
		return -EINVAL;

	s->arr = calloc(cap, sizeof(*s->arr));
	if (!s->arr)
		return -ENOMEM;

	ret = pthread_mutex_init(&s->lock, NULL);
	if (ret) {
		free(s->arr);
		s->arr = NULL;
		return -ret;
	}

	s->bp = s->sp = cap;
	return 0;
}

__cold
static void gwstack32_free(struct gwstack32 *s)
{
	if (!s || !s->arr)
		return;

	pthread_mutex_destroy(&s->lock);
	free(s->arr);
	s->arr = NULL;
	s->sp = 0;
	s->bp = 0;
}

__hot
static int __gwstack32_push(struct gwstack32 *s, uint32_t v)
{
	if (!s->sp)
		return -EAGAIN;

	s->arr[--s->sp] = v;
	return 0;
}

__hot
static int gwstack32_push(struct gwstack32 *s, uint32_t v)
{
	int ret;

	pthread_mutex_lock(&s->lock);
	ret = __gwstack32_push(s, v);
	pthread_mutex_unlock(&s->lock);
	return ret;
}

__hot
static int __gwstack32_pop(struct gwstack32 *s, uint32_t *v)
{
	if (s->sp == s->bp)
		return -EAGAIN;

	*v = s->arr[s->sp++];
	return 0;
}

__hot
static int gwstack32_pop(struct gwstack32 *s, uint32_t *v)
{
	int ret;

	pthread_mutex_lock(&s->lock);
	ret = __gwstack32_pop(s, v);
	pthread_mutex_unlock(&s->lock);
	return ret;
}

#define NR_CLIENTS_PER_BUCKET 300000

__cold
static int init_client_bucket(struct gwnet_tcp_srv *s)
{
	struct gwnet_tcp_cli_bucket *c = &s->clients;
	uint32_t i;
	int ret;

	ret = gwstack32_init(&c->stack, NR_CLIENTS_PER_BUCKET);
	if (ret)
		return ret;

	c->arr = calloc(NR_CLIENTS_PER_BUCKET, sizeof(*c->arr));
	if (!c->arr) {
		gwstack32_free(&c->stack);
		return -ENOMEM;
	}

	c->next = NULL;
	i = NR_CLIENTS_PER_BUCKET;
	while (i--) {
		c->arr[i].fd = -1;
		c->arr[i].idx = i;
		__gwstack32_push(&c->stack, i);
	}

	return 0;
}

__hot
static void gwnet_tcp_buf_free(struct gwnet_tcp_buf *buf)
{
	if (!buf)
		return;

	if (buf->type == GWNET_TCP_BUF_CUSTOM) {
		if (buf->cust.free_fn)
			buf->cust.free_fn(buf->cust.udata);
	} else {
		gwbuf_free(&buf->buf);
	}

	memset(buf, 0, sizeof(*buf));
	buf->type = GWNET_TCP_BUF_DEFAULT;
}

__hot
static void free_client(struct gwnet_tcp_cli *c)
{
	struct gwnet_tcp_srv *s = c->ctx;
	uint32_t idx = c->idx;

	if (c->free_cb)
		c->free_cb(c->udata, c);

	if (c->fd >= 0)
		__sys_close(c->fd);

	gwnet_tcp_buf_free(&c->tx_buf);
	gwnet_tcp_buf_free(&c->rx_buf);
	memset(c, 0, sizeof(*c));
	c->fd = -1;
	c->idx = idx;
	c->ctx = s;
}

__cold
static void free_client_bucket(struct gwnet_tcp_srv *s)
{
	struct gwnet_tcp_cli_bucket *cur, *next;
	size_t i;

	cur = &s->clients;
	while (cur) {
		next = cur->next;
		for (i = 0; i < NR_CLIENTS_PER_BUCKET; i++) {
			if (cur->arr[i].fd >= 0)
				free_client(&cur->arr[i]);
		}

		gwstack32_free(&cur->stack);
		free(cur->arr);
		if (cur != &s->clients)
			free(cur);
		cur = next;
	}
}

__cold
static int init_socket_str_to_addr(struct sockaddr_storage *a,
				   const char *addr_str, uint16_t port)
{
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)a;
	struct sockaddr_in *in = (struct sockaddr_in *)a;

	memset(a, 0, sizeof(*a));
	if (inet_pton(AF_INET6, addr_str, &in6->sin6_addr) > 0) {
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		return sizeof(struct sockaddr_in6);
	} else if (inet_pton(AF_INET, addr_str, &in->sin_addr) > 0) {
		in->sin_family = AF_INET;
		in->sin_port = htons(port);
		return sizeof(struct sockaddr_in);
	}

	return -EINVAL;
}

__cold
static int init_socket(struct gwnet_tcp_srv *s)
{
	static const int sock_type = SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK;
	struct gwnet_tcp_srv_cfg *cfg = &s->cfg;
	struct sockaddr_storage addr;
	int ret, fd;

	ret = init_socket_str_to_addr(&addr, cfg->bind_addr, cfg->port);
	if (ret < 0)
		return ret;

	fd = __sys_socket(addr.ss_family, sock_type, 0);
	if (fd < 0)
		return fd;

#ifdef SO_REUSEPORT
	if (cfg->reuse_port) {
		int v = 1;
		__sys_setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v));
	}
#endif

#ifdef SO_REUSEADDR
	if (cfg->reuse_addr) {
		int v = 1;
		__sys_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
	}
#endif

	if (cfg->tcp_backlog <= 0)
		cfg->tcp_backlog = SOMAXCONN;
	if (cfg->tcp_backlog > SOMAXCONN)
		cfg->tcp_backlog = SOMAXCONN;

	s->addr_len = (socklen_t)ret;
	ret = __sys_bind(fd, (struct sockaddr *)&addr, s->addr_len);
	if (ret < 0)
		goto out_err;

	ret = __sys_listen(fd, cfg->tcp_backlog);
	if (ret < 0)
		goto out_err;

	s->fd = fd;
	return 0;

out_err:
	__sys_close(fd);
	return ret;
}

static void free_socket(struct gwnet_tcp_srv *s)
{
	__sys_close(s->fd);
	s->fd = -1;
}

static void *gwnet_tcp_srv_worker_thread(void *arg);

__cold
static int init_worker(struct gwnet_tcp_srv_wrk *w)
{
	struct gwnet_tcp_srv *s = w->ctx;
	struct epoll_event ev;
	int ret;

	w->nr_events = GWTCP_SRV_NR_EVENTS_EPOLL;
	ret = __sys_epoll_create1(EPOLL_CLOEXEC);
	if (ret < 0)
		return ret;

	w->ep_fd = ret;
	ret = __sys_eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (ret < 0)
		goto out_close_ep;

	w->ev_fd = ret;
	if (w->id == 0) {
		/*
		 * The first worker is the main thread, it will handle
		 * the server socket and accept new connections.
		 */
		ev.events = EPOLLIN;
		ev.data.u64 = GWNET_EPL_EV_ACCEPT;
		ret = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, s->fd, &ev);
		if (ret < 0)
			goto out_close_ev;
	}

	ev.events = EPOLLIN;
	ev.data.u64 = GWNET_EPL_EV_EVENTFD;
	ret = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, w->ev_fd, &ev);
	if (ret < 0)
		goto out_close_ev;

	/*
	 * Do not spawn a thread for the main worker (id 0),
	 * it will run in the main thread.
	 */
	if (w->id == 0)
		return 0;

	ret = pthread_create(&w->thread, NULL, &gwnet_tcp_srv_worker_thread, w);
	if (ret) {
		ret = -ret;
		goto out_close_ev;
	}

	return 0;

out_close_ev:
	__sys_close(w->ev_fd);
out_close_ep:
	__sys_close(w->ep_fd);
	return ret;
}

__cold
static int ev_signal(struct gwnet_tcp_srv_wrk *w)
{
	uint64_t val = 1;
	ssize_t ret;

	ret = __sys_write(w->ev_fd, &val, sizeof(val));
	if (ret < 0)
		return ret;

	return (ret != sizeof(val)) ? -EIO : 0;
}

__cold
static void free_worker(struct gwnet_tcp_srv_wrk *w)
{
	if (w->id != 0) {
		w->ctx->should_stop = true;
		ev_signal(w);
		pthread_join(w->thread, NULL);
	}

	if (w->ev_fd >= 0) {
		__sys_close(w->ev_fd);
		w->ev_fd = -1;
	}

	if (w->ep_fd >= 0) {
		__sys_close(w->ep_fd);
		w->ep_fd = -1;
	}
}

__cold
static void free_workers(struct gwnet_tcp_srv *s)
{
	struct gwnet_tcp_srv_wrk *workers = s->workers;
	uint16_t i;

	if (!workers)
		return;

	for (i = 0; i < s->nr_workers; i++)
		free_worker(&workers[i]);

	free(workers);
	s->workers = NULL;
	s->nr_workers = 0;
}

__cold
static int init_workers(struct gwnet_tcp_srv *s)
{
	struct gwnet_tcp_srv_cfg *cfg = &s->cfg;
	struct gwnet_tcp_srv_wrk *workers;
	uint16_t i;
	int ret;

	workers = calloc(cfg->nr_workers, sizeof(*workers));
	if (!workers)
		return -ENOMEM;

	for (i = 0; i < cfg->nr_workers; i++) {
		workers[i].ctx = s;
		workers[i].id = i;

		ret = init_worker(&workers[i]);
		if (ret)
			goto free_workers;
	}

	s->workers = workers;
	s->nr_workers = cfg->nr_workers;

	return 0;

free_workers:
	s->should_stop = true;
	while (i--)
		free_worker(&workers[i]);

	free(workers);
	return ret;
}

__hot
static int get_client(struct gwnet_tcp_srv *ctx, struct gwnet_tcp_cli **cp)
{
	struct gwnet_tcp_cli *c;
	uint32_t idx;
	int ret;

	ret = gwstack32_pop(&ctx->clients.stack, &idx);
	if (unlikely(ret)) {
		/*
		 * TODO(ammarfaizi2): Expand the client bucket if we
		 * run out of space.
		 */
		return -EAGAIN;
	}

	c = &ctx->clients.arr[idx];
	assert(c->idx == idx);
	c->tx_buf.type = GWNET_TCP_BUF_DEFAULT;
	c->rx_buf.type = GWNET_TCP_BUF_DEFAULT;

	c->pre_recv_cb = NULL;
	c->post_recv_cb = NULL;
	c->pre_send_cb = NULL;
	c->post_send_cb = NULL;

	ret = gwbuf_init(&c->tx_buf.buf, 0);
	if (unlikely(ret))
		goto out_err;

	ret = gwbuf_init(&c->rx_buf.buf, 0);
	if (unlikely(ret))
		goto out_free_tx_buf;

	c->conn_id = atomic_fetch_add(&ctx->conn_id_gen, 1ull);
	*cp = c;
	return 0;

out_free_tx_buf:
	gwnet_tcp_buf_free(&c->tx_buf);
out_err:
	gwstack32_push(&ctx->clients.stack, idx);
	return ret;
}

__hot
static int put_client(struct gwnet_tcp_srv_wrk *w, struct gwnet_tcp_cli *c)
{
	struct gwnet_tcp_srv *ctx = w->ctx;
	int ret;

	if (c->fd >= 0) {
		ret = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, c->fd, NULL);
		if (unlikely(ret < 0))
			return ret;
	}

	/*
	 * TODO(ammarfaizi2): Handle the client bucket expansion.
	 */
	free_client(c);
	gwstack32_push(&ctx->clients.stack, c->idx);
	atomic_fetch_sub(&w->nr_on_clients, 1ull);

	if (unlikely(ctx->accept_stopped)) {
		int ep_fd = ctx->workers[0].ep_fd;
		struct epoll_event ev;

		ctx->accept_stopped = false;
		ev.events = EPOLLIN;
		ev.data.u64 = GWNET_EPL_EV_ACCEPT;

		ret = __sys_epoll_ctl(ep_fd, EPOLL_CTL_MOD, ctx->fd, &ev);
		if (unlikely(ret < 0))
			return ret;

		if (w != &ctx->workers[0]) {
			ret = ev_signal(w);
			if (unlikely(ret < 0))
				return ret;
		}
	}

	return 0;
}

__hot
static int handle_accept_err(struct gwnet_tcp_srv_wrk *w,
					   int err)
{
	struct gwnet_tcp_srv *ctx = w->ctx;

	if (err == -EAGAIN || err == -EINTR)
		return 0;

	if (err == -ENFILE || err == -EMFILE) {
		struct epoll_event ev;

		/*
		 * If we hit the limit of open files, we must
		 * stop accepting new connections.
		 *
		 * We can start accepting again when we have
		 * closed some client connections. The close
		 * handler will take care of re-arming
		 * the accept event.
		 */
		ctx->accept_stopped = true;
		ev.events = 0;
		ev.data.u64 = GWNET_EPL_EV_ACCEPT;
		return __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, ctx->fd, &ev);
	}

	return err;
}

__hot
static int gwnet_tcp_srv_pass_client(struct gwnet_tcp_srv_wrk *w_from,
				     struct gwnet_tcp_cli *c)
{
	struct gwnet_tcp_srv *ctx = w_from->ctx;
	struct gwnet_tcp_srv_wrk *w;
	struct epoll_event ev;
	int ret;

	w = &ctx->workers[c->conn_id % ctx->nr_workers];
	ev.events = EPOLLIN;
	ev.data.u64 = 0;
	ev.data.ptr = c;
	ev.data.u64 |= GWNET_EPL_EV_CLIENT;
	c->ep_mask = ev.events;
	ret = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, c->fd, &ev);
	if (unlikely(ret < 0))
		return ret;

	atomic_fetch_add(&w->nr_on_clients, 1ull);
	if (w != w_from)
		return ev_signal(w);

	return 0;
}

__hot
static int handle_accept_opts(int fd)
{
	int r = 0, v;
	static const size_t l = sizeof(v);

	v = 1;
	r |= __sys_setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &v, l);

	/*
	 * Wait 5 seconds before sending the first probe.
	 */
	v = 5;
	r |= __sys_setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &v, l);

	/*
	 * Then every 5 seconds send a probe.
	 */
	v = 3;
	r |= __sys_setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &v, l);

	/*
	 * Give up after 3 unanswered probes.
	 */
	v = 3;
	r |= __sys_setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &v, l);

	return r;
}

__hot
static int __handle_accept(struct gwnet_tcp_srv_wrk *w)
{
	static const int flags = SOCK_CLOEXEC | SOCK_NONBLOCK;
	struct sockaddr_storage addr;
	struct gwnet_tcp_srv *ctx;
	struct gwnet_tcp_cli *c;
	struct sockaddr *sa;
	int ret, fd;

	ctx = w->ctx;
	ret = get_client(ctx, &c);
	if (unlikely(ret))
		return handle_accept_err(w, -ENFILE);

	sa = (struct sockaddr *)&addr;
	fd = __sys_accept4(ctx->fd, sa, &ctx->addr_len, flags);
	if (unlikely(fd < 0)) {
		ret = put_client(w, c);
		return ret ? ret : handle_accept_err(w, fd);
	}

	c->fd = fd;
	if (sa->sa_family == AF_INET)
		c->addr.in = *(struct sockaddr_in *)sa;
	else
		c->addr.in6 = *(struct sockaddr_in6 *)sa;

	ret = handle_accept_opts(fd);
	if (unlikely(ret < 0))
		goto out_put_client;

	if (ctx->accept_cb) {
		ret = ctx->accept_cb(ctx->accept_cb_data, ctx, c);
		if (unlikely(ret < 0))
			goto out_put_client;
	}

	ret = gwnet_tcp_srv_pass_client(w, c);
	if (unlikely(ret < 0))
		goto out_put_client;

	return 1;

out_put_client:
	put_client(w, c);
	return 0;
}

__hot
static int handle_accept(struct gwnet_tcp_srv_wrk *w)
{
	uint32_t i = 128;
	int ret = 0;

	while (i--) {
		ret = __handle_accept(w);
		if (ret <= 0)
			break;
	}

	return 0;
}

__hot
static int handle_eventfd(struct gwnet_tcp_srv_wrk *w)
{
	uint64_t val;
	ssize_t ret;

	ret = __sys_read(w->ev_fd, &val, sizeof(val));
	if (unlikely(ret < 0)) {
		if (ret == -EINTR || ret == -EAGAIN)
			return 0;

		return ret;
	}

	if (unlikely(ret != sizeof(val)))
		return -EIO;

	return 0;
}

/*
 * Allow the client to provide a custom buffer for receiving data.
 */
__hot
static int buf_get_rx_ptrnlen(struct gwnet_tcp_cli *c, void **buf_p,
			      size_t *len_p, bool exec_pre_cb)
{
	struct gwnet_tcp_buf *b = &c->rx_buf;
	int ret;

	if (exec_pre_cb && c->pre_recv_cb) {
		ret = c->pre_recv_cb(c->udata, c->ctx, c);
		if (ret < 0)
			return ret;
	}

	if (b->type == GWNET_TCP_BUF_CUSTOM) {
		if (!b->cust.buf || !b->cust.len)
			return -ENOBUFS;
		*buf_p = b->cust.buf;
		*len_p = b->cust.len;
		return 0;
	} else if (b->type == GWNET_TCP_BUF_DEFAULT) {
		size_t len = b->buf.cap - b->buf.len;

		if (len < 1024) {
			if (gwbuf_prepare_need(&b->buf, 1024) < 0)
				return -ENOMEM;

			len = b->buf.cap - b->buf.len;
		}

		*buf_p = b->buf.buf + b->buf.len;
		*len_p = len;
		return 0;
	}

	return -EINVAL;
}

__hot
static int gwnet_tcp_buf_process_rx(struct gwnet_tcp_cli *c, ssize_t len)
{
	struct gwnet_tcp_buf *b = &c->rx_buf;
	int ret;

	b->buf.len += len;
	if (c->post_recv_cb) {
		ret = c->post_recv_cb(c->udata, c->ctx, c, len);
		if (ret < 0)
			return ret;
	}

	return 0;
}

__hot
static int buf_get_tx_ptrnlen(struct gwnet_tcp_cli *c, void **buf_p,
			      size_t *len_p, bool exec_pre_cb)
{
	struct gwnet_tcp_buf *b = &c->tx_buf;
	int ret;

	if (exec_pre_cb && c->pre_send_cb) {
		ret = c->pre_send_cb(c->udata, c->ctx, c);
		if (ret < 0)
			return ret;
	}

	if (b->type == GWNET_TCP_BUF_CUSTOM) {
		if (!b->cust.buf || !b->cust.len)
			return -ENOBUFS;
		*buf_p = b->cust.buf;
		*len_p = b->cust.len;
		return 0;
	} else if (b->type == GWNET_TCP_BUF_DEFAULT) {
		*buf_p = b->buf.buf;
		*len_p = b->buf.len;
		return 0;
	}

	return -EINVAL;
}

__hot
static ssize_t gwnet_tcp_buf_adv_tx(struct gwnet_tcp_cli *c, ssize_t len)
{
	struct gwnet_tcp_buf *b = &c->tx_buf;
	int ret;

	if (b->type == GWNET_TCP_BUF_DEFAULT)
		gwbuf_advance(&b->buf, len);

	if (c->post_send_cb) {
		ret = c->post_send_cb(c->udata, c->ctx, c, len);
		if (ret < 0)
			return ret;
	}

	return len;
}

__hot
static ssize_t do_recv(struct gwnet_tcp_cli *c)
{
	char *buf = NULL;
	size_t len = 0;
	ssize_t ret;

	ret = buf_get_rx_ptrnlen(c, (void **)&buf, &len, true);
	if (ret < 0)
		return ret;

	if (!len)
		return 0;

	ret = __sys_recv(c->fd, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);
	if (ret < 0)
		return ret;

	if (!ret)
		return -ECONNRESET;

	gwnet_tcp_buf_process_rx(c, ret);
	return ((size_t)ret != len) ? -EAGAIN : ret;
}

__hot
static ssize_t do_send(struct gwnet_tcp_cli *c)
{
	void *buf = NULL;
	size_t len = 0;
	ssize_t ret;

	ret = buf_get_tx_ptrnlen(c, &buf, &len, true);
	if (ret < 0)
		return ret;

	if (!len)
		return 0;

	ret = __sys_send(c->fd, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);
	if (ret < 0)
		return ret;

	if (!ret)
		return -ECONNRESET;

	return gwnet_tcp_buf_adv_tx(c, ret);
}

__hot
static int handle_client_in(struct epoll_event *ev, struct gwnet_tcp_cli *c)
{
	size_t tx_len;
	ssize_t ret;
	void *buf;

	ret = do_recv(c);
	if (ret < 0) {
		if (ret != -EAGAIN && ret != -EINTR)
			return ret;
	}

	if (!buf_get_tx_ptrnlen(c, &buf, &tx_len, false)) {
		if (tx_len > 0)
			ev->events |= EPOLLOUT;
	}

	return 0;
}

__hot
static int handle_client_out(struct gwnet_tcp_srv_wrk *w,
			     struct gwnet_tcp_cli *c)
{
	struct epoll_event ev_out;
	bool need_epctl = false;
	uint32_t i = 0;
	size_t tx_len;
	ssize_t ret;
	void *buf;

	do {
		/*
		 * Reduce roundtrip latency to `epoll_wait()` by
		 * repeatedly calling `send()` while tx_buf has
		 * data. Limit to 8 iterations to prevent starving
		 * other clients. It's very useful when the buffer
		 * is large, like sending a file.
		 */
		ret = do_send(c);
		if (ret < 0) {
			if (ret != -EAGAIN && ret != -EINTR)
				return ret;
		}

		ret = buf_get_tx_ptrnlen(c, &buf, &tx_len, false);
		if (unlikely(ret < 0))
			return ret;
	} while (i++ <= 8 && tx_len > 0);

	if (tx_len == 0 && (c->ep_mask & EPOLLOUT)) {
		ev_out.events = EPOLLIN;
		need_epctl = true;
	} else if (tx_len > 0 && !(c->ep_mask & EPOLLOUT)) {
		ev_out.events = EPOLLOUT | EPOLLIN;
		need_epctl = true;
	}

	if (need_epctl) {
		c->ep_mask = ev_out.events;
		ev_out.data.u64 = 0;
		ev_out.data.ptr = c;
		ev_out.data.u64 |= GWNET_EPL_EV_CLIENT;
		ret = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, c->fd, &ev_out);
		if (ret < 0)
			return ret;
	}

	return 0;
}

__hot
static int handle_client(struct gwnet_tcp_srv_wrk *w, struct epoll_event *ev)
{
	struct gwnet_tcp_cli *c = GWNET_EPL_EV_GET_PTR(ev->data.u64);
	int ret = 0;

	if (ev->events & EPOLLIN) {
		ret = handle_client_in(ev, c);
		if (unlikely(ret))
			goto out_err;
	}

	if (ev->events & EPOLLOUT) {
		ret = handle_client_out(w, c);
		if (unlikely(ret))
			goto out_err;
	}

	if (ev->events & (EPOLLHUP | EPOLLERR))
		goto out_err;

	return 0;

out_err:
	return put_client(w, c);
}

__hot
static int handle_event(struct gwnet_tcp_srv_wrk *w, struct epoll_event *ev)
{
	uint64_t ev_type = GWNET_EPL_EV_GET_EV(ev->data.u64);
	int ret = 0;

	switch (ev_type) {
	case GWNET_EPL_EV_ACCEPT:
		ret = handle_accept(w);
		break;
	case GWNET_EPL_EV_EVENTFD:
		ret = handle_eventfd(w);
		break;
	case GWNET_EPL_EV_CLIENT:
		ret = handle_client(w, ev);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

__hot
static int handle_events(int nr_events, struct gwnet_tcp_srv_wrk *w)
{
	int ret = 0, i;

	w->epl_need_rearm = false;
	for (i = 0; i < nr_events; i++) {
		struct epoll_event *ev = &w->events[i];

		ret = handle_event(w, ev);
		if (unlikely(ret))
			break;

		if (w->epl_need_rearm)
			break;

		if (w->ctx->should_stop)
			break;
	}

	return ret;
}

__hot
static int poll_events(struct gwnet_tcp_srv_wrk *w)
{
	int ret = __sys_epoll_wait(w->ep_fd, w->events, w->nr_events, -1);
	if (unlikely(ret < 0)) {
		if (ret == -EINTR || ret == -EAGAIN)
			return 0;
	}

	return ret;
}

__hot
static void *gwnet_tcp_srv_worker_thread(void *arg)
{
	struct gwnet_tcp_srv_wrk *w = arg;
	struct gwnet_tcp_srv *s = w->ctx;
	void *ret_ptr;
	int ret = 0;

	while (!s->should_stop) {
		ret = poll_events(w);
		if (unlikely(ret < 0))
			break;

		ret = handle_events(ret, w);
		if (unlikely(ret < 0))
			break;
	}

	s->should_stop = true;
	ret_ptr = (void *)((intptr_t)ret);
	return ret_ptr;
}

__cold
static int validate_cfg(struct gwnet_tcp_srv_cfg *cfg)
{
	if (!*cfg->bind_addr) {
		strncpy(cfg->bind_addr, "::", sizeof(cfg->bind_addr) - 1);
		cfg->bind_addr[sizeof(cfg->bind_addr) - 1] = '\0';
	}

	if (!cfg->port)
		return -EINVAL;

	if (cfg->nr_workers < 1 || cfg->nr_workers > 512)
		return -EINVAL;

	if (!cfg->tcp_backlog)
		cfg->tcp_backlog = SOMAXCONN;

	if (cfg->tcp_backlog < 0 || cfg->tcp_backlog > SOMAXCONN)
		return -EINVAL;

	if (cfg->reuse_addr && cfg->reuse_addr != 1)
		return -EINVAL;

	if (cfg->reuse_port && cfg->reuse_port != 1)
		return -EINVAL;

	return 0;
}

__cold
gwnet_tcp_srv_t *gwnet_tcp_srv_init(const struct gwnet_tcp_srv_cfg *cfg)
{
	struct gwnet_tcp_srv *s;
	int ret;

	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;

	s->fd = -1;
	s->cfg = *cfg;
	s->should_stop = false;

	ret = validate_cfg(&s->cfg);
	if (ret < 0)
		goto free_s;

	ret = init_client_bucket(s);
	if (ret)
		goto free_s;

	ret = init_socket(s);
	if (ret)
		goto free_client_bucket;

	ret = init_workers(s);
	if (ret)
		goto free_socket;

	return s;

free_socket:
	free_socket(s);
free_client_bucket:
	free_client_bucket(s);
free_s:
	free(s);
	return NULL;
}

__cold
void gwnet_tcp_srv_free(gwnet_tcp_srv_t *s)
{
	if (!s)
		return;

	free_workers(s);
	free_socket(s);
	free_client_bucket(s);
	memset(s, 0, sizeof(*s));
	free(s);
}

__hot
int gwnet_tcp_srv_run(gwnet_tcp_srv_t *srv)
{
	return (intptr_t)gwnet_tcp_srv_worker_thread(&srv->workers[0]);
}

__cold
void gwnet_tcp_srv_stop(gwnet_tcp_srv_t *s)
{
	uint16_t i;

	if (!s)
		return;

	s->should_stop = true;
	for (i = 0; i < s->nr_workers; i++)
		ev_signal(&s->workers[i]);
}

void gwnet_tcp_srv_cli_set_pre_recv_cb(gwnet_tcp_cli_t *c,
				       gwnet_tcp_cli_pre_recv_t cb)
{
	c->pre_recv_cb = cb;
}

void gwnet_tcp_srv_cli_set_post_recv_cb(gwnet_tcp_cli_t *c,
					gwnet_tcp_cli_post_recv_t cb)
{
	c->post_recv_cb = cb;
}

void gwnet_tcp_srv_cli_set_pre_send_cb(gwnet_tcp_cli_t *c,
				       gwnet_tcp_cli_pre_send_t cb)
{
	c->pre_send_cb = cb;
}

void gwnet_tcp_srv_cli_set_post_send_cb(gwnet_tcp_cli_t *c,
					gwnet_tcp_cli_post_send_t cb)
{
	c->post_send_cb = cb;
}

void gwnet_tcp_srv_cli_set_free_cb(gwnet_tcp_cli_t *c,
				   gwnet_tcp_cli_free_t cb)
{
	c->free_cb = cb;
}

void gwnet_tcp_srv_cli_set_data(gwnet_tcp_cli_t *c, void *data)
{
	c->udata = data;
}

void gwnet_tcp_srv_set_accept_cb(gwnet_tcp_srv_t *s,
				 gwnet_tcp_srv_accept_t cb,
				 void *data)
{
	s->accept_cb = cb;
	s->accept_cb_data = data;
}

struct gwnet_tcp_buf *gwnet_tcp_srv_cli_get_tx_buf(gwnet_tcp_cli_t *c)
{
	return &c->tx_buf;
}

struct gwnet_tcp_buf *gwnet_tcp_srv_cli_get_rx_buf(gwnet_tcp_cli_t *c)
{
	return &c->rx_buf;
}

void gwnet_tcp_srv_set_tcp_buf_rx(gwnet_tcp_cli_t *c,
				  const struct gwnet_tcp_buf *buf)
{
	gwnet_tcp_buf_free(&c->rx_buf);
	c->rx_buf = *buf;
}

void gwnet_tcp_srv_set_tcp_buf_tx(gwnet_tcp_cli_t *c,
				  const  struct gwnet_tcp_buf *buf)
{
	gwnet_tcp_buf_free(&c->tx_buf);
	c->tx_buf = *buf;
}
