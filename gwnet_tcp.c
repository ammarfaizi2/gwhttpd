// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

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
#include <sys/epoll.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>

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
	struct gwbuf			tx_buf;
	struct gwbuf			rx_buf;
	uint32_t			ep_mask;
	uint64_t			conn_id;
	gwnet_tcp_cli_post_recv_t	post_recv_cb;
	gwnet_tcp_cli_pre_send_t	pre_send_cb;
	gwnet_tcp_cli_post_send_t	post_send_cb;
	gwnet_tcp_cli_free_t		free_cb;
	void				*data;
};

struct gwstack16 {
	uint16_t		sp;
	uint16_t		bp;
	uint16_t		*arr;
	pthread_mutex_t		lock;
};

struct gwnet_tcp_cli_bucket {
	struct gwstack16		stack;
	struct gwnet_tcp_cli		*arr;
	struct gwnet_tcp_cli_bucket	*next;
};

#define GWTCP_SRV_NR_EVENTS_EPOLL 64

struct gwnet_tcp_srv_wrk {
	int			ep_fd;
	int			ev_fd;
	struct gwnet_tcp_srv	*ctx;
	struct epoll_event	events[GWTCP_SRV_NR_EVENTS_EPOLL];
	uint16_t		nr_events;
	uint16_t		id;
	bool			epl_need_rearm;
	atomic_uint_fast32_t	nr_on_clients;
	pthread_t		thread;
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

static int gwstack16_init(struct gwstack16 *s, size_t cap)
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

static void gwstack16_free(struct gwstack16 *s)
{
	if (!s || !s->arr)
		return;

	pthread_mutex_destroy(&s->lock);
	free(s->arr);
	s->arr = NULL;
	s->sp = 0;
	s->bp = 0;
}

static int __gwstack16_push(struct gwstack16 *s, uint16_t v)
{
	if (!s->sp)
		return -EAGAIN;

	s->arr[--s->sp] = v;
	return 0;
}

static int gwstack16_push(struct gwstack16 *s, uint16_t v)
{
	int ret;

	pthread_mutex_lock(&s->lock);
	ret = __gwstack16_push(s, v);
	pthread_mutex_unlock(&s->lock);
	return ret;
}

static int __gwstack16_pop(struct gwstack16 *s, uint16_t *v)
{
	if (s->sp == s->bp)
		return -EAGAIN;

	*v = s->arr[s->sp++];
	return 0;
}

static int gwstack16_pop(struct gwstack16 *s, uint16_t *v)
{
	int ret;

	pthread_mutex_lock(&s->lock);
	ret = __gwstack16_pop(s, v);
	pthread_mutex_unlock(&s->lock);
	return ret;
}

#define NR_CLIENTS_PER_BUCKET 30000

static int gwnet_tcp_srv_init_client_bucket(struct gwnet_tcp_srv *s)
{
	struct gwnet_tcp_cli_bucket *c = &s->clients;
	uint16_t i;
	int ret;

	ret = gwstack16_init(&c->stack, NR_CLIENTS_PER_BUCKET);
	if (ret)
		return ret;

	c->arr = calloc(NR_CLIENTS_PER_BUCKET, sizeof(*c->arr));
	if (!c->arr) {
		gwstack16_free(&c->stack);
		return -ENOMEM;
	}

	c->next = NULL;
	i = NR_CLIENTS_PER_BUCKET;
	while (i--) {
		c->arr[i].fd = -1;
		__gwstack16_push(&c->stack, i);
	}

	return 0;
}

static void gwnet_tcp_srv_free_client(struct gwnet_tcp_cli *c)
{
	if (c->free_cb)
		c->free_cb(c->data, c);

	if (c->fd >= 0) {
		close(c->fd);
		c->fd = -1;
	}

	gwbuf_free(&c->tx_buf);
	gwbuf_free(&c->rx_buf);
	c->post_recv_cb = NULL;
	c->pre_send_cb = NULL;
	c->post_send_cb = NULL;
	c->free_cb = NULL;
	c->conn_id = 0;
}

static void gwnet_tcp_srv_free_client_bucket(struct gwnet_tcp_srv *s)
{
	struct gwnet_tcp_cli_bucket *cur, *next;
	size_t i;

	cur = &s->clients;
	while (cur) {
		next = cur->next;
		for (i = 0; i < NR_CLIENTS_PER_BUCKET; i++) {
			if (cur->arr[i].fd >= 0)
				gwnet_tcp_srv_free_client(&cur->arr[i]);
		}

		gwstack16_free(&cur->stack);
		free(cur->arr);
		if (cur != &s->clients)
			free(cur);
		cur = next;
	}
}

static int gwnet_tcp_srv_init_socket_str_to_addr(struct sockaddr_storage *a,
						 const char *addr_str,
						 uint16_t port)
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

static int gwnet_tcp_srv_init_socket(struct gwnet_tcp_srv *s)
{
	static const int sock_type = SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK;
	struct gwnet_tcp_srv_cfg *cfg = &s->cfg;
	struct sockaddr_storage addr;
	int ret, fd;

	ret = gwnet_tcp_srv_init_socket_str_to_addr(&addr, cfg->bind_addr,
						    cfg->port);
	if (ret < 0)
		return ret;

	fd = socket(addr.ss_family, sock_type, 0);
	if (fd < 0)
		return -errno;

#ifdef SO_REUSEPORT
	if (cfg->reuse_port) {
		int val = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
	}
#endif

#ifdef SO_REUSEADDR
	if (cfg->reuse_addr) {
		int val = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	}
#endif

	if (cfg->tcp_backlog <= 0)
		cfg->tcp_backlog = SOMAXCONN;
	if (cfg->tcp_backlog > SOMAXCONN)
		cfg->tcp_backlog = SOMAXCONN;

	s->addr_len = (socklen_t)ret;
	ret = bind(fd, (struct sockaddr *)&addr, s->addr_len);
	if (ret < 0)
		goto out_err;

	ret = listen(fd, cfg->tcp_backlog);
	if (ret < 0)
		goto out_err;

	s->fd = fd;
	return 0;

out_err:
	ret = -errno;
	close(fd);
	return ret;
}

static void gwnet_tcp_srv_free_socket(struct gwnet_tcp_srv *s)
{
	close(s->fd);
	s->fd = -1;
}

static void *gwnet_tcp_srv_worker_thread(void *arg);

static int gwnet_tcp_srv_init_worker(struct gwnet_tcp_srv_wrk *w)
{
	struct gwnet_tcp_srv *s = w->ctx;
	struct epoll_event ev;
	int ret;

	w->nr_events = GWTCP_SRV_NR_EVENTS_EPOLL;
	w->ep_fd = epoll_create1(EPOLL_CLOEXEC);
	if (w->ep_fd < 0)
		return -errno;

	w->ev_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (w->ev_fd < 0) {
		ret = -errno;
		goto out_close_ep;
	}

	if (w->id == 0) {
		/*
		 * The first worker is the main thread, it will handle
		 * the server socket and accept new connections.
		 */
		ev.events = EPOLLIN;
		ev.data.u64 = GWNET_EPL_EV_ACCEPT;
		ret = epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, s->fd, &ev);
		if (ret < 0) {
			ret = -errno;
			goto out_close_ev;
		}
	}

	ev.events = EPOLLIN;
	ev.data.u64 = GWNET_EPL_EV_EVENTFD;
	ret = epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, w->ev_fd, &ev);
	if (ret < 0) {
		ret = -errno;
		goto out_close_ev;
	}

	/*
	 * Do not spawn a thread for the main worker (id 0),
	 * it will run in the main thread.
	 */
	if (w->id != 0) {	
		ret = pthread_create(&w->thread, NULL,
				     gwnet_tcp_srv_worker_thread, w);
		if (ret) {
			ret = -ret;
			goto out_close_ev;
		}
	}

	return 0;

out_close_ev:
	close(w->ev_fd);
out_close_ep:
	close(w->ep_fd);
	return ret;
}

static int gwnet_tcp_srv_ev_signal(struct gwnet_tcp_srv_wrk *w)
{
	uint64_t val = 1;
	ssize_t ret;

	ret = write(w->ev_fd, &val, sizeof(val));
	if (ret < 0)
		return -errno;

	return (ret != sizeof(val)) ? -EIO : 0;
}

static void gwnet_tcp_srv_free_worker(struct gwnet_tcp_srv_wrk *w)
{
	if (w->id != 0) {
		w->ctx->should_stop = true;
		gwnet_tcp_srv_ev_signal(w);
		pthread_join(w->thread, NULL);
	}

	if (w->ev_fd >= 0) {
		close(w->ev_fd);
		w->ev_fd = -1;
	}

	if (w->ep_fd >= 0) {
		close(w->ep_fd);
		w->ep_fd = -1;
	}
}

static void gwnet_tcp_srv_free_workers(struct gwnet_tcp_srv *s)
{
	struct gwnet_tcp_srv_wrk *workers = s->workers;
	uint16_t i;

	if (!workers)
		return;

	for (i = 0; i < s->nr_workers; i++)
		gwnet_tcp_srv_free_worker(&workers[i]);

	free(workers);
	s->workers = NULL;
	s->nr_workers = 0;
}

static int gwnet_tcp_srv_init_workers(struct gwnet_tcp_srv *s)
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

		ret = gwnet_tcp_srv_init_worker(&workers[i]);
		if (ret)
			goto free_workers;
	}

	s->workers = workers;
	s->nr_workers = cfg->nr_workers;

	return 0;
free_workers:
	s->should_stop = true;
	while (i--)
		gwnet_tcp_srv_free_worker(&workers[i]);

	free(workers);
	return ret;
}

static int gwnet_tcp_srv_get_client(struct gwnet_tcp_srv *ctx,
				    struct gwnet_tcp_cli **cp)
{
	struct gwnet_tcp_cli *c;
	uint16_t idx;
	int ret;

	ret = gwstack16_pop(&ctx->clients.stack, &idx);
	if (ret) {
		/*
		 * TODO(ammarfaizi2): Expand the client bucket if we
		 * run out of space.
		 */
		return -EAGAIN;
	}

	c = &ctx->clients.arr[idx];
	ret = gwbuf_init(&c->tx_buf, 0);
	if (ret)
		goto out_err;
	ret = gwbuf_init(&c->rx_buf, 0);
	if (ret)
		goto out_free_tx_buf;

	c->conn_id = atomic_fetch_add(&ctx->conn_id_gen, 1ull);
	*cp = c;
	return 0;

out_free_tx_buf:
	gwbuf_free(&c->tx_buf);
out_err:
	gwstack16_push(&ctx->clients.stack, idx);
	return ret;
}

static int gwnet_tcp_srv_put_client(struct gwnet_tcp_srv_wrk *w,
				    struct gwnet_tcp_cli *c)
{
	struct gwnet_tcp_srv *ctx = w->ctx;

	/*
	 * TODO(ammarfaizi2): Handle the client bucket expansion.
	 */
	gwnet_tcp_srv_free_client(c);
	gwstack16_push(&ctx->clients.stack, c - ctx->clients.arr);
	atomic_fetch_sub(&w->nr_on_clients, 1ull);

	if (unlikely(ctx->accept_stopped)) {
		int ret, ep_fd = ctx->workers[0].ep_fd;
		struct epoll_event ev;

		ctx->accept_stopped = false;
		ev.events = EPOLLIN;
		ev.data.u64 = GWNET_EPL_EV_ACCEPT;

		ret = epoll_ctl(ep_fd, EPOLL_CTL_MOD, ctx->fd, &ev);
		if (ret < 0)
			return -errno;

		if (w != &ctx->workers[0]) {
			ret = gwnet_tcp_srv_ev_signal(w);
			if (ret < 0)
				return ret;
		}
	}

	return 0;
}

static int gwnet_tcp_srv_handle_accept_err(struct gwnet_tcp_srv_wrk *w,
					   int err)
{
	struct gwnet_tcp_srv *ctx = w->ctx;

	if (err == -EAGAIN || err == -EINTR)
		return 0;

	if (err == -ENFILE || err == -EMFILE) {
		struct epoll_event ev;
		int ret;

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
		ret = epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, ctx->fd, &ev);
		if (ret < 0)
			ret = -errno;

		return ret;
	}

	return err;
}

static int gwnet_tcp_srv_pass_client(struct gwnet_tcp_srv_wrk *w_from,
				     struct gwnet_tcp_cli *c)
{
	static const uint16_t minimum_nr_clients = 16;
	struct gwnet_tcp_srv *ctx = w_from->ctx;
	struct gwnet_tcp_srv_wrk *w = NULL, *workers = ctx->workers;
	struct epoll_event ev;
	int ret;

	if (ctx->nr_workers == 1) {
		w = &workers[0];
	} else {
		uint16_t i, n, min = workers[0].nr_on_clients;

		for (i = 0; i < ctx->nr_workers; i++) {
			w = &workers[i];
			n = atomic_load(&w->nr_on_clients);

			if (n < minimum_nr_clients)
				break;

			if (n < min) {
				min = n;
				w = &workers[i];
			}
		}
	}

	ev.events = EPOLLIN;
	ev.data.u64 = 0;
	ev.data.ptr = c;
	ev.data.u64 |= GWNET_EPL_EV_CLIENT;
	ret = epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, c->fd, &ev);
	if (unlikely(ret < 0))
		return -errno;

	c->ep_mask = ev.events;
	atomic_fetch_add(&w->nr_on_clients, 1ull);
	if (w != w_from)
		return gwnet_tcp_srv_ev_signal(w);

	return 0;
}

static int gwnet_tcp_srv_handle_accept(struct gwnet_tcp_srv_wrk *w)
{
	struct sockaddr_storage addr;
	struct gwnet_tcp_srv *ctx;
	struct gwnet_tcp_cli *c;
	struct sockaddr *sa;
	int ret, fd;

	ctx = w->ctx;
	sa = (struct sockaddr *)&addr;
	fd = accept4(ctx->fd, sa, &ctx->addr_len, SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (unlikely(fd < 0))
		return gwnet_tcp_srv_handle_accept_err(w, -errno);

	ret = gwnet_tcp_srv_get_client(ctx, &c);
	if (unlikely(ret))
		goto out_close;

	c->fd = fd;
	if (sa->sa_family == AF_INET)
		c->addr.in = *(struct sockaddr_in *)sa;
	else
		c->addr.in6 = *(struct sockaddr_in6 *)sa;

	if (ctx->accept_cb) {
		ret = ctx->accept_cb(ctx->accept_cb_data, ctx, c);
		if (unlikely(ret < 0))
			goto out_put_client;
	}

	ret = gwnet_tcp_srv_pass_client(w, c);
	if (unlikely(ret < 0))
		goto out_put_client;

	return 0;

out_put_client:
	gwnet_tcp_srv_put_client(w, c);
out_close:
	close(fd);
	return 0;
}

static int gwnet_tcp_srv_handle_eventfd(struct gwnet_tcp_srv_wrk *w)
{
	uint64_t val;
	ssize_t ret;

	ret = read(w->ev_fd, &val, sizeof(val));
	if (unlikely(ret < 0)) {
		ret = -errno;
		if (ret == -EINTR || ret == -EAGAIN)
			return 0;

		return ret;
	}

	if (unlikely(ret != sizeof(val)))
		return -EIO;

	return 0;
}

static int gwnet_tcp_srv_do_recv(struct gwnet_tcp_cli *c)
{
	ssize_t ret;
	size_t len;
	char *buf;

	len = c->rx_buf.cap - c->rx_buf.len;
	if (!len) {
		ret = gwbuf_increase(&c->rx_buf, 1023);
		if (ret < 0)
			return ret;

		len = c->rx_buf.cap - c->rx_buf.len;
	}

	buf = c->rx_buf.buf + c->rx_buf.len;
	ret = recv(c->fd, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EAGAIN || ret == -EINTR)
			return 0;

		return ret;
	}

	if (ret == 0)
		return -ECONNRESET;

	c->rx_buf.len += ret;
	c->rx_buf.buf[c->rx_buf.len] = '\0';
	return 0;
}

static int gwnet_tcp_srv_do_send(struct gwnet_tcp_cli *c)
{
	struct gwbuf *t = &c->tx_buf;
	ssize_t sent;
	int err;

	if (t->len == 0)
		return 0;

	sent = send(c->fd, t->buf, t->len, MSG_NOSIGNAL | MSG_DONTWAIT);
	if (sent < 0) {
		err = -errno;
		if (err == -EAGAIN || err == -EINTR)
			return 0;

		return err;
	}

	if (sent == 0)
		return -ECONNRESET;

	gwbuf_advance(t, sent);
	return 0;
}

static int gwnet_tcp_srv_handle_client_in(struct gwnet_tcp_srv_wrk *w,
					  struct epoll_event *ev,
					  struct gwnet_tcp_cli *c)
{
	int ret = gwnet_tcp_srv_do_recv(c);
	if (ret < 0)
		return ret;

	if (c->post_recv_cb)
		ret = c->post_recv_cb(c->data, w->ctx, c, &c->rx_buf);

	if (c->tx_buf.len > 0)
		ev->events |= EPOLLOUT;

	return ret;
}

static int gwnet_tcp_srv_handle_client_out(struct gwnet_tcp_srv_wrk *w,
					   struct gwnet_tcp_cli *c)
{
	struct epoll_event ev_out;
	bool need_epctl = false;
	int ret;

	if (c->pre_send_cb) {
		ret = c->pre_send_cb(c->data, w->ctx, c, &c->tx_buf);
		if (ret < 0)
			return ret;
	}

	ret = gwnet_tcp_srv_do_send(c);
	if (ret < 0)
		return ret;

	if (c->post_send_cb) {
		ret = c->post_send_cb(c->data, w->ctx, c, &c->tx_buf);
		if (ret < 0)
			return ret;
	}

	if (c->tx_buf.len == 0 && (c->ep_mask & EPOLLOUT)) {
		ev_out.events = EPOLLIN;
		need_epctl = true;
	} else if (c->tx_buf.len > 0 && !(c->ep_mask & EPOLLOUT)) {
		ev_out.events = EPOLLOUT | EPOLLIN;
		need_epctl = true;
	}

	if (need_epctl) {
		c->ep_mask = ev_out.events;
		ev_out.data.u64 = 0;
		ev_out.data.ptr = c;
		ev_out.data.u64 |= GWNET_EPL_EV_CLIENT;
		ret = epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, c->fd, &ev_out);
		if (ret < 0)
			return -errno;
	}

	return 0;
}

static int gwnet_tcp_srv_handle_client(struct gwnet_tcp_srv_wrk *w,
				       struct epoll_event *ev)
{
	struct gwnet_tcp_cli *c = GWNET_EPL_EV_GET_PTR(ev->data.u64);
	int ret = 0;

	if (ev->events & EPOLLIN) {
		ret = gwnet_tcp_srv_handle_client_in(w, ev, c);
		if (ret)
			goto out_err;
	}

	if (ev->events & EPOLLOUT) {
		ret = gwnet_tcp_srv_handle_client_out(w, c);
		if (ret)
			goto out_err;
	}

	return 0;

out_err:
	ret = gwnet_tcp_srv_put_client(w, c);
	if (ret < 0)
		return ret;
	w->epl_need_rearm = true;
	return 0;
}

static int gwnet_tcp_srv_handle_event(struct gwnet_tcp_srv_wrk *w,
				      struct epoll_event *ev)
{
	uint64_t ev_type = GWNET_EPL_EV_GET_EV(ev->data.u64);
	int ret;

	switch (ev_type) {
	case GWNET_EPL_EV_ACCEPT:
		ret = gwnet_tcp_srv_handle_accept(w);
		break;
	case GWNET_EPL_EV_EVENTFD:
		ret = gwnet_tcp_srv_handle_eventfd(w);
		break;
	case GWNET_EPL_EV_CLIENT:
		ret = gwnet_tcp_srv_handle_client(w, ev);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int gwnet_tcp_srv_handle_events(int nr_events,
				       struct gwnet_tcp_srv_wrk *w)
{
	int ret = 0, i;

	for (i = 0; i < nr_events; i++) {
		struct epoll_event *ev = &w->events[i];

		ret = gwnet_tcp_srv_handle_event(w, ev);
		if (unlikely(ret))
			break;

		if (w->epl_need_rearm)
			break;
	}

	return ret;
}

static int gwnet_tcp_srv_poll_events(struct gwnet_tcp_srv_wrk *w)
{
	int ret;

	ret = epoll_wait(w->ep_fd, w->events, w->nr_events, -1);
	if (unlikely(ret < 0)) {
		ret = -errno;
		if (ret == -EINTR || ret == -EAGAIN)
			return 0;
	}

	return ret;
}

static void *gwnet_tcp_srv_worker_thread(void *arg)
{
	struct gwnet_tcp_srv_wrk *w = arg;
	struct gwnet_tcp_srv *s = w->ctx;
	void *ret_ptr;
	int ret = 0;

	while (!s->should_stop) {
		ret = gwnet_tcp_srv_poll_events(w);
		if (unlikely(ret < 0))
			break;

		ret = gwnet_tcp_srv_handle_events(ret, w);
		if (unlikely(ret < 0))
			break;
	}

	s->should_stop = true;
	ret_ptr = (void *)((intptr_t)ret);
	return ret_ptr;
}

static int gwnet_tcp_srv_validate_cfg(struct gwnet_tcp_srv_cfg *cfg)
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

	ret = gwnet_tcp_srv_validate_cfg(&s->cfg);
	if (ret < 0)
		goto free_s;

	ret = gwnet_tcp_srv_init_client_bucket(s);
	if (ret)
		goto free_s;

	ret = gwnet_tcp_srv_init_socket(s);
	if (ret)
		goto free_client_bucket;

	ret = gwnet_tcp_srv_init_workers(s);
	if (ret)
		goto free_socket;

	return s;

free_socket:
	gwnet_tcp_srv_free_socket(s);
free_client_bucket:
	gwnet_tcp_srv_free_client_bucket(s);
free_s:
	free(s);
	return NULL;
}

void gwnet_tcp_srv_free(gwnet_tcp_srv_t *s)
{
	if (!s)
		return;

	gwnet_tcp_srv_free_workers(s);
	gwnet_tcp_srv_free_socket(s);
	gwnet_tcp_srv_free_client_bucket(s);
	memset(s, 0, sizeof(*s));
}

int gwnet_tcp_srv_run(gwnet_tcp_srv_t *srv)
{
	return (intptr_t)gwnet_tcp_srv_worker_thread(&srv->workers[0]);
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
	c->data = data;
}

void gwnet_tcp_srv_set_accept_cb(gwnet_tcp_srv_t *s,
				 gwnet_tcp_srv_accept_t cb,
				 void *data)
{
	s->accept_cb = cb;
	s->accept_cb_data = data;
}

struct gwbuf *gwnet_tcp_srv_cli_get_tx_buf(gwnet_tcp_cli_t *c)
{
	return &c->tx_buf;
}

struct gwbuf *gwnet_tcp_srv_cli_get_rx_buf(gwnet_tcp_cli_t *c)
{
	return &c->rx_buf;
}
