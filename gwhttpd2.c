// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdatomic.h>
#include <stdbool.h>
#include <stdarg.h>
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

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define MIN_T(TYPE, A, B)		\
({					\
	TYPE ___a = (A);		\
	TYPE ___b = (B);		\
	((___a < ___b) ? ___a : ___b);	\
})

#define pr_log(fmt, ...) printf(fmt, ##__VA_ARGS__)

struct gwsockaddr {
	union {
		struct sockaddr		sa;
		struct sockaddr_in	in;
		struct sockaddr_in6	in6;
	};
};

struct gwbuf {
	char	*buf;
	size_t	len;
	size_t	cap;
};

struct gwnet_tcp_srv;

struct gwnet_tcp_cli;

enum {
	GWNET_EPL_EV_ACCEPT	= (1ull << 48ull),
	GWNET_EPL_EV_EVENTFD	= (2ull << 48ull),
	GWNET_EPL_EV_CLIENT	= (3ull << 48ull),
};

#define GWNET_EPL_EV_ALL	(GWNET_EPL_EV_ACCEPT | GWNET_EPL_EV_EVENTFD \
			 	 | GWNET_EPL_EV_CLIENT)

#define GWNET_EPL_EV_GET_EV(ev)		((ev) & GWNET_EPL_EV_ALL)
#define GWNET_EPL_EV_GET_PTR(ev)	((void *)((ev) & ~GWNET_EPL_EV_ALL))

typedef int (*gwnet_tcp_cli_post_recv_t)(void *data, struct gwnet_tcp_srv *s,
					 struct gwnet_tcp_cli *c,
					 struct gwbuf *b);
typedef int (*gwnet_tcp_cli_pre_send_t)(void *data, struct gwnet_tcp_srv *s,
					struct gwnet_tcp_cli *c,
					struct gwbuf *b);
typedef int (*gwnet_tcp_cli_post_send_t)(void *data, struct gwnet_tcp_srv *s,
					 struct gwnet_tcp_cli *c,
					 struct gwbuf *b);
typedef void (*gwnet_tcp_cli_free_t)(void *data, struct gwnet_tcp_cli *c);
typedef int (*gwnet_tcp_srv_accept_t)(void *data, struct gwnet_tcp_srv *s,
				      struct gwnet_tcp_cli *c);

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

struct gwnet_tcp_srv_cfg {
	char				bind_addr[255];
	uint16_t			port;
	uint8_t				reuse_port;
	int				tcp_backlog;
	uint16_t			nr_workers;
	gwnet_tcp_srv_accept_t		accept_cb;
	void				*accept_cb_data;
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
};

static int gwbuf_init(struct gwbuf *b, size_t cap)
{
	if (cap == 0)
		cap = 1023;

	b->buf = malloc(cap + 1);
	if (!b->buf)
		return -ENOMEM;

	b->len = 0;
	b->cap = cap;
	b->buf[0] = b->buf[cap] = '\0';
	return 0;
}

static int gwbuf_increase(struct gwbuf *b, size_t inc)
{
	size_t new_cap = b->cap + inc;
	char *new_buf;

	if (new_cap < b->cap)
		return -ENOMEM; // Overflow

	new_buf = realloc(b->buf, new_cap + 1);
	if (!new_buf)
		return -ENOMEM;

	b->buf = new_buf;
	b->cap = new_cap;
	b->buf[b->len] = b->buf[b->cap] = '\0';
	return 0;
}

static void gwbuf_free(struct gwbuf *b)
{
	if (b->buf) {
		free(b->buf);
		b->buf = NULL;
		b->len = 0;
		b->cap = 0;
	}
}

static void gwbuf_advance(struct gwbuf *b, size_t len)
{
	if (len > b->len)
		return;

	if (len == b->len) {
		gwbuf_free(b);
		return;
	}

	memmove(b->buf, b->buf + len, b->len - len);
	b->len -= len;
	b->buf[b->len] = '\0';
}

static int gwbuf_set_cap(struct gwbuf *b, size_t cap)
{
	char *new_buf;

	if (cap == b->cap)
		return 0;

	new_buf = realloc(b->buf, cap + 1);
	if (!new_buf)
		return -ENOMEM;

	b->buf = new_buf;
	b->cap = cap;
	if (b->len > b->cap)
		b->len = b->cap;

	b->buf[b->len] = b->buf[b->cap] = '\0';
	return 0;
}

static int gwbuf_apfmt(struct gwbuf *b, const char *fmt, ...)
{
	va_list args, args2;
	int len, ret;

	va_start(args, fmt);
	va_copy(args2, args);
	len = vsnprintf(NULL, 0, fmt, args2);
	va_end(args2);

	ret = gwbuf_increase(b, len + 1);
	if (ret < 0)	
		goto out;

	ret = vsnprintf(b->buf + b->len, b->cap - b->len + 1, fmt, args);
	b->len += ret;
	b->buf[b->len] = '\0';
	ret = 0;
out:
	va_end(args);
	return ret;
}

static int gwbuf_append(struct gwbuf *b, const void *data, size_t len)
{
	static const size_t base_buf = 1023;

	if (b->len + len > b->cap) {
		size_t new_cap = b->cap ? b->cap * 2 : base_buf;
		char *new_buf;

		if (new_cap < b->len + len)
			new_cap = b->len + len + base_buf;

		new_buf = realloc(b->buf, new_cap + 1);
		if (!new_buf)
			return -ENOMEM;

		b->buf = new_buf;
		b->cap = new_cap;
	}

	memcpy(b->buf + b->len, data, len);
	b->len += len;
	b->buf[b->len] = b->buf[b->cap] = '\0';
	return 0;
}

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
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
		setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
	}
#endif

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

int gwnet_tcp_srv_init(struct gwnet_tcp_srv *s,
		       const struct gwnet_tcp_srv_cfg *cfg)
{
	int ret;

	if (!s || !cfg)
		return -EINVAL;

	memset(s, 0, sizeof(*s));
	s->fd = -1;
	s->cfg = *cfg;
	s->should_stop = false;

	ret = gwnet_tcp_srv_init_client_bucket(s);
	if (ret)
		return ret;

	ret = gwnet_tcp_srv_init_socket(s);
	if (ret)
		goto free_client_bucket;

	ret = gwnet_tcp_srv_init_workers(s);
	if (ret)
		goto free_socket;

	return 0;

free_socket:
	gwnet_tcp_srv_free_socket(s);
free_client_bucket:
	gwnet_tcp_srv_free_client_bucket(s);
	return ret;
}

static void gwnet_tcp_srv_free(struct gwnet_tcp_srv *s)
{
	if (!s)
		return;

	gwnet_tcp_srv_free_workers(s);
	gwnet_tcp_srv_free_socket(s);
	gwnet_tcp_srv_free_client_bucket(s);
	memset(s, 0, sizeof(*s));
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

	if (ctx->cfg.accept_cb) {
		ret = ctx->cfg.accept_cb(ctx->cfg.accept_cb_data, ctx, c);
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
	ssize_t ret;
	size_t len;
	char *buf;

	if (c->tx_buf.len == 0)
		return 0;

	len = c->tx_buf.len;
	buf = c->tx_buf.buf;

	ret = send(c->fd, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EAGAIN || ret == -EINTR)
			return 0;

		return ret;
	}

	if (!ret)
		return -ECONNRESET;

	gwbuf_advance(&c->tx_buf, ret);
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
					   struct epoll_event *ev,
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
		ret = gwnet_tcp_srv_handle_client_out(w, ev, c);
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

static int gwnet_tcp_srv_run(struct gwnet_tcp_srv *srv)
{
	return (intptr_t)gwnet_tcp_srv_worker_thread(&srv->workers[0]);
}

static void gwnet_tcp_srv_cli_set_post_recv_cb(struct gwnet_tcp_cli *c,
					       gwnet_tcp_cli_post_recv_t cb)
{
	c->post_recv_cb = cb;
}

static void gwnet_tcp_srv_cli_set_pre_send_cb(struct gwnet_tcp_cli *c,
					      gwnet_tcp_cli_pre_send_t cb)
{
	c->pre_send_cb = cb;
}

static void gwnet_tcp_srv_cli_set_post_send_cb(struct gwnet_tcp_cli *c,
					       gwnet_tcp_cli_post_send_t cb)
{
	c->post_send_cb = cb;
}

static void gwnet_tcp_srv_cli_set_free_cb(struct gwnet_tcp_cli *c,
					  gwnet_tcp_cli_free_t cb)
{
	c->free_cb = cb;
}

static void gwnet_tcp_srv_cli_set_data(struct gwnet_tcp_cli *c, void *data)
{
	c->data = data;
}

#define GWNET_HTTP_HEADER_MAX_LEN	8192
#define GWNET_HTTP_BODY_MAX_LEN		(1024 * 1024 * 10) // 10 MB

struct gwnet_http_srv_cfg {
	char				bind_addr[255];
	uint16_t			port;
	uint8_t				reuse_port;
	int				tcp_backlog;
	uint16_t			nr_workers;
};

struct gwnet_http_srv {
	struct gwnet_tcp_srv		tcp;
	struct gwnet_http_srv_cfg	cfg;
};

enum {
	GWNET_HTTP_CLI_ST_INIT		= 0,
	GWNET_HTTP_CLI_ST_REQ_HEADER	= 1,
	GWNET_HTTP_CLI_ST_REQ_BODY	= 2,
	GWNET_HTTP_CLI_ST_REQ_OK	= 3,
	GWNET_HTTP_CLI_ST_RES_HEADER	= 4,
	GWNET_HTTP_CLI_ST_RES_BODY	= 5,
	GWNET_HTTP_CLI_ST_RES_OK	= 6,
};

enum {
	GWNET_HTTP_VER_1_0	= 0,
	GWNET_HTTP_VER_1_1	= 1,
};

enum {
	GWNET_HTTP_METHOD_GET		= 0,
	GWNET_HTTP_METHOD_POST		= 1,
	GWNET_HTTP_METHOD_PUT		= 2,
	GWNET_HTTP_METHOD_DELETE	= 3,
	GWNET_HTTP_METHOD_HEAD		= 4,
	GWNET_HTTP_METHOD_OPTIONS	= 5,
	GWNET_HTTP_METHOD_PATCH		= 6,
	GWNET_HTTP_METHOD_TRACE		= 7,
	GWNET_HTTP_METHOD_CONNECT	= 8,
	GWNET_HTTP_METHOD_UNKNOWN	= 100,
};

enum {
	GWNET_HTTP_CHUNK_ST_NONE	= 0,
	GWNET_HTTP_CHUNK_ST_LEN		= 1,
	GWNET_HTTP_CHUNK_ST_DATA	= 2,
	GWNET_HTTP_CHUNK_ST_TRAILER	= 3,
	GWNET_HTTP_CHUNK_ST_END		= 4,
};

struct gwnet_http_hdr_pair {
	char	*key;
	char	*val;
};

struct gwnet_http_hdr {
	struct gwnet_http_hdr_pair	*pairs;
	size_t				nr_pairs;
};

struct gwnet_http_res {
	int			code;
	struct gwnet_http_hdr	hdr;
};

#define GWNET_HTTP_BODY_LEN_CHUNKED	((uint64_t)-1)

struct gwnet_http_req {
	uint8_t			method;
	uint8_t			version;
	uint8_t			chunk_state;
	bool			body_oversized;
	uint64_t		missing_body_len;
	struct gwbuf		body_buf;
	struct gwnet_http_hdr	hdr;
	struct gwnet_http_res	res;
	char			*uri;
	char			*qs;
	struct gwnet_http_req	*next;
};

struct gwnet_http_cli {
	uint8_t			state;
	bool			keep_alive;
	struct gwnet_http_srv	*srv;
	struct gwnet_http_req	*reqs;
	struct gwnet_http_req	*req_tail;
	uint16_t		nr_reqs;
};

static void gwnet_http_hdr_free(struct gwnet_http_hdr *hdr)
{
	size_t i;

	if (!hdr || !hdr->pairs)
		return;

	for (i = 0; i < hdr->nr_pairs; i++) {
		free(hdr->pairs[i].key);
		free(hdr->pairs[i].val);
	}

	free(hdr->pairs);
	hdr->pairs = NULL;
	hdr->nr_pairs = 0;
}

static int gwnet_http_hdr_find_idx(struct gwnet_http_hdr *hdr,
				   const char *key)
{
	size_t i;

	for (i = 0; i < hdr->nr_pairs; i++) {
		if (!strcmp(hdr->pairs[i].key, key))
			return i;
	}

	return -ENOENT;
}

static const char *gwnet_http_hdr_get_val(struct gwnet_http_hdr *hdr,
					  const char *key)
{
	int i = gwnet_http_hdr_find_idx(hdr, key);
	if (i < 0)
		return NULL;

	return hdr->pairs[i].val;
}

static int gwnet_http_hdr_add(struct gwnet_http_hdr *hdr, const char *key,
			      const char *val)
{
	struct gwnet_http_hdr_pair *new_pairs;
	size_t new_size;
	char *k, *v;
	int i;

	i = gwnet_http_hdr_find_idx(hdr, key);
	if (i >= 0) {
		free(hdr->pairs[i].val);
		hdr->pairs[i].val = strdup(val);
		if (!hdr->pairs[i].val)
			return -ENOMEM;
		return 0;
	}

	new_size = (hdr->nr_pairs + 1) * sizeof(*hdr->pairs);
	new_pairs = realloc(hdr->pairs, new_size);
	if (!new_pairs)
		return -ENOMEM;

	hdr->pairs = new_pairs;
	k = strdup(key);
	v = strdup(val);
	if (!k || !v) {
		free(k);
		free(v);
		return -ENOMEM;
	}

	hdr->pairs[hdr->nr_pairs].key = k;
	hdr->pairs[hdr->nr_pairs].val = v;
	hdr->nr_pairs++;
	return 0;
}

static struct gwnet_http_req *gwnet_http_req_alloc(void)
{
	return calloc(1, sizeof(struct gwnet_http_req));
}

static void gwnet_http_req_plug(struct gwnet_http_req *req,
				struct gwnet_http_cli *hc)
{
	if (!hc->reqs) {
		hc->reqs = hc->req_tail = req;
		hc->nr_reqs++;
		return;
	}

	hc->req_tail->next = req;
	hc->req_tail = req;
	hc->nr_reqs++;
}

static void gwnet_http_reqs_free(struct gwnet_http_req *req)
{
	struct gwnet_http_req *cur;
	if (!req)
		return;

	cur = req;
	while (cur) {
		struct gwnet_http_req *next = cur->next;

		gwnet_http_hdr_free(&cur->hdr);
		gwnet_http_hdr_free(&cur->res.hdr);
		gwbuf_free(&cur->body_buf);
		free(cur->uri);
		free(cur->qs);
		free(cur);
		cur = next;
	}
}

static struct gwnet_http_cli *gwnet_http_cli_alloc(struct gwnet_http_srv *srv)
{
	struct gwnet_http_cli *hc = calloc(1, sizeof(*hc));
	if (!hc)
		return NULL;

	hc->state = GWNET_HTTP_CLI_ST_INIT;
	hc->reqs = NULL;
	hc->nr_reqs = 0;
	hc->srv = srv;
	return hc;
}

static void gwnet_http_cli_free(struct gwnet_http_cli *hc)
{
	struct gwnet_http_req *req, *cur;

	if (hc) {
		gwnet_http_reqs_free(hc->reqs);
		free(hc);
	}
}

static int gwnet_http_recv_cb_init(struct gwnet_http_cli *hc, struct gwbuf *b)
{
	struct gwnet_http_req *req = gwnet_http_req_alloc();
	if (!req)
		return -ENOMEM;

	gwnet_http_req_plug(req, hc);
	hc->state = GWNET_HTTP_CLI_ST_REQ_HEADER;
	return 0;
}

static void c_strtolower(char *str)
{
	char *p = str;
	while (*p) {
		if (*p >= 'A' && *p <= 'Z')
			*p += ('a' - 'A');
		p++;
	}
}

static int gwnet_http_recv_cb_req_header(struct gwnet_http_cli *hc,
					 struct gwbuf *b)
{
	char *qs, *uri, *x, *ver, *end, *line, *next;
	struct gwnet_http_req *req = hc->req_tail;
	size_t len = b->len;

	/*
	 * b->buf is always null-terminated, so we can safely
	 * strncmp() it.
	 */
	#define IF_HDR_CMP_METHOD(METHOD, RET) \
	if (!strncmp(b->buf, #METHOD " ", len > (sizeof(#METHOD) - 1) ? \
			(sizeof(#METHOD) - 1) : len)) { \
		uri = b->buf + (sizeof(#METHOD) - 1) + 1; \
		req->method = GWNET_HTTP_METHOD_##METHOD; \
		if (RET) \
			return RET; \
	}

	/*
	 * TODO(amamrfaizi2): Add more HTTP method supports.
	 */
	IF_HDR_CMP_METHOD(GET, 0) else
	IF_HDR_CMP_METHOD(POST, 0) else
	IF_HDR_CMP_METHOD(PUT, -EINVAL) else
	IF_HDR_CMP_METHOD(DELETE, -EINVAL) else
	IF_HDR_CMP_METHOD(HEAD, -EINVAL) else
	IF_HDR_CMP_METHOD(OPTIONS, -EINVAL) else
	IF_HDR_CMP_METHOD(PATCH, -EINVAL) else
	IF_HDR_CMP_METHOD(TRACE, -EINVAL) else
	IF_HDR_CMP_METHOD(CONNECT, -EINVAL) else {
		req->method = GWNET_HTTP_METHOD_UNKNOWN;
		return -EINVAL;
	}

	#undef IF_HDR_CMP_METHOD

	/*
	 * Shortest possible HTTP header.
	 *
	 *    "GET / HTTP/1.0\r\n\r\n"
	 *
	 * It is 18 characters long.
	 */
	if (len < 18)
		return -EAGAIN;

	/*
	 * Find the end of header, double CRLF.
	 */
	end = strstr(b->buf, "\r\n\r\n");
	if (!end)
		return (len > GWNET_HTTP_HEADER_MAX_LEN) ? -EINVAL : -EAGAIN;
	end += 4;

	/*
	 * The request URI must start with a slash.
	 */
	if (*uri != '/')
		return -EINVAL;

	/*
	 * Find the space between the URI and the HTTP version.
	 */
	x = strchr(uri, ' ');
	if (!x)
		return -EINVAL;
	*x = '\0';

	/*
	 * The URI is now a null-terminated string, now split the path
	 * and the query string.
	 *
	 * `qs` will point to the query string if it exists,
	 * otherwise it will be NULL.
	 */
	qs = strchr(uri, '?');
	if (qs) {
		*qs = '\0';
		qs++;
	}

	/*
	 * Parse the HTTP version.
	 */
	ver = x + 1;
	if (!strncmp(ver, "HTTP/", 5)) {
		if (!strncmp(ver + 5, "1.0", 3)) {
			req->version = GWNET_HTTP_VER_1_0;
			hc->keep_alive = false;
		} else if (!strncmp(ver + 5, "1.1", 3)) {
			req->version = GWNET_HTTP_VER_1_1;
			hc->keep_alive = true;
		} else {
			return -EINVAL;
		}
	} else {
		return -EINVAL;
	}

	/*
	 * Prepare a pointer to the second line of the HTTP header.
	 */
	line = ver + 8;	/* Skip "HTTP/1.x" */
	if (strncmp(line, "\r\n", 2))
		return -EINVAL;
	line += 2;
	/*
	 * Now we have the method, URI, query string and version.
	 */
	req->uri = strdup(uri);
	req->qs = qs ? strdup(qs) : NULL;
	if (!req->uri || (qs && !req->qs)) {
		free(req->uri);
		free(req->qs);
		return -ENOMEM;
	}

	/*
	 * Parse HTTP header key-val pairs.
	 */
	while (1) {
		char *k, *v;
		int ret;

		next = strstr(line, "\r\n");
		if (!next)
			return -EINVAL;
		if (next >= end)
			return -EINVAL;

		*next = '\0';
		k = line;
		v = strchr(k, ':');
		if (!v || v == k)
			return -EINVAL;

		*v = '\0';
		v++;

		/*
		 * Skip leading spaces.
		 */
		while (*v == ' ')
			v++;

		c_strtolower(k);
		if (!strcmp(k, "connection")) {
			c_strtolower(v);
			if (strstr(v, "keep-alive"))
				hc->keep_alive = true;
			else if (strstr(v, "close"))
				hc->keep_alive = false;
			else
				return -EINVAL;
		} else if (!strcmp(k, "content-length")) {
			char *ep;
			req->missing_body_len = strtoull(v, &ep, 10);
			if (*ep != '\0')
				return -EINVAL;
		} else if (!strcmp(k, "transfer-encoding")) {
			if (strstr(v, "chunked")) {
				req->missing_body_len = 0;
				req->chunk_state = GWNET_HTTP_CHUNK_ST_LEN;
			} else {
				return -EINVAL;
			}
		}

		ret = gwnet_http_hdr_add(&req->hdr, k, v);
		if (ret < 0)
			return ret;

		line = next + 2;
		if (!strncmp(line, "\r\n", 2))
			break;
	}

	if (req->missing_body_len || req->chunk_state != GWNET_HTTP_CHUNK_ST_NONE) {
		size_t alloc = req->missing_body_len;
		if (alloc > GWNET_HTTP_BODY_MAX_LEN)
			alloc = GWNET_HTTP_BODY_MAX_LEN;
		if (gwbuf_init(&req->body_buf, alloc) < 0)
			return -ENOMEM;
		hc->state = GWNET_HTTP_CLI_ST_REQ_BODY;
	} else {
		hc->state = GWNET_HTTP_CLI_ST_REQ_OK;
	}

	gwbuf_advance(b, end - b->buf);
	return 0;
}

static bool str_is_hexdigit(const char *x)
{
	while (1) {
		char c = *x;
		if (!c)
			break;

		if (!((c >= '0' && c <= '9') ||
		      (c >= 'a' && c <= 'f') ||
		      (c >= 'A' && c <= 'F')))
			return false;

		x++;
	}
	return true;
}

static int

gwnet_http_recv_cb_req_body_chunked_len(struct gwnet_http_req *req,
					   struct gwbuf *b)
{
	char *cr, *endp;

	assert(req->missing_body_len == 0);

	/*
	 * Shortest chunk size is 1 hex digit plus CRLF (3 bytes).
	 */
	if (b->len < 3)
		return -EAGAIN;

	/*
	 * Look for CR marking end of hex length field.
	 */
	cr = memchr(b->buf, '\r', b->len);
	if (!cr) {
		/*
		 * Too many hex digits or invalid character?
		 */
		if (b->len > 16 || !str_is_hexdigit(b->buf))
			return -EINVAL;

		/*
		 * Still waiting for CRLF.
		 */
		return -EAGAIN;
	}

	/*
	 * Ensure LF follows CR and is within buffer.
	 */
	if ((size_t)(cr - b->buf) + 2 > b->len)
		return -EAGAIN;
	if (cr[1] != '\n')
		return -EINVAL;

	/*
	 * Null-terminate the length string and parse.
	 */
	*cr = '\0';
	req->missing_body_len = strtoull(b->buf, &endp, 16);
	if (*endp != '\0')
		return -EINVAL;

	req->chunk_state =
		req->missing_body_len == 0 ?
			GWNET_HTTP_CHUNK_ST_END :
			GWNET_HTTP_CHUNK_ST_DATA;

	/*
	 * Consume the length line and CRLF.
	 */
	gwbuf_advance(b, (cr - b->buf) + 2);
	return 0;
}

static int __gwnet_http_recv_cb_req_body(struct gwnet_http_req *req,
					 struct gwbuf *b)
{
	struct gwbuf *bb = &req->body_buf;
	size_t to_advance, to_copy;
	int ret;

	to_copy = to_advance = MIN_T(size_t, b->len, req->missing_body_len);

	if (req->body_oversized)
		goto out;

	if (to_copy + bb->len > GWNET_HTTP_BODY_MAX_LEN) {
		/*
		 * This append would make the body oversized,
		 * so we just copy the maximum amount of data
		 * that would fit and mark the request as oversized.
		 */
		req->body_oversized = true;
		to_copy = GWNET_HTTP_BODY_MAX_LEN - bb->len;
	}

	if (to_copy > 0) {
		ret = gwbuf_append(bb, b->buf, to_copy);
		if (ret < 0)
			return ret;
	}

out:
	req->missing_body_len -= to_advance;
	gwbuf_advance(b, to_advance);
	return req->missing_body_len > 0 ? -EAGAIN : 0;
}

static int gwnet_http_recv_cb_req_body_chunked_data(struct gwnet_http_req *req,
						    struct gwbuf *b)
{
	int ret;

	ret = __gwnet_http_recv_cb_req_body(req, b);
	if (ret < 0)
		return ret;

	if (req->missing_body_len == 0)
		req->chunk_state = GWNET_HTTP_CHUNK_ST_TRAILER;

	return 0;
}

static int gwnet_http_recv_cb_req_body_chunked_tr(struct gwnet_http_req *req,
						  struct gwbuf *b)
{
	size_t cmp_len;

	assert(req->missing_body_len == 0);
	if (b->len == 0)
		return -EAGAIN;
	cmp_len = b->len < 2 ? b->len : 2;
	if (memcmp(b->buf, "\r\n", cmp_len) != 0)
		return -EINVAL;
	if (b->len < 2)
		return -EAGAIN;

	gwbuf_advance(b, 2);
	if (req->chunk_state != GWNET_HTTP_CHUNK_ST_END)
		req->chunk_state = GWNET_HTTP_CHUNK_ST_LEN;

	return 0;
}

static int gwnet_http_recv_cb_req_body_chunked(struct gwnet_http_cli *hc,
					       struct gwbuf *b)
{
	struct gwnet_http_req *req = hc->req_tail;
	int ret = 0;

	while (1) {
		if (ret)
			break;
		if (!b->len) {
			ret = -EAGAIN;
			break;
		}
		if (hc->state != GWNET_HTTP_CLI_ST_REQ_BODY)
			break;

		switch (req->chunk_state) {
		case GWNET_HTTP_CHUNK_ST_LEN:
			ret = gwnet_http_recv_cb_req_body_chunked_len(req, b);
			break;
		case GWNET_HTTP_CHUNK_ST_DATA:
			ret = gwnet_http_recv_cb_req_body_chunked_data(req, b);
			break;
		case GWNET_HTTP_CHUNK_ST_TRAILER:
			ret = gwnet_http_recv_cb_req_body_chunked_tr(req, b);
			break;
		case GWNET_HTTP_CHUNK_ST_END:
			ret = gwnet_http_recv_cb_req_body_chunked_tr(req, b);
			if (!ret)
				hc->state = GWNET_HTTP_CLI_ST_REQ_OK;
			goto out;
		default:
			ret = -EINVAL;
			break;
		}
	}

out:
	return ret;
}

static int gwnet_http_recv_cb_req_body(struct gwnet_http_cli *hc,
				       struct gwbuf *b)
{
	struct gwnet_http_req *req = hc->req_tail;
	int ret;

	if (req->chunk_state != GWNET_HTTP_CHUNK_ST_NONE)
		return gwnet_http_recv_cb_req_body_chunked(hc, b);

	ret = __gwnet_http_recv_cb_req_body(hc->req_tail, b);
	if (ret < 0)
		return ret;

	if (req->missing_body_len == 0)
		hc->state = GWNET_HTTP_CLI_ST_REQ_OK;

	return 0;
}

static int gwnet_http_recv_cb_req_ok(struct gwnet_tcp_cli *c,
				     struct gwnet_http_cli *hc,
				     struct gwbuf *b)
{
	struct gwnet_http_req *req = hc->req_tail;
	struct gwbuf *s = &c->tx_buf;
	int r = 0;

	r |= gwbuf_apfmt(s, "HTTP/1.%d 200 OK\r\n", req->version);
	r |= gwbuf_apfmt(s, "Content-Length: 13\r\n");
	r |= gwbuf_apfmt(s, "Content-Type: text/plain\r\n");
	r |= gwbuf_apfmt(s, "Connection: %s\r\n", hc->keep_alive ? "keep-alive" : "close");
	r |= gwbuf_apfmt(s, "\r\n");
	r |= gwbuf_apfmt(s, "Hello World!\n");

	hc->state = GWNET_HTTP_CLI_ST_INIT;
	return r;
}

static int gwnet_http_recv_cb(void *data, struct gwnet_tcp_srv *s,
			      struct gwnet_tcp_cli *c, struct gwbuf *b)
{
	struct gwnet_http_cli *hc = data;
	int ret = 0;

	while (b->len > 0) {
		switch (hc->state) {
		case GWNET_HTTP_CLI_ST_INIT:
			ret = gwnet_http_recv_cb_init(hc, b);
			break;
		case GWNET_HTTP_CLI_ST_REQ_HEADER:
			ret = gwnet_http_recv_cb_req_header(hc, b);
			break;
		case GWNET_HTTP_CLI_ST_REQ_BODY:
			ret = gwnet_http_recv_cb_req_body(hc, b);
			break;
		default:
			ret = -EINVAL;
			break;
		}

		if (ret == -EAGAIN) {
			ret = 0;
			break;
		}

		if (!ret && hc->state == GWNET_HTTP_CLI_ST_REQ_OK) {
			/*
			 * We have a complete request, process it!
			 */
			ret = gwnet_http_recv_cb_req_ok(c, hc, b);
		}

		if (ret < 0)
			break;
	}

	return ret;
}

static int gwnet_http_send_cb(void *data, struct gwnet_tcp_srv *s,
			      struct gwnet_tcp_cli *c, struct gwbuf *b)
{
	return 0;
}

static int gwnet_http_send_cb_post(void *data, struct gwnet_tcp_srv *s,
				   struct gwnet_tcp_cli *c, struct gwbuf *b)
{
	struct gwnet_http_cli *hc = data;

	if (b->len == 0 && !hc->keep_alive)
		return -ECONNRESET;

	return 0;
}

static void gwnet_http_cli_free_cb(void *data, struct gwnet_tcp_cli *c)
{
	struct gwnet_http_cli *hc = data;
	gwnet_http_cli_free(hc);
}

static int gwnet_http_accept_cb(void *data, struct gwnet_tcp_srv *s,
				struct gwnet_tcp_cli *c)
{
	struct gwnet_http_srv *srv = data;
	struct gwnet_http_cli *hc;

	hc = gwnet_http_cli_alloc(srv);
	if (!hc)
		return -ENOMEM;

	gwnet_tcp_srv_cli_set_data(c, hc);
	gwnet_tcp_srv_cli_set_post_recv_cb(c, gwnet_http_recv_cb);
	gwnet_tcp_srv_cli_set_pre_send_cb(c, gwnet_http_send_cb);
	gwnet_tcp_srv_cli_set_post_send_cb(c, gwnet_http_send_cb_post);
	gwnet_tcp_srv_cli_set_free_cb(c, gwnet_http_cli_free_cb);
	return 0;
}

static int gwnet_http_srv_init(struct gwnet_http_srv *srv,
			       const struct gwnet_http_srv_cfg *cfg)
{
	struct gwnet_tcp_srv_cfg tc = {
		.bind_addr = "",
		.reuse_port = cfg->reuse_port,
		.port = cfg->port,
		.tcp_backlog = cfg->tcp_backlog,
		.nr_workers = cfg->nr_workers,
		.accept_cb = gwnet_http_accept_cb,
		.accept_cb_data = srv,
	};

	strncpy(tc.bind_addr, cfg->bind_addr, sizeof(tc.bind_addr) - 1);
	tc.bind_addr[sizeof(tc.bind_addr) - 1] = '\0';
	return gwnet_tcp_srv_init(&srv->tcp, &tc);
}

static int gwnet_http_srv_run(struct gwnet_http_srv *srv)
{
	return gwnet_tcp_srv_run(&srv->tcp);
}

static void gwnet_http_srv_free(struct gwnet_http_srv *srv)
{
	if (!srv)
		return;

	gwnet_tcp_srv_free(&srv->tcp);
	memset(srv, 0, sizeof(*srv));
}

int main(int argc, char *argv[])
{
	static const struct gwnet_http_srv_cfg cfg = {
		.bind_addr = "::",
		.port = 8080,
		.reuse_port = 1,
		.tcp_backlog = 128,
		.nr_workers = 4,
	};
	struct gwnet_http_srv srv;
	int ret;

	ret = gwnet_http_srv_init(&srv, &cfg);
	if (ret < 0) {
		pr_log("Failed to initialize HTTP server: %s\n", strerror(-ret));
		return -ret;
	}

	ret = gwnet_http_srv_run(&srv);
	if (ret < 0)
		pr_log("Failed to run HTTP server: %s\n", strerror(-ret));

	gwnet_http_srv_free(&srv);
	return -ret;
}
