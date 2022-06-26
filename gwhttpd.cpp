// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <cerrno>
#include <stack>
#include <mutex>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>

#define likely(COND)		__builtin_expect(!!(COND), 1)
#define unlikely(COND)		__builtin_expect(!!(COND), 0)
#define NR_EPOLL_EVT		32
#define NR_MAX_CLIENTS		4096
#define IPV4_LEN		(sizeof("xxx.xxx.xxx.xxx"))
#define FCIP			"%s:%u"
#define FCIP_ARG(P)		(P)->src_addr, (P)->src_port

enum http_method {
	HTTP_GET,
	HTTP_POST
};

struct client_sess {
	int			fd;
	size_t			buf_size;
	char			buf[4096];
	enum http_method	method;
	char			*uri;
	char			*http_ver;
	char			*body;
	bool			got_http_header;
	struct sockaddr_in	addr;
	uint16_t		src_port;
	char			src_addr[IPV4_LEN];
	uint32_t		idx;
};

struct server_state {
	volatile bool		stop;
	int			tcp_fd;
	int			epl_fd;
	struct epoll_event	events[NR_EPOLL_EVT];
	std::mutex		*sfi_lock;
	std::stack<uint32_t>	*sess_free_idx;
	struct client_sess	sess[NR_MAX_CLIENTS];

	/*
	 * Signal caught by the interrupt handler.
	 */
	int			sig;
};

static struct server_state *g_state;

static void interrupt_handler(int sig)
{
	if (!g_state)
		return;

	g_state->stop = true;
	g_state->sig = sig;
}

static int init_state(struct server_state *state)
{
	struct sigaction act;
	uint32_t i;
	int ret;

	memset(state, 0, sizeof(*state));
	state->tcp_fd = -1;
	state->epl_fd = -1;
	state->sig = -1;

	memset(&act, 0, sizeof(act));
	act.sa_handler = interrupt_handler;
	ret = sigaction(SIGINT, &act, NULL);
	ret |= sigaction(SIGHUP, &act, NULL);
	ret |= sigaction(SIGTERM, &act, NULL);
	act.sa_handler = SIG_IGN;
	ret |= sigaction(SIGPIPE, &act, NULL);
	if (ret) {
		fprintf(stderr, "Failed to set up the interrupt handler.\n");
		return ret;
	}

	state->sfi_lock = new std::mutex;
	if (!state->sfi_lock) {
		fprintf(stderr, "Cannot allocate mutex\n");
		return -ENOMEM;
	}

	state->sess_free_idx = new __typeof__(*state->sess_free_idx);
	if (!state->sess_free_idx) {
		fprintf(stderr, "Cannot allocate sess_free_idx\n");
		delete state->sfi_lock;
		return -ENOMEM;
	}

	for (i = NR_MAX_CLIENTS - 1; i--; ) {
		state->sess[i].fd = -1;
		state->sess[i].idx = i;
		state->sess_free_idx->push(i);
	}

	return 0;
}

static int init_socket(struct server_state *state, const char *addr,
		       uint16_t port)
{
	struct sockaddr_in saddr;
	int tcp_fd;
	int ret;
	int y;

	tcp_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (tcp_fd < 0) {
		ret = -errno;
		perror("socket");
		return ret;
	}

	y = 1;
	ret = setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&y, sizeof(y));
	if (ret < 0) {
		ret = -errno;
		perror("setsockopt");
		goto out_err;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	saddr.sin_addr.s_addr = inet_addr(addr);

	ret = bind(tcp_fd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret < 0) {
		ret = -errno;
		perror("bind");
		goto out_err;
	}

	ret = listen(tcp_fd, 1000);
	if (ret < 0) {
		ret = -errno;
		perror("listen");
		goto out_err;	
	}

	printf("Listening on %s:%u...\n", addr, port);
	state->tcp_fd = tcp_fd;
	return 0;

out_err:
	close(tcp_fd);
	return ret;
}

static int init_epoll(struct server_state *state)
{
	struct epoll_event evt;
	int epl_fd;
	int ret;

	epl_fd = epoll_create(255);
	if (epl_fd < 0) {
		ret = -errno;
		perror("epoll_create");
		return ret;
	}

	memset(&evt, 0, sizeof(evt));
	evt.events = EPOLLIN | EPOLLPRI;
	ret = epoll_ctl(epl_fd, EPOLL_CTL_ADD, state->tcp_fd, &evt);
	if (ret < 0) {
		ret = -errno;
		perror("epoll_ctl");
		return ret;
	}

	state->epl_fd = epl_fd;
	return 0;
}

static void put_sess_idx(uint32_t idx, struct server_state *state)
{
	state->sfi_lock->lock();
	state->sess_free_idx->push(idx);
	state->sfi_lock->unlock();
}

static int64_t get_sess_idx(struct server_state *state)
{
	int64_t ret;
	state->sfi_lock->lock();
	if (unlikely(state->sess_free_idx->empty())) {
		state->sfi_lock->unlock();
		return -EAGAIN;
	}
	ret = state->sess_free_idx->top();
	state->sess_free_idx->pop();
	state->sfi_lock->unlock();
	return ret;
}

static int delete_client(int epl_fd, struct client_sess *sess)
{
	int ret;

	ret = epoll_ctl(epl_fd, EPOLL_CTL_DEL, sess->fd, NULL);
	if (ret < 0) {
		ret = -errno;
		perror("epoll_ctl");
		return ret;
	}
	return 0;
}

static int register_new_client(int epl_fd, struct client_sess *sess)
{
	struct epoll_event evt;
	int ret;

	memset(&evt, 0, sizeof(evt));
	evt.events = EPOLLIN | EPOLLPRI;
	evt.data.ptr = (void *)sess;
	ret = epoll_ctl(epl_fd, EPOLL_CTL_ADD, sess->fd, &evt);
	if (ret < 0) {
		ret = -errno;
		perror("epoll_ctl");
		return ret;
	}
	return 0;
}

static int handle_new_client(struct server_state *state)
{	
	struct sockaddr_in caddr;
	socklen_t addrlen = sizeof(caddr);
	struct client_sess *sess;
	int64_t idx;
	int cli_fd;
	int ret;

	memset(&caddr, 0, sizeof(caddr));
	cli_fd = accept(state->tcp_fd, (struct sockaddr *)&caddr, &addrlen);
	if (unlikely(cli_fd < 0)) {
		ret = errno;
		perror("accept");
		if (ret == EAGAIN || ret == EMFILE)
			return 0;
		return -ret;
	}

	idx = get_sess_idx(state);
	if (unlikely(idx == -EAGAIN)) {
		close(cli_fd);
		fprintf(stderr, "Cannot handle a new client\n");
		return 0;
	}

	sess = &state->sess[idx];
	sess->fd = cli_fd;
	sess->buf_size = 0;
	sess->got_http_header = false;
	sess->addr = caddr;

	sess->src_addr[0] = '\0';
	sess->src_port = 0;
	if (addrlen <= sizeof(caddr)) {
		const char *p;
		sess->src_port = ntohs(caddr.sin_port);
		p = inet_ntop(AF_INET, &caddr.sin_addr.s_addr, sess->src_addr,
			      sizeof(sess->src_addr));
		if (!p) {
			perror("inet_ntop");
			fprintf(stderr, "inet_ntop() error?\n");
		}
	} else {
		fprintf(stderr, "Warning, accept overflow!\n");
	}

	ret = register_new_client(state->epl_fd, sess);
	if (unlikely(ret < 0))
		return ret;

	printf("Got a new client (idx = %u) " FCIP "\n", sess->idx,
		FCIP_ARG(sess));
	return 0;
}

static int parse_http_header(struct client_sess *sess)
{
	char *tmp;

	/*
	 * CRLF = Carriage Return, Line Feed.
	 */
	tmp = strstr(sess->buf, "\r\n\r\n");
	if (!tmp)
		return 0;

	sess->body = tmp + 4;
	if (!strncmp(sess->buf, "GET", sizeof("GET") - 1)) {
		sess->method = HTTP_GET;
		sess->uri = &sess->buf[sizeof("GET")];
	} else if (!strncmp(sess->buf, "POST", sizeof("POST") - 1)) {
		sess->method = HTTP_POST;
		sess->uri = &sess->buf[sizeof("POST")];
	} else {
		return -EBADMSG;
	}

	sess->http_ver = strstr(sess->uri, " ");
	if (!sess->http_ver)
		return -EBADMSG;

	sess->http_ver[0] = '\0';
	tmp = strstr(++sess->http_ver, "\r\n");
	tmp[0] = '\0';
	sess->got_http_header = true;
	return 0;
}

static void close_sess(struct client_sess *sess, struct server_state *state)
{
	printf("Closing session " FCIP " (idx = %u)\n", FCIP_ARG(sess),
		sess->idx);
	delete_client(state->epl_fd, sess);
	close(sess->fd);
	put_sess_idx(sess->idx, state);
}

static ssize_t send_to_client(struct client_sess *sess, const char *buf,
			      size_t len)
{
	ssize_t ret;
	int tmp;

repeat:
	ret = send(sess->fd, buf, len, MSG_DONTWAIT);
	if (unlikely(ret < 0)) {
		tmp = errno;
		if (tmp == EAGAIN)
			goto repeat;
		perror("send");
		return -tmp;
	} else if (unlikely(ret == 0)) {
		return -ENETDOWN;
	} else if (unlikely((size_t)ret < len)) {
		buf = &buf[len];
		len -= (size_t)ret;
		goto repeat;
	}
	return ret;
}

static void send_http_error(int code, struct client_sess *sess)
{
	char buf[128];
	int tmp;

	tmp = snprintf(buf, sizeof(buf),
			"HTTP/1.1 %d\r\n"
			"Content-Type: text/plain\r\n\r\n"
			"HTTP Error %d",
			code, code);
	send_to_client(sess, buf, (size_t)tmp);
}

#define HTTP_200_HTML "HTTP/1.1 200\r\nContent-Type: text/html\r\n\r\n"
#define HTTP_200_TEXT "HTTP/1.1 200\r\nContent-Type: text/plain\r\n\r\n"

static int route_show_index(struct client_sess *sess,
			    struct server_state *state)
{
	static const char buf[] =
		HTTP_200_HTML
		"<!DOCTYPE html>"
		"<html>"
			"<body>"
				"<h1>This is the index!</h1>"
			"</body>"
		"</html>";

	send_to_client(sess, buf, sizeof(buf) - 1);
	close_sess(sess, state);
	return 0;
}

static int route_show_hello(struct client_sess *sess,
			    struct server_state *state)
{
	static const char buf[] =
		HTTP_200_HTML
		"<!DOCTYPE html>"
		"<html>"
			"<body>"
				"<h1>Hello World!</h1>"
			"</body>"
		"</html>";

	send_to_client(sess, buf, sizeof(buf) - 1);
	close_sess(sess, state);
	return 0;
}

static int handle_route_get(struct client_sess *sess,
			    struct server_state *state)
{
	const char *uri = sess->uri;

	if (!strcmp(uri, "/"))
		return route_show_index(sess, state);
	if (!strcmp(uri, "/hello"))
		return route_show_hello(sess, state);

	send_http_error(404, sess);
	close_sess(sess, state);
	return 0;
}

static int route_show_echo(struct client_sess *sess, struct server_state *state)
{
	char buf[4096] = HTTP_200_TEXT;
	constexpr size_t max_body_len = sizeof(buf) - sizeof(HTTP_200_TEXT);

	size_t header_size = (size_t)(sess->body - sess->buf);
	size_t body_len = sess->buf_size - header_size;
	size_t send_len;

	if (body_len > max_body_len)
		body_len = max_body_len;

	send_len = body_len + sizeof(HTTP_200_TEXT) - 1;
	memcpy(&buf[sizeof(HTTP_200_TEXT) - 1], sess->body, body_len);
	send_to_client(sess, buf, send_len);
	close_sess(sess, state);
	return 0;
}

static int handle_route_post(struct client_sess *sess,
			     struct server_state *state)
{
	const char *uri = sess->uri;

	if (!strcmp(uri, "/echo"))
		return route_show_echo(sess, state);

	send_http_error(404, sess);
	close_sess(sess, state);
	return 0;
}

static int handle_route(struct client_sess *sess, struct server_state *state)
{
	int ret;

	switch (sess->method) {
	case HTTP_GET:
		ret = handle_route_get(sess, state);
		break;
	case HTTP_POST:
		ret = handle_route_post(sess, state);
		break;
	default:
		send_http_error(405, sess);
		close_sess(sess, state);
		return 0;
	}

	return ret;
}

static int _handle_client(struct client_sess *sess, struct server_state *state)
{
	int ret = 0;

	sess->buf[sess->buf_size] = '\0';
	if (!sess->got_http_header) {
		ret = parse_http_header(sess);
		if (ret) {
			send_http_error(400, sess);
			return 0;
		}
		if (!sess->got_http_header)
			return 0;
	}

	ret = handle_route(sess, state);
	if (ret) {
		close_sess(sess, state);
		if (likely(ret == -EBADMSG || ret == -ENETDOWN))
			ret = 0;
	}
	return ret;
}

static int handle_client(struct client_sess *sess, struct server_state *state)
{
	ssize_t recv_ret;
	size_t len;
	char *buf;
	int ret;

	len = sizeof(sess->buf) - sess->buf_size - 1;
	buf = &sess->buf[sess->buf_size];

	recv_ret = recv(sess->fd, buf, len, 0);
	if (unlikely(recv_ret < 0)) {
		ret = errno;
		if (ret == EAGAIN)
			return 0;
		perror("recv");
		return -ret;
	}

	if (unlikely(recv_ret == 0 && len != 0)) {
		close_sess(sess, state);
		return 0;
	}

	sess->buf_size += (size_t)recv_ret;
	return _handle_client(sess, state);
}

static int handle_event(struct epoll_event *event, struct server_state *state)
{
	int ret = 0;

	if (event->data.fd == 0) {
		ret = handle_new_client(state);
	} else {
		struct client_sess *sess =
			(struct client_sess *)event->data.ptr;

		ret = handle_client(sess, state);
	}

	return ret;
}

static int _run_server(int epl_fd, struct server_state *state)
{
	struct epoll_event *events = state->events;
	int ret;
	int i;

	ret = epoll_wait(epl_fd, events, NR_EPOLL_EVT, 1000);
	if (unlikely(ret < 0)) {
		ret = -errno;
		perror("epoll_wait");
		return ret;
	}

	for (i = 0; i < ret; i++) {
		ret = handle_event(&events[i], state);
		if (unlikely(ret))
			return ret;
	}

	return ret;
}

static int run_server(struct server_state *state)
{
	int epl_fd = state->epl_fd;
	int ret = 0;

	while (likely(!state->stop)) {
		ret = _run_server(epl_fd, state);
		if (unlikely(ret))
			break;
	}

	return ret;
}

static void destroy_state(struct server_state *state)
{
	uint32_t i;

	if (state->tcp_fd != -1)
		close(state->tcp_fd);
	if (state->epl_fd != -1)
		close(state->epl_fd);

	for (i = 0; i < NR_MAX_CLIENTS; i++) {
		int fd = state->sess[i].fd;
		if (fd != -1)
			close(fd);
	}

	delete state->sess_free_idx;
	delete state->sfi_lock;
#ifdef USE_ASAN
	delete state;
#else
	munmap(state, sizeof(*state));
#endif
	g_state = NULL;
}

/**
 *
 * ./gwhttpd 0.0.0.0 8000
 *
 */
int main(int argc, char *argv[])
{
	struct server_state *state;
	int ret;

	setvbuf(stdout, NULL, _IOLBF, 4096);

	if (argc != 3) {
		printf("Usage: %s [bind_address] [bind_port]\n", argv[0]);
		return 0;
	}

#ifdef USE_ASAN
	state = new struct server_state;
	if (!state) {
		perror("malloc");
		return ret;
	}
#else
	state = (struct server_state *)mmap(NULL, sizeof(*state),
					    PROT_READ|PROT_WRITE,
					    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (state == MAP_FAILED) {
		ret = errno;
		perror("mmap");
		return ret;
	}

	mlock(state, sizeof(*state));
#endif

	g_state = state;
	ret = init_state(state);
	if (ret)
		return ret;
	ret = init_socket(state, argv[1], (uint16_t)atoi(argv[2]));
	if (ret)
		goto out;
	ret = init_epoll(state);
	if (ret)
		goto out;

	ret = run_server(state);

out:
	destroy_state(state);
	if (ret < 0)
		ret = -ret;
	return ret;
}
