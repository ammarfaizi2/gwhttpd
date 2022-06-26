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
#include <queue>
#include <mutex>
#include <dirent.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>

#define likely(COND)		__builtin_expect(!!(COND), 1)
#define unlikely(COND)		__builtin_expect(!!(COND), 0)
#define NR_EPOLL_EVT		128
#define NR_MAX_CLIENTS		4096
#define IPV4_LEN		(sizeof("xxx.xxx.xxx.xxx"))
#define FCIP			"%s:%u"
#define FCIP_ARG(P)		(P)->src_addr, (P)->src_port

enum http_method {
	HTTP_GET,
	HTTP_POST,
	HTTP_PATCH,
	HTTP_PUT,
	HTTP_DELETE,
};

enum http_action {
	HTTP_ACT_NONE = 0,
	HTTP_ACT_DIRLIST,
	HTTP_ACT_FILE_STREAM,
};

struct dir_list_data {
	char			pathname[4096];
	DIR			*dr;
};

struct client_sess {
	int			fd;
	enum http_method	method;
	char			*uri;
	char			*qs;
	char			*http_ver;
	char			*body;
	struct sockaddr_in	addr;
	uint16_t		src_port;
	uint32_t		idx;
	bool			got_http_header;
	char			src_addr[IPV4_LEN];
	size_t			buf_size;
	char			buf[4096];
	enum http_action	action;
	void			*private_data;
};

struct server_state {
	volatile bool		stop;
	int			tcp_fd;
	int			epl_fd;
	struct epoll_event	events[NR_EPOLL_EVT];
	std::mutex		*sfi_lock;
	std::stack<uint32_t>	*sess_free_idx;
	std::mutex		*bq_lock;
	std::queue<uint32_t>	*buf_queue;
	struct client_sess	sess[NR_MAX_CLIENTS];

	/*
	 * Signal caught by the interrupt handler.
	 */
	int			sig;
};

static struct server_state *g_state;

static void interrupt_handler(int sig)
{
	putchar('\n');
	printf("Got signal: %d\n", sig);
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
		fprintf(stderr, "Cannot allocate sfi_lock\n");
		return -ENOMEM;
	}

	state->bq_lock = new std::mutex;
	if (!state->sfi_lock) {
		fprintf(stderr, "Cannot allocate bq_lock\n");
		goto out_err_bq_lock;
	}

	state->sess_free_idx = new __typeof__(*state->sess_free_idx);
	if (!state->sess_free_idx) {
		fprintf(stderr, "Cannot allocate sess_free_idx\n");
		goto out_err_sess_free_idx;
	}

	state->buf_queue = new __typeof__(*state->buf_queue);
	if (!state->buf_queue) {
		fprintf(stderr, "Cannot allocate buf_queue\n");
		goto out_err_buf_queue;
	}

	for (i = NR_MAX_CLIENTS - 1; i--; ) {
		state->sess[i].fd = -1;
		state->sess[i].idx = i;
		state->sess_free_idx->push(i);
	}

	return 0;

out_err_buf_queue:
	delete state->sess_free_idx;
out_err_sess_free_idx:
	delete state->bq_lock;
out_err_bq_lock:
	delete state->sfi_lock;
	return -ENOMEM;
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
		if (ret == EAGAIN)
			return -EAGAIN;
		perror("accept");
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
	sess->action = HTTP_ACT_NONE;

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

static ssize_t send_to_client(struct client_sess *sess, const char *buf,
			      size_t len)
{
	constexpr uint32_t max_try = 10;
	uint32_t try_count = 0;
	ssize_t ret;
	int tmp;

repeat:
	if (unlikely(try_count++ >= max_try))
		return -ENETDOWN;
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
			"Connection: closed\r\n\r\n"
			"Content-Type: text/plain\r\n\r\n"
			"HTTP Error %d",
			code, code);
	send_to_client(sess, buf, (size_t)tmp);
}

static char *parse_http_method(char *buf, enum http_method *method_p)
{
	if (!strncmp("GET ", buf, sizeof("GET"))) {
		*method_p = HTTP_GET;
		return buf + sizeof("GET");
	}

	if (!strncmp("POST ", buf, sizeof("POST"))) {
		*method_p = HTTP_POST;
		return buf + sizeof("POST");
	}

	if (!strncmp("PUT ", buf, sizeof("PUT"))) {
		*method_p = HTTP_PUT;
		return buf + sizeof("PUT");
	}

	if (!strncmp("PATCH ", buf, sizeof("PATCH"))) {
		*method_p = HTTP_PATCH;
		return buf + sizeof("PATCH");
	}

	if (!strncmp("DELETE ", buf, sizeof("DELETE"))) {
		*method_p = HTTP_DELETE;
		return buf + sizeof("DELETE");
	}

	return NULL;
}

static char *parse_query_string(char *uri, char *end_uri)
{
	while (uri < end_uri) {
		if (*uri++ != '?')
			continue;
		if (uri == end_uri)
			/*
			 * We got an empty query string:
			 *  "http://somehwere.com/path?"
			 */
			return NULL;
		return uri;
	}
	return NULL;
}

static int parse_http_header(struct client_sess *sess)
{
	char *buf = sess->buf;
	char *end;
	char *ret;

	/*
	 * Split the HTTP header and HTTP body.
	 */
	ret = strstr(buf, "\r\n\r\n");
	if (!ret) {
		/*
		 * If we fail here, we may got a partial packet.
		 * Don't fail here if still have enough buffer,
		 * we will wait for the next recv() iteration.
		 */
		if (sess->buf_size >= sizeof(sess->buf) - 1)
			goto bad_req;

		return 0;
	}
	end = ret;

	/*
	 * The HTTP body is located right after "\r\n\r\n".
	 */
	sess->body = &ret[4];

	ret = parse_http_method(buf, &sess->method);
	if (unlikely(!ret))
		goto bad_req;

	/*
	 * Now @ret is pointing to URI. For example:
	 *
	 *  "GET / HTTP/1.1"
	 *       ^
	 *     @ret
	 */
	sess->uri = ret;
	ret = strstr(sess->uri, " ");
	if (unlikely(!ret))
		goto bad_req;

	ret[0] = '\0';
	if (unlikely(&ret[1] >= end))
		goto bad_req;

	sess->qs = parse_query_string(sess->uri, end);
	ret = strstr(&ret[1], "HTTP/");
	if (unlikely(!ret))
		goto bad_req;

	sess->http_ver = ret;
	ret = strstr(sess->http_ver, "\r\n");
	if (unlikely(!ret))
		goto bad_req;

	ret[0] = '\0';
	sess->got_http_header = true;
	return 0;

bad_req:
	send_http_error(400, sess);
	return -EBADMSG;
}

static void close_sess(struct client_sess *sess, struct server_state *state)
{
	printf("Closing session " FCIP " (idx = %u)\n", FCIP_ARG(sess),
		sess->idx);
	delete_client(state->epl_fd, sess);
	close(sess->fd);
	sess->action = HTTP_ACT_NONE;
	put_sess_idx(sess->idx, state);
}

static int construct_file_list(char *buf, size_t buf_size, const char *path,
			       const char *file)
{
	char pathname[4352];
	const char *ftype;
	struct stat st;
	int ret;

	snprintf(pathname, sizeof(pathname), "%s/%s", path, file);
	ret = stat(pathname, &st);
	if (unlikely(ret < 0)) {
		ret = errno;
		fprintf(stderr, "Cannot open \"%s\": %s\n", pathname,
			strerror(ret));
		return -ret;
	}

	if (st.st_mode & S_IFDIR)
		ftype = "Directory";
	else if (st.st_mode & S_IFREG)
		ftype = "Regular File";
	else
		return -ENOTSUP;

	return snprintf(
		buf,
		buf_size,
		"\t\t<tr>"
			"<td><a href=\"%s%s\">%s</a></td>"
			"<td>%s</td>"
			"<td>%d%d%d%d</td>"
		"</tr>\n",
		file, (st.st_mode & S_IFDIR) ? "/" : "", file,
		ftype,
		(st.st_mode & 07000) >> 9,
		(st.st_mode & 00700) >> 6,
		(st.st_mode & 00070) >> 3,
		(st.st_mode & 00007)
	);
}

static int send_http_forbidden(struct client_sess *sess)
{
	static const char buf[] =
		"HTTP/1.1 403 Forbidden\r\n"
		"Content-Type: text/html\r\n"
		"Connection: closed\r\n\r\n"
		"<!DOCTYPE html>"
		"<html>"
		"<body>"
		"<h1>403 Forbidden</h1>"
		"</body>"
		"</html>\n";

	return send_to_client(sess, buf, sizeof(buf) - 1);
}

static int show_directory_listing(const char *path, struct client_sess *sess,
				  struct server_state *state)
{
	static const char dl_head[] =
		"HTTP/1.1 200\r\n"
		"Content-Type: text/html\r\n"
		"Connection: closed\r\n\r\n"
		"<!DOCTYPE html>\n"
		"<html>\n"
		"<style type=\"text/css\">"
			"td {padding: 10px;}"
			"a {color: blue; text-decoration: none}"
			"a:hover {text-decoration: underline}"
		"</style>"
		"<body>\n"
		"\t<h1>GNU/Weeb HTTP Server</h1>\n"
		"\t<table border=\"1\">\n"
		"\t\t<tr>"
			"<th>Filename</th>"
			"<th>Type</th>"
			"<th>Mode</th>"
		"</tr>\n";


	struct dir_list_data *pdata = NULL;
	char buf[1024 * 512];
	constexpr size_t buf_max = sizeof(buf) / 2;
	size_t buf_len;
	DIR *dr;
	char *p;
	int ret;

	if (!sess->action) {
		dr = opendir(path);
		if (unlikely(!dr)) {
			ret = errno;
			perror("opendir");
			if (ret == EPERM || ret == EACCES) {
				send_http_forbidden(sess);
				close_sess(sess, state);
				return 0;
			}
			return -ret;
		}
		memcpy(buf, dl_head, sizeof(dl_head) - 1);
		buf_len = sizeof(dl_head) - 1;
		p = &buf[sizeof(dl_head) - 1];
		sess->private_data = NULL;

		ret = construct_file_list(p, buf_max - buf_len, path, ".");
		if (ret > 0) {
			p += ret;
			buf_len += ret;
		}

		ret = construct_file_list(p, buf_max - buf_len, path, ".");
		if (ret > 0) {
			p += ret;
			buf_len += ret;
		}
	} else {
		pdata = (struct dir_list_data *)sess->private_data;
		path = pdata->pathname;
		dr = pdata->dr;
		p = buf;
		p[0] = '\0';
		buf_len = 0;
	}
	sess->action = HTTP_ACT_DIRLIST;

	while (1) {
		struct dirent *de;
		const char *f;

		de = readdir(dr);
		if (!de)
			break;

		f = de->d_name;
		if (!strcmp(f, ".") || !strcmp(f, ".."))
			continue;

		ret = construct_file_list(p, buf_max - buf_len, path, f);
		if (ret > 0) {
			p += ret;
			buf_len += ret;
		}

		if (sizeof(buf) - buf_len < 8192) {

			send_to_client(sess, buf, buf_len);
			if (!pdata) {
				pdata = new struct dir_list_data;
				if (unlikely(!pdata))
					return -ENOMEM;
				pdata->dr = dr;
				strncpy(pdata->pathname, path,
					sizeof(pdata->pathname));
				sess->private_data = (void *)pdata;
			}

			state->bq_lock->lock();
			state->buf_queue->push(sess->idx);
			state->bq_lock->unlock();
			return 0;
		}
	}

	closedir(dr);

	do {
		static const char x[] = "\t</table>\n</body>\n</html>\n";
		if (buf_max - buf_len < sizeof(x)) {
			send_to_client(sess, buf, buf_len);
			buf_len = 0;
			p = buf;
		}
		buf_len += snprintf(p, buf_len, x);
	} while (0);

	send_to_client(sess, buf, buf_len);
	close_sess(sess, state);
	if (pdata) {
		sess->private_data = NULL;
		delete pdata;
	}
	return 0;
}

static int http_redirect(struct client_sess *sess, const char *location)
{
	char buf[4096 + 4096 + 256];
	int len;

	len = snprintf(buf, sizeof(buf),
			"HTTP/1.1 302\r\n"
			"Connection: closed\r\n"
			"Location: %s\r\n\r\nYou are redirected to %s\n\n",
			location, location);

	return send_to_client(sess, buf, (size_t)len);
}

static int __handle_route_get(struct client_sess *sess,
			      struct server_state *state)
{
	char pathname[4096];
	struct stat st;
	int ret;

	snprintf(pathname, sizeof(pathname), "./%s", sess->uri);

	ret = stat(pathname, &st);
	if (unlikely(ret < 0)) {
		ret = errno;
		if (ret == EPERM || ret == EACCES) {
			send_http_forbidden(sess);
			close_sess(sess, state);
			return 0;
		}

		fprintf(stderr, "Cannot open \"%s\": %s\n", pathname,
			strerror(ret));
		return -ret;
	}

	if (st.st_mode & S_IFDIR) {

		if (sess->uri[strlen(sess->uri) - 1] != '/') {
			char *redirect = pathname;

			snprintf(redirect, sizeof(pathname), "%s/",
				 sess->uri);
			http_redirect(sess, redirect);
			close_sess(sess, state);
			return 0;
		}

		/*
		 * This is a directory! Do a directory listing here...
		 */
		return show_directory_listing(pathname, sess, state);
	}

	if (st.st_mode & S_IFREG) {
		/*
		 * This is a regular file! Send to client...
		 */
	}

	return -ENOTSUP;
}

static int _handle_route_get(struct client_sess *sess,
			     struct server_state *state)
{
	int ret;

	/*
	 * Don't allow to step up to the parent directory.
	 */
	if (unlikely(strstr(sess->uri, "/..")))
		return -ENOENT;

	ret = __handle_route_get(sess, state);
	if (ret)
		return -ENOENT;

	return 0;
}

static int handle_route_get(struct client_sess *sess,
			    struct server_state *state)
{
	int ret;

	ret = _handle_route_get(sess, state);
	if (!ret)
		return 0;

	if (ret == -ENOENT) {
		send_http_error(404, sess);
		close_sess(sess, state);
		return 0;
	}

	return ret;
}

static int handle_route(struct client_sess *sess, struct server_state *state)
{
	int ret;

	switch (sess->method) {
	case HTTP_GET:
		ret = handle_route_get(sess, state);
		break;
	case HTTP_POST:
	case HTTP_DELETE:
	case HTTP_PATCH:
	case HTTP_PUT:
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

	sess->recv[sess->buf_size] = '\0';
	if (!sess->got_http_header) {
		ret = parse_http_header(sess);
		if (ret)
			goto out;
		if (!sess->got_http_header)
			return 0;
	}

#if 0
	printf("URI: %s\n", sess->uri);
	printf("Query String: %s\n", sess->qs);
	printf("HTTP version: %s\n", sess->http_ver);
#endif

	ret = handle_route(sess, state);
out:
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
		close_sess(sess, state);
		return 0;
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
		while (1) {
			ret = handle_new_client(state);
			if (ret == -EAGAIN || ret == -EMFILE)
				return 0;
			if (ret)
				break;
		}
	} else {
		struct client_sess *sess =
			(struct client_sess *)event->data.ptr;

		ret = handle_client(sess, state);
	}

	return ret;
}

static void handle_buf_queue(uint32_t idx, struct server_state *state)
{
	struct client_sess *sess = &state->sess[idx];

	switch (sess->action) {
	case HTTP_ACT_DIRLIST:
		show_directory_listing(NULL, sess, state);
		break;
	case HTTP_ACT_NONE:
		break;
	case HTTP_ACT_FILE_STREAM:
		break;
	}
}

static int _run_server(int epl_fd, struct server_state *state)
{
	struct epoll_event *events = state->events;
	int timeout = 1000;
	size_t bq_len;
	int nr_events;
	int ret;
	int i;

	state->bq_lock->lock();
	bq_len = state->buf_queue->size();
	if (bq_len > 0)
		timeout = 0;
	state->bq_lock->unlock();

do_poll:
	nr_events = epoll_wait(epl_fd, events, NR_EPOLL_EVT, timeout);
	if (unlikely(nr_events < 0)) {
		ret = errno;
		perror("epoll_wait");
		if (ret == EINTR)
			return 0;
		return -ret;
	}

	for (i = 0; i < nr_events; i++) {
		ret = handle_event(&events[i], state);
		if (unlikely(ret))
			return ret;
	}

	state->bq_lock->lock();
	i = 0;
	while (state->buf_queue->size() && unlikely(!state->stop)) {
		uint32_t idx = state->buf_queue->front();
		state->buf_queue->pop();
		state->bq_lock->unlock();
		handle_buf_queue(idx, state);
		if (i++ > 32) {
			timeout = 0;
			goto do_poll;
		}
		state->bq_lock->lock();
	}
	state->bq_lock->unlock();

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

	delete state->buf_queue;
	delete state->sess_free_idx;
	delete state->bq_lock;
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
		return ENOMEM;
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
