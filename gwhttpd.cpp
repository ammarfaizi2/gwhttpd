// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <poll.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <cerrno>
#include <stack>
#include <queue>
#include <atomic>
#include <mutex>
#include <dirent.h>
#include <signal.h>
#include <thread>
#include <unordered_map>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>

#define noinline		__attribute__((__noinline__))
#define __hot			__attribute__((__hot__))
#define __cold			__attribute__((__cold__))
#define likely(COND)		__builtin_expect(!!(COND), 1)
#define unlikely(COND)		__builtin_expect(!!(COND), 0)
#define NR_WORKERS		64
#define NR_EPOLL_EVT		512
#define NR_MAX_CLIENTS		999999
#define IPV4_LEN		(sizeof("xxx.xxx.xxx.xxx"))
#define FCIP			"%s:%u"
#define FCIP_ARG(P)		((P)->src_addr), ((P)->src_port)

template<typename T>
struct wq_stack {
	T	*arr_;
	size_t	pos_;
	size_t	max_;

	inline wq_stack(size_t max):
		pos_(max),
		max_(max)
	{
		arr_ = new T[max];
	}

	inline ~wq_stack(void)
	{
		delete[] arr_;
	}

	inline int64_t push(T val)
	{
		arr_[--pos_] = val;
		return pos_;
	}

	inline T top(void)
	{
		return arr_[pos_];
	}

	inline T pop(void)
	{
		return arr_[pos_++];
	}

	inline bool empty(void)
	{
		return max_ == pos_;
	}
};


template<typename T>
struct wq_queue {
	T	*arr_;
	size_t	front_;
	size_t	rear_;
	size_t	and_;

	inline wq_queue(size_t want_max):
		front_(0),
		rear_(0)
	{
		size_t max = 1;
		while (max < want_max)
			max *= 2;

		and_ = max - 1;
		arr_ = new T[max];
	}

	inline ~wq_queue(void)
	{
		delete[] arr_;
	}

	inline size_t size(void)
	{
		if (rear_ >= front_)
			return rear_ - front_;
		else
			return front_ - rear_;
	}

	inline int64_t push(T val)
	{
		arr_[rear_ & and_] = val;
		return rear_++;
	}

	inline T front(void)
	{
		return arr_[front_ & and_];
	}

	inline T pop(void)
	{
		return arr_[front_++ & and_];
	}
};

enum http_method {
	HTTP_NOP = 0,
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
	DIR			*dir;
	char			path[4096];
};

struct stream_file_data {
	char			*map;
	off_t			size;
	off_t			cur_off;
};

struct client_sess {
	int			fd;
	uint32_t		idx;
	void			*priv_data;

	enum http_action	action;
	enum http_method	method;
	char			*uri;
	char			*qs;
	char			*http_ver;
	char			*header;
	char			*body;
	bool			got_http_header;
	bool			in_queue;
	char			src_addr[IPV4_LEN];
	uint16_t		src_port;
	char			recv_buf[4096];
	size_t			rbuf_len;
	std::unordered_map<std::string, std::string>	*http_headers;
} __attribute__((__aligned__(4096)));

struct server_state;
struct worker {
	int			epl_fd;
	struct epoll_event	events[NR_EPOLL_EVT];
	uint32_t		idx;
	struct server_state	*state;
	wq_queue<uint32_t>	*buf_queue;
	std::thread		thread;
	volatile bool		need_join;
} __attribute__((__aligned__(4096)));

struct server_state {
	volatile bool		stop;
	std::atomic<uint32_t>	wrk_idx_use;
	int			tcp_fd;
	int			sig;

	/*
	 * Stack of free session indexes.
	 */
	wq_stack<uint32_t>	*sess_free;
	std::mutex		*sess_free_lock;

	/*
	 * Array of client sessions.
	 */
	struct client_sess	sess[NR_MAX_CLIENTS];
	std::atomic<uint32_t>	nr_on_thread;

	struct worker		*workers;

	const char		*bind_addr;
	uint16_t		bind_port;
};

static struct server_state *g_state = NULL;

static __cold void signal_handler_func(int sig)
{
	printf("\nGot signal: %d\n", sig);
	if (!g_state)
		return;

	g_state->stop = true;
	g_state->sig = sig;
}

static __cold struct server_state *alloc_state(void)
{
	struct server_state *state;

#ifdef USE_ASAN
	state = new struct server_state;
	if (!state) {
		errno = ENOMEM;
		perror("new()");
		return NULL;
	}
#else /* #ifdef USE_ASAN */
	state = (struct server_state *)mmap(NULL, sizeof(*state),
					    PROT_READ|PROT_WRITE,
					    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (state == MAP_FAILED) {
		perror("mmap");
		return NULL;
	}
	mlock(state, sizeof(*state));
#endif /* #ifdef USE_ASAN */

	return state;
}

static __cold void free_state(struct server_state *state)
{
#ifdef USE_ASAN
	delete state;
#else
	munlock(state, sizeof(*state));
	munmap(state, sizeof(*state));
#endif
}

static __cold int setup_signal_handler(void)
{
	struct sigaction act;
	int ret;

	memset(&act, 0, sizeof(act));
	act.sa_handler = signal_handler_func;
	ret = sigaction(SIGINT, &act, NULL);
	if (unlikely(ret))
		goto err;
	ret = sigaction(SIGHUP, &act, NULL);
	if (unlikely(ret))
		goto err;
	ret = sigaction(SIGTERM, &act, NULL);
	if (unlikely(ret))
		goto err;

	act.sa_handler = SIG_IGN;
	ret = sigaction(SIGPIPE, &act, NULL);
	if (unlikely(ret))
		goto err;

	return 0;
err:
	perror("sigaction");
	return -errno;
}

static __cold int init_state(struct server_state **state_p)
{
	struct server_state *state;
	uint32_t i;
	int ret;

	ret = setup_signal_handler();
	if (unlikely(ret))
		return ret;

	state = alloc_state();
	if (unlikely(!state))
		return -ENOMEM;

	state->tcp_fd = -1;

	state->sess_free = new wq_stack<uint32_t>(NR_MAX_CLIENTS);
	if (unlikely(!state->sess_free)) {
		errno = ENOMEM;
		perror("state->sess_free = new()");
		return -ENOMEM;
	}

	state->sess_free_lock = new std::mutex;
	if (unlikely(!state->sess_free_lock)) {
		errno = ENOMEM;
		perror("state->sess_free_lock = new()");
		goto out_err_sess_free_lock;
	}

	state->workers = new struct worker[NR_WORKERS];
	if (unlikely(!state->workers)) {
		ret = -ENOMEM;
		errno = -ret;
		perror("state->workers = new()");
		goto out_err_workers;
	}

	i = NR_MAX_CLIENTS;
	while (i--) {
		state->sess[i].fd = -1;
		state->sess[i].idx = i;
		state->sess_free->push(i);
	}

	i = NR_WORKERS;
	while (i--)
		state->workers[i].buf_queue = NULL;

	i = NR_WORKERS;
	while (i--) {
		wq_queue<uint32_t> *p = new wq_queue<uint32_t>(NR_MAX_CLIENTS);
		if (unlikely(!p))
			goto out_err_wq_queue;
		state->workers[i].idx = i;
		state->workers[i].epl_fd = -1;
		state->workers[i].state = state;
		state->workers[i].need_join = false;
		state->workers[i].buf_queue = p;
	}

	state->stop = false;
	atomic_store(&state->nr_on_thread, 0);
	atomic_store(&state->wrk_idx_use, 0);
	*state_p = state;
	g_state = state;
	return 0;

out_err_wq_queue:
	while (i < NR_WORKERS) {
		delete state->workers[i].buf_queue;
		state->workers[i].buf_queue = NULL;
	}
out_err_workers:
	delete state->sess_free_lock;
	state->sess_free_lock = NULL;
out_err_sess_free_lock:
	delete state->sess_free;
	state->sess_free = NULL;
	return ret;
}

static __cold int set_socket_options(int tcp_fd)
{
	int val;
	const void *y = (const void *)&val;
	const char *on, *ov;
	int ret;

	val = 1;
	ret = setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &y, sizeof(val));
	if (ret < 0) {
		on = "SOL_SOCKET";
		ov = "SO_REUSEADDR";
		goto out_err;
	}

	return 0;

out_err:
	ret = errno;
	fprintf(stderr, "setsockopt(%d, %s, %s, ...): %s\n", tcp_fd, on, ov,
		strerror(ret));
	return -ret;
}

static __cold int init_socket(struct server_state *state)
{
	struct sockaddr_in saddr;
	int tcp_fd;
	int ret;

	if (unlikely(!state->bind_addr)) {
		fprintf(stderr, "Error: state->bind_addr is empty!\n");
		return -EINVAL;
	}

	if (unlikely(!state->bind_port)) {
		fprintf(stderr, "Error: state->bind_port is empty!\n");
		return -EINVAL;
	}

	tcp_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (unlikely(tcp_fd < 0)) {
		ret = -errno;
		perror("socket");
		return ret;
	}

	ret = set_socket_options(tcp_fd);
	if (unlikely(ret))
		goto out_err;

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = inet_addr(state->bind_addr);
	saddr.sin_port = htons(state->bind_port);

	ret = bind(tcp_fd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (unlikely(ret < 0)) {
		ret = -errno;
		perror("bind");
		goto out_err;
	}

	ret = listen(tcp_fd, 4096);
	if (unlikely(ret < 0)) {
		ret = -errno;
		perror("listen");
		goto out_err;
	}

	printf("Listening on %s:%u...\n", state->bind_addr, state->bind_port);
	state->tcp_fd = tcp_fd;
	return 0;

out_err:
	close(tcp_fd);
	return ret;
}

static __cold void wait_for_ready_state(struct worker *worker)
{
	uint32_t i = 0;
	uint32_t on;

	while (true) {
		on = atomic_load(&worker->state->nr_on_thread);
		if (on >= NR_WORKERS || worker->state->stop)
			break;

		usleep(1000);
		if (i++ < 10000)
			continue;

		fprintf(stderr, "Timedout while waiting for ready state");
		worker->state->stop = true;
		return;
	}
}

static int install_infd_to_worker(int fd, struct worker *worker,
				  epoll_data_t data)
{
	struct epoll_event evt;
	int ret;

	memset(&evt, 0, sizeof(evt));
	evt.events = EPOLLIN | EPOLLPRI;
	evt.data = data;
	ret = epoll_ctl(worker->epl_fd, EPOLL_CTL_ADD, fd, &evt);
	if (ret < 0) {
		ret = -errno;
		perror("epoll_ctl");
		return ret;
	}
	return ret;
}

static int64_t get_sess_idx(struct server_state *state)
{
	int64_t idx;

	state->sess_free_lock->lock();
	if (unlikely(state->sess_free->empty())) {
		state->sess_free_lock->unlock();
		return -EAGAIN;
	}
	idx = (int64_t)state->sess_free->pop();
	state->sess_free_lock->unlock();
	return idx;
}

static void put_sess_idx(uint32_t idx, struct server_state *state)
{
	state->sess_free_lock->lock();
	state->sess_free->push(idx);
	state->sess_free_lock->unlock();
}

static int uninstall_fd_from_worker(int fd, struct worker *worker)
{
	int ret;

	ret = epoll_ctl(worker->epl_fd, EPOLL_CTL_DEL, fd, NULL);
	if (ret < 0) {
		ret = -errno;
		perror("epoll_ctl");
		return ret;
	}
	return ret;
}

static void close_sess(struct client_sess *sess, struct worker *worker)
{
	printf("Closing session " FCIP " (idx = %u)\n", FCIP_ARG(sess),
		sess->idx);
	uninstall_fd_from_worker(sess->fd, worker);
	close(sess->fd);
	sess->fd = -1;
	sess->action = HTTP_ACT_NONE;
	delete sess->http_headers;
	sess->http_headers = NULL;
	put_sess_idx(sess->idx, worker->state);
}

static int _handle_new_client(int tcp_fd, struct worker *worker)
{
	struct server_state *state = worker->state;
	struct sockaddr_in caddr;
	socklen_t addrlen = sizeof(caddr);
	struct client_sess *sess;
	epoll_data_t epld;
	uint32_t wrk_idx;
	int64_t idx;
	int cli_fd;
	int ret;

	memset(&caddr, 0, sizeof(caddr));
	cli_fd = accept(tcp_fd, (struct sockaddr *)&caddr, &addrlen);
	if (unlikely(cli_fd < 0)) {
		ret = errno;
		if (ret != EAGAIN)
			perror("accept");
		return -ret;
	}

	idx = get_sess_idx(state);
	if (unlikely(idx == -EAGAIN)) {
		close(cli_fd);
		fprintf(stderr, "Client session is full, cannot handle a new "
			"client\n");
		return -EAGAIN;
	}

	sess = &state->sess[idx];
	sess->fd = cli_fd;
	sess->rbuf_len = 0;
	sess->got_http_header = false;
	sess->action = HTTP_ACT_NONE;
	sess->method = HTTP_NOP;
	sess->in_queue = false;

	if (addrlen <= sizeof(caddr)) {
		const char *p;
		p = inet_ntop(AF_INET, &caddr.sin_addr.s_addr, sess->src_addr,
			      sizeof(sess->src_addr));
		if (p)
			sess->src_port = ntohs(caddr.sin_port);
		else
			perror("inet_ntop");
	} else {
		sess->src_addr[0] = '\0';
		sess->src_port = 0;
		fprintf(stderr, "Warning, accept overflow!\n");
	}

	epld.ptr = (void *)sess;
	wrk_idx = atomic_fetch_add(&state->wrk_idx_use, 1) % NR_WORKERS;
	ret = install_infd_to_worker(cli_fd, &state->workers[wrk_idx], epld);
	if (unlikely(ret < 0))
		return ret;

	printf("Got a new client (idx = %u) " FCIP "\n", sess->idx,
		FCIP_ARG(sess));
	return 0;
}

static __hot int handle_new_client(struct worker *worker)
{
	int tcp_fd = worker->state->tcp_fd;
	uint32_t acc_iter = 512;
	int ret;

	while (acc_iter--) {
		ret = _handle_new_client(tcp_fd, worker);
		if (likely(!ret))
			continue;

		if (likely(ret == -EAGAIN) || unlikely(ret == -EMFILE))
			return 0;

		return ret;
	}
	return 0;
}

static int poll_wait_for_fd_be_writable(int fd)
{
	struct pollfd fds[1];
	int ret;

	fds[0].fd = fd;
	fds[0].events = POLLOUT;
	fds[0].revents = 0;

	ret = poll(fds, 1, -1);
	if (unlikely(ret < 0)) {
		ret = errno;
		if (ret != EINTR)
			return -ret;
	}
	return 0;
}

static ssize_t send_to_sess(struct client_sess *sess, const char *buf,
			    size_t len)
{
	const char *bptr = buf;
	ssize_t total_sent = 0;
	size_t blen = len;
	int fd = sess->fd;
	ssize_t ret;	

repeat:
	ret = send(fd, bptr, blen, MSG_DONTWAIT);
	if (unlikely(ret < 0)) {
		int ret = errno;
		if (unlikely(ret != EAGAIN)) {
			perror("send");
			return -ret;
		}

		ret = poll_wait_for_fd_be_writable(fd);
		if (unlikely(ret))
			return ret;

		goto repeat;
	}

	total_sent += ret;
	if (unlikely((size_t)total_sent < len)) {
		bptr = &buf[total_sent];
		blen = len - (size_t)total_sent;
		goto repeat;
	}

	return total_sent;
}

static ssize_t send_http_error(struct client_sess *sess, int code,
			       const char *errstr)
{
	char buf[128];
	int tmp;

	tmp = snprintf(buf, sizeof(buf),
			"HTTP/1.1 %d%s%s\r\n"
			"Connection: closed\r\n"
			"Content-Type: text/plain\r\n\r\n"
			"HTTP Error %d",
			code, (errstr ? " " : ""), (errstr ? errstr : ""),
			code);
	return send_to_sess(sess, buf, (size_t)tmp);
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
		uri[-1] = '\0';
		if (uri == end_uri)
			/*
			 * We got an empty query string:
			 *  "http://somehwere.com/path?"
			 */
			return NULL;
		return uri[0] ? uri : NULL;
	}
	return NULL;
}

static int parse_http_header(struct client_sess *sess)
{
	char *buf = sess->recv_buf;
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
		if (sess->rbuf_len >= sizeof(sess->recv_buf) - 1)
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
	if (unlikely(ret[0] != '/'))
		goto bad_req;
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
	sess->header = &ret[1];
	sess->got_http_header = true;
	return 0;

bad_req:
	send_http_error(sess, 400, "Bad Request");
	return -EBADMSG;
}

static ssize_t http_redirect(struct client_sess *sess, const char *location)
{
	size_t need_len;
	ssize_t ret;
	char *buf;
	int len;

	need_len = strlen(location) * 2 + 256;
	buf = new char[need_len];
	if (unlikely(!buf))
		return -ENOMEM;

	len = snprintf(buf, need_len,
			"HTTP/1.1 302\r\n"
			"Connection: closed\r\n"
			"Location: %s\r\n\r\nYou are redirected to %s\n\n",
			location, location);

	ret = send_to_sess(sess, buf, (size_t)len);
	delete[] buf;
	return ret;
}

static int sdl_open_dir(const char *path, struct client_sess *sess, DIR **dir_p)
{
	DIR *dir;
	int ret;

	dir = opendir(path);
	if (unlikely(!dir)) {
		ret = errno;
		if (ret == ENOENT)
			send_http_error(sess, 404, "Not Found");
		else
			send_http_error(sess, 403, "Forbidden");

		return -EBADMSG;
	}
	*dir_p = dir;
	return 0;
}

static int construct_flist(const char *path, const char *file, char *buf,
			   size_t buf_size)
{
	char fpath[4096 + 256];
	const char *type;
	struct stat st;
	int ret;

	snprintf(fpath, sizeof(fpath), "%s/%s", path, file);

	ret = stat(fpath, &st);
	if (unlikely(ret < 0)) {
		ret = errno;
		fprintf(stderr, "Can't stat \"%s\": %s\n", fpath, strerror(ret));
		return -ret;
	}

	if (S_ISDIR(st.st_mode))
		type = "Directory";
	else if (S_ISREG(st.st_mode))
		type = "Regular File";
	else if (S_ISCHR(st.st_mode))
		type = "Char dev";
	else if (S_ISBLK(st.st_mode))
		type = "Block dev";
	else if (S_ISFIFO(st.st_mode))
		type = "FIFO";
	else if (S_ISLNK(st.st_mode))
		type = "Symlink";
	else if (S_ISSOCK(st.st_mode))
		type = "Socket";
	else
		return -ENOTSUP;

	return snprintf(buf, buf_size,
		"\t\t<tr>"
			"<td><a href=\"%s%s\">%s</a></td>"
			"<td>%s</td>"
			"<td>%d%d%d%d</td>"
		"</tr>\n",
		file, S_ISDIR(st.st_mode) ? "/" : "", file,
		type,
		(st.st_mode & 07000) >> 9,
		(st.st_mode & 00700) >> 6,
		(st.st_mode & 00070) >> 3,
		(st.st_mode & 00007)
	);
}

static int queue_dirlist_action(struct client_sess *sess, struct worker *worker,
				const char *path, DIR *dir)
{
	struct dir_list_data *dld;

	if (unlikely(!sess->priv_data)) {
		dld = new struct dir_list_data;
		if (unlikely(!dld)) {
			fprintf(stderr, "Cannot allcoate dir_list_data!\n");
			return -ENOMEM;
		}

		dld->dir = dir;
		snprintf(dld->path, sizeof(dld->path), "%s", path);
		sess->priv_data = (void *)dld;
	}

	sess->action = HTTP_ACT_DIRLIST;
	sess->in_queue = true;
	worker->buf_queue->push(sess->idx);
	return 0;
}

static int show_directory_listing(const char *path, struct client_sess *sess,
				  struct worker *worker)
{
	constexpr static const char dl_head[] =
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

	constexpr static const char dl_foot[] =
		"\t</table>\n</body>\n</html>\n";

	struct dir_list_data *dld = NULL;
	char buf[1024 * 128];
	char *p = buf;
	DIR *dir = NULL;
	int ret;

	#define BSIZE(P)  ((size_t)((P) - (buf)))
	#define BREM(P)	  (sizeof(buf) - BSIZE(P))

	if (sess->action == HTTP_ACT_NONE) {
		ret = sdl_open_dir(path, sess, &dir);
		if (unlikely(ret))
			return ret;

		memcpy(p, dl_head, sizeof(dl_head) - 1);
		p += sizeof(dl_head) - 1;

		ret = construct_flist(path, ".", p, BREM(p));
		if (likely(ret > 0))
			p += (size_t)ret;

		ret = construct_flist(path, "..", p, BREM(p));
		if (likely(ret > 0))
			p += (size_t)ret;
	} else {
		dld = (struct dir_list_data *)sess->priv_data;
		dir = dld->dir;
		path = dld->path;
	}


	while (1) {
		struct dirent *de;
		const char *f;

		if (unlikely(BREM(p) < 8192)) {

			ret = send_to_sess(sess, buf, BSIZE(p));
			if (unlikely(ret < 0))
				goto out_net_down;

			ret = queue_dirlist_action(sess, worker, path, dir);
			if (unlikely(ret))
				goto out_net_down;

			return 0;
		}

		de = readdir(dir);
		if (unlikely(!de))
			break;

		f = de->d_name;
		if (unlikely(!strcmp(f, ".") || !strcmp(f, "..")))
			continue;

		ret = construct_flist(path, f, p, BREM(p));
		if (likely(ret > 0))
			p += (size_t)ret;
	}

	if (BREM(p) < sizeof(dl_foot) - 1) {

		ret = send_to_sess(sess, buf, BSIZE(p));
		if (unlikely(ret < 0))
			goto out_net_down;

		ret = send_to_sess(sess, dl_foot, sizeof(dl_foot) - 1);
		if (unlikely(ret < 0))
			goto out_net_down;
		p = buf;

	} else {
		memcpy(p, dl_foot, sizeof(dl_foot) - 1);
		p += (size_t)(sizeof(dl_foot) - 1);
		ret = send_to_sess(sess, buf, BSIZE(p));
		if (unlikely(ret < 0))
			goto out_net_down;
	}

	ret = 1;
out:
	if (dir)
		closedir(dir);

	if (dld) {
		delete dld;
		sess->priv_data = NULL;
	}
	return 1;

out_net_down:
	ret = -ENETDOWN;
	goto out;


	#undef BSIZE
	#undef BREM
}

static void not_found_or_forbidden(int e, struct client_sess *sess)
{
	if (e == ENOENT)
		send_http_error(sess, 404, "Not Found");
	else
		send_http_error(sess, 403, "Forbidden");
}

static int parse_http_header2(struct client_sess *sess)
{
	char *hdr = sess->header + 1;

	if (!sess->http_headers)
		sess->http_headers = new __typeof__(*sess->http_headers);

	while (1) {
		char *keyval, *key, *val, *it;

		key = hdr;
		keyval = strstr(key, "\r\n");
		if (!keyval)
			break;
		keyval[0] = '\0';

		hdr = &keyval[2];
		val = strstr(key, ":");
		if (!val)
			continue;
		val[0] = '\0';
		val++;

		while (*val == ' ')
			val++;

		it = key;
		while (*it) {
			*it = tolower((unsigned char)*it);
			it++;
		}

		sess->http_headers->emplace(key, val);
	}

	return 0;
}

constexpr size_t max_send_len_file = 1024 * 1024;

static int start_stream_file(const char *file, struct client_sess *sess,
			     struct worker *worker, char **map_p,
			     size_t *map_size_p)
{
	struct stream_file_data *sfd = NULL;
	off_t offset_file = 0;
	size_t send_len;
	size_t map_size;
	struct stat st;
	char buf[1024];
	char *map;
	int ret;
	int fd;

	fd = open(file, O_RDONLY);
	if (unlikely(fd < 0)) {
		fd = errno;
		not_found_or_forbidden(fd, sess);
		fprintf(stderr, "Cannot open file: \"%s\": %s\n", file,
			strerror(fd));
		return -EBADMSG;
	}

	ret = fstat(fd, &st);
	if (unlikely(ret < 0)) {
		ret = errno;
		not_found_or_forbidden(ret, sess);
		close(fd);
		fprintf(stderr, "Cannot stat file: \"%s\": %s\n", file,
			strerror(ret));
		return -EBADMSG;
	}

	parse_http_header2(sess);

	map = (char *)mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (unlikely(map == MAP_FAILED)) {
		ret = errno;
		not_found_or_forbidden(ret, sess);
		close(fd);
		fprintf(stderr, "Cannot map file: \"%s\": %s\n", file,
			strerror(ret));
		return -EBADMSG;
	}
	map_size = st.st_size;
	close(fd);

	{
		const auto &http_headers = *sess->http_headers;
		auto it = http_headers.find("range");
		if (it != http_headers.end()) {
			const char *val = it->second.c_str();
			const char *start_bytes;

			start_bytes = strstr(val, "bytes=");
			if (start_bytes) {
				start_bytes += 6;
				offset_file = strtoull(start_bytes, NULL, 10);
			}
		}
	}

	ret = snprintf(buf, sizeof(buf),
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Range: bytes: %lu-%lu/%lu\r\n"
			"Content-Length: %zu\r\n\r\n",
			offset_file, map_size, map_size,
			st.st_size);

	ret = send_to_sess(sess, buf, (size_t)ret);
	if (unlikely(ret < 0)) {
		munmap(map, map_size);
		return -EBADMSG;
	}

	if (map_size > max_send_len_file) {
		sfd = new struct stream_file_data;
		if (unlikely(!sfd)) {
			send_http_error(sess, 503, "");
			munmap(map, map_size);
			return -EBADMSG;
		}
		sfd->map = map;
		sfd->size = map_size;
		sfd->cur_off = offset_file + max_send_len_file;
		if (sfd->cur_off >= sfd->size) {
			sfd->cur_off = sfd->size - 1;
			send_len = sfd->size - offset_file + 1;
		} else {
			send_len = max_send_len_file;
		}

		sess->priv_data = (void *)sfd;
		sess->action = HTTP_ACT_FILE_STREAM;

		sess->in_queue = true;
		worker->buf_queue->push(sess->idx);

		madvise(map, map_size, MADV_SEQUENTIAL);
		if (offset_file > 0)
			map = &map[offset_file];
	} else {
		send_len = map_size;
	}

	ret = send_to_sess(sess, map, send_len);
	if (unlikely(ret < 0)) {
		if (sfd) {
			delete sfd;
			sess->priv_data = NULL;
		}
		munmap(map, map_size);
		return -EBADMSG;
	}
	*map_p = map;
	*map_size_p = map_size;
	return 0;
}

static int stream_file(const char *file, struct client_sess *sess,
		       struct worker *worker)
{
	struct stream_file_data *sfd = NULL;
	size_t map_size;
	char *map;
	int ret;

	if (sess->action == HTTP_ACT_NONE) {
		ret = start_stream_file(file, sess, worker, &map, &map_size);
		if (unlikely(ret))
			return ret;
		if (sess->action == HTTP_ACT_FILE_STREAM)
			return 0;
	} else {
		size_t remaining_len;
		size_t send_len;
		char *ptr;

		sfd = (struct stream_file_data *)sess->priv_data;
		map = sfd->map;
		ptr = &map[sfd->cur_off];
		map_size = sfd->size;
		remaining_len = sfd->size - sfd->cur_off;

		if (remaining_len > max_send_len_file)
			send_len = max_send_len_file;
		else
			send_len = remaining_len;

		ret = send_to_sess(sess, ptr, send_len);
		if (unlikely(ret < 0)) {
			if (sfd) {
				delete sfd;
				sess->priv_data = NULL;
			}
			munmap(map, map_size);
			return -EBADMSG;
		}
		sfd->cur_off += (off_t)ret;
		remaining_len = sfd->size - sfd->cur_off;

		if (remaining_len > 0) {
			sess->in_queue = true;
			sess->action = HTTP_ACT_FILE_STREAM;
			worker->buf_queue->push(sess->idx);
			return 0;
		}
	}

	if (sfd) {
		delete sfd;
		sess->priv_data = NULL;
	}
	munmap(map, map_size);
	return 1;
}

static int handle_route_get(struct client_sess *sess, struct worker *worker)
{
	char path[4096 + 128];
	struct stat st;
	int ret;

	snprintf(path, sizeof(path), "./%s", sess->uri);

	/*
	 * Don't allow to step up to the parent directory.
	 */
	if (unlikely(strstr(path, "/.."))) {
		send_http_error(sess, 404, "Not Found");
		return -EBADMSG;
	}

	ret = stat(path, &st);
	if (unlikely(ret < 0)) {
		ret = errno;
		fprintf(stderr, "Can't stat \"%s\": %s\n", path, strerror(ret));

		if (ret == ENOENT)
			send_http_error(sess, 404, "Not Found");
		else
			send_http_error(sess, 403, "Forbidden");

		return -EBADMSG;
	}

	if (S_ISDIR(st.st_mode)) {
		size_t plen;
		size_t lloc;
		char *loc;

		plen = strlen(path);
		if (path[plen - 1] == '/')
			return show_directory_listing(path, sess, worker);

		lloc = plen + 16;
		if (sess->qs)
			lloc += strlen(sess->qs) + 2;

		loc = new char[lloc];
		if (unlikely(!loc))
			return -ENETDOWN;

		if (sess->qs)
			snprintf(loc, lloc, "%s/?%s", path, sess->qs);
		else
			snprintf(loc, lloc, "%s/", path);

		http_redirect(sess, loc);
		delete[] loc;
		return -ENETDOWN;
	}

	if (S_ISREG(st.st_mode))
		return stream_file(path, sess, worker);

	return 0;
}

static int handle_route(struct client_sess *sess, struct worker *worker)
{
	int ret;

	switch (sess->method) {
	case HTTP_GET:
		ret = handle_route_get(sess, worker);
		break;
	case HTTP_POST:
	case HTTP_DELETE:
	case HTTP_PATCH:
	case HTTP_PUT:
	default:
		send_http_error(sess, 405, "Method not allowed");
		return -EBADMSG;
	}

	return ret;
}

static int _handle_client(struct client_sess *sess, struct worker *worker)
{
	int ret = 0;

	if (!sess->got_http_header) {
		sess->recv_buf[sess->rbuf_len] = '\0';
		ret = parse_http_header(sess);
		if (unlikely(ret))
			goto out;
		if (unlikely(!sess->got_http_header))
			goto out;
	}

#if 0
	printf("URI: %s\n", sess->uri);
	printf("Query String: %s\n", sess->qs);
	printf("HTTP version: %s\n", sess->http_ver);
#endif

	ret = handle_route(sess, worker);
out:
	if (ret) {
		if (!sess->in_queue)
			close_sess(sess, worker);
		if (likely(ret == -EBADMSG || ret == -ENETDOWN || ret == 1))
			ret = 0;
	}
	return ret;
}

static int handle_client(struct client_sess *sess, struct worker *worker)
{
	ssize_t recv_ret;
	size_t len;
	char *buf;
	int ret;

	if (unlikely(sess->in_queue))
		return 0;

	len = sizeof(sess->recv_buf) - 1 - sess->rbuf_len;
	buf = &sess->recv_buf[sess->rbuf_len];

	recv_ret = recv(sess->fd, buf, len, 0);
	if (unlikely(recv_ret <= 0)) {

		if (recv_ret == 0) {
			close_sess(sess, worker);
			return 0;
		}

		ret = errno;
		if (ret == EAGAIN)
			return 0;

		close_sess(sess, worker);
		perror("recv");
		return 0;
	}
	sess->rbuf_len += (size_t)recv_ret;
	return _handle_client(sess, worker);
}

static __hot int handle_event(struct epoll_event *event,
			      struct worker *worker)
{
	struct client_sess *sess;

	if (!event->data.ptr)
		return handle_new_client(worker);

	sess = (struct client_sess *)event->data.ptr;
	return handle_client(sess, worker);
}

static __hot int handle_buf_queue(uint32_t idx, struct worker *worker)
{
	struct server_state *state = worker->state;
	struct client_sess *sess = &state->sess[idx];
	int ret = 0;

	switch (sess->action) {
	case HTTP_ACT_NONE:
		ret = -ENETDOWN;
		break;
	case HTTP_ACT_DIRLIST:
		ret = show_directory_listing(NULL, sess, worker);
		break;
	case HTTP_ACT_FILE_STREAM:
		ret = stream_file(NULL, sess, worker);
		break;
	}

	if (ret)
		close_sess(sess, worker);

	return 0;
}

static __hot int run_worker(int epl_fd, struct epoll_event *events,
			    struct worker *worker)
{
	int timeout = 1000;
	size_t qlen;
	int nr_evt;
	int ret;
	int i;

	qlen = worker->buf_queue->size();
	if (qlen)
		timeout = 0;

	nr_evt = epoll_wait(epl_fd, events, NR_EPOLL_EVT, timeout);
	if (unlikely(nr_evt < 0)) {
		ret = errno;
		perror("epoll_wait");
		if (ret == EINTR)
			return 0;
		return -ret;
	}

	for (i = 0; i < nr_evt; i++) {
		ret = handle_event(&events[i], worker);
		if (unlikely(ret))
			return ret;
	}

	while (qlen--) {
		uint32_t idx;

		idx = worker->buf_queue->pop();
		ret = handle_buf_queue(idx, worker);
		if (unlikely(ret))
			return ret;
	}

	return 0;
}

static __hot int _worker_func(struct worker *worker)
{
	struct epoll_event *events = worker->events;
	struct server_state *state = worker->state;
	int epl_fd = worker->epl_fd;
	int ret = 0;

	while (likely(!state->stop)) {
		ret = run_worker(epl_fd, events, worker);
		if (likely(!ret))
			continue;

		state->stop = true;
		break;
	}

	return ret;
}

static noinline int worker_func(struct worker *worker)
{
	int ret;

	if (worker->idx > 0)
		worker->need_join = true;

	atomic_fetch_add(&worker->state->nr_on_thread, 1);
	wait_for_ready_state(worker);
	ret = _worker_func(worker);
	atomic_fetch_sub(&worker->state->nr_on_thread, 1);
	return ret;
}

static int init_epoll_for_worker(struct worker *worker)
{
	int epl_fd;

	epl_fd = epoll_create(255);
	if (unlikely(epl_fd < 0)) {
		int ret = errno;
		perror("epoll_create");
		return -ret;
	}

	worker->epl_fd = epl_fd;
	return 0;
}

static __cold int wait_for_worker_online(struct worker *worker)
{
	uint32_t i = 0;
	while (!worker->need_join) {
		usleep(1000);
		if (i++ < 10000)
			continue;

		fprintf(stderr, "Timedout while waiting for thread %u\n",
			worker->idx);
		worker->state->stop = true;
		worker->thread.join();
		worker->need_join = false;
		return -ETIMEDOUT;
	}
	return 0;
}

static __cold int run_workers(struct server_state *state)
{
	struct worker *workers = state->workers;
	epoll_data_t edt;
	int ret = 0;
	uint32_t i;

	i = NR_WORKERS;
	while (i--) {
		ret = init_epoll_for_worker(&workers[i]);
		if (unlikely(ret))
			return ret;
	}


	i = NR_WORKERS;
	/*
	 * Skip i == 0, we will run the worker
	 * on the main thread.
	 */
	while (--i > 0) {
		workers[i].thread = std::thread(worker_func, &workers[i]);
		ret = wait_for_worker_online(&workers[i]);
		if (unlikely(ret))
			return ret;
	}

	edt.ptr = NULL;
	ret = install_infd_to_worker(state->tcp_fd, &workers[0], edt);
	if (unlikely(ret))
		return ret;

	return worker_func(&workers[0]);
}

static __cold void destroy_state(struct server_state *state)
{
	uint32_t i;
	int fd;

	if (!state)
		return;

	fd = state->tcp_fd;
	if (fd != -1)
		close(fd);

	/*
	 * Do not join @workers[0].thread, it doesn't
	 * have an LWP!
	 */
	for (i = 1; i < NR_WORKERS; i++) {
		if (state->workers[i].need_join)
			state->workers[i].thread.join();
	}

	for (i = 0; i < NR_WORKERS; i++) {
		fd = state->workers[i].epl_fd;
		if (fd != -1)
			close(fd);
	}

	for (i = 0; i < NR_MAX_CLIENTS; i++) {
		fd = state->sess[i].fd;
		if (fd != -1)
			close(fd);
	}

	i = NR_WORKERS;
	while (i--) {
		wq_queue<uint32_t> *p = state->workers[i].buf_queue;
		if (p)
			delete p;
	}

	if (state->workers)
		delete[] state->workers;
	if (state->sess_free_lock)
		delete state->sess_free_lock;
	if (state->sess_free)
		delete state->sess_free;

	free_state(state);
}

int main(int argc, char *argv[])
{
	struct server_state *state = NULL;
	int ret;

	setvbuf(stdout, NULL, _IOLBF, 4096);
	if (argc != 3) {
		printf("Usage: %s [bind_address] [bind_port]\n", argv[0]);
		return 0;
	}

	ret = init_state(&state);
	if (unlikely(ret))
		return ret;

	state->bind_addr = argv[1];
	state->bind_port = (uint16_t)atoi(argv[2]);

	ret = init_socket(state);
	if (unlikely(ret))
		goto out;
	ret = run_workers(state);
out:
	destroy_state(state);
	return ret;
}
