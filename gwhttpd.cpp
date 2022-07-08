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
#include <getopt.h>
#include <netinet/tcp.h>

#define noinline		__attribute__((__noinline__))
#define __hot			__attribute__((__hot__))
#define __cold			__attribute__((__cold__))
#define likely(COND)		__builtin_expect(!!(COND), 1)
#define unlikely(COND)		__builtin_expect(!!(COND), 0)
#define NR_WORKERS		16
#define NR_EPOLL_EVT		512
#define NR_MAX_CLIENTS		10240
#define IPV4_LEN		(sizeof("xxx.xxx.xxx.xxx"))
#define FCIP			"%s:%u"
#define FCIP_ARG(P)		((P)->src_addr), ((P)->src_port)

#if defined(__x86_64__)
#define	__page_size_aligned_in_smp	__attribute__((__aligned__(4096)))
#else
#define	__page_size_aligned_in_smp
#endif

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

struct stream_dir_list_data {
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
	char			src_addr[IPV4_LEN];
	uint16_t		src_port;
	char			recv_buf[4096];
	size_t			rbuf_len;
	bool			need_epl_del;
	std::unordered_map<std::string, std::string>	*http_headers;
} __page_size_aligned_in_smp;

struct server_state;
struct worker {
	int			epl_fd;
	struct epoll_event	events[NR_EPOLL_EVT];
	uint32_t		idx;
	struct server_state	*state;
	wq_queue<uint32_t>	*buf_queue;
	std::thread		thread;
	volatile bool		need_join;
} __page_size_aligned_in_smp;

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
	atomic_store(&state->nr_on_thread, 0u);
	atomic_store(&state->wrk_idx_use, 0u);
	*state_p = state;
	g_state = state;
	return 0;

out_err_wq_queue:
	while (i < NR_WORKERS) {
		delete state->workers[i].buf_queue;
		state->workers[i].buf_queue = NULL;
		i++;
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

	if (sess->need_epl_del)
		uninstall_fd_from_worker(sess->fd, worker);

	close(sess->fd);
	sess->fd = -1;
	sess->action = HTTP_ACT_NONE;
	if (sess->http_headers) {
		delete sess->http_headers;
		sess->http_headers = NULL;
	}
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
	wrk_idx = atomic_fetch_add(&state->wrk_idx_use, 1u) % NR_WORKERS;
	ret = install_infd_to_worker(cli_fd, &state->workers[wrk_idx], epld);
	if (unlikely(ret < 0))
		return ret;

	sess->need_epl_del = true;
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

static char *open_file_for_stream(const char *file, struct stat *st,
				  struct client_sess *sess,
				  struct stream_file_data *sfd)
{
	char *map;
	int ret;
	int fd;

	fd = open(file, O_RDONLY);
	if (unlikely(fd < 0)) {
		fd = errno;
		not_found_or_forbidden(fd, sess);
		fprintf(stderr, "Cannot open file: \"%s\": %s\n", file,
			strerror(fd));
		return NULL;
	}

	ret = fstat(fd, st);
	if (unlikely(ret < 0)) {
		ret = errno;
		not_found_or_forbidden(ret, sess);
		close(fd);
		fprintf(stderr, "Cannot stat file: \"%s\": %s\n", file,
			strerror(ret));
		return NULL;
	}

	map = (char *)mmap(NULL, st->st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (unlikely(map == MAP_FAILED)) {
		ret = errno;
		not_found_or_forbidden(ret, sess);
		fprintf(stderr, "Cannot map file: \"%s\": %s\n", file,
			strerror(ret));
		return NULL;
	}

	sfd->size = st->st_size;
	sfd->map = map;
	sfd->cur_off = 0;
	return map;
}

static int send_http_header_for_stream_file(struct client_sess *sess,
					    off_t start_offset,
					    off_t content_length)
{
	char buf[1024];
	int ret;

	ret = snprintf(buf, sizeof(buf),
			"HTTP/1.1 %s\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Range: bytes %lu-%lu/%lu\r\n"
			"Content-Length: %zu\r\n\r\n",
			start_offset ? "206 Partial Content" : "200 OK",
			start_offset, content_length - 1, content_length,
			content_length);

	ret = send_to_sess(sess, buf, (size_t)ret);
	if (unlikely(ret < 0))
		return -EBADMSG;

	return 0;
}

static int stream_file_once(struct stream_file_data *sfd,
			    struct client_sess *sess)
{
	size_t send_len;
	int ret;

	if (unlikely(sfd->cur_off >= sfd->size))
		return 1;

	send_len = (size_t)(sfd->size - sfd->cur_off);
	ret = send_to_sess(sess, &sfd->map[sfd->cur_off], send_len);
	if (unlikely(ret < 0))
		return -EBADMSG;

	return 1;
}

constexpr off_t max_send_len_file = 1024 * 128;

static int stream_file_loop(struct stream_file_data *sfd,
			    struct client_sess *sess,
			    struct worker *worker)
{
	size_t send_len;
	int ret;

	if (unlikely(sfd->cur_off >= sfd->size)) {
		ret = 1;
		goto out;
	}

	if (unlikely(!sess->priv_data)) {
		struct stream_file_data *sfd_h;

		sfd_h = new struct stream_file_data;
		if (unlikely(!sfd_h))
			return -ENOMEM;

		*sfd_h = *sfd;
		sfd = sfd_h;
		sess->priv_data = (void *)sfd_h;
		madvise(sfd->map, sfd->size, MADV_SEQUENTIAL);
		send_len = max_send_len_file;
	} else {
		send_len = (size_t)(sfd->size - sfd->cur_off);
		if (send_len > max_send_len_file)
			send_len = max_send_len_file;
	}

	ret = send_to_sess(sess, &sfd->map[sfd->cur_off], send_len);
	if (unlikely(ret < 0)) {
		ret = -EBADMSG;
		goto out;
	}
	sfd->cur_off += (off_t)ret;
	ret = 1;

	if (sfd->cur_off < sfd->size) {
		sess->action = HTTP_ACT_FILE_STREAM;
		worker->buf_queue->push(sess->idx);
		return 0;
	}

out:
	munmap(sfd->map, sfd->size);
	if (likely(sess->priv_data)) {
		delete (struct stream_file_data *)sess->priv_data;
		sess->priv_data = NULL;
	}

	return ret;
}

static void handle_range_header(struct client_sess *sess, off_t *start_offset_p)
{
	parse_http_header2(sess);

	const auto &http_headers = *sess->http_headers;
	auto it = http_headers.find("range");
	if (it != http_headers.end()) {
		const char *val = it->second.c_str();
		const char *start_bytes;

		start_bytes = strstr(val, "bytes=");
		if (!start_bytes)
			return;

		start_bytes += 6;
		*start_offset_p = strtoll(start_bytes, NULL, 10);
	}
}

static void stream_file_bad_req(struct client_sess *sess, const char *msg)
{
	char buf[512];
	int ret;

	ret = snprintf(buf, sizeof(buf),
			"HTTP/1.1 400 Bad Request\r\n"
			"Connection: closed\r\n"
			"Content-Type: text/plain\r\n\r\n"
			"%s\n\n", msg);

	send_to_sess(sess, buf, (size_t)ret);
}

static int start_stream_file(const char *file, struct client_sess *sess,
			     struct worker *worker)
{
	struct stream_file_data sfd;
	off_t start_offset = 0;
	struct stat st;
	char *map;
	int ret;

	map = open_file_for_stream(file, &st, sess, &sfd);
	if (unlikely(!map))
		return -EBADMSG;

	handle_range_header(sess, &start_offset);
	if (start_offset >= sfd.size || start_offset < 0) {
		stream_file_bad_req(sess, "Bad range offset!");
		return -EBADMSG;
	}

	sfd.cur_off = start_offset;
	ret = send_http_header_for_stream_file(sess, start_offset, st.st_size);
	if (unlikely(ret))
		return -EBADMSG;

	if (st.st_size <= max_send_len_file) {
		ret = stream_file_once(&sfd, sess);
		munmap(sfd.map, sfd.size);
	} else {
		ret = stream_file_loop(&sfd, sess, worker);
	}

	return ret;
}

static int stream_file(const char *file, struct client_sess *sess,
		       struct worker *worker)
{
	int ret;

	if (sess->action == HTTP_ACT_NONE) {
		ret = start_stream_file(file, sess, worker);
		if (unlikely(ret))
			return ret;
		if (sess->action == HTTP_ACT_FILE_STREAM)
			return 0;
	}
	return 1;
}

#if 0
static size_t htmlspecialchars(char *_output, size_t outlen, const char *_input,
			       size_t inlen)
{
	struct html_char_map {
		const char	to[8];
		const uint8_t	len;
	};

	static const struct html_char_map html_map[0x100u] = {
		['<'] = {"&lt;",	4},
		['>'] = {"&gt;",	4},
		['"'] = {"&quot;",	6},
		['&'] = {"&amp;",	5},
	};


	size_t j = 0;
	uint8_t len = 0;
	unsigned char *output = (unsigned char *)_output;
	const unsigned char *input  = (const unsigned char *)_input;
	const unsigned char *in_end = input + inlen;

	while (likely(input < in_end)) {
		const unsigned char *cp;
		const struct html_char_map *map_to = &html_map[(size_t)*input];

		if (likely(*map_to->to == '\0')) {
			cp  = input;
			len = 1;
		} else {
			cp  = (const unsigned char *)map_to->to;
			len = map_to->len;
		}

		if (unlikely((j + len - 1) >= outlen))
			break;

		memcpy(&output[j], cp, len);
		j += len;
		input++;
	}

	if (likely(outlen > 0)) {
		if (unlikely((j + 1) > outlen))
			j -= len;
		output[++j] = '\0';
	}

	return j;
}
#endif

static int redirect_on_no_trailing_slash(const char *path,
					 struct client_sess *sess)
{
	size_t len;
	char *buf;
	char *qs;

	len = strlen(path);
	if (path[len - 1] == '/')
		return 0;

	qs = sess->qs;
	if (qs)
		len += strlen(qs);

	len += 16;
	buf = new char[len];
	if (unlikely(!buf))
		return -ENETDOWN;

	if (qs)
		snprintf(buf, len, "%s/?%s", path, qs);
	else
		snprintf(buf, len, "%s/", path);

	http_redirect(sess, buf);
	delete[] buf;
	return 1;
}

static int stream_dir_list_open(const char *path, struct client_sess *sess,
				DIR **dir_p)
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

static int send_init_payload_for_stream_dir_list(struct client_sess *sess)
{
	constexpr static const char buf[] =
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

	int ret;

	ret = send_to_sess(sess, buf, sizeof(buf) - 1);
	if (unlikely(ret < 0))
		return -EBADMSG;

	return 0;
}

static int construct_file_row(const char *path, const char *file, char **pbuf_p,
			      size_t *capacity_p)
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

	ret = snprintf(*pbuf_p, *capacity_p,
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
	*pbuf_p += (size_t)ret;
	*capacity_p -= (size_t)ret;
	return 0;
}

static int _stream_dir_list_loop(struct stream_dir_list_data *sdld,
				 char **pbuf_p, size_t *capacity_p)
{
	struct dirent *de;
	const char *f;
	int ret;

	de = readdir(sdld->dir);
	if (unlikely(!de))
		return -1;

	f = de->d_name;
	if (unlikely(!strcmp(f, ".") || !strcmp(f, "..")))
		return 0;

	ret = construct_file_row(sdld->path, f, pbuf_p, capacity_p);
	if (unlikely(ret > 0))
		return 0;

	return 0;
}

static int stream_dir_list_queue(struct stream_dir_list_data *sdld_s,
				 struct client_sess *sess,
				 struct worker *worker)
{
	if (unlikely(!sess->priv_data)) {
		struct stream_dir_list_data *sdld;

		sdld = new struct stream_dir_list_data;
		if (unlikely(!sdld))
			return -EBADMSG;

		*sdld = *sdld_s;
		sess->priv_data = (void *)sdld;
	}

	sess->action = HTTP_ACT_DIRLIST;
	worker->buf_queue->push(sess->idx);
	return 0;
}

constexpr static const char dir_list_foot[] =
	"\t</table>\n</body>\n</html>\n";

static int send_footer_dir_list(struct client_sess *sess)
{
	int ret;

	ret = send_to_sess(sess, dir_list_foot, sizeof(dir_list_foot) - 1);
	if (unlikely(ret < 0))
		return ret;

	return 0;
}

static int stream_dir_list_loop(struct stream_dir_list_data *sdld,
				struct client_sess *sess,
				struct worker *worker)
{
	bool need_send_footer;
	char buf[1024 * 128];
	size_t capacity = sizeof(buf) - 1;
	size_t send_len;
	char *pbuf = buf;
	int ret;

	while (1) {

		if (unlikely(capacity < 8192)) {
			send_len = sizeof(buf) - 1 - capacity;
			ret = send_to_sess(sess, buf, send_len);
			if (unlikely(ret < 0))
				goto out_close;

			ret = stream_dir_list_queue(sdld, sess, worker);
			if (unlikely(ret))
				goto out_close;

			/*
			 * We are still in the queue loop.
			 */
			return 0;
		}

		ret = _stream_dir_list_loop(sdld, &pbuf, &capacity);
		if (unlikely(ret))
			break;
	}

	if (capacity > sizeof(dir_list_foot) - 1) {
		capacity -= sizeof(dir_list_foot) - 1;
		memcpy(pbuf, dir_list_foot, sizeof(dir_list_foot) - 1);
		need_send_footer = false;
	} else {
		need_send_footer = true;
	}

	send_len = sizeof(buf) - 1 - capacity;
	if (send_len > 0) {
		ret = send_to_sess(sess, buf, send_len);
		if (unlikely(ret < 0))
			goto out_close;
	}

	if (need_send_footer) {
		ret = send_footer_dir_list(sess);
		if (unlikely(ret))
			goto out_close;
	}

	ret = 1;

out_close:
	closedir(sdld->dir);
	if (sess->priv_data) {
		delete (struct stream_dir_list_data *)sess->priv_data;
		sess->priv_data = NULL;
	}

	return ret;
}

static int stream_dir_list(const char *path, struct client_sess *sess,
			   struct worker *worker)
{
	struct stream_dir_list_data sdld;
	int ret;

	/*
	 * If we are going to list the directory, the URI path must be
	 * ended with a trailing slash. We it's not, put the a trailing
	 * slash by redirecting the client.
	 */
	ret = redirect_on_no_trailing_slash(path, sess);
	if (ret)
		return ret;

	ret = stream_dir_list_open(path, sess, &sdld.dir);
	if (unlikely(ret))
		return ret;

	ret = send_init_payload_for_stream_dir_list(sess);
	if (unlikely(ret))
		return ret;

	snprintf(sdld.path, sizeof(sdld.path), "%s", path);
	return stream_dir_list_loop(&sdld, sess, worker);
}

static int handle_route_get(struct client_sess *sess, struct worker *worker)
{
	char path[4096 + 128];
	struct stat st;
	int ret;

	if (likely(sess->need_epl_del)) {
		sess->need_epl_del = false;
		uninstall_fd_from_worker(sess->fd, worker);
	}

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

	if (S_ISDIR(st.st_mode))
		return stream_dir_list(path, sess, worker);

	if (S_ISREG(st.st_mode))
		return stream_file(path, sess, worker);

	return -EBADMSG;
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
		close_sess(sess, worker);
		if (likely(ret == -EBADMSG || ret == -ENETDOWN ||
			   ret == -ECONNRESET || ret == -EPIPE ||
			   ret == 1))
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
	case HTTP_ACT_DIRLIST: {
		struct stream_dir_list_data *sdld;

		sdld = (struct stream_dir_list_data *)sess->priv_data;
		ret = stream_dir_list_loop(sdld, sess, worker);
		break;
	}
	case HTTP_ACT_FILE_STREAM: {
		struct stream_file_data *sfd;

		sfd = (struct stream_file_data *)sess->priv_data;
		ret = stream_file_loop(sfd, sess, worker);
		break;
	}
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

	atomic_fetch_add(&worker->state->nr_on_thread, 1u);
	wait_for_ready_state(worker);
	ret = _worker_func(worker);
	atomic_fetch_sub(&worker->state->nr_on_thread, 1u);
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

struct cmd_arg {
	const char		*bind_addr;
	const char		*bind_port;
	const char		*slc_addr;
	const char		*slc_port;
};

static std::atomic<bool> g_slc_stop;
#define PKT_DATA_BUFFER 1024

struct slc_packet {
	uint8_t		type;
	uint8_t		pad;
	uint16_t	len;
	uint8_t		data[PKT_DATA_BUFFER];
};

struct client_private_data {
	struct slc_packet	pkt;
	const char		*server_addr;
	const char		*target_addr;
	uint16_t		target_port;
	uint16_t		server_port;
};

enum {
	PKT_TYPE_SERVER_GET_A_REAL_CLIENT,
	PKT_TYPE_CLIENT_INIT_CIRCUIT,
	PKT_TYPE_CLIENT_START_PRIVATE_SOCK
};

static int create_tcp_sock(void)
{
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		fd = errno;
		perror("socket");
		return -fd;
	}
	return fd;
}

static int start_circuit(int fd_circuit)
{
	struct slc_packet pkt;
	ssize_t ret;
	int err;

	memset(&pkt, 0, sizeof(pkt));
	pkt.type = PKT_TYPE_CLIENT_INIT_CIRCUIT;
	ret = send(fd_circuit, &pkt, sizeof(pkt), 0);
	if (unlikely(ret < 0)) {
		err = errno;
		perror("send");
		return -err;
	}
	return 0;
}

static int setup_socket(int fd)
{
	int ret, y;
	size_t len = sizeof(y);

	/*
	 * Ignore any error from these calls. They are not mandatory.
	 */
	y = 1;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *)&y, len);
	if (unlikely(ret < 0)) {
		perror("setsockopt(IPPROTO_TCP, TCP_NODELAY)");
		puts("Failed to set TCP nodelay, but this is fine.");
	}

	y = 1024 * 1024 * 100;
	ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, (void *)&y, len);
	y = 1024 * 1024 * 100;
	ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, (void *)&y, len);

	return 0;
}

static int connect_tcp_sock(int fd, const char *addr, uint16_t port)
{
	struct sockaddr_in dst_addr;
	int err;

	memset(&dst_addr, 0, sizeof(dst_addr));
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = htons(port);
	dst_addr.sin_addr.s_addr = inet_addr(addr);

	// printf("SLC Connecting to %s:%u...\n", addr, port);
	err = connect(fd, (struct sockaddr *)&dst_addr, sizeof(dst_addr));
	if (err < 0) {
		err = errno;
		perror("connect");
		return -err;
	}
	err = setup_socket(fd);
	// printf("SLC Connected!\n");
	return 0;
}

static int recv_and_send(int fd_in, int fd_out, int *pipes, size_t len)
{
	unsigned int fl = SPLICE_F_MOVE | SPLICE_F_NONBLOCK;
	ssize_t read_ret;
	ssize_t write_ret;
	int ret;

	read_ret = splice(fd_in, NULL, pipes[1], NULL, len, fl);
	if (unlikely(read_ret <= 0)) {
		if (read_ret == 0) {
			// puts("fd_in is down");
			return -ENETDOWN;
		}
		ret = errno;
		// perror("splice fd_in");
		return -ret;
	}

do_write:
	write_ret = splice(pipes[0], NULL, fd_out, NULL, read_ret, fl);
	if (unlikely(write_ret <= 0)) {
		if (write_ret == 0) {
			// puts("fd_out is down");
			return -ENETDOWN;
		}
		ret = errno;
		// perror("splice fd_out");
		return -ret;
	}

	read_ret -= write_ret;
	if (unlikely(read_ret > 0))
		goto do_write;

	return 0;
}

static int socket_bridge(int fd1, int fd2)
{
	static const size_t len = 1024 * 1024;
	struct pollfd fds[2];
	int pipes[2] = {-1, -1};
	int ret;

	if (pipe(pipes)) {
		ret = errno;
		perror("pipe");
		return -ret;
	}

	fds[0].fd = fd1;
	fds[0].events = POLLIN | POLLPRI;
	fds[1].fd = fd2;
	fds[1].events = POLLIN | POLLPRI;

do_poll:
	if (atomic_load(&g_slc_stop)) {
		ret = 0;
		goto out;
	}

	ret = poll(fds, 2, 1000);
	if (unlikely(ret < 0)) {
		ret = errno;
		perror("poll");
		goto out;
	}

	if (ret == 0)
		goto do_poll;

	if (fds[0].revents & POLLIN) {
		ret = recv_and_send(fd1, fd2, pipes, len);
		if (unlikely(ret < 0))
			goto out;
	}

	if (fds[1].revents & POLLIN) {
		ret = recv_and_send(fd2, fd1, pipes, len);
		if (unlikely(ret < 0))
			goto out;
	}
	goto do_poll;

out:
	if (pipes[0] != -1)
		close(pipes[0]);
	if (pipes[1] != -1)
		close(pipes[1]);
	return ret;
}

static void *start_private_conn(void *pp)
{
	struct client_private_data *p = (struct client_private_data *)pp;
	int fd_pa = -1, fd_pb = -1;
	int err = 0;
	ssize_t ret;

	fd_pa = create_tcp_sock();
	if (unlikely(fd_pa < 0)) {
		err = fd_pa;
		goto out_free;
	}

	fd_pb = create_tcp_sock();
	if (unlikely(fd_pb < 0)) {
		err = fd_pb;
		goto out_free;
	}

	err = connect_tcp_sock(fd_pa, p->server_addr, p->server_port);
	if (unlikely(err))
		goto out_free;

	err = connect_tcp_sock(fd_pb, p->target_addr, p->target_port);
	if (unlikely(err))
		goto out_free;

	p->pkt.type = PKT_TYPE_CLIENT_START_PRIVATE_SOCK;
	ret = send(fd_pa, &p->pkt, sizeof(p->pkt), 0);
	if (unlikely(ret < 0)) {
		err = errno;
		perror("send");
		goto out_free;
	}

out_free:
	delete p;
	if (err)
		goto out;

	socket_bridge(fd_pa, fd_pb);
out:
	if (fd_pa != -1)
		close(fd_pa);
	if (fd_pb != -1)
		close(fd_pb);
	return NULL;
}

static int handle_private_conn(int fd_circuit, const char *target_addr,
			       uint16_t target_port, const char *server_addr,
			       uint16_t server_port)
{
	struct client_private_data *pp;
	struct slc_packet pkt;
	pthread_t thread;
	ssize_t ret;
	int err;

do_recv:
	ret = recv(fd_circuit, &pkt, sizeof(pkt), 0);
	if (unlikely(ret <= 0)) {
		if (ret == 0) {
			puts("SLC Server has been disconnected!");
			return -ENETDOWN;
		}
		err = errno;
		perror("recv");
		return -err;
	}

	pp = new struct client_private_data;
	if (unlikely(!pp))
		return -ENOMEM;

	pp->pkt = pkt;
	pp->server_addr = server_addr;
	pp->server_port = server_port;
	pp->target_addr = target_addr;
	pp->target_port = target_port;
	err = pthread_create(&thread, NULL, start_private_conn, pp);
	if (unlikely(ret < 0)) {
		errno = ret;
		perror("pthread_create");
		delete pp;
		return -ret;
	}
	pthread_detach(thread);

	if (!atomic_load(&g_slc_stop))
		goto do_recv;

	return 0;
}

static int _run_slc_client(const char *target_addr, uint16_t target_port,
			   const char *server_addr, uint16_t server_port)
{
	int fd_circuit = -1;
	int err;

	fd_circuit = create_tcp_sock();
	if (unlikely(fd_circuit < 0))
		return -fd_circuit;

	err = connect_tcp_sock(fd_circuit, server_addr, server_port);
	if (unlikely(err))
		goto out;

	err = start_circuit(fd_circuit);
	if (unlikely(err))
		goto out;

	err = handle_private_conn(fd_circuit, target_addr, target_port,
				  server_addr, server_port);
out:
	close(fd_circuit);
	return (err < 0) ? -err : err;
}

static int run_slc_client(const char *target_addr, uint16_t target_port,
			  const char *server_addr, uint16_t server_port)
{
	int ret = 0;

	atomic_store(&g_slc_stop, false);

repeat:
	ret = _run_slc_client(target_addr, target_port, server_addr,
			      server_port);
	if (unlikely(ret)) {
		errno = ret;
		perror("_run_slc_client()");
	}

	if (atomic_load(&g_slc_stop))
		return ret;

	puts("SLC: Sleeping for 3 seconds before reconnecting...");
	sleep(3);
	goto repeat;
}

static int _main(struct cmd_arg *arg)
{
	struct server_state *state = NULL;
	uint16_t bport = (uint16_t)atoi(arg->bind_port);
	pid_t slc_pid = -1;
	int ret;

	if (arg->slc_addr && arg->slc_port) {
		slc_pid = fork();
		if (slc_pid < 0) {
			ret = errno;
			perror("fork()");
			return -ret;
		}

		if (!slc_pid)
			return run_slc_client(arg->bind_addr, bport,
					      arg->slc_addr,
					      (uint16_t)atoi(arg->slc_port));
	}

	ret = init_state(&state);
	if (unlikely(ret))
		return ret;

	state->bind_addr = arg->bind_addr;
	state->bind_port = bport;

	ret = init_socket(state);
	if (unlikely(ret))
		goto out;
	ret = run_workers(state);
out:
	destroy_state(state);
	if (slc_pid > 0)
		kill(slc_pid, SIGTERM);

	return ret;
}

static const struct option long_options[] = {
	{"bind-addr",		required_argument,	0,	'h'},
	{"bind-port",		required_argument,	0,	'p'},
	{"slc-addr",		required_argument,	0,	'H'},
	{"slc-port",		required_argument,	0,	'P'},
	{NULL,			0,			0,	0}
};

static __cold int _parse_cmd_arg(int argc, char *argv[], struct cmd_arg *arg)
{
	int opt_idx;
	int c;

	c = getopt_long(argc, argv, "h:p:H:P:", long_options, &opt_idx);
	if (c == -1)
		return 1;

	switch (c) {
	case 'h':
		arg->bind_addr = optarg;
		break;
	case 'p':
		arg->bind_port = optarg;
		break;
	case 'H':
		arg->slc_addr = optarg;
		break;
	case 'P':
		arg->slc_port = optarg;
		break;
	default:
		printf("Unknown option: %s\n", optarg);
		return -EINVAL;
	}

	return 0;
}

static __cold int parse_cmd_arg(int argc, char *argv[], struct cmd_arg *arg)
{
	int ret;

	while (1) {
		ret = _parse_cmd_arg(argc, argv, arg);
		if (ret)
			break;
	}

	if (ret == 1)
		return 0;

	return ret;
}

static noinline __cold void show_help(const char *app)
{
	putchar('\n');
	puts("Usage:\n");
	printf("   %s [options]\n\n", app);
	puts("Options:");
	puts("  -h,--bind-addr=<addr>\tSet gwhttpd bind address");
	puts("  -p,--bind-port=<port>\tSet gwhttpd bind port");
	puts("  -H,--slc-addr=<addr>\tSet gwhttpd SLC address");
	puts("  -P,--slc-port=<port>\tSet gwhttpd SLC port");
	puts("\n");
	puts("GitHub repo: https://github.com/ammarfaizi2/gwhttpd.git\n");
	puts("Copyright (C) 2022 Ammar Faizi <ammarfaizi2@gnuweeb.org>");
	puts("This is free software; see the source for copying conditions.  There is NO");
	puts("warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
}

int main(int argc, char *argv[])
{
	struct cmd_arg arg;
	int ret;

	setvbuf(stdout, NULL, _IOLBF, 4096);
	if (argc == 1) {
		show_help(argv[0]);
		return EINVAL;
	}

	memset(&arg, 0, sizeof(arg));
	ret = parse_cmd_arg(argc, argv, &arg);
	if (unlikely(ret)) {
		if (ret < 0)
			ret = -ret;
		show_help(argv[0]);
		return ret;
	}

	if (!arg.bind_addr) {
		puts("Error: Missing bind_addr!");
		show_help(argv[0]);
		return EINVAL;
	}

	if (!arg.bind_port) {
		puts("Error: Missing bind_port!");
		show_help(argv[0]);
		return EINVAL;
	}

	return _main(&arg);
}
