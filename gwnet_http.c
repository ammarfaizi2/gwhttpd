// SPDX-License-Identifier: GPL-2.0-only
/*
 * gwnet_http.c
 *
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <time.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "gwnet_http.h"
#include "gwnet_tcp.h"
#include "gwbuf.h"

#include "common.h"

#define GWNET_HTTP_SEND_BUF		8192

enum {
	GWNET_HTTP_TX_ST_INIT		= 0,
	GWNET_HTTP_TX_ST_HDR		= 1,
	GWNET_HTTP_TX_ST_BODY		= 2,
	GWNET_HTTP_TX_ST_DONE		= 3,
	GWNET_HTTP_TX_ST_ERROR		= 4,
};

enum {
	GWNET_HTTP_RX_ST_INIT		= 0,
	GWNET_HTTP_RX_ST_HDR		= 1,
	GWNET_HTTP_RX_ST_BODY		= 2,
	GWNET_HTTP_RX_ST_DONE		= 3,
	GWNET_HTTP_RX_ST_ERROR		= 4,
};

struct gwnet_http_res_body_zero {
	uint64_t	zero_len;
	uint64_t	zero_off;
};

struct gwnet_http_res_body_urandom {
	int		fd;
	uint64_t	ur_len;
	uint64_t	ur_off;
};

struct gwnet_http_res_body_file {
	int		fd;
	uint64_t	file_len;
	uint64_t	file_off;
};

struct gwnet_http_res_body_buf {
	struct gwbuf	buf;
};

struct gwnet_http_res_body {
	uint8_t	type;
	union {
		struct gwnet_http_res_body_zero		zero;
		struct gwnet_http_res_body_urandom	urandom;
		struct gwnet_http_res_body_file		file;
		struct gwnet_http_res_body_buf		buf;
	};
};

struct gwnet_http_res {
	uint16_t			status;
	uint8_t				version;
	struct gwnet_http_hdr_fields	hdr;
	uint64_t			content_length;
	char				content_type[128];
	struct gwnet_http_res_body	body;
};

struct gwnet_http_req {
	struct gwnet_http_req		*next;
	bool				is_chunked;
	bool				is_body_oversized;
	bool				keep_alive;
	union {
		struct gwnet_http_hdr_pctx	hpctx;
		struct gwnet_http_body_pctx	bpctx;
	};
	struct gwnet_http_req_hdr	hdr;
	struct gwbuf			body_buf;
	uint64_t			con_len;
	uint64_t			rcon_len;
	char				*content_type;
	char				*uri;
	char				*qs;
	struct gwnet_http_res		res;
};

struct gwnet_http_cli {
	uint8_t				tx_state;
	uint8_t				rx_state;
	bool				stop_receiving;
	struct gwnet_http_srv		*srv;
	struct gwnet_http_req		*req_head;
	struct gwnet_http_req		*req_tail;
	void				*data_cb;
	gwnet_http_srv_rt_cb_t		rt_cb;
	gwnet_http_srv_rt_on_hdr_cb_t	rt_on_hdr_cb;
	gwnet_http_srv_rt_on_body_cb_t	rt_on_body_cb;
};

struct gwnet_http_srv {
	gwnet_tcp_srv_t			*tcp;
	struct gwnet_http_srv_cfg	cfg;
	void				*data_cb;
	gwnet_http_srv_accept_cb_t	accept_cb;
};

static const char *translate_http_code(uint16_t code)
{
	switch (code) {
	case 100: return "Continue";
	case 101: return "Switching Protocols";
	case 102: return "Processing";
	case 103: return "Early Hints";
	case 200: return "OK";
	case 201: return "Created";
	case 202: return "Accepted";
	case 203: return "Non-Authoritative Information";
	case 204: return "No Content";
	case 205: return "Reset Content";
	case 206: return "Partial Content";
	case 207: return "Multi-Status";
	case 208: return "Already Reported";
	case 226: return "IM Used";
	case 300: return "Multiple Choices";
	case 301: return "Moved Permanently";
	case 302: return "Found";
	case 303: return "See Other";
	case 304: return "Not Modified";
	case 305: return "Use Proxy";
	case 307: return "Temporary Redirect";
	case 308: return "Permanent Redirect";
	case 400: return "Bad Request";
	case 401: return "Unauthorized";
	case 402: return "Payment Required";
	case 403: return "Forbidden";
	case 404: return "Not Found";
	case 405: return "Method Not Allowed";
	case 406: return "Not Acceptable";
	case 407: return "Proxy Authentication Required";
	case 408: return "Request Timeout";
	case 409: return "Conflict";
	case 410: return "Gone";
	case 411: return "Length Required";
	case 412: return "Precondition Failed";
	case 413: return "Payload Too Large";
	case 414: return "URI Too Long";
	case 415: return "Unsupported Media Type";
	case 416: return "Range Not Satisfiable";
	case 417: return "Expectation Failed";
	case 418: return "I'm a teapot";
	case 421: return "Misdirected Request";
	case 422: return "Unprocessable Entity";
	case 423: return "Locked";
	case 424: return "Failed Dependency";
	case 425: return "Too Early";
	case 426: return "Upgrade Required";
	case 428: return "Precondition Required";
	case 429: return "Too Many Requests";
	case 431: return "Request Header Fields Too Large";
	case 451: return "Unavailable For Legal Reasons";
	case 500: return "Internal Server Error";
	case 501: return "Not Implemented";
	case 502: return "Bad Gateway";
	case 503: return "Service Unavailable";
	case 504: return "Gateway Timeout";
	case 505: return "HTTP Version Not Supported";
	case 506: return "Variant Also Negotiates";
	case 507: return "Insufficient Storage";
	case 508: return "Loop Detected";
	case 510: return "Not Extended";
	case 511: return "Network Authentication Required";
	default: return "Unknown";
	}
}

struct gwnet_http_req_hdr *gwnet_http_req_get_hdr(gwnet_http_req_t *req)
{
	return &req->hdr;
}

void gwnet_http_srv_set_data_cb(gwnet_http_srv_t *srv, void *data)
{
	srv->data_cb = data;
}

void gwnet_http_srv_set_accept_cb(gwnet_http_srv_t *srv,
				  gwnet_http_srv_accept_cb_t cb)
{
	srv->accept_cb = cb;
}

void gwnet_http_cli_set_data_cb(gwnet_http_cli_t *hc, void *data)
{
	hc->data_cb = data;
}

void gwnet_http_cli_set_rt_cb(gwnet_http_cli_t *hc,
			      gwnet_http_srv_rt_cb_t cb)
{
	hc->rt_cb = cb;
}

void gwnet_http_cli_set_rt_on_hdr_cb(gwnet_http_cli_t *hc,
				     gwnet_http_srv_rt_on_hdr_cb_t cb)
{
	hc->rt_on_hdr_cb = cb;
}

void gwnet_http_cli_set_rt_on_body_cb(gwnet_http_cli_t *hc,
				      gwnet_http_srv_rt_on_body_cb_t cb)
{
	hc->rt_on_body_cb = cb;
}

static inline uint64_t min_st(uint64_t a, uint64_t b)
{
	return (a < b) ? a : b;
}

struct gwnet_http_res *gwnet_http_req_get_res(gwnet_http_req_t *req)
{
	return &req->res;
}

void gwnet_http_res_set_code(gwnet_http_res_t *res, uint16_t code)
{
	res->status = code;
}

void gwnet_http_res_set_content_type(gwnet_http_res_t *res,
				     const char *content_type)
{
	const size_t l = sizeof(res->content_type) - 1;
	char *s = res->content_type;
	strncpy(s, content_type, l);
	s[l] = '\0';
}

static void gwnet_http_res_body_free(struct gwnet_http_res_body *b)
{
	switch (b->type) {
	case GWNET_HTTP_RES_TYPE_NO_CONTENT:
		break;
	case GWNET_HTTP_RES_TYPE_BUF:
		gwbuf_free(&b->buf.buf);
		break;
	case GWNET_HTTP_RES_TYPE_ZERO:
		b->zero.zero_len = 0;
		b->zero.zero_off = 0;
		break;
	case GWNET_HTTP_RES_TYPE_URANDOM:
		b->urandom.ur_len = 0;
		b->urandom.ur_off = 0;
		if (b->urandom.fd >= 0) {
			__sys_close(b->urandom.fd);
			b->urandom.fd = -1;
		}
		break;
	case GWNET_HTTP_RES_TYPE_FILE:
		if (b->file.fd >= 0) {
			__sys_close(b->file.fd);
			b->file.fd = -1;
		}
		b->file.file_len = 0;
		b->file.file_off = 0;
		break;
	default:
		assert(0 && "Unknown response body type");
		break;
	}

	memset(b, 0, sizeof(*b));
	b->type = GWNET_HTTP_RES_TYPE_NO_CONTENT;
}

void gwnet_http_res_body_set_zero(gwnet_http_res_t *res, uint64_t len)
{
	gwnet_http_res_body_free(&res->body);
	res->body.type = GWNET_HTTP_RES_TYPE_ZERO;
	res->body.zero.zero_len = len;
	res->body.zero.zero_off = 0;
}

int gwnet_http_res_body_set_urandom(gwnet_http_res_t *res, uint64_t len)
{
	int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	gwnet_http_res_body_free(&res->body);
	res->body.type = GWNET_HTTP_RES_TYPE_URANDOM;
	res->body.urandom.ur_len = len;
	res->body.urandom.ur_off = 0;
	res->body.urandom.fd = fd;
	return 0;
}

void gwnet_http_res_body_set_file(gwnet_http_res_t *res, int fd,
				  uint64_t len)
{
	gwnet_http_res_body_free(&res->body);
	res->body.type = GWNET_HTTP_RES_TYPE_FILE;
	res->body.file.fd = fd;
	res->body.file.file_len = len;
	res->body.file.file_off = 0;
}

int gwnet_http_res_body_set_file_path(gwnet_http_res_t *res,
				      const char *path)
{
	struct stat st;
	int ret, fd;
	
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	if (fstat(fd, &st) < 0) {
		ret = -errno;
		goto out_err;
	}

	if (!S_ISREG(st.st_mode)) {
		ret = -EINVAL;
		goto out_err;
	}

	gwnet_http_res_body_set_file(res, fd, st.st_size);
	return 0;

out_err:
	__sys_close(fd);
	return ret;
}

void gwnet_http_res_body_set_buf(gwnet_http_res_t *res, struct gwbuf *buf)
{
	gwnet_http_res_body_free(&res->body);
	res->body.type = GWNET_HTTP_RES_TYPE_BUF;
	gwbuf_move(&res->body.buf.buf, buf);
}

struct gwbuf *gwnet_http_res_body_get_buf(gwnet_http_res_t *res)
{
	if (res->body.type != GWNET_HTTP_RES_TYPE_BUF)
		return NULL;

	return &res->body.buf.buf;
}

struct gwnet_http_hdr_fields *gwnet_http_res_get_hdr_fields(
						gwnet_http_res_t *res)
{
	return &res->hdr;
}

static int gwnet_http_srv_validate_cfg(struct gwnet_http_srv_cfg *cfg)
{
	if (!cfg->max_req_hdr_len)
		cfg->max_req_hdr_len = GWNET_HTTP_DEF_MAX_REQ_HDR_LEN;

	if (!cfg->max_req_body_len)
		cfg->max_req_body_len = GWNET_HTTP_DEF_MAX_REQ_BODY_LEN;

	return 0;
}

static int gwnet_http_srv_accept_cb(void *data, gwnet_tcp_srv_t *s,
				    gwnet_tcp_cli_t *c);

__cold
gwnet_http_srv_t *gwnet_http_srv_init(const struct gwnet_http_srv_cfg *cfg)
{
	struct gwnet_http_srv *s;
	int ret;

	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;

	s->cfg = *cfg;
	ret = gwnet_http_srv_validate_cfg(&s->cfg);
	if (ret < 0)
		goto free_s;

	s->tcp = gwnet_tcp_srv_init(&s->cfg.tcp_cfg);
	if (!s->tcp)
		goto free_s;

	gwnet_tcp_srv_set_accept_cb(s->tcp, &gwnet_http_srv_accept_cb, s);
	return s;

free_s:
	free(s);
	return NULL;
}

__cold
int gwnet_http_srv_run(gwnet_http_srv_t *srv)
{
	return gwnet_tcp_srv_run(srv->tcp);
}

__cold
void gwnet_http_srv_stop(gwnet_http_srv_t *srv)
{
	gwnet_tcp_srv_stop(srv->tcp);
}

__cold
void gwnet_http_srv_free(gwnet_http_srv_t *srv)
{
	gwnet_tcp_srv_free(srv->tcp);
	free(srv);
}

__hot
static void gwnet_http_res_free(struct gwnet_http_res *res)
{
	if (!res)
		return;

	gwnet_http_res_body_free(&res->body);
	gwnet_http_hdr_fields_free(&res->hdr);
}

__hot
static gwnet_http_req_t *gwnet_http_req_alloc(void)
{
	gwnet_http_req_t *req = calloc(1, sizeof(*req));
	int r;

	if (!req)
		return NULL;

	r = gwnet_http_hdr_pctx_init(&req->hpctx);
	if (r < 0) {
		free(req);
		return NULL;
	}

	return req;
}

__hot
static void http_req_free(gwnet_http_req_t *req)
{
	if (!req)
		return;

	free(req->uri);
	free(req->qs);
	free(req->content_type);
	gwbuf_free(&req->body_buf);
	gwnet_http_req_hdr_free(&req->hdr);
	gwnet_http_res_free(&req->res);
	free(req);
}

__hot
static void free_requests(struct gwnet_http_cli *hc)
{
	gwnet_http_req_t *req = hc->req_head;

	while (req) {
		gwnet_http_req_t *next = req->next;
		http_req_free(req);
		req = next;
	}

	hc->req_head = hc->req_tail = NULL;
}

__hot
static void req_push(gwnet_http_cli_t *hc, gwnet_http_req_t *req)
{
	if (!hc->req_head) {
		hc->req_head = hc->req_tail = req;
	} else {
		hc->req_tail->next = req;
		hc->req_tail = req;
	}
}

__hot
static void gwnet_http_srv_cli_req_pop_head(gwnet_http_cli_t *hc)
{
	gwnet_http_req_t *req = hc->req_head;

	if (!req)
		return;

	hc->req_head = req->next;
	if (!hc->req_head)
		hc->req_tail = NULL;

	http_req_free(req);
}

static gwnet_http_req_t *gwnet_http_srv_cli_req_head(gwnet_http_cli_t *hc)
{
	return hc->req_head;
}

static struct gwnet_http_cli *gwnet_http_cli_alloc(gwnet_http_srv_t *srv)
{
	struct gwnet_http_cli *hc = calloc(1, sizeof(*hc));
	if (!hc)
		return NULL;

	hc->tx_state = GWNET_HTTP_TX_ST_INIT;
	hc->rx_state = GWNET_HTTP_RX_ST_INIT;
	hc->srv = srv;
	return hc;
}

__hot
static void gwnet_http_cli_free(struct gwnet_http_cli *hc)
{
	if (!hc)
		return;

	free_requests(hc);
	free(hc);
}

__hot
static int handle_rx_st_init(gwnet_http_cli_t *hc, struct gwbuf *b)
{
	gwnet_http_req_t *req;

	if (!b->len)
		return -EAGAIN;

	req = gwnet_http_req_alloc();
	if (!req)
		return -ENOMEM;

	req_push(hc, req);
	hc->rx_state = GWNET_HTTP_RX_ST_HDR;
	return 1;
}

__hot
static int process_req_hdr(gwnet_http_cli_t *hc, struct gwnet_http_req *req)
{
	struct gwnet_http_hdr_fields *ff = &req->hdr.fields;
	const char *v;
	char *e;
	
	/*
	 * TODO(ammarfaizi2): Handle keep-alive with timeout.
	 */
	v = gwnet_http_hdr_fields_get(ff, "connection");
	if (v)
		req->keep_alive = !strcasecmp(v, "keep-alive");
	else
		req->keep_alive = (req->hdr.version == GWNET_HTTP_VER_1_1);

	v = gwnet_http_hdr_fields_get(ff, "content-length");
	if (v) {
		if (gwnet_http_hdr_fields_get(ff, "transfer-encoding"))
			return -EINVAL;

		errno = 0;
		req->con_len = strtoull(v, &e, 10);
		if (errno || *e)
			return -EINVAL;

		req->rcon_len = req->con_len;
		req->is_chunked = false;
		hc->rx_state = GWNET_HTTP_RX_ST_BODY;
		return 1;
	}

	/*
	 * TODO(ammarfaizi2): Handle various transfer encodings
	 * other than chunked.
	 */
	v = gwnet_http_hdr_fields_get(ff, "transfer-encoding");
	if (v) {
		req->is_chunked = !strcasecmp(v, "chunked");
		hc->rx_state = GWNET_HTTP_RX_ST_BODY;
		return gwnet_http_body_pctx_init(&req->bpctx);
	}

	hc->rx_state = GWNET_HTTP_RX_ST_DONE;
	return 0;
}

__hot
static int handle_rx_st_hdr(gwnet_http_cli_t *hc, struct gwbuf *b)
{
	struct gwnet_http_req *req = hc->req_tail;
	int r;

	if (!req)
		return -EINVAL;
	if (!b->len)
		return -EAGAIN;

	req->hpctx.buf = b->buf;
	req->hpctx.len = b->len;
	req->hpctx.off = 0;
	r = gwnet_http_req_hdr_parse(&req->hpctx, &req->hdr);
	if (req->hpctx.off)
		gwbuf_soft_advance(b, req->hpctx.off);

	if (r < 0)
		return r;

	r = process_req_hdr(hc, req);
	if (r < 0)
		return r;

	if (hc->rt_on_hdr_cb) {
		r = hc->rt_on_hdr_cb(hc->data_cb, hc->srv, hc, req);
		if (r < 0)
			return r;
	}

	return 1;
}

__hot
static int handle_rx_st_body_chunked(gwnet_http_cli_t *hc,
				     struct gwnet_http_req *req,
				     struct gwbuf *b)
{
	size_t max_req_body_len = hc->srv->cfg.max_req_body_len;
	struct gwnet_http_body_pctx *x = &req->bpctx;
	uint64_t to_copy, copied, prev_tot_len;
	struct gwbuf *bb = &req->body_buf;
	char *dst_buf;
	int r = 0;

loop:
	to_copy = bb->cap - bb->len;
	if (!to_copy) {
		r = gwbuf_prepare_need(bb, 4096);
		if (unlikely(r < 0))
			return r;

		to_copy = bb->cap - bb->len;
	}

	if (req->is_body_oversized) {
		dst_buf = NULL;
		to_copy = 0;
		prev_tot_len = 0;
	} else {
		if (to_copy + bb->len > max_req_body_len) {
			req->is_body_oversized = true;
			to_copy = max_req_body_len - bb->len;
		}

		dst_buf = &bb->buf[bb->len];
		prev_tot_len = x->tot_len;
	}

	x->buf = b->buf;
	x->len = b->len;
	x->off = 0;
	r = gwnet_http_body_parse_chunked(x, dst_buf, to_copy);
	if (x->off)
		gwbuf_soft_advance(b, x->off);

	if (to_copy) {
		copied = x->tot_len - prev_tot_len;
		bb->len += copied;
	}

	if (r == -ENOBUFS)
		goto loop;

	return r;
}

__hot
static int handle_rx_st_body_non_chunked(gwnet_http_cli_t *hc,
					 struct gwnet_http_req *req,
					 struct gwbuf *b)
{
	size_t max_req_body_len = hc->srv->cfg.max_req_body_len;
	size_t to_copy_len, orig_to_copy_len;
	struct gwbuf *bb = &req->body_buf;
	int r;

	orig_to_copy_len = to_copy_len = min_st(req->rcon_len, b->len);

	if (!req->is_body_oversized) {
		if (to_copy_len + bb->len > max_req_body_len) {
			req->is_body_oversized = true;
			to_copy_len = max_req_body_len - bb->len;
		}

		r = gwbuf_append(bb, b->buf, to_copy_len);
		if (r < 0)
			return r;
	}

	gwbuf_soft_advance(b, orig_to_copy_len);
	req->rcon_len -= orig_to_copy_len;
	return (req->rcon_len > 0) ? -EAGAIN : 0;
}

__hot
static int handle_rx_st_body(gwnet_http_cli_t *hc, struct gwbuf *b)
{
	struct gwnet_http_req *req = hc->req_tail;
	int r;

	if (!req)
		return -EINVAL;
	if (!b->len)
		return -EAGAIN;

	if (req->is_chunked)
		r = handle_rx_st_body_chunked(hc, req, b);
	else
		r = handle_rx_st_body_non_chunked(hc, req, b);

	if (r < 0)
		return r;

	if (hc->rt_on_body_cb) {
		r = hc->rt_on_body_cb(hc->data_cb, hc->srv, hc, req);
		if (r < 0)
			return r;
	}

	hc->rx_state = GWNET_HTTP_RX_ST_DONE;
	return 1;
}

static int default_hello_world_resp(gwnet_http_req_t *req)
{
	struct gwnet_http_res *res = gwnet_http_req_get_res(req);
	struct gwbuf b;
	int r;

	r = gwbuf_init(&b, 13);
	if (r < 0)
		return r;

	r = gwbuf_append(&b, "Hello World!\n", 13);
	if (r < 0)
		return r;

	gwnet_http_res_set_code(res, 200);
	gwnet_http_res_set_content_type(res, "text/plain; charset=utf-8");
	gwnet_http_res_body_set_buf(res, &b);
	return 0;
}

__hot
static int handle_rx_st_done(gwnet_http_cli_t *hc)
{
	struct gwnet_http_req *req = hc->req_tail;
	int r;

	if (!req)
		return -EINVAL;

	if (hc->rt_cb)
		r = hc->rt_cb(hc->data_cb, hc->srv, hc, req);
	else
		r = default_hello_world_resp(req);

	if (r > 0)
		r = 0;

	if (!r)
		hc->rx_state = GWNET_HTTP_RX_ST_INIT;

	if (!req->keep_alive)
		hc->stop_receiving = true;

	return r;
}

__hot
static int handle_rx(gwnet_http_cli_t *hc, struct gwbuf *b)
{
	int r = -EINVAL;

	switch (hc->rx_state) {
	case GWNET_HTTP_RX_ST_INIT:
		r = handle_rx_st_init(hc, b);
		break;
	case GWNET_HTTP_RX_ST_HDR:
		r = handle_rx_st_hdr(hc, b);
		break;
	case GWNET_HTTP_RX_ST_BODY:
		r = handle_rx_st_body(hc, b);
		break;
	case GWNET_HTTP_RX_ST_DONE:
		r = handle_rx_st_done(hc);
		break;
	}

	return r;
}

__hot
static int prepare_content_related_headers(struct gwnet_http_hdr_fields *hf,
					   struct gwnet_http_res *res)
{
	struct gwnet_http_res_body *body = &res->body;
	uint64_t len;

	switch (body->type) {
	case GWNET_HTTP_RES_TYPE_NO_CONTENT:
		return 0;
	case GWNET_HTTP_RES_TYPE_BUF:
		len = body->buf.buf.len;
		break;
	case GWNET_HTTP_RES_TYPE_ZERO:
		len = body->zero.zero_len;
		break;
	case GWNET_HTTP_RES_TYPE_URANDOM:
		len = body->urandom.ur_len;
		break;
	case GWNET_HTTP_RES_TYPE_FILE:
		len = body->file.file_len;
		break;
	default:
		assert(0 && "Unknown response body type");
		return -EINVAL;
	}

	if (res->content_type[0]) {
		int r = gwnet_http_hdr_fields_add(hf, "Content-Type",
						  res->content_type);
		if (r < 0)
			return r;
	}

	return gwnet_http_hdr_fields_addf(hf, "Content-Length", "%llu",
					  (unsigned long long)len);
}

__hot
static int prepare_date_header(struct gwnet_http_hdr_fields *hf)
{
	time_t now = time(NULL);
	char date[64];
	struct tm tm;
	size_t len;

	if (!gmtime_r(&now, &tm))
		return 0;

	len = strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", &tm);
	if (len == 0)
		return -EINVAL;

	return gwnet_http_hdr_fields_add(hf, "Date", date);
}

__hot
static int handle_tx_init(struct gwnet_http_cli *hc, struct gwnet_http_req *req)
{
	const char *conn = req->keep_alive ? "keep-alive" : "close";
	struct gwnet_http_res *res = &req->res;
	struct gwnet_http_hdr_fields *hf = &res->hdr;
	int r = 0;

	if (!res->status)
		res->status = 200;

	res->version = req->hdr.version;
	r |= gwnet_http_hdr_fields_add(hf, "Server", "gwhttpd2");
	r |= prepare_date_header(hf);
	r |= gwnet_http_hdr_fields_add(hf, "Connection", conn);
	r |= prepare_content_related_headers(hf, res);
	if (r < 0)
		return r;
	
	hc->tx_state = GWNET_HTTP_TX_ST_HDR;
	return 1;
}

__hot
static int handle_tx_hdr(struct gwnet_http_cli *hc, struct gwnet_http_req *req,
			 struct gwbuf *b)
{
	struct gwnet_http_res *res = &req->res;
	const char *stt = translate_http_code(res->status);
	int r = 0;
	size_t i;
	char ver;

	ver = (res->version == GWNET_HTTP_VER_1_0) ? '0' : '1';
	r |= gwbuf_apfmt(b, "HTTP/1.%c %d %s\r\n", ver, res->status, stt);
	for (i = 0; i < res->hdr.nr; i++) {
		struct gwnet_http_hdr_field *f = &res->hdr.ff[i];
		r |= gwbuf_append(b, f->key, strlen(f->key));
		r |= gwbuf_append(b, ": ", 2);
		r |= gwbuf_append(b, f->val, strlen(f->val));
		r |= gwbuf_append(b, "\r\n", 2);
	}
	r |= gwbuf_append(b, "\r\n", 2);

	if (r < 0)
		return -ENOMEM;

	hc->tx_state = GWNET_HTTP_TX_ST_BODY;
	return 1;
}

static int handle_tx_body_buf(struct gwnet_http_cli *hc,
			      struct gwnet_http_req *req, struct gwbuf *b)
{
	struct gwnet_http_res *res = &req->res;
	struct gwnet_http_res_body *body = &res->body;
	struct gwbuf *bb = &body->buf.buf;
	uint64_t to_copy;
	int r;

	to_copy = min_st(GWNET_HTTP_SEND_BUF, bb->len);
	r = gwbuf_append(b, bb->buf, to_copy);
	if (unlikely(r < 0))
		return -ENOMEM;

	gwbuf_advance(bb, to_copy);
	if (bb->len == 0) {
		hc->tx_state = GWNET_HTTP_TX_ST_DONE;
		return 1;
	}

	return 0;
}

static int handle_tx_body_zero(struct gwnet_http_cli *hc,
			       struct gwnet_http_req *req, struct gwbuf *b)
{
	struct gwnet_http_res *res = &req->res;
	struct gwnet_http_res_body *body = &res->body;
	struct gwnet_http_res_body_zero *z = &body->zero;
	uint64_t to_copy;
	int r;

	if (b->cap < GWNET_HTTP_SEND_BUF) {
		r = gwbuf_increase(b, GWNET_HTTP_SEND_BUF - b->cap);
		if (unlikely(r < 0))
			return -ENOMEM;
	}

	to_copy = min_st(GWNET_HTTP_SEND_BUF, b->cap - b->len);
	to_copy = min_st(to_copy, z->zero_len - z->zero_off);
	r = gwbuf_prepare_need(b, to_copy);
	if (unlikely(r < 0))
		return -ENOMEM;

	memset(&b->buf[b->len], 0, to_copy);
	b->len += to_copy;
	z->zero_off += to_copy;

	if (z->zero_off >= z->zero_len) {
		assert(z->zero_off == z->zero_len);
		hc->tx_state = GWNET_HTTP_TX_ST_DONE;
		return 1;
	}

	return 0;
}

static int handle_tx_body_urandom(struct gwnet_http_cli *hc,
				  struct gwnet_http_req *req, struct gwbuf *b)
{
	struct gwnet_http_res *res = &req->res;
	struct gwnet_http_res_body *body = &res->body;
	struct gwnet_http_res_body_urandom *ur = &body->urandom;
	uint64_t to_copy;
	int r;

	if (b->cap < GWNET_HTTP_SEND_BUF) {
		r = gwbuf_increase(b, GWNET_HTTP_SEND_BUF - b->cap);
		if (unlikely(r < 0))
			return -ENOMEM;
	}

	to_copy = min_st(GWNET_HTTP_SEND_BUF, b->cap - b->len);
	to_copy = min_st(to_copy, ur->ur_len - ur->ur_off);
	r = gwbuf_prepare_need(b, to_copy);
	if (unlikely(r < 0))
		return -ENOMEM;

	r = __sys_read(ur->fd, &b->buf[b->len], to_copy);
	if (unlikely(r < 0))
		return r;

	b->len += r;
	ur->ur_off += r;

	if (ur->ur_off >= ur->ur_len) {
		assert(ur->ur_off == ur->ur_len);
		hc->tx_state = GWNET_HTTP_TX_ST_DONE;
		return 1;
	}

	return 0;
}

__hot
static int handle_tx_body(struct gwnet_http_cli *hc, struct gwnet_http_req *req,
			  struct gwbuf *b)
{
	struct gwnet_http_res *res = &req->res;
	struct gwnet_http_res_body *body = &res->body;
	int r = 0;

	switch (body->type) {
	case GWNET_HTTP_RES_TYPE_NO_CONTENT:
		hc->tx_state = GWNET_HTTP_TX_ST_DONE;
		return 1;
	case GWNET_HTTP_RES_TYPE_BUF:
		r = handle_tx_body_buf(hc, req, b);
		break;
	case GWNET_HTTP_RES_TYPE_ZERO:
		r = handle_tx_body_zero(hc, req, b);
		break;
	case GWNET_HTTP_RES_TYPE_URANDOM:
		r = handle_tx_body_urandom(hc, req, b);
		break;
	case GWNET_HTTP_RES_TYPE_FILE:
		return -EINVAL;
	default:
		assert(0 && "Unknown response body type");
		return -EINVAL;
	}

	return r;
}

__hot
static int __handle_tx(struct gwnet_http_cli *hc, struct gwnet_http_req *req,
		       struct gwbuf *b)
{
	int r = 0;

	switch (hc->tx_state) {
	case GWNET_HTTP_TX_ST_INIT:
		r = handle_tx_init(hc, req);
		break;
	case GWNET_HTTP_TX_ST_HDR:
		r = handle_tx_hdr(hc, req, b);
		break;
	case GWNET_HTTP_TX_ST_BODY:
		r = handle_tx_body(hc, req, b);
		break;
	case GWNET_HTTP_TX_ST_DONE:
		hc->tx_state = GWNET_HTTP_TX_ST_INIT;
		gwnet_http_srv_cli_req_pop_head(hc);
		break;
	default:
		assert(0 && "Unknown HTTP TX state");
		return -EINVAL;
	}

	return r;
}

__hot
static int handle_tx(struct gwnet_http_cli *hc, gwnet_tcp_cli_t *c)
{
	struct gwnet_http_req *req = gwnet_http_srv_cli_req_head(hc);
	struct gwnet_tcp_buf *b = gwnet_tcp_srv_cli_get_tx_buf(c);
	struct gwbuf *sb = &b->buf;
	int r = 0;

	assert(b->type == GWNET_TCP_BUF_DEFAULT);

	while (1) {
		r = __handle_tx(hc, req, sb);
		if (r <= 0)
			break;
	}

	if (r == -EAGAIN)
		r = 0;

	return r;
}

__hot
static int handle_req_done(struct gwnet_http_cli *hc, gwnet_tcp_cli_t *c)
{
	hc->rx_state = GWNET_HTTP_RX_ST_INIT;
	if (hc->tx_state != GWNET_HTTP_TX_ST_INIT)
		return 0;

	return handle_tx(hc, c);
}

__hot
static int gwnet_http_srv_pre_recv_cb(void *data, gwnet_tcp_srv_t *s,
				      gwnet_tcp_cli_t *c)
{
	(void)data; (void)s; (void)c;
	return 0;
}

__hot
static int gwnet_http_srv_post_recv_cb(void *data, gwnet_tcp_srv_t *s,
				       gwnet_tcp_cli_t *c, ssize_t recv_ret)
{
	struct gwnet_tcp_buf *rb = gwnet_tcp_srv_cli_get_rx_buf(c);
	struct gwnet_http_cli *hc = data;
	struct gwbuf *b = &rb->buf;
	int ret = 0;

	assert(rb->type == GWNET_TCP_BUF_DEFAULT);

	if (hc->stop_receiving) {
		gwbuf_advance(b, b->len);
		return 0;
	}

	while (1) {
		ret = handle_rx(hc, b);
		if (ret < 0)
			break;

		if (ret == 0) {
			ret = handle_req_done(hc, c);
			if (ret)
				break;
		}
	}

	if (ret == -EAGAIN)
		ret = 0;

	gwbuf_soft_advance_sync(b);
	return ret;
	(void)s;
	(void)recv_ret;
}

__hot
static int gwnet_http_srv_pre_send_cb(void *data, gwnet_tcp_srv_t *s,
				      gwnet_tcp_cli_t *c)
{
	struct gwnet_http_cli *hc = data;
	(void)s;
	(void)c;
	(void)hc;
	return 0;
}

__hot
static int gwnet_http_srv_post_send_cb(void *data, gwnet_tcp_srv_t *s,
				       gwnet_tcp_cli_t *c, ssize_t send_ret)
{
	struct gwnet_http_cli *hc = data;
	struct gwnet_tcp_buf *tb = gwnet_tcp_srv_cli_get_tx_buf(c);
	struct gwbuf *b = &tb->buf;
	struct gwnet_http_req *req;

	if (hc->stop_receiving && !b->len)
		return -ECONNRESET;

	req = gwnet_http_srv_cli_req_head(hc);
	if (unlikely(!req))
		return 0;

	return __handle_tx(hc, req, b);
	(void)s;
	(void)send_ret;
}

__hot
static void gwnet_http_srv_free_cb(void *data, gwnet_tcp_cli_t *c)
{
	struct gwnet_http_cli *hc = data;

	gwnet_http_cli_free(hc);
	(void)c;
}

__hot
static int gwnet_http_srv_accept_cb(void *data, gwnet_tcp_srv_t *s,
				    gwnet_tcp_cli_t *c)
{
	struct gwnet_http_srv *srv = data;
	struct gwnet_http_cli *hc = gwnet_http_cli_alloc(srv);
	if (!hc)
		return -ENOMEM;

	if (srv->accept_cb) {
		int r = srv->accept_cb(srv->data_cb, srv, hc);
		if (r < 0) {
			gwnet_http_cli_free(hc);
			return r;
		}
	}

	gwnet_tcp_srv_cli_set_data(c, hc);
	gwnet_tcp_srv_cli_set_free_cb(c, &gwnet_http_srv_free_cb);
	gwnet_tcp_srv_cli_set_pre_recv_cb(c, &gwnet_http_srv_pre_recv_cb);
	gwnet_tcp_srv_cli_set_post_recv_cb(c, &gwnet_http_srv_post_recv_cb);
	gwnet_tcp_srv_cli_set_pre_send_cb(c, &gwnet_http_srv_pre_send_cb);
	gwnet_tcp_srv_cli_set_post_send_cb(c, &gwnet_http_srv_post_send_cb);
	return 0;
	(void)s;
}
