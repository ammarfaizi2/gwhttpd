
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>

#include "gwnet_http.h"
#include "gwnet_tcp.h"
#include "gwbuf.h"

#define MIN_T(TYPE, A, B)		\
({					\
	TYPE ___a = (A);		\
	TYPE ___b = (B);		\
	((___a < ___b) ? ___a : ___b);	\
})

#define GWNET_HTTP_SEND_BUF		4096

struct gwnet_http_srv {
	gwnet_tcp_srv_t			*tcp;
	struct gwnet_http_srv_cfg	cfg;
	void				*data_cb;
	gwnet_http_srv_route_cb_t	route_cb;
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

struct gwnet_http_res {
	int			type;
	int			code;
	struct gwnet_http_hdr	hdr;
	char			content_type[64];
union {
	struct {
		size_t		zero_len;
		size_t		zero_rem;
	};

	struct gwbuf	body_buf;
};
};

struct gwnet_http_req {
	uint8_t			method;
	uint8_t			version;
	uint8_t			chunk_state;
	bool			body_oversized;
	uint64_t		missing_body_len;
	struct gwbuf		body_buf;
	struct gwnet_http_hdr	hdr;
	char			*uri;
	char			*qs;
};

struct gwnet_http_cli {
	uint8_t				state;
	bool				keep_alive;
	struct gwnet_http_srv		*srv;
	struct gwnet_http_req		req;
	struct gwnet_http_res		res;
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

static void gwnet_http_req_free(struct gwnet_http_req *req)
{
	if (!req)
		return;

	gwnet_http_hdr_free(&req->hdr);
	gwbuf_free(&req->body_buf);
	free(req->uri);
	free(req->qs);
	memset(req, 0, sizeof(*req));
}

static struct gwnet_http_cli *gwnet_http_cli_alloc(struct gwnet_http_srv *srv)
{
	struct gwnet_http_cli *hc = calloc(1, sizeof(*hc));
	if (!hc)
		return NULL;

	hc->state = GWNET_HTTP_CLI_ST_INIT;
	hc->srv = srv;
	hc->res.code = 204;
	return hc;
}


static void gwnet_http_res_free(struct gwnet_http_res *res)
{
	if (!res)
		return;

	gwnet_http_hdr_free(&res->hdr);

	switch (res->type) {
	case GWNET_HTTP_RES_TYPE_NO_CONTENT:
		break;
	case GWNET_HTTP_RES_TYPE_BUF:
		gwbuf_free(&res->body_buf);
		break;
	case GWNET_HTTP_RES_TYPE_ZERO:
		break;
	default:
		assert(0 && "Unknown response type");
		break;
	}
	memset(res, 0, sizeof(*res));
}

static void gwnet_http_cli_free(struct gwnet_http_cli *hc)
{
	if (hc) {
		gwnet_http_res_free(&hc->res);
		gwnet_http_req_free(&hc->req);
		free(hc);
	}
}

static int gwnet_http_recv_cb_init(struct gwnet_http_cli *hc)
{
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
	struct gwnet_http_req *req = &hc->req;
	size_t len = b->len, max;

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

	max = hc->srv->cfg.max_req_hdr_len;

	/*
	 * Find the end of header, double CRLF.
	 */
	end = strstr(b->buf, "\r\n\r\n");
	if (!end)
		return (len > max) ? -EINVAL : -EAGAIN;
	end += 4;

	if ((size_t)(end - b->buf) > max) {
		/*
		 * The header is too long.
		 */
		return -EINVAL;
	}

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
		size_t max = hc->srv->cfg.max_req_body_len;

		if (alloc > max)
			alloc = max;
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

static int gwnet_http_recv_cb_req_body_chunked_len(struct gwnet_http_req *req,
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

static int __gwnet_http_recv_cb_req_body(struct gwnet_http_cli *hc,
					 struct gwnet_http_req *req,
					 struct gwbuf *b)
{
	struct gwbuf *bb = &req->body_buf;
	size_t to_advance, to_copy, max;
	int ret;

	to_copy = to_advance = MIN_T(size_t, b->len, req->missing_body_len);

	if (req->body_oversized)
		goto out;

	max = hc->srv->cfg.max_req_body_len;
	if (to_copy + bb->len > max) {
		/*
		 * This append would make the body oversized,
		 * so we just copy the maximum amount of data
		 * that would fit and mark the request as oversized.
		 */
		req->body_oversized = true;
		to_copy = max - bb->len;
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

static int gwnet_http_recv_cb_req_body_chunked_data(struct gwnet_http_cli *hc,
						    struct gwnet_http_req *req,
						    struct gwbuf *b)
{
	int ret;

	ret = __gwnet_http_recv_cb_req_body(hc, req, b);
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
	struct gwnet_http_req *req = &hc->req;
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
			ret = gwnet_http_recv_cb_req_body_chunked_data(hc, req, b);
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
	struct gwnet_http_req *req = &hc->req;
	int ret;

	if (req->chunk_state != GWNET_HTTP_CHUNK_ST_NONE)
		return gwnet_http_recv_cb_req_body_chunked(hc, b);

	ret = __gwnet_http_recv_cb_req_body(hc, req, b);
	if (ret < 0)
		return ret;

	if (req->missing_body_len == 0)
		hc->state = GWNET_HTTP_CLI_ST_REQ_OK;

	return 0;
}

static const char *translate_http_code(int code)
{
	switch (code) {
	case 100: return "Continue";
	case 101: return "Switching Protocols";
	case 200: return "OK";
	case 201: return "Created";
	case 202: return "Accepted";
	case 204: return "No Content";
	case 301: return "Moved Permanently";
	case 302: return "Found";
	case 303: return "See Other";
	case 304: return "Not Modified";
	case 307: return "Temporary Redirect";
	case 308: return "Permanent Redirect";
	case 400: return "Bad Request";
	case 401: return "Unauthorized";
	case 403: return "Forbidden";
	case 404: return "Not Found";
	case 405: return "Method Not Allowed";
	case 418: return "I'm a teapot";
	case 429: return "Too Many Requests";
	case 500: return "Internal Server Error";
	case 501: return "Not Implemented";
	case 502: return "Bad Gateway";
	case 503: return "Service Unavailable";
	case 504: return "Gateway Timeout";
	case 505: return "HTTP Version Not Supported";
	default:  return "Unknown";
	}
}

static int gwnet_http_handle_request(struct gwnet_http_cli *hc, struct gwbuf *b)
{
	int ret;

	while (1) {
		if (b->len == 0) {
			ret = -EAGAIN;
			break;
		}

		switch (hc->state) {
		case GWNET_HTTP_CLI_ST_RES_OK:
		case GWNET_HTTP_CLI_ST_INIT:
			ret = gwnet_http_recv_cb_init(hc);
			break;
		case GWNET_HTTP_CLI_ST_REQ_HEADER:
			ret = gwnet_http_recv_cb_req_header(hc, b);
			break;
		case GWNET_HTTP_CLI_ST_REQ_BODY:
			ret = gwnet_http_recv_cb_req_body(hc, b);
			break;
		case GWNET_HTTP_CLI_ST_REQ_OK:
			return 0;
		default:
			ret = -EINVAL;
			break;
		}

		if (ret)
			break;

		if (!ret && hc->state == GWNET_HTTP_CLI_ST_REQ_OK) {
			ret = 0;
			break;
		}
	}

	return ret;
}

static int gwnet_http_res_hello_world(struct gwnet_http_cli *hc)
{
	struct gwnet_http_res *res = &hc->res;
	struct gwbuf *b = gwnet_http_res_get_body_buf(res);
	int r = 0;

	gwnet_http_res_set_content_type(res, "text/plain");
	gwnet_http_res_set_type(res, GWNET_HTTP_RES_TYPE_BUF);
	gwbuf_apfmt(b, "Hello world!\n");
	gwnet_http_res_set_code(res, 200);
	return r;
}

static int gwnet_http_process_request(struct gwnet_http_cli *hc)
{
	int ret;

	if (hc->srv->route_cb)
		ret = hc->srv->route_cb(hc->srv, hc);
	else
		ret = gwnet_http_res_hello_world(hc);

	return ret;
}

static int gwnet_http_construct_res_body_buf(struct gwbuf *t,
					     struct gwnet_http_cli *hc)
{
	struct gwnet_http_res *res = &hc->res;
	size_t max_append;
	size_t to_copy;

	max_append = GWNET_HTTP_SEND_BUF - t->len;
	to_copy = MIN_T(size_t, max_append, res->body_buf.len);

	if (gwbuf_append(t, res->body_buf.buf, to_copy) < 0)
		return -ENOMEM;

	gwbuf_advance(&res->body_buf, to_copy);
	if (res->body_buf.len == 0) {
		gwnet_http_res_free(res);
		hc->state = GWNET_HTTP_CLI_ST_RES_OK;
	} else {
		hc->state = GWNET_HTTP_CLI_ST_RES_BODY;
	}
	return 0;
}

static int gwnet_http_construct_res_body_zero(struct gwbuf *t,
					      struct gwnet_http_cli *hc)
{
	struct gwnet_http_res *res = &hc->res;
	size_t max_append;
	size_t to_copy;
	size_t to_cap;

	max_append = GWNET_HTTP_SEND_BUF - t->len;
	to_copy = MIN_T(size_t, max_append, res->zero_rem);
	to_cap = t->cap + to_copy;
	if (gwbuf_set_cap(t, to_cap) < 0)
		return -ENOMEM;

	memset(t->buf + t->len, 0, to_copy);
	t->len += to_copy;
	res->zero_rem -= to_copy;
	if (res->zero_rem == 0) {
		gwnet_http_res_free(res);
		hc->state = GWNET_HTTP_CLI_ST_RES_OK;
	} else {
		hc->state = GWNET_HTTP_CLI_ST_RES_BODY;
	}
	return 0;
}

static int gwnet_http_construct_res_body(struct gwbuf *t,
					 struct gwnet_http_cli *hc)
{
	struct gwnet_http_res *res = &hc->res;
	int r = 0;

	switch (res->type) {
	case GWNET_HTTP_RES_TYPE_NO_CONTENT:
		break;
	case GWNET_HTTP_RES_TYPE_BUF:
		r = gwnet_http_construct_res_body_buf(t, hc);
		break;
	case GWNET_HTTP_RES_TYPE_ZERO:
		r = gwnet_http_construct_res_body_zero(t, hc);
		break;
	}

	return r;
}

static int gwnet_http_construct_response(gwnet_tcp_cli_t *c,
					 struct gwnet_http_cli *hc)
{
	const char *conn = hc->keep_alive ? "keep-alive" : "close";
	struct gwbuf *t = gwnet_tcp_srv_cli_get_tx_buf(c);
	struct gwnet_http_req *req = &hc->req;
	struct gwnet_http_res *res = &hc->res;
	const char *code = translate_http_code(res->code);
	int r = 0;

	r |= gwbuf_apfmt(t, "HTTP/1.%d %d %s\r\n", req->version, res->code, code);
	r |= gwbuf_apfmt(t, "Server: gwhttpd2\r\n");
	r |= gwbuf_apfmt(t, "Connection: %s\r\n", conn);
	r |= gwbuf_apfmt(t, "Content-Type: %s\r\n", res->content_type);

	switch (res->type) {
	case GWNET_HTTP_RES_TYPE_NO_CONTENT:
		r |= gwbuf_apfmt(t, "Content-Length: 0\r\n");
		break;
	case GWNET_HTTP_RES_TYPE_BUF:
		r |= gwbuf_apfmt(t, "Content-Length: %zu\r\n", res->body_buf.len);
		break;
	case GWNET_HTTP_RES_TYPE_ZERO:
		r |= gwbuf_apfmt(t, "Content-Length: %zu\r\n", res->zero_len);
		break;
	}

	r |= gwbuf_append(t, "\r\n", 2);
	if (r)
		return r;

	r = gwnet_http_construct_res_body(t, hc);
	hc->state = GWNET_HTTP_CLI_ST_RES_BODY;
	if (hc->state == GWNET_HTTP_CLI_ST_RES_OK)
		gwnet_http_res_free(res);

	gwnet_http_req_free(req);
	return r;
}

static int gwnet_http_recv_cb(void *data, struct gwnet_tcp_srv *s,
			      gwnet_tcp_cli_t *c, struct gwbuf *b)
{
	struct gwnet_http_cli *hc = data;
	int ret = 0;

	switch (hc->state) {
	case GWNET_HTTP_CLI_ST_RES_BODY:
		return gwnet_http_construct_res_body(
			gwnet_tcp_srv_cli_get_tx_buf(c), hc);
	}

	while (b->len > 0) {
		ret = gwnet_http_handle_request(hc, b);
		if (ret)
			break;

		ret = gwnet_http_process_request(hc);
		if (ret)
			break;

		ret = gwnet_http_construct_response(c, hc);
		if (ret)
			break;

		if (hc->state == GWNET_HTTP_CLI_ST_RES_OK)
			hc->state = GWNET_HTTP_CLI_ST_INIT;
	}

	if (ret == -EAGAIN)
		ret = 0;

	(void)s;
	return ret;
}

const char *gwnet_http_hdr_get_val(struct gwnet_http_hdr *hdr, const char *key)
{
	int i = gwnet_http_hdr_find_idx(hdr, key);
	if (i < 0)
		return NULL;

	return hdr->pairs[i].val;
}

int gwnet_http_hdr_addf(struct gwnet_http_hdr *hdr, const char *key,
		        const char *fmt, ...)
{
	va_list a1, a2;
	char *v;
	int ret;

	va_start(a1, fmt);
	va_copy(a2, a1);
	ret = vsnprintf(NULL, 0, fmt, a1);
	va_end(a1);

	v = malloc(ret + 1);
	if (!v) {
		ret = -ENOMEM;
		goto out;
	}

	vsnprintf(v, ret + 1, fmt, a2);
	ret = gwnet_http_hdr_add(hdr, key, v);
	free(v);
out:
	va_end(a2);
	return ret;
}

int gwnet_http_hdr_add(struct gwnet_http_hdr *hdr, const char *key,
		       const char *val)
{
	int i;

	i = gwnet_http_hdr_find_idx(hdr, key);
	if (i >= 0) {
		/*
		 * If the key already exists, update the value.
		 */
		char *new_val = strdup(val);
		if (!new_val)
			return -ENOMEM;
		free(hdr->pairs[i].val);
		hdr->pairs[i].val = new_val;
		return 0;
	} else {
		struct gwnet_http_hdr_pair *new_pairs;
		size_t new_size;
		char *k, *v;

		/*
		 * If the key does not exist, add a new key-value pair.
		 */
		k = strdup(key);
		v = strdup(val);
		if (!k || !v) {
			free(k);
			free(v);
			return -ENOMEM;
		}

		new_size = (hdr->nr_pairs + 1) * sizeof(*hdr->pairs);
		new_pairs = realloc(hdr->pairs, new_size);
		if (!new_pairs) {
			free(k);
			free(v);
			return -ENOMEM;
		}

		hdr->pairs = new_pairs;
		hdr->pairs[hdr->nr_pairs].key = k;
		hdr->pairs[hdr->nr_pairs].val = v;
		hdr->nr_pairs++;
		return 0;
	}
}

static int gwnet_http_send_cb(void *data, struct gwnet_tcp_srv *s,
			      gwnet_tcp_cli_t *c, struct gwbuf *b)
{
	(void)data;
	(void)s;
	(void)c;
	(void)b;
	return 0;
}

static int gwnet_http_send_cb_post(void *data, struct gwnet_tcp_srv *s,
				   gwnet_tcp_cli_t *c, struct gwbuf *b)
{
	struct gwnet_http_cli *hc = data;

	if (hc->state == GWNET_HTTP_CLI_ST_RES_OK) {
		if (b->len == 0 && !hc->keep_alive)
			return -ECONNRESET;
	} else if (hc->state == GWNET_HTTP_CLI_ST_RES_BODY) {
		return gwnet_http_construct_res_body(b, hc);
	} else {
		struct gwbuf *rx_buf = gwnet_tcp_srv_cli_get_rx_buf(c);

		if (rx_buf->len > 0)
			return gwnet_http_recv_cb(data, s, c, rx_buf);
	}

	(void)s;
	(void)c;
	(void)b;
	return 0;
}

static void gwnet_http_cli_free_cb(void *data, gwnet_tcp_cli_t *c)
{
	struct gwnet_http_cli *hc = data;
	gwnet_http_cli_free(hc);

	(void)c;
}

static int gwnet_http_accept_cb(void *data, struct gwnet_tcp_srv *s,
				gwnet_tcp_cli_t *c)
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
	(void)c;
	(void)s;
	return 0;
}

static int gwnet_http_srv_validate_cfg(struct gwnet_http_srv_cfg *cfg)
{
	if (!cfg->max_req_hdr_len)
		cfg->max_req_hdr_len = GWNET_HTTP_DEF_MAX_REQ_HDR_LEN;

	if (!cfg->max_req_body_len)
		cfg->max_req_body_len = GWNET_HTTP_DEF_MAX_REQ_BODY_LEN;

	return 0;
}

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

	gwnet_tcp_srv_set_accept_cb(s->tcp, gwnet_http_accept_cb, s);
	return s;

free_s:
	free(s);
	return NULL;
}

int gwnet_http_srv_run(gwnet_http_srv_t *s)
{
	return gwnet_tcp_srv_run(s->tcp);
}

void gwnet_http_srv_free(struct gwnet_http_srv *s)
{
	if (s) {
		gwnet_tcp_srv_free(s->tcp);
		memset(s, 0, sizeof(*s));
		free(s);
	}
}

void gwnet_http_srv_set_route_cb(gwnet_http_srv_t *s,
				 gwnet_http_srv_route_cb_t cb, void *data)
{
	s->data_cb = data;
	s->route_cb = cb;
}

static const char *translate_http_method(uint8_t method)
{
	switch (method) {
	case GWNET_HTTP_METHOD_GET: return "GET";
	case GWNET_HTTP_METHOD_POST: return "POST";
	case GWNET_HTTP_METHOD_PUT: return "PUT";
	case GWNET_HTTP_METHOD_DELETE: return "DELETE";
	case GWNET_HTTP_METHOD_HEAD: return "HEAD";
	case GWNET_HTTP_METHOD_OPTIONS: return "OPTIONS";
	case GWNET_HTTP_METHOD_PATCH: return "PATCH";
	case GWNET_HTTP_METHOD_TRACE: return "TRACE";
	case GWNET_HTTP_METHOD_CONNECT: return "CONNECT";
	default: return "UNKNOWN";
	}
}

const char *gwnet_http_req_get_uri(struct gwnet_http_req *req)
{
	return req->uri;
}

const char *gwnet_http_req_get_qs(struct gwnet_http_req *req)
{
	return req->qs;
}

const char *gwnet_http_req_get_method(struct gwnet_http_req *req)
{
	return translate_http_method(req->method);
}

char *gwnet_http_req_get_nc_uri(struct gwnet_http_req *req)
{
	return req->uri;
}

char *gwnet_http_req_get_nc_qs(struct gwnet_http_req *req)
{
	return req->qs;
}

struct gwnet_http_req *gwnet_http_req_get(struct gwnet_http_cli *hc)
{
	return &hc->req;
}

struct gwnet_http_res *gwnet_http_res_get(struct gwnet_http_cli *hc)
{
	return &hc->res;
}

void gwnet_http_res_set_content_type(struct gwnet_http_res *res,
				     const char *content_type)
{
	strncpy(res->content_type, content_type,
		sizeof(res->content_type) - 1);
	res->content_type[sizeof(res->content_type) - 1] = '\0';
}

struct gwnet_http_hdr *gwnet_http_res_get_hdr(struct gwnet_http_res *res)
{
	return &res->hdr;
}

void gwnet_http_res_set_code(struct gwnet_http_res *res, int code)
{
	res->code = code;
}

struct gwbuf *gwnet_http_res_get_body_buf(struct gwnet_http_res *res)
{
	return &res->body_buf;
}

void gwnet_http_res_set_type(struct gwnet_http_res *res, int type)
{
	res->type = type;
}

void gwnet_http_res_set_zero_len(struct gwnet_http_res *res, size_t len)
{
	res->type = GWNET_HTTP_RES_TYPE_ZERO;
	res->zero_len = len;
	res->zero_rem = len;
}
