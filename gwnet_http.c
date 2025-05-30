#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "gwnet_http.h"
#include "gwnet_tcp.h"
#include "gwbuf.h"

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#define MIN_T(TYPE, A, B)		\
({					\
	TYPE ___a = (A);		\
	TYPE ___b = (B);		\
	((___a < ___b) ? ___a : ___b);	\
})

#define GWNET_HTTP_SEND_BUF		4096

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

struct gwnet_http_res_body_zero {
	uint64_t	zero_len;
	uint64_t	zero_off;
};

struct gwnet_http_res_body_urandom {
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
	int				code;
	struct gwnet_http_hdr		hdr;
	uint64_t			content_length;
	char				content_type[128];
	struct gwnet_http_res_body	body;
};

struct gwnet_http_req {
	uint8_t			method;
	uint8_t			version;
	uint8_t			chunk_state;
	bool			is_body_oversized;
	bool			keep_alive;

	struct gwnet_http_hdr	hdr;
	char			content_type[128];
	uint64_t		content_length;
	struct gwbuf		body_buf;
	char			*uri;
	char			*qs;

	struct gwnet_http_res	res;
	struct gwnet_http_req	*next;
};

struct gwnet_http_cli {
	uint8_t			tx_state;
	uint8_t			rx_state;
	struct gwnet_http_srv	*srv;
	struct gwnet_http_req	*req_head;
	struct gwnet_http_req	*req_tail;
};

struct gwnet_http_srv {
	gwnet_tcp_srv_t			*tcp;
	struct gwnet_http_srv_cfg	cfg;

	void				*data_cb;
	gwnet_http_srv_route_cb_t	route_cb;
};

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

int gwnet_http_req_get_method(gwnet_http_req_t *req)
{
	return req->method;
}

int gwnet_http_req_get_version(gwnet_http_req_t *req)
{
	return req->version;
}

bool gwnet_http_req_is_body_oversized(gwnet_http_req_t *req)
{
	return req->is_body_oversized;
}

struct gwnet_http_hdr *gwnet_http_req_get_hdr(gwnet_http_req_t *req)
{
	return &req->hdr;
}

const char *gwnet_http_req_get_content_type(gwnet_http_req_t *req)
{
	return req->content_type;
}

uint64_t gwnet_http_req_get_content_length(gwnet_http_req_t *req)
{
	return req->content_length;
}

struct gwbuf *gwnet_http_req_get_body_buf(gwnet_http_req_t *req)
{
	return &req->body_buf;
}

char *gwnet_http_req_get_nc_uri(gwnet_http_req_t *req)
{
	return req->uri;
}

char *gwnet_http_req_get_nc_qs(gwnet_http_req_t *req)
{
	return req->qs;
}

const char *gwnet_http_req_get_uri(gwnet_http_req_t *req)
{
	return gwnet_http_req_get_nc_uri(req);
}

const char *gwnet_http_req_get_qs(gwnet_http_req_t *req)
{
	return gwnet_http_req_get_nc_qs(req);
}

gwnet_http_res_t *gwnet_http_res_get(gwnet_http_req_t *req)
{
	return &req->res;
}

int gwnet_http_res_get_code(gwnet_http_res_t *res)
{
	return res->code;
}

void gwnet_http_res_set_code(gwnet_http_res_t *res, int code)
{
	res->code = code;
}

const char *gwnet_http_res_get_content_type(gwnet_http_res_t *res)
{
	return res->content_type;
}

void gwnet_http_res_set_content_type(gwnet_http_res_t *res,
					 const char *content_type)
{
	size_t l = sizeof(res->content_type) - 1;
	char *p = res->content_type;
	strncpy(p, content_type, l);
	p[l] = '\0';
}

static void gwnet_http_res_body_free(gwnet_http_res_t *res)
{
	struct gwnet_http_res_body *b = &res->body;

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
		break;
	case GWNET_HTTP_RES_TYPE_FILE:
		if (b->file.fd >= 0) {
			close(b->file.fd);
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
	gwnet_http_res_body_free(res);
	res->body.type = GWNET_HTTP_RES_TYPE_ZERO;
	res->body.zero.zero_len = len;
	res->body.zero.zero_off = 0;
}

void gwnet_http_res_body_set_urandom(gwnet_http_res_t *res, uint64_t len)
{
	gwnet_http_res_body_free(res);
	res->body.type = GWNET_HTTP_RES_TYPE_URANDOM;
	res->body.urandom.ur_len = len;
	res->body.urandom.ur_off = 0;
}

void gwnet_http_res_body_set_file(gwnet_http_res_t *res, int fd,
				  uint64_t len)
{
	gwnet_http_res_body_free(res);
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
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode)) {
		close(fd);
		return -EINVAL;
	}

	gwnet_http_res_body_set_file(res, fd, st.st_size);
	return 0;
}

void gwnet_http_res_body_set_buf(gwnet_http_res_t *res, struct gwbuf *buf)
{
	gwnet_http_res_body_free(res);
	res->body.type = GWNET_HTTP_RES_TYPE_BUF;
	gwbuf_move(&res->body.buf.buf, buf);
}

struct gwbuf *gwnet_http_res_body_get_buf(gwnet_http_res_t *res)
{
	if (res->body.type != GWNET_HTTP_RES_TYPE_BUF)
		return NULL;

	return &res->body.buf.buf;
}

static int gwnet_http_hdr_find_idx(struct gwnet_http_hdr *hdr, const char *key)
{
	size_t i;

	for (i = 0; i < hdr->nr_pairs; i++) {
		if (!strcasecmp(hdr->pairs[i].key, key))
			return (int)i;
	}

	return -ENOENT;
}

const char *gwnet_http_hdr_get_val(struct gwnet_http_hdr *hdr, const char *key)
{
	return gwnet_http_hdr_get_nc_val(hdr, key);
}

char *gwnet_http_hdr_get_nc_val(struct gwnet_http_hdr *hdr, const char *key)
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
	int i = gwnet_http_hdr_find_idx(hdr, key);
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


int gwnet_http_srv_run(gwnet_http_srv_t *srv)
{
	return gwnet_tcp_srv_run(srv->tcp);
}

void gwnet_http_srv_stop(gwnet_http_srv_t *srv)
{
	gwnet_tcp_srv_stop(srv->tcp);
}

void gwnet_http_srv_free(gwnet_http_srv_t *srv)
{
	gwnet_tcp_srv_free(srv->tcp);
	free(srv);
}

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


static void gwnet_http_res_free(struct gwnet_http_res *res)
{
	if (!res)
		return;

	gwnet_http_hdr_free(&res->hdr);
	gwnet_http_res_body_free(res);
	res->code = 0;
	res->content_length = 0;
	res->content_type[0] = '\0';
}

static void cstrlower(char *s)
{
	while (*s) {
		if (*s >= 'A' && *s <= 'Z')
			*s += ('a' - 'A');
		s++;
	}
}

static char *ctrim_spaces(char *s)
{
	char *end;

	/*
	 * Skip leading spaces.
	 */
	while (*s && isspace((unsigned char)*s))
		s++;

	if (!*s)
		return s;

	/*
	 * Skip trailing spaces.
	 */
	end = s + strlen(s) - 1;
	while (end > s && isspace((unsigned char)*end))
		end--;

	end[1] = '\0';
	return s;
}


struct hdr_parse_ctx {
	struct gwbuf		*in_hdr_buf;
	uint64_t		in_max_hdr_len;
	struct gwnet_http_req	*in_req;

	size_t			out_hdr_len;
	bool			out_expect_body;
};

/*
 * Return -EAGAIN = Need more data (buffer may be incomplete).
 * Return -EINVAL = Invalid header.
 * Return 0 = Success.
 * Return any other negative value = Other errors.
 */
static int gwnet_http_parse_req_header(struct hdr_parse_ctx *c)
{
	char *qs, *uri, *x, *ver, *end, *line, *next;
	const size_t max_hdr_len = c->in_max_hdr_len;
	struct gwnet_http_req *req = c->in_req;
	struct gwbuf *b = c->in_hdr_buf;
	size_t len = b->len;
	size_t len_hdr;
	int ret;

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
	 *   "GET / HTTP/1.0\r\n\r\n"
	 *
	 * It is 18 characters long.
	 */
	if (unlikely(len < 18))
		return -EAGAIN;

	/*
	 * Find the end of header by looking for double CRLF.
	 *
	 * If we do not find it, check the buffer length.
	 *
	 * If it is larger than the maximum header length,
	 * assume it's invalid, otherwise wait for more data.
	 */
	end = strstr(b->buf, "\r\n\r\n");
	if (unlikely(!end))
		return (len > max_hdr_len) ? -EINVAL : -EAGAIN;

	/*
	 * We found the end of the header. The buffer contains
	 * a full HTTP header, it's now safe to parse it.
	 *
	 * Kill the last CRLF to avoid string functions exceeding
	 * the header section as the buffer may already contain
	 * the body or pipelined requests.
	 */
	end[2] = end[3] = '\0';
	end += 4;

	len_hdr = (size_t)(end - b->buf);
	if (unlikely(len_hdr > max_hdr_len)) {
		/*
		 * The header is too long.
		 */
		return -EINVAL;
	}

	/*
	 * The request URI must start with a slash.
	 *
	 * @uri is set by the temporary macro above.
	 */
	if (unlikely(*uri != '/'))
		return -EINVAL;

	/*
	 * Find the space between the URI and the HTTP version and
	 * null-terminate the URI.
	 */
	x = strchr(uri, ' ');
	if (unlikely(!x))
		return -EINVAL;
	*x = '\0';

	/*
	 * The URI is now a null-terminated string, now split the path
	 * and the query string.
	 *
	 * `qs` will point to the query string if it exists, otherwise
	 * it will be NULL.
	 */
	qs = strchr(uri, '?');
	if (qs) {
		*qs = '\0';
		qs++;
	} else {
		qs = NULL;
	}

	/*
	 * Parse the HTTP version.
	 */
	ver = x + 1;
	if (unlikely(strncmp(ver, "HTTP/", 5)))
		return -EINVAL;

	if (!strncmp(ver + 5, "1.0", 3)) {
		req->version = GWNET_HTTP_VER_1_0;
		req->keep_alive = false;
	} else if (!strncmp(ver + 5, "1.1", 3)) {
		req->version = GWNET_HTTP_VER_1_1;
		req->keep_alive = true;
	} else {
		return -EINVAL;
	}

	/*
	 * After the HTTP version, there must be a CRLF. Also, prepare
	 * a pointer to the second line of the HTTP header.
	 */
	line = ver + 8;	/* Skip "HTTP/1.x" */
	if (unlikely(strncmp(line, "\r\n", 2)))
		return -EINVAL;

	line += 2;

	/*
	 * Now we have the method, URI, query string and version. Copy
	 * them to the request structure.
	 */
	req->uri = strdup(uri);
	if (unlikely(!req->uri))
		return -ENOMEM;

	/*
	 * req->qs will be NULL if there is no query string.
	 */
	req->qs = qs ? strdup(qs) : NULL;
	if (unlikely(!req->qs && qs)) {
		ret = -ENOMEM;
		goto free_uri;
	}

	assert(req->hdr.nr_pairs == 0);
	assert(req->hdr.pairs == NULL);
	gwnet_http_hdr_free(&req->hdr);

	while (1) {
		char *k, *v;

		/*
		 * Each line of the HTTP header is separated by a CRLF.
		 */
		next = strstr(line, "\r\n");
		if (!next)
			break;

		k = line;

		/*
		 * The key-val pair is terminated by a colon. If we do not
		 * find a colon, assume the value is an empty string.
		 */
		v = strchr(k, ':');
		if (v) {
			*v = '\0';
			v++;
			v = ctrim_spaces(v);
		} else {
			v = (char *)"";
		}

		k = ctrim_spaces(k);
		cstrlower(k);

		ret = -EINVAL;
		if (!strcmp(k, "connection")) {
			cstrlower(v);
			if (strstr(v, "keep-alive"))
				req->keep_alive = true;
			else if (strstr(v, "close"))
				req->keep_alive = false;
			else
				goto free_hdr;
		} else if (!strcmp(k, "content-length")) {
			char *ep;

			if (req->chunk_state != GWNET_HTTP_CHUNK_ST_NONE)
				goto free_hdr;

			errno = 0;
			req->content_length = strtoull(v, &ep, 10);
			if (errno || *ep != '\0')
				goto free_hdr;
			c->out_expect_body = (req->content_length > 0);
		} else if (!strcmp(k, "transfer-encoding")) {
			if (strstr(v, "chunked")) {
				if (req->content_length)
					goto free_hdr;
				req->content_length = 0;
				req->chunk_state = GWNET_HTTP_CHUNK_ST_LEN;
				c->out_expect_body = true;
			} else {
				goto free_hdr;
			}
		}

		ret = gwnet_http_hdr_add(&req->hdr, k, v);
		if (ret)
			goto free_hdr;
	}

	c->out_hdr_len = len_hdr;
	return 0;

free_hdr:
	gwnet_http_hdr_free(&req->hdr);
	free(req->qs);
	req->qs = NULL;
free_uri:
	free(req->uri);
	req->uri = NULL;
	return ret;
}

static gwnet_http_req_t *gwnet_http_req_alloc(void)
{
	struct gwnet_http_req *req = calloc(1, sizeof(*req));
	if (!req)
		return NULL;

	req->method = GWNET_HTTP_METHOD_UNKNOWN;
	req->version = GWNET_HTTP_VER_UNKNOWN;
	req->chunk_state = GWNET_HTTP_CHUNK_ST_NONE;
	return req;
}

static void gwnet_http_req_free(gwnet_http_req_t *req)
{
	if (!req)
		return;

	gwnet_http_res_free(&req->res);
	gwnet_http_hdr_free(&req->hdr);
	free(req->uri);
	free(req->qs);
	gwbuf_free(&req->body_buf);
	free(req);
}

static void gwnet_http_srv_cli_req_push(gwnet_http_cli_t *hc,
					gwnet_http_req_t *req)
{
	if (!hc->req_head) {
		hc->req_head = hc->req_tail = req;
	} else {
		hc->req_tail->next = req;
		hc->req_tail = req;
	}
}

static void gwnet_http_srv_cli_req_pop_front(gwnet_http_cli_t *hc)
{
	gwnet_http_req_t *req = hc->req_head;

	if (!req)
		return;

	hc->req_head = req->next;
	if (!hc->req_head)
		hc->req_tail = NULL;

	gwnet_http_req_free(req);
}

static void gwnet_http_srv_cli_req_pop_back(gwnet_http_cli_t *hc)
{
	gwnet_http_req_t *req = hc->req_tail;

	if (!req)
		return;

	if (hc->req_head == req) {
		hc->req_head = hc->req_tail = NULL;
	} else {
		gwnet_http_req_t *prev = hc->req_head;
		while (prev->next != req)
			prev = prev->next;
		prev->next = NULL;
		hc->req_tail = prev;
	}

	gwnet_http_req_free(req);
}

static gwnet_http_req_t *gwnet_http_srv_cli_req_front(gwnet_http_cli_t *hc)
{
	return hc->req_head;
}

static gwnet_http_req_t *gwnet_http_srv_cli_req_back(gwnet_http_cli_t *hc)
{
	return hc->req_tail;
}

static int gwnet_http_srv_cli_handle_rx_st_init(gwnet_http_cli_t *hc,
						struct gwbuf *b)
{
	gwnet_http_req_t *req;

	if (!b->len)
		return -EAGAIN;

	req = gwnet_http_req_alloc();
	if (!req)
		return -ENOMEM;

	gwnet_http_srv_cli_req_push(hc, req);
	hc->rx_state = GWNET_HTTP_RX_ST_HDR;
	return 1;
}

static int gwnet_http_srv_cli_handle_rx_st_hdr(gwnet_http_cli_t *hc,
					       struct gwbuf *b)
{
	struct hdr_parse_ctx ctx;
	int ret;

	if (!b->len)
		return -EAGAIN;

	memset(&ctx, 0, sizeof(ctx));
	ctx.in_hdr_buf = b;
	ctx.in_max_hdr_len = hc->srv->cfg.max_req_hdr_len;
	ctx.in_req = gwnet_http_srv_cli_req_back(hc);
	ctx.out_hdr_len = 0;

	ret = gwnet_http_parse_req_header(&ctx);
	if (ret < 0 && ret != -EAGAIN) {
		gwnet_http_srv_cli_req_pop_back(hc);
		hc->rx_state = GWNET_HTTP_RX_ST_ERROR;
	} else {
		hc->rx_state = ctx.out_expect_body ? GWNET_HTTP_RX_ST_BODY
						   : GWNET_HTTP_RX_ST_DONE;
		gwbuf_advance(b, ctx.out_hdr_len);
		ret = 1;
	}

	return ret;
}

static int gwnet_http_srv_cli_handle_rx_st_body(gwnet_http_cli_t *hc,
						struct gwbuf *b)
{
	hc->rx_state = GWNET_HTTP_RX_ST_DONE;
	return 1;
}

static int gwnet_http_srv_cli_construct_resp(gwnet_http_cli_t *hc,
					     gwnet_tcp_cli_t *c)
{
	struct gwnet_tcp_buf *tb = gwnet_tcp_srv_cli_get_tx_buf(c);
	gwnet_http_req_t *req = gwnet_http_srv_cli_req_front(hc);
	gwnet_http_res_t *res = &req->res;
	struct gwbuf *b = &tb->buf;
	const char *code_str;
	const char *ver = (req->version == GWNET_HTTP_VER_1_0) ? "1.0" : "1.1";
	int r = 0;

	res->content_length = 13;
	res->code = 200;
	snprintf(res->content_type, sizeof(res->content_type),
			"text/plain; charset=utf-8");
	code_str = translate_http_code(res->code);

	r |= gwbuf_apfmt(b, "HTTP/%s %d %s\r\n", ver, res->code, code_str);
	r |= gwbuf_apfmt(b, "Connection: %s\r\n",
			 req->keep_alive ? "keep-alive" : "close");

	if (*res->content_type)
		r |= gwbuf_apfmt(b, "Content-Type: %s\r\n", res->content_type);

	if (res->content_length > 0)
		r |= gwbuf_apfmt(b, "Content-Length: %llu\r\n",
				 (unsigned long long)res->content_length);

	if (res->hdr.nr_pairs > 0) {
		size_t i;

		for (i = 0; i < res->hdr.nr_pairs; i++) {
			const char *k = res->hdr.pairs[i].key;
			const char *v = res->hdr.pairs[i].val;
			r |= gwbuf_apfmt(b, "%s: %s\r\n", k, v);
		}
	}

	r |= gwbuf_append(b, "\r\n", 2);
	r |= gwbuf_apfmt(b, "Hello World!\n");
	return 1;
}

static int gwnet_http_srv_cli_handle_rx_st_done(gwnet_http_cli_t *hc,
						gwnet_tcp_cli_t *c)
{
	int ret = gwnet_http_srv_cli_construct_resp(hc, c);
	hc->rx_state = GWNET_HTTP_RX_ST_INIT;
	return ret;
}

static int gwnet_http_srv_cli_handle_rx(gwnet_http_cli_t *hc, struct gwbuf *b,
					gwnet_tcp_cli_t *c)
{
	int ret;

	ret = -EINVAL;
	switch (hc->rx_state) {
	case GWNET_HTTP_RX_ST_INIT:
		ret = gwnet_http_srv_cli_handle_rx_st_init(hc, b);
		break;
	case GWNET_HTTP_RX_ST_HDR:
		ret = gwnet_http_srv_cli_handle_rx_st_hdr(hc, b);
		break;
	case GWNET_HTTP_RX_ST_BODY:
		ret = gwnet_http_srv_cli_handle_rx_st_body(hc, b);
		break;
	case GWNET_HTTP_RX_ST_DONE:
		ret = gwnet_http_srv_cli_handle_rx_st_done(hc, c);
		break;
	}

	return ret;
}

static struct gwnet_http_cli *gwnet_http_srv_alloc_cli(gwnet_http_srv_t *srv)
{
	struct gwnet_http_cli *hc = calloc(1, sizeof(*hc));
	if (!hc)
		return NULL;

	hc->tx_state = GWNET_HTTP_TX_ST_INIT;
	hc->rx_state = GWNET_HTTP_RX_ST_INIT;
	hc->srv = srv;
	return hc;
}

static void gwnet_http_srv_cli_free_requests(struct gwnet_http_cli *hc)
{
	gwnet_http_req_t *req = hc->req_head;

	while (req) {
		gwnet_http_req_t *next = req->next;
		gwnet_http_req_free(req);
		req = next;
	}

	hc->req_head = hc->req_tail = NULL;
}

static void gwnet_http_srv_free_cb(void *data, gwnet_tcp_cli_t *c)
{
	struct gwnet_http_cli *hc = data;

	gwnet_http_srv_cli_free_requests(hc);
	free(hc);
}

static int gwnet_http_srv_pre_recv_cb(void *data, gwnet_tcp_srv_t *s,
				      gwnet_tcp_cli_t *c)
{
	struct gwnet_http_cli *hc = data;

	return 0;
}

static int gwnet_http_srv_post_recv_cb(void *data, gwnet_tcp_srv_t *s,
				       gwnet_tcp_cli_t *c, ssize_t recv_ret)
{
	struct gwnet_tcp_buf *rb = gwnet_tcp_srv_cli_get_rx_buf(c);
	struct gwnet_http_cli *hc = data;
	struct gwbuf *b = &rb->buf;
	int ret = 0;

	while (1) {
		ret = gwnet_http_srv_cli_handle_rx(hc, b, c);
		if (ret <= 0)
			break;
	}

	if (ret == -EAGAIN)
		ret = 0;

	return ret;
}

static int gwnet_http_srv_pre_send_cb(void *data, gwnet_tcp_srv_t *s,
				      gwnet_tcp_cli_t *c)
{
	struct gwnet_http_cli *hc = data;
	return 0;
}

static int gwnet_http_srv_post_send_cb(void *data, gwnet_tcp_srv_t *s,
					 gwnet_tcp_cli_t *c, ssize_t send_ret)
{
	struct gwnet_http_cli *hc = data;
	struct gwnet_http_req *req = gwnet_http_srv_cli_req_front(hc);
	struct gwnet_tcp_buf *tb = gwnet_tcp_srv_cli_get_tx_buf(c);
	struct gwbuf *b = &tb->buf;

	if (!b->len && !req->keep_alive)
		return -ECONNRESET;

	return 0;
}

static int gwnet_http_srv_accept_cb(void *data, gwnet_tcp_srv_t *s,
				    gwnet_tcp_cli_t *c)
{
	struct gwnet_http_srv *srv = data;
	struct gwnet_http_cli *hc = gwnet_http_srv_alloc_cli(srv);
	if (!hc)
		return -ENOMEM;

	gwnet_tcp_srv_cli_set_data(c, hc);
	gwnet_tcp_srv_cli_set_free_cb(c, &gwnet_http_srv_free_cb);
	gwnet_tcp_srv_cli_set_pre_recv_cb(c, &gwnet_http_srv_pre_recv_cb);
	gwnet_tcp_srv_cli_set_post_recv_cb(c, &gwnet_http_srv_post_recv_cb);
	gwnet_tcp_srv_cli_set_pre_send_cb(c, &gwnet_http_srv_pre_send_cb);
	gwnet_tcp_srv_cli_set_post_send_cb(c, &gwnet_http_srv_post_send_cb);
	return 0;
}
