// SPDX-License-Identifier: GPL-2.0-only
/*
 * gwnet_http1.c - HTTP/1.0 and HTTP/1.1 parser.
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

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#include "gwnet_http1.h"

struct gwnet_http_parse_hdr_cb {
	int (*on_http_ver)(void *u, uint8_t code);

	int (*on_field)(void *u, const char *k, size_t klen, const char *v,
			size_t vlen);

	int (*on_req_method)(void *u, uint8_t method);
	int (*on_req_uri)(void *u, const char *uri, size_t uri_len,
			  const char *qs, size_t qs_len);

	int (*on_res_code)(void *u, uint16_t code, const char *reason,
			   size_t reason_len);

	void (*on_error)(void *u, int err);
};

static bool gwnet_http_field_is_comma_separated(const char *key, size_t n)
{
	static const char *comma_separated_list_headers[] = {
		/* RFC 7231, Section 5.3.2 */
		"Accept",
		/* RFC 7231, Section 5.3.3 */
		"Accept-Charset",
		/* RFC 7231, Section 5.3.4 */
		"Accept-Encoding",
		/* RFC 7231, Section 5.3.5 */
		"Accept-Language",
		/* RFC 7233, Section 2.3 */
		"Accept-Ranges",
		/* RFC 7231, Section 7.4.1 */
		"Allow",
		/* RFC 7234, Section 5.2 */
		"Cache-Control",
		/* RFC 7230, Section 6.1 */
		"Connection",
		/* RFC 7232, Section 3.1 */
		"If-Match",
		/* RFC 7232, Section 3.2 */
		"If-None-Match",
		/* RFC 7233, Section 3.1 */
		"Range",
		/* RFC 7234, Section 5.4 */
		"Pragma",
		/* RFC 7235, Section 4.3 */
		"Proxy-Authenticate",
		/* RFC 7230, Section 4.3 */
		"TE",
		/* RFC 7230, Section 4.4 */
		"Trailer",
		/* RFC 7230, Section 3.3.1 */
		"Transfer-Encoding",
		/* RFC 7230, Section 6.7 */
		"Upgrade",
		/* RFC 7231, Section 7.1.4 */
		"Vary",
		/* RFC 7230, Section 5.7.1 */
		"Via",
		/* RFC 7234, Section 5.5 */
		"Warning",
		/* RFC 7235, Section 4.1 */
		"WWW-Authenticate",

		NULL
	};

	const char **p;

	for (p = comma_separated_list_headers; *p; p++) {
		const char *hdr = *p;
		size_t hdr_len = strlen(hdr);

		if (n == hdr_len && !strncasecmp(key, hdr, n))
			return true;
	}

	return false;
}

void gwnet_http_req_hdr_fields_free(struct gwnet_http_hdr_fields *hdrf)
{
	size_t i;

	if (!hdrf)
		return;

	for (i = 0; i < hdrf->nr_fields; i++) {
		free(hdrf->fields[i].key);
		free(hdrf->fields[i].val);
	}
	free(hdrf->fields);
	memset(hdrf, 0, sizeof(*hdrf));
}

void gwnet_http_req_hdr_free(struct gwnet_http_req_hdr *req)
{
	if (req) {
		free(req->uri);
		free(req->qs);
		gwnet_http_req_hdr_fields_free(&req->fields);
		memset(req, 0, sizeof(*req));
	}
}

void gwnet_http_res_hdr_free(struct gwnet_http_res_hdr *res)
{
	if (res) {
		gwnet_http_req_hdr_fields_free(&res->fields);
		memset(res, 0, sizeof(*res));
	}
}

void gwnet_http_hdr_free(struct gwnet_http_hdr *hdr)
{
	if (!hdr)
		return;

	switch (hdr->type) {
	case GWNET_HTTP_HDR_TYPE_REQ:
		gwnet_http_req_hdr_free(&hdr->req);
		break;
	case GWNET_HTTP_HDR_TYPE_RES:
		gwnet_http_res_hdr_free(&hdr->res);
		break;
	}
}

static
ssize_t gwnet_http_hdr_fields_find_idx(
	const struct gwnet_http_hdr_fields *hdr_fields, const char *key,
	size_t key_len)
{
	size_t i;

	for (i = 0; i < hdr_fields->nr_fields; i++) {
		struct gwnet_http_hdr_field *f = &hdr_fields->fields[i];
		size_t l = strlen(f->key);
		if (l == key_len && !strncasecmp(f->key, key, key_len))
			return i;
	}

	return -ENOENT;
}

int gwnet_http_hdr_fields_add(struct gwnet_http_hdr_fields *hdrf,
			      const char *key, size_t key_len, const char *val,
			      size_t val_len)
{
	ssize_t idx = gwnet_http_hdr_fields_find_idx(hdrf, key, key_len);
	if (idx >= 0) {
		struct gwnet_http_hdr_field *f = &hdrf->fields[idx];
		size_t clen = strlen(f->val);
		char *new_val;
		int ret;

		if (gwnet_http_field_is_comma_separated(key, key_len)) {
			size_t len = clen + val_len + 3;
			new_val = realloc(f->val, len);
			if (unlikely(!new_val))
				return -ENOMEM;

			if (!clen) {
				memcpy(new_val, val, val_len);
				new_val[val_len] = '\0';
			} else {
				memcpy(&new_val[clen], ", ", 2);
				memcpy(&new_val[clen + 2], val, val_len);
				new_val[len - 1] = '\0';
			}
			ret = 0;
		} else {
			new_val = realloc(f->val, val_len + 1);
			if (unlikely(!new_val))
				return -ENOMEM;

			memcpy(new_val, val, val_len);
			new_val[val_len] = '\0';

			/*
			 * Allow overwrite, but notify the caller with EEXIST.
			 */
			ret = EEXIST;
		}

		f->val = new_val;
		return ret;
	} else {
		struct gwnet_http_hdr_field *new_fields;
		size_t new_size;
		char *k, *v;

		k = malloc(key_len + 1);
		if (unlikely(!k))
			return -ENOMEM;
		memcpy(k, key, key_len);
		k[key_len] = '\0';

		v = malloc(val_len + 1);
		if (unlikely(!v)) {
			free(k);
			return -ENOMEM;
		}
		memcpy(v, val, val_len);
		v[val_len] = '\0';

		new_size = (hdrf->nr_fields + 1) * sizeof(*hdrf->fields);
		new_fields = realloc(hdrf->fields, new_size);
		if (unlikely(!new_fields)) {
			free(k);
			free(v);
			return -ENOMEM;
		}

		hdrf->fields = new_fields;
		hdrf->fields[hdrf->nr_fields].key = k;
		hdrf->fields[hdrf->nr_fields].val = v;
		hdrf->nr_fields++;
		return 0;
	}
}

int gwnet_http_hdr_fields_fadd(struct gwnet_http_hdr_fields *hdrf,
			       const char *key, const char *fmt, ...)
{
	va_list args1, args2;
	char *val;
	int ret;

	va_start(args1, fmt);
	va_copy(args2, args1);
	ret = vsnprintf(NULL, 0, fmt, args1);
	va_end(args1);

	val = malloc(ret + 1);
	if (unlikely(!val)) {
		va_end(args2);
		return -ENOMEM;
	}
	ret = vsnprintf(val, ret + 1, fmt, args2);
	va_end(args2);

	ret = gwnet_http_hdr_fields_add(hdrf, key, strlen(key), val, ret);
	free(val);
	return ret;
}

int gwnet_http_hdr_fields_sadd(struct gwnet_http_hdr_fields *hdrf,
			       const char *key, const char *val)
{
	size_t key_len = strlen(key);
	size_t val_len = strlen(val);

	if (key_len == 0)
		return -EINVAL;

	return gwnet_http_hdr_fields_add(hdrf, key, key_len, val, val_len);
}

const char *gwnet_http_hdr_fields_get(const struct gwnet_http_hdr_fields *hdrf,
				      const char *key, size_t key_len)
{
	ssize_t idx = gwnet_http_hdr_fields_find_idx(hdrf, key, key_len);
	if (idx < 0)
		return NULL;

	return hdrf->fields[idx].val;
}

const char *gwnet_http_hdr_fields_sget(const struct gwnet_http_hdr_fields *hdrf,
				       const char *key)
{
	size_t key_len = strlen(key);
	if (key_len == 0)
		return NULL;

	return gwnet_http_hdr_fields_get(hdrf, key, key_len);
}

static inline size_t min_st(size_t a, size_t b)
{
	return (a < b) ? a : b;
}

/*
 * tchar  = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-"
 *        / "." / "^" / "_" / "`" / "|" / "~"
 *        / DIGIT / ALPHA
 *        ; any VCHAR, except delimiters
 */
static inline int is_tchar(int c)
{
	/* Digits. */
	if (c >= '0' && c <= '9')
		return 1;

	/* Uppercase */
	if (c >= 'A' && c <= 'Z')
		return 1;

	/* Lowercase */
	if (c >= 'a' && c <= 'z')
		return 1;

	/* The 15 extra symbols from the spec */
	switch (c) {
	case '!': case '#': case '$': case '%': case '&':
	case '\'': case '*': case '+': case '-': case '.':
	case '^': case '_': case '`': case '|': case '~':
		return 1;
	default:
		return 0;
	}
}

static inline int is_space(int c)
{
	return (c == ' ' || c == '\t');
}

static inline int is_vchar(int c)
{
	/* Visible characters are from 0x20 to 0x7E, inclusive. */
	if (c >= 0x20 && c <= 0x7E)
		return 1;

	/* DEL character is not a visible character. */
	if (c == 0x7F)
		return 0;

	return 0;
}

static int gwnet_http_parse_header_req(struct gwnet_http_parse_hdr_ctx *ctx,
				       struct gwnet_http_parse_hdr_cb *cb)
{
	struct method_entry {
		const char *str;
		uint8_t len;
		uint8_t code;
	};
	static const struct method_entry methods[] = {
		{ "GET",	3, GWNET_HTTP_METHOD_GET },
		{ "POST",	4, GWNET_HTTP_METHOD_POST },
		{ "PUT",	3, GWNET_HTTP_METHOD_PUT },
		{ "DELETE",	6, GWNET_HTTP_METHOD_DELETE },
		{ "HEAD",	4, GWNET_HTTP_METHOD_HEAD },
		{ "OPTIONS",	7, GWNET_HTTP_METHOD_OPTIONS },
		{ "PATCH",	5, GWNET_HTTP_METHOD_PATCH },
		{ "TRACE",	5, GWNET_HTTP_METHOD_TRACE },
		{ "CONNECT",	7, GWNET_HTTP_METHOD_CONNECT }
	};
	static const size_t nr_methods = sizeof(methods) / sizeof(methods[0]);
	size_t i, cmpl, reml, off = 0, len = ctx->buf_len - ctx->off;
	const char *uri, *qs, *buf = &ctx->buf[ctx->off];
	uint8_t method_code, version_code;
	uint32_t uri_len, qs_len;
	int r;

	if (!len)
		return -EAGAIN;

	method_code = GWNET_HTTP_METHOD_UNKNOWN;
	for (i = 0; i < nr_methods; i++) {
		const struct method_entry *me = &methods[i];
		size_t mlen = me->len;

		cmpl = min_st(len, mlen);
		if (memcmp(buf, me->str, cmpl))
			continue;

		if (cmpl < mlen)
			return -EAGAIN;

		method_code = me->code;
		off += mlen;
		break;
	}

	if (method_code == GWNET_HTTP_METHOD_UNKNOWN)
		return -EINVAL;

	if (off >= len)
		return -EAGAIN;

	/*
	 * After the method, there must be a space.
	 */
	if (!is_space(buf[off]))
		return -EINVAL;

	/*
	 * Keep going until we find a non-space character.
	 */
	while (is_space(buf[off])) {
		if (++off >= len)
			return -EAGAIN;
	}

	/*
	 * Per RFC 7230, Section 5.3.1:
	 * When making a request directly to an origin server,
	 * other than a CONNECT or server-wide OPTIONS request
	 * a client MUST send only the absolute path and query
	 * components of the target URI as the request-target.
	 * If the target URI's path component is empty, the
	 * client MUST send "/" as the path within the
	 * origin-form of request-target.
	 */
	if (method_code != GWNET_HTTP_METHOD_CONNECT &&
	    method_code != GWNET_HTTP_METHOD_OPTIONS) {
		if (buf[off] != '/')
			return -EINVAL;
	} else {
		if (!is_vchar(buf[off]))
			return -EINVAL;
	}

	uri = &buf[off];
	qs = NULL;
	uri_len = 0;
	qs_len = 0;

	/*
	 * Keep going until we find a space character.
	 */
	while (1) {
		char c = buf[off++];

		if (off >= len)
			return -EAGAIN;

		if (is_space(c))
			break;

		if (!is_vchar(c))
			return -EINVAL;

		uri_len++;
		if (qs)
			qs_len++;

		/*
		 * If we find a question mark, start assigning the
		 * the query string.
		 */
		if (c == '?')
			qs = &buf[off];
	}

	/*
	 * Keep going until we find a non-space character.
	 */
	while (is_space(buf[off])) {
		if (++off >= len)
			return -EAGAIN;
	}

	/*
	 * Parse the HTTP version. Only support HTTP/1.0 and HTTP/1.1.
	 */
	reml = len - off;
	cmpl = min_st(reml, 7);
	if (memcmp(&buf[off], "HTTP/1.", cmpl))
		return -EINVAL;
	if (cmpl < 7)
		return -EAGAIN;

	off += 7;
	if (off >= len)
		return -EAGAIN;

	switch (buf[off]) {
	case '0':
		version_code = GWNET_HTTP_VER_1_0;
		break;
	case '1':
		version_code = GWNET_HTTP_VER_1_1;
		break;
	default:
		return -EINVAL;
	}

	if (++off >= len)
		return -EAGAIN;

	/*
	 * After the HTTP version, expect a CRLF. But the CR
	 * is optional, so we can also accept just LF.
	 */
	if (buf[off] == '\r') {
		if (++off >= len)
			return -EAGAIN;
	}

	if (buf[off] != '\n')
		return -EINVAL;

	++off;
	ctx->off += off;

	if (cb->on_req_method) {
		r = cb->on_req_method(ctx->udata, method_code);
		if (r < 0)
			return r;
	}

	if (cb->on_req_uri) {
		r = cb->on_req_uri(ctx->udata, uri, uri_len, qs, qs_len);
		if (r < 0)
			return r;
	}

	if (cb->on_http_ver) {
		r = cb->on_http_ver(ctx->udata, version_code);
		if (r < 0)
			return r;
	}
	
	return 0;
}

static int gwnet_http_parse_header_res(struct gwnet_http_parse_hdr_ctx *ctx,
				       struct gwnet_http_parse_hdr_cb *cb)
{
	size_t off = 0, len = ctx->buf_len - ctx->off, cmpl, reml, i;
	const char *reason, *buf = &ctx->buf[ctx->off], *p;
	uint8_t version_code;
	uint32_t reason_len;
	char rcode[3];
	uint16_t code;
	int r;

	if (!len)
		return -EAGAIN;

	/*
	 * Parse the HTTP version. Only support HTTP/1.0 and HTTP/1.1.
	 */
	reml = len - off;
	cmpl = min_st(reml, 7);
	if (memcmp(buf, "HTTP/1.", cmpl))
		return -EINVAL;
	if (cmpl < 7)
		return -EAGAIN;

	off += 7;
	if (off >= len)
		return -EAGAIN;

	switch (buf[off]) {
	case '0':
		version_code = GWNET_HTTP_VER_1_0;
		break;
	case '1':
		version_code = GWNET_HTTP_VER_1_1;
		break;
	default:
		return -EINVAL;
	}

	if (++off >= len)
		return -EAGAIN;

	/*
	 * After the HTTP version, there must be a space.
	 */
	if (!is_space(buf[off]))
		return -EINVAL;

	/*
	 * Keep going until we find a non-space character.
	 */
	while (is_space(buf[off])) {
		if (++off >= len)
			return -EAGAIN;
	}

	/*
	 * Parse the HTTP response code. It must be a 3-digit number
	 * between 100 and 599, inclusive.
	 */
	rcode[0] = buf[off++];
	if (rcode[0] < '1' || rcode[0] > '5')
		return -EINVAL;
	if (off >= len)
		return -EAGAIN;

	for (i = 1; i <= 2; i++) {
		rcode[i] = buf[off++];
		if (rcode[i] < '0' || rcode[i] > '9')
			return -EINVAL;
		if (off >= len)
			return -EAGAIN;
	}

	code = (rcode[0] - '0') * 100 +
	       (rcode[1] - '0') * 10 +
	       (rcode[2] - '0');

	/*
	 * After the response code, there must be a space.
	 */
	if (!is_space(buf[off]))
		return -EINVAL;

	/*
	 * Keep going until we find a non-space character.
	 */
	while (is_space(buf[off])) {
		if (++off >= len)
			return -EAGAIN;
	}

	/*
	 * After the space, there may be a reason phrase.
	 * The reason phrase is optional, if it exists,
	 * it must only contain vchar or space chars.
	 *
	 * It ends with a CRLF, but the CR is optional.
	 */
	reason = &buf[off];
	reason_len = 0;

	while (1) {
		char c = buf[off];

		if (c == '\r' || c == '\n')
			break;

		if (++off >= len)
			return -EAGAIN;

		if (!is_vchar(c) && !is_space(c))
			return -EINVAL;

		reason_len++;
	}

	if (buf[off] == '\r') {
		if (++off >= len)
			return -EAGAIN;
	}

	if (buf[off] != '\n')
		return -EINVAL;
	++off;
	ctx->off += off;

	if (reason_len) {
		/*
		 * Trim the trailing whitespaces from
		 * the reason phrase.
		 */
		p = &reason[reason_len - 1];
		while (p >= reason && is_space(*p)) {
			--reason_len;
			--p;
		}
	}

	if (cb->on_http_ver) {
		r = cb->on_http_ver(ctx->udata, version_code);
		if (r < 0)
			return r;
	}

	if (cb->on_res_code) {
		r = cb->on_res_code(ctx->udata, code, reason, reason_len);
		if (r < 0)
			return r;
	}

	return 0;
}

static int gwnet_http_parse_header_fields(struct gwnet_http_parse_hdr_ctx *ctx,
					  struct gwnet_http_parse_hdr_cb *cb)
{
	size_t off = 0, len = ctx->buf_len - ctx->off;
	const char *buf = &ctx->buf[ctx->off];
	int r;

	if (!len)
		return -EAGAIN;

	while (1) {
		const char *k, *v, *p;
		uint32_t kl, vl;

		if (buf[off] == '\r') {
			if (++off >= len)
				return -EAGAIN;
		}

		if (buf[off] == '\n') {
			++off;
			ctx->off += off;
			break;
		}

		/*
		 * Parse the key. The key must only contain tchar
		 * characters, and must end with a colon.
		 *
		 * After the colon, there may be a space, but it is
		 * optional. If it exists, it must be followed by
		 * a vchar or space characters.
		 *
		 * The value may contain trailing space characters,
		 * they must be trimmed.
		 *
		 * The value may be empty, but the key must not.
		 */
		k = &buf[off];
		kl = 0;
		while (1) {
			if (off >= len)
				return -EAGAIN;

			if (buf[off] == ':')
				break;

			if (!is_tchar(buf[off]))
				return -EINVAL;

			kl++;
			off++;
		}

		if (!kl)
			return -EINVAL;

		if (++off >= len)
			return -EAGAIN;

		/*
		 * Keep going until we find a non-space character.
		 */
		while (is_space(buf[off])) {
			if (++off >= len)
				return -EAGAIN;
		}

		v = &buf[off];
		vl = 0;
		while (1) {
			char c = buf[off];

			if (c == '\r' || c == '\n')
				break;

			if (!is_vchar(c) && !is_space(c))
				return -EINVAL;

			vl++;
			off++;
			if (off >= len)
				return -EAGAIN;
		}

		if (buf[off] == '\r') {
			if (++off >= len)
				return -EAGAIN;
		}

		if (buf[off] != '\n')
			return -EINVAL;
		++off;

		if (vl) {
			/*
			 * Trim trailing whitespaces from the value.
			 */
			p = &v[vl - 1];
			while (p >= v && is_space(*p)) {
				--vl;
				--p;
			}
		}

		if (cb->on_field) {
			r = cb->on_field(ctx->udata, k, kl, v, vl);
			if (r < 0)
				return r;
			if (r > 0)
				return -EINVAL;
		}

		ctx->off += off;
		if (off >= len)
			return -EAGAIN;

		buf = &ctx->buf[ctx->off];
		len = ctx->buf_len - ctx->off;
		off = 0;
	}

	return 0;
}

void gwnet_http_parse_header_init(struct gwnet_http_parse_hdr_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->state = GWNET_HTTP_PARSE_STATE_INIT;
}

/*
 * Return -EINVAL if the header is invalid.
 * Return -EAGAIN if the header is incomplete and more data is needed.
 * Return 0 on success.
 */
static ssize_t __gwnet_http_parse_header(struct gwnet_http_parse_hdr_ctx *ctx,
					 struct gwnet_http_parse_hdr_cb *cb)
{
	int ret;

	if (ctx->state == GWNET_HTTP_PARSE_STATE_INIT)
		ctx->state = GWNET_HTTP_PARSE_STATE_HDR_FIRST_LINE;

	if (ctx->state == GWNET_HTTP_PARSE_STATE_HDR_FIRST_LINE) {
		switch (ctx->type) {
		case GWNET_HTTP_HDR_TYPE_REQ:
			ret = gwnet_http_parse_header_req(ctx, cb);
			break;
		case GWNET_HTTP_HDR_TYPE_RES:
			ret = gwnet_http_parse_header_res(ctx, cb);
			break;
		default:
			return -EINVAL;
		}

		if (ret < 0)
			return ret;

		ctx->state = GWNET_HTTP_PARSE_STATE_HDR_FIELDS;
	}

	if (ctx->state == GWNET_HTTP_PARSE_STATE_HDR_FIELDS) {
		ret = gwnet_http_parse_header_fields(ctx, cb);

		if (ret < 0)
			return ret;

		ctx->state = GWNET_HTTP_PARSE_STATE_HDR_DONE;
	}

	return 0;
}

static int gwnet_http_on_http_ver(void *u, uint8_t code)
{
	struct gwnet_http_hdr *hdr = u;

	switch (hdr->type) {
	case GWNET_HTTP_HDR_TYPE_REQ:
		hdr->req.version = code;
		return 0;
	case GWNET_HTTP_HDR_TYPE_RES:
		hdr->res.version = code;
		return 0;
	default:
		return -EINVAL;
	}
}

static int gwnet_http_on_field(void *u, const char *k, size_t klen,
				 const char *v, size_t vlen)
{
	struct gwnet_http_hdr *hdr = u;
	struct gwnet_http_hdr_fields *fields;

	if (unlikely(klen == 0))
		return -EINVAL;

	switch (hdr->type) {
	case GWNET_HTTP_HDR_TYPE_REQ:
		fields = &hdr->req.fields;
		break;
	case GWNET_HTTP_HDR_TYPE_RES:
		fields = &hdr->res.fields;
		break;
	default:
		return -EINVAL;
	}

	return gwnet_http_hdr_fields_add(fields, k, klen, v, vlen);
}

static int gwnet_http_on_req_method(void *u, uint8_t method)
{
	struct gwnet_http_hdr *hdr = u;
	struct gwnet_http_req_hdr *req = &hdr->req;

	if (unlikely(hdr->type != GWNET_HTTP_HDR_TYPE_REQ))
		return -EINVAL;

	switch (method) {
	case GWNET_HTTP_METHOD_GET:
	case GWNET_HTTP_METHOD_POST:
	case GWNET_HTTP_METHOD_PUT:
	case GWNET_HTTP_METHOD_DELETE:
	case GWNET_HTTP_METHOD_HEAD:
	case GWNET_HTTP_METHOD_OPTIONS:
	case GWNET_HTTP_METHOD_PATCH:
	case GWNET_HTTP_METHOD_TRACE:
	case GWNET_HTTP_METHOD_CONNECT:
		req->method = method;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int gwnet_http_on_req_uri(void *u, const char *uri, size_t uri_len,
				 const char *qs, size_t qs_len)
{
	struct gwnet_http_hdr *hdr = u;
	struct gwnet_http_req_hdr *req = &hdr->req;
	char *new_uri, *new_qs = NULL;

	if (hdr->type != GWNET_HTTP_HDR_TYPE_REQ)
		return -EINVAL;

	new_uri = malloc(uri_len + 1);
	if (unlikely(!new_uri))
		return -ENOMEM;

	if (qs && qs_len > 0) {
		new_qs = malloc(qs_len + 1);
		if (unlikely(!new_qs)) {
			free(new_uri);
			return -ENOMEM;
		}

		memcpy(new_qs, qs, qs_len);
		new_qs[qs_len] = '\0';
	} else {
		new_qs = NULL;
		qs_len = 0;
	}

	memcpy(new_uri, uri, uri_len);
	new_uri[uri_len] = '\0';
	req->uri = new_uri;
	req->qs = new_qs;
	return 0;
}

static int gwnet_http_on_res_code(void *u, uint16_t code, const char *reason,
				  size_t reason_len)
{
	struct gwnet_http_hdr *hdr = u;
	struct gwnet_http_res_hdr *res = &hdr->res;

	if (unlikely(hdr->type != GWNET_HTTP_HDR_TYPE_RES))
		return -EINVAL;

	if (unlikely(reason_len >= sizeof(res->reason)))
		return -EINVAL;

	if (unlikely(code < 100 || code > 599))
		return -EINVAL;

	if (reason_len > 0) {
		memcpy(res->reason, reason, reason_len);
		res->reason[reason_len] = '\0';
	} else {
		res->reason[0] = '\0';
	}

	res->code = code;
	return 0;
}

/*
 * Return -ENOMEM if memory allocation fails.
 * Return -EINVAL if the header is invalid.
 * Return -EAGAIN if the header is incomplete and more data is needed.
 * Return 0 on success.
 */
int gwnet_http_parse_header(struct gwnet_http_parse_hdr_ctx *ctx,
			    struct gwnet_http_hdr *hdr)
{
	struct gwnet_http_parse_hdr_cb cb = {
		.on_http_ver = &gwnet_http_on_http_ver,
		.on_req_method = &gwnet_http_on_req_method,
		.on_req_uri = &gwnet_http_on_req_uri,
		.on_field = &gwnet_http_on_field,
		.on_res_code = &gwnet_http_on_res_code,
	};

	if (unlikely(!ctx || !hdr))
		return -EINVAL;

	if (unlikely(hdr->type != ctx->type))
		return -EINVAL;

	if (ctx->state == GWNET_HTTP_PARSE_STATE_INIT) {
		switch (hdr->type) {
		case GWNET_HTTP_HDR_TYPE_REQ:
			memset(&hdr->req, 0, sizeof(hdr->req));
			break;
		case GWNET_HTTP_HDR_TYPE_RES:
			memset(&hdr->res, 0, sizeof(hdr->res));
			break;
		default:
			return -EINVAL;
		}
	}

	if (unlikely(!ctx->buf_len))
		return -EAGAIN;

	ctx->udata = hdr;
	return __gwnet_http_parse_header(ctx, &cb);
}

int gwnet_http_parse_req_header(struct gwnet_http_parse_hdr_ctx *ctx,
				struct gwnet_http_req_hdr *hdr)
{
	struct gwnet_http_hdr h;
	int ret;

	h.type = GWNET_HTTP_HDR_TYPE_REQ;
	h.req = *hdr;
	ret = gwnet_http_parse_header(ctx, &h);
	*hdr = h.req;
	return ret;
}

int gwnet_http_parse_res_header(struct gwnet_http_parse_hdr_ctx *ctx,
				struct gwnet_http_res_hdr *hdr)
{
	struct gwnet_http_hdr h;
	int ret;

	h.type = GWNET_HTTP_HDR_TYPE_RES;
	h.res = *hdr;
	ret = gwnet_http_parse_header(ctx, &h);
	*hdr = h.res;
	return ret;
}

#define PRTEST_OK()	\
do { \
	printf("Test passed: %s\n", __func__); \
} while (0)

static void test_req_hdr_simple(void)
{
	static const char buf[] =
		"GET /index.html?q=1&a=b HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"User-Agent: gwhttp\r\n"
		"Accept: */*\r\n"
		"Connection: keep-alive\r\n\r\n";
	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(!ret);
	assert(!strcmp(hdr.uri, "/index.html?q=1&a=b"));
	assert(!strcmp(hdr.qs, "q=1&a=b"));
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.fields.nr_fields == 4);
	assert(!strcmp(hdr.fields.fields[0].key, "Host"));
	assert(!strcmp(hdr.fields.fields[0].val, "example.com"));
	assert(!strcmp(hdr.fields.fields[1].key, "User-Agent"));
	assert(!strcmp(hdr.fields.fields[1].val, "gwhttp"));
	assert(!strcmp(hdr.fields.fields[2].key, "Accept"));
	assert(!strcmp(hdr.fields.fields[2].val, "*/*"));
	assert(!strcmp(hdr.fields.fields[3].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[3].val, "keep-alive"));
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_simple(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Content-Length: 1234\r\n"
		"Connection: keep-alive\r\n\r\n";
	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_RES;
	ret = gwnet_http_parse_res_header(&ctx, &hdr);
	assert(!ret);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.code == 200);
	assert(!strcmp(hdr.reason, "OK"));
	assert(hdr.fields.nr_fields == 3);
	assert(!strcmp(hdr.fields.fields[0].key, "Content-Type"));
	assert(!strcmp(hdr.fields.fields[0].val, "text/html; charset=UTF-8"));
	assert(!strcmp(hdr.fields.fields[1].key, "Content-Length"));
	assert(!strcmp(hdr.fields.fields[1].val, "1234"));
	assert(!strcmp(hdr.fields.fields[2].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[2].val, "keep-alive"));
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

/*
 * Per RFC 2616 section 19.3:
 * The line terminator for the request line is a CRLF. However,
 * we recommend that applications, when parsing such headers,
 * recognize a single LF as a line terminator and ignore the
 * leading CR.
 */
static void test_req_hdr_with_no_cr_line_terminator(void)
{
	static const char buf[] =
		"GET /index.html?q=1&a=b HTTP/1.1\n"
		"Host: example.com\n"
		"User-Agent: gwhttp\n"
		"Accept: */*\n"
		"Connection: keep-alive, close\n\n";
	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(!ret);
	assert(!strcmp(hdr.uri, "/index.html?q=1&a=b"));
	assert(!strcmp(hdr.qs, "q=1&a=b"));
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.fields.nr_fields == 4);
	assert(!strcmp(hdr.fields.fields[0].key, "Host"));
	assert(!strcmp(hdr.fields.fields[0].val, "example.com"));
	assert(!strcmp(hdr.fields.fields[1].key, "User-Agent"));
	assert(!strcmp(hdr.fields.fields[1].val, "gwhttp"));
	assert(!strcmp(hdr.fields.fields[2].key, "Accept"));
	assert(!strcmp(hdr.fields.fields[2].val, "*/*"));
	assert(!strcmp(hdr.fields.fields[3].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[3].val, "keep-alive, close"));
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_with_no_cr_line_terminator(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\n"
		"Content-Type: text/html; charset=UTF-8\n"
		"Content-Length: 1234\n"
		"Connection: keep-alive\n\n";
	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_RES;
	ret = gwnet_http_parse_res_header(&ctx, &hdr);
	assert(!ret);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.code == 200);
	assert(!strcmp(hdr.reason, "OK"));
	assert(hdr.fields.nr_fields == 3);
	assert(!strcmp(hdr.fields.fields[0].key, "Content-Type"));
	assert(!strcmp(hdr.fields.fields[0].val, "text/html; charset=UTF-8"));
	assert(!strcmp(hdr.fields.fields[1].key, "Content-Length"));
	assert(!strcmp(hdr.fields.fields[1].val, "1234"));
	assert(!strcmp(hdr.fields.fields[2].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[2].val, "keep-alive"));
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_comma_append_simple(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Accept-Language: en-US\r\n"
		"Accept-Language: en-GB\r\n"
		"Accept-Language: fr-FR\r\n"
		"Accept: text/html, application/xhtml+xml, */*\r\n"
		"Connection: keep-alive\r\n\r\n";
	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(!ret);
	assert(!strcmp(hdr.uri, "/index.html"));
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.fields.nr_fields == 4);
	assert(!strcmp(hdr.fields.fields[0].key, "Host"));
	assert(!strcmp(hdr.fields.fields[0].val, "example.com"));
	assert(!strcmp(hdr.fields.fields[1].key, "Accept-Language"));
	assert(!strcmp(hdr.fields.fields[1].val, "en-US, en-GB, fr-FR"));
	assert(!strcmp(hdr.fields.fields[2].key, "Accept"));
	assert(!strcmp(hdr.fields.fields[2].val,
		       "text/html, application/xhtml+xml, */*"));
	assert(!strcmp(hdr.fields.fields[3].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[3].val, "keep-alive"));
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_comma_append_simple(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Transfer-Encoding: gzip\r\n"
		"Transfer-Encoding: chunked\r\n"
		"Connection: keep-alive\r\n"
		"Cache-Control: no-cache\r\n"
		"Cache-Control: no-store\r\n"
		"Cache-Control: must-revalidate\r\n\r\n";
	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_RES;
	ret = gwnet_http_parse_res_header(&ctx, &hdr);
	assert(!ret);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.code == 200);
	assert(!strcmp(hdr.reason, "OK"));
	assert(hdr.fields.nr_fields == 4);
	assert(!strcmp(hdr.fields.fields[0].key, "Content-Type"));
	assert(!strcmp(hdr.fields.fields[0].val, "application/octet-stream"));
	assert(!strcmp(hdr.fields.fields[1].key, "Transfer-Encoding"));
	assert(!strcmp(hdr.fields.fields[1].val, "gzip, chunked"));
	assert(!strcmp(hdr.fields.fields[2].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[2].val, "keep-alive"));
	assert(!strcmp(hdr.fields.fields[3].key, "Cache-Control"));
	assert(!strcmp(hdr.fields.fields[3].val,
		       "no-cache, no-store, must-revalidate"));
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_invalid(void)
{
	static const char buf[] =
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(ret == -EINVAL);
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_invalid(void)
{
	static const char buf[] =
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_RES;
	ret = gwnet_http_parse_res_header(&ctx, &hdr);
	assert(ret == -EINVAL);
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_invalid_uri(void)
{
	static const char buf[] =
		"GET index.html HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"User-Agent: gwhttp\r\n"
		"Accept: */*\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(ret == -EINVAL);
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_invalid_method(void)
{
	static const char buf[] =
		"INVALID /index.html HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"User-Agent: gwhttp\r\n"
		"Accept: */*\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(ret == -EINVAL);
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_invalid_version(void)
{
	static const char buf[] =
		"GET /index.html HTTP/2.0\r\n"
		"Host: example.com\r\n"
		"User-Agent: gwhttp\r\n"
		"Accept: */*\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(ret == -EINVAL);
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_invalid_version(void)
{
	static const char buf[] =
		"HTTP/2.0 200 OK\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Content-Length: 1234\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_RES;
	ret = gwnet_http_parse_res_header(&ctx, &hdr);
	assert(ret == -EINVAL);
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_invalid_hdr_fields(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"User-Agent: gwhttp\r\n"
		"Invalid-Header\r\n"
		"Accept: */*\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(ret == -EINVAL);
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_invalid_hdr_fields(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Invalid-Header\r\n"
		"Content-Length: 1234\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_RES;
	ret = gwnet_http_parse_res_header(&ctx, &hdr);
	assert(ret == -EINVAL);
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_invalid_hdr_fields_sp_before_colon(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"User-Agent : gwhttp\r\n"
		"Accept: */*\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(ret == -EINVAL);
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_invalid_hdr_fields_sp_before_colon(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Invalid-Header : value\r\n"
		"Content-Length: 1234\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_RES;
	ret = gwnet_http_parse_res_header(&ctx, &hdr);
	assert(ret == -EINVAL);
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_invalid_duplicate_no_merge(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"User-Agent: gwhttp\r\n"
		"User-Agent: gwhttp2\r\n"
		"Accept: */*\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(ret == -EINVAL);
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_invalid_duplicate_no_merge(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: 1234\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_RES;
	ret = gwnet_http_parse_res_header(&ctx, &hdr);
	assert(ret == -EINVAL);
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_val_trailing_spaces(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"User-Agent: gwhttp \r\n"
		"Accept: */* \r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(!ret);
	assert(!strcmp(hdr.uri, "/index.html"));
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.fields.nr_fields == 4);
	assert(!strcmp(hdr.fields.fields[0].key, "Host"));
	assert(!strcmp(hdr.fields.fields[0].val, "example.com"));
	assert(!strcmp(hdr.fields.fields[1].key, "User-Agent"));
	assert(!strcmp(hdr.fields.fields[1].val, "gwhttp"));
	assert(!strcmp(hdr.fields.fields[2].key, "Accept"));
	assert(!strcmp(hdr.fields.fields[2].val, "*/*"));
	assert(!strcmp(hdr.fields.fields[3].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[3].val, "keep-alive"));
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_val_trailing_spaces(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html; charset=UTF-8 \r\n"
		"Content-Length: 1234 \r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_RES;
	ret = gwnet_http_parse_res_header(&ctx, &hdr);
	assert(!ret);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.code == 200);
	assert(!strcmp(hdr.reason, "OK"));
	assert(hdr.fields.nr_fields == 3);
	assert(!strcmp(hdr.fields.fields[0].key, "Content-Type"));
	assert(!strcmp(hdr.fields.fields[0].val, "text/html; charset=UTF-8"));
	assert(!strcmp(hdr.fields.fields[1].key, "Content-Length"));
	assert(!strcmp(hdr.fields.fields[1].val, "1234"));
	assert(!strcmp(hdr.fields.fields[2].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[2].val, "keep-alive"));
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_val_leading_spaces(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.1\r\n"
		"Host:                      example.com\r\n"
		"User-Agent:        gwhttp\r\n"
		"Accept:  */*\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(!ret);
	assert(!strcmp(hdr.uri, "/index.html"));
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.fields.nr_fields == 4);
	assert(!strcmp(hdr.fields.fields[0].key, "Host"));
	assert(!strcmp(hdr.fields.fields[0].val, "example.com"));
	assert(!strcmp(hdr.fields.fields[1].key, "User-Agent"));
	assert(!strcmp(hdr.fields.fields[1].val, "gwhttp"));
	assert(!strcmp(hdr.fields.fields[2].key, "Accept"));
	assert(!strcmp(hdr.fields.fields[2].val, "*/*"));
	assert(!strcmp(hdr.fields.fields[3].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[3].val, "keep-alive"));
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_val_leading_spaces(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type:        text/html; charset=UTF-8\r\n"
		"Content-Length: 1234\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_RES;
	ret = gwnet_http_parse_res_header(&ctx, &hdr);
	assert(!ret);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.code == 200);
	assert(!strcmp(hdr.reason, "OK"));
	assert(hdr.fields.nr_fields == 3);
	assert(!strcmp(hdr.fields.fields[0].key, "Content-Type"));
	assert(!strcmp(hdr.fields.fields[0].val, "text/html; charset=UTF-8"));
	assert(!strcmp(hdr.fields.fields[1].key, "Content-Length"));
	assert(!strcmp(hdr.fields.fields[1].val, "1234"));
	assert(!strcmp(hdr.fields.fields[2].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[2].val, "keep-alive"));
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_empty_qs_with_question_mark(void)
{
	static const char buf[] =
		"GET /index.html? HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"User-Agent: gwhttp\r\n"
		"Accept: */*\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(!ret);
	assert(!strcmp(hdr.uri, "/index.html?"));
	assert(!hdr.qs);
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.fields.nr_fields == 4);
	assert(!strcmp(hdr.fields.fields[0].key, "Host"));
	assert(!strcmp(hdr.fields.fields[0].val, "example.com"));
	assert(!strcmp(hdr.fields.fields[1].key, "User-Agent"));
	assert(!strcmp(hdr.fields.fields[1].val, "gwhttp"));
	assert(!strcmp(hdr.fields.fields[2].key, "Accept"));
	assert(!strcmp(hdr.fields.fields[2].val, "*/*"));
	assert(!strcmp(hdr.fields.fields[3].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[3].val, "keep-alive"));
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_invalid_field_contains_unprintable_char(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"User-Agent: gwhttp\r\n"
		"Invalid-Header: value\x01\r\n"
		"Accept: */*\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(ret == -EINVAL);
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_invalid_field_contains_unprintable_char(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Invalid-Header: value\x01\r\n"
		"Content-Length: 1234\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_RES;
	ret = gwnet_http_parse_res_header(&ctx, &hdr);
	assert(ret == -EINVAL);
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_invalid_reason_contains_unprintable_char(void)
{
	static const char buf[] =
		"HTTP/1.1 404 Not\x01 Found\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Content-Length: 1234\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_RES;
	ret = gwnet_http_parse_res_header(&ctx, &hdr);
	assert(ret == -EINVAL);
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_incomplete(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.0\r\n"
		"Host: example.com\r\n"
		"User-Agent: gwhttp\r\n"
		"Accept: */*\r\n"
		"Connection: keep-alive\r\n\r\n";
	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	size_t i, len = sizeof(buf) - 1;
	int ret;

	for (i = 0; i < len; i++) {
		gwnet_http_parse_header_init(&ctx);
		ctx.buf = buf;
		ctx.buf_len = i;
		ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
		ret = gwnet_http_parse_req_header(&ctx, &hdr);
		assert(ret == -EAGAIN);
		gwnet_http_req_hdr_free(&hdr);
	}

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = len;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(!ret);
	assert(!strcmp(hdr.uri, "/index.html"));
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_0);
	assert(hdr.fields.nr_fields == 4);
	assert(!strcmp(hdr.fields.fields[0].key, "Host"));
	assert(!strcmp(hdr.fields.fields[0].val, "example.com"));
	assert(!strcmp(hdr.fields.fields[1].key, "User-Agent"));
	assert(!strcmp(hdr.fields.fields[1].val, "gwhttp"));
	assert(!strcmp(hdr.fields.fields[2].key, "Accept"));
	assert(!strcmp(hdr.fields.fields[2].val, "*/*"));
	assert(!strcmp(hdr.fields.fields[3].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[3].val, "keep-alive"));
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_incomplete(void)
{
	static const char buf[] =
		"HTTP/1.0 200 OK\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Content-Length: 1234\r\n"
		"Connection: keep-alive\r\n\r\n";
	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	size_t i, len = sizeof(buf) - 1;
	int ret;

	for (i = 0; i < len; i++) {
		gwnet_http_parse_header_init(&ctx);
		ctx.buf = buf;
		ctx.buf_len = i;
		ctx.type = GWNET_HTTP_HDR_TYPE_RES;
		ret = gwnet_http_parse_res_header(&ctx, &hdr);
		assert(ret == -EAGAIN);
		gwnet_http_res_hdr_free(&hdr);
	}

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = len;
	ctx.type = GWNET_HTTP_HDR_TYPE_RES;
	ret = gwnet_http_parse_res_header(&ctx, &hdr);
	assert(!ret);
	assert(hdr.version == GWNET_HTTP_VER_1_0);
	assert(hdr.code == 200);
	assert(!strcmp(hdr.reason, "OK"));
	assert(hdr.fields.nr_fields == 3);
	assert(!strcmp(hdr.fields.fields[0].key, "Content-Type"));
	assert(!strcmp(hdr.fields.fields[0].val, "text/html; charset=UTF-8"));
	assert(!strcmp(hdr.fields.fields[1].key, "Content-Length"));
	assert(!strcmp(hdr.fields.fields[1].val, "1234"));
	assert(!strcmp(hdr.fields.fields[2].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[2].val, "keep-alive"));
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_short_recv_interruptible(void)
{
	static const char buf[] =
		"GET /index.html?abc=123&def=456 HTTP/1.1\r\n"	// 42
		"Host: example.com\r\n"				// 42 + 19 = 61
		"User-Agent: gwhttp\r\n"			// 61 + 20 = 81
		"Accept: */*\r\n"				// 81 + 13 = 94
		"Connection: keep-alive\r\n"			// 94 + 24 = 118
		"\r\n";						// 118 + 2 = 120
	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	size_t i, l = sizeof(buf) - 1, chk_count = 0;
	const char *bp = buf;
	int ret;

	gwnet_http_parse_header_init(&ctx);

	i = 0;
	while (bp < &buf[l]) {
		i++;

		ctx.buf = bp;
		ctx.buf_len = i;
		ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
		ret = gwnet_http_parse_req_header(&ctx, &hdr);

		if (!ctx.off) {
			assert(ret == -EAGAIN);
			assert(bp < &buf[l]);
			continue;
		}

		bp += ctx.off;
		i -= ctx.off;
		ctx.off = 0;

		if (bp == &buf[42]) {
			chk_count++;
			assert(ret == -EAGAIN);
			assert(!strcmp(hdr.uri, "/index.html?abc=123&def=456"));
			assert(!strcmp(hdr.qs, "abc=123&def=456"));
			assert(hdr.method == GWNET_HTTP_METHOD_GET);
			assert(hdr.version == GWNET_HTTP_VER_1_1);
			assert(hdr.fields.nr_fields == 0);
		} else if (bp == &buf[61]) {
			chk_count++;
			assert(ret == -EAGAIN);
			assert(!strcmp(hdr.uri, "/index.html?abc=123&def=456"));
			assert(!strcmp(hdr.qs, "abc=123&def=456"));
			assert(hdr.method == GWNET_HTTP_METHOD_GET);
			assert(hdr.version == GWNET_HTTP_VER_1_1);
			assert(hdr.fields.nr_fields == 1);
			assert(!strcmp(hdr.fields.fields[0].key, "Host"));
			assert(!strcmp(hdr.fields.fields[0].val, "example.com"));
		} else if (bp == &buf[81]) {
			chk_count++;
			assert(ret == -EAGAIN);
			assert(!strcmp(hdr.uri, "/index.html?abc=123&def=456"));
			assert(!strcmp(hdr.qs, "abc=123&def=456"));
			assert(hdr.method == GWNET_HTTP_METHOD_GET);
			assert(hdr.version == GWNET_HTTP_VER_1_1);
			assert(hdr.fields.nr_fields == 2);
			assert(!strcmp(hdr.fields.fields[0].key, "Host"));
			assert(!strcmp(hdr.fields.fields[0].val, "example.com"));
			assert(!strcmp(hdr.fields.fields[1].key, "User-Agent"));
			assert(!strcmp(hdr.fields.fields[1].val, "gwhttp"));
		} else if (bp == &buf[94]) {
			chk_count++;
			assert(ret == -EAGAIN);
			assert(!strcmp(hdr.uri, "/index.html?abc=123&def=456"));
			assert(!strcmp(hdr.qs, "abc=123&def=456"));
			assert(hdr.method == GWNET_HTTP_METHOD_GET);
			assert(hdr.version == GWNET_HTTP_VER_1_1);
			assert(hdr.fields.nr_fields == 3);
			assert(!strcmp(hdr.fields.fields[0].key, "Host"));
			assert(!strcmp(hdr.fields.fields[0].val, "example.com"));
			assert(!strcmp(hdr.fields.fields[1].key, "User-Agent"));
			assert(!strcmp(hdr.fields.fields[1].val, "gwhttp"));
			assert(!strcmp(hdr.fields.fields[2].key, "Accept"));
			assert(!strcmp(hdr.fields.fields[2].val, "*/*"));
		} else if (bp == &buf[118]) {
			chk_count++;
			assert(ret == -EAGAIN);
			assert(!strcmp(hdr.uri, "/index.html?abc=123&def=456"));
			assert(!strcmp(hdr.qs, "abc=123&def=456"));
			assert(hdr.method == GWNET_HTTP_METHOD_GET);
			assert(hdr.version == GWNET_HTTP_VER_1_1);
			assert(hdr.fields.nr_fields == 4);
			assert(!strcmp(hdr.fields.fields[0].key, "Host"));
			assert(!strcmp(hdr.fields.fields[0].val, "example.com"));
			assert(!strcmp(hdr.fields.fields[1].key, "User-Agent"));
			assert(!strcmp(hdr.fields.fields[1].val, "gwhttp"));
			assert(!strcmp(hdr.fields.fields[2].key, "Accept"));
			assert(!strcmp(hdr.fields.fields[2].val, "*/*"));
			assert(!strcmp(hdr.fields.fields[3].key, "Connection"));
			assert(!strcmp(hdr.fields.fields[3].val, "keep-alive"));
		} else if (bp == &buf[120]) {
			chk_count++;
			assert(ret == 0);
			assert(!strcmp(hdr.uri, "/index.html?abc=123&def=456"));
			assert(!strcmp(hdr.qs, "abc=123&def=456"));
			assert(hdr.method == GWNET_HTTP_METHOD_GET);
			assert(hdr.version == GWNET_HTTP_VER_1_1);
			assert(hdr.fields.nr_fields == 4);
			assert(!strcmp(hdr.fields.fields[0].key, "Host"));
			assert(!strcmp(hdr.fields.fields[0].val, "example.com"));
			assert(!strcmp(hdr.fields.fields[1].key, "User-Agent"));
			assert(!strcmp(hdr.fields.fields[1].val, "gwhttp"));
			assert(!strcmp(hdr.fields.fields[2].key, "Accept"));
			assert(!strcmp(hdr.fields.fields[2].val, "*/*"));
			assert(!strcmp(hdr.fields.fields[3].key, "Connection"));
			assert(!strcmp(hdr.fields.fields[3].val, "keep-alive"));
		} else {
			assert(0 && "Unexpected buffer position");
		}
	}

	assert(chk_count == 6);
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_short_recv_interruptible(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"				// 17
		"Content-Type: text/html; charset=UTF-8\r\n"	// 17 + 40 = 57
		"Content-Length: 1234\r\n"			// 57 + 22 = 79
		"Connection: keep-alive\r\n"			// 79 + 24 = 103
		"\r\n";						// 103 + 2 = 105
	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	size_t i, l = sizeof(buf) - 1, chk_count = 0;
	const char *bp = buf;
	int ret;

	gwnet_http_parse_header_init(&ctx);

	i = 0;
	while (bp < &buf[l]) {
		i++;

		ctx.buf = bp;
		ctx.buf_len = i;
		ctx.type = GWNET_HTTP_HDR_TYPE_RES;
		ret = gwnet_http_parse_res_header(&ctx, &hdr);

		if (!ctx.off) {
			assert(ret == -EAGAIN);
			assert(bp < &buf[l]);
			continue;
		}

		bp += ctx.off;
		i -= ctx.off;
		ctx.off = 0;

		if (bp == &buf[17]) {
			chk_count++;
			assert(ret == -EAGAIN);
			assert(hdr.version == GWNET_HTTP_VER_1_1);
			assert(hdr.code == 200);
			assert(!strcmp(hdr.reason, "OK"));
			assert(hdr.fields.nr_fields == 0);
		} else if (bp == &buf[57]) {
			chk_count++;
			assert(ret == -EAGAIN);
			assert(hdr.version == GWNET_HTTP_VER_1_1);
			assert(hdr.code == 200);
			assert(!strcmp(hdr.reason, "OK"));
			assert(hdr.fields.nr_fields == 1);
			assert(!strcmp(hdr.fields.fields[0].key, "Content-Type"));
			assert(!strcmp(hdr.fields.fields[0].val, "text/html; charset=UTF-8"));
		} else if (bp == &buf[79]) {
			chk_count++;
			assert(ret == -EAGAIN);
			assert(hdr.version == GWNET_HTTP_VER_1_1);
			assert(hdr.code == 200);
			assert(!strcmp(hdr.reason, "OK"));
			assert(hdr.fields.nr_fields == 2);
			assert(!strcmp(hdr.fields.fields[0].key, "Content-Type"));
			assert(!strcmp(hdr.fields.fields[0].val, "text/html; charset=UTF-8"));
			assert(!strcmp(hdr.fields.fields[1].key, "Content-Length"));
			assert(!strcmp(hdr.fields.fields[1].val, "1234"));
		} else if (bp == &buf[103]) {
			chk_count++;
			assert(ret == -EAGAIN);
			assert(hdr.version == GWNET_HTTP_VER_1_1);
			assert(hdr.code == 200);
			assert(!strcmp(hdr.reason, "OK"));
			assert(hdr.fields.nr_fields == 3);
			assert(!strcmp(hdr.fields.fields[0].key, "Content-Type"));
			assert(!strcmp(hdr.fields.fields[0].val, "text/html; charset=UTF-8"));
			assert(!strcmp(hdr.fields.fields[1].key, "Content-Length"));
			assert(!strcmp(hdr.fields.fields[1].val, "1234"));
			assert(!strcmp(hdr.fields.fields[2].key, "Connection"));
			assert(!strcmp(hdr.fields.fields[2].val, "keep-alive"));
		} else if (bp == &buf[105]) {
			chk_count++;
			assert(ret == 0);
			assert(hdr.version == GWNET_HTTP_VER_1_1);
			assert(hdr.code == 200);
			assert(!strcmp(hdr.reason, "OK"));
			assert(hdr.fields.nr_fields == 3);
			assert(!strcmp(hdr.fields.fields[0].key, "Content-Type"));
			assert(!strcmp(hdr.fields.fields[0].val, "text/html; charset=UTF-8"));
			assert(!strcmp(hdr.fields.fields[1].key, "Content-Length"));
			assert(!strcmp(hdr.fields.fields[1].val, "1234"));
			assert(!strcmp(hdr.fields.fields[2].key, "Connection"));
			assert(!strcmp(hdr.fields.fields[2].val, "keep-alive"));
		} else {
			assert(0 && "Unexpected buffer position");
		}
	}

	assert(chk_count == 5);
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_empty_hdr_fields(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"X-Test-A:\r\n"
		"X-Test-B:\r\n"
		"X-Test-C:\r\n"
		"X-Test-D:\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(!ret);
	assert(!strcmp(hdr.uri, "/index.html"));
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.fields.nr_fields == 6);
	assert(!strcmp(hdr.fields.fields[0].key, "Host"));
	assert(!strcmp(hdr.fields.fields[0].val, "example.com"));
	assert(!strcmp(hdr.fields.fields[1].key, "X-Test-A"));
	assert(!strcmp(hdr.fields.fields[1].val, ""));
	assert(!strcmp(hdr.fields.fields[2].key, "X-Test-B"));
	assert(!strcmp(hdr.fields.fields[2].val, ""));
	assert(!strcmp(hdr.fields.fields[3].key, "X-Test-C"));
	assert(!strcmp(hdr.fields.fields[3].val, ""));
	assert(!strcmp(hdr.fields.fields[4].key, "X-Test-D"));
	assert(!strcmp(hdr.fields.fields[4].val, ""));
	assert(!strcmp(hdr.fields.fields[5].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[5].val, "keep-alive"));
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_empty_hdr_fields(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"X-Test-A:\r\n"
		"X-Test-B:\r\n"
		"X-Test-C:\r\n"
		"X-Test-D:\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_RES;
	ret = gwnet_http_parse_res_header(&ctx, &hdr);
	assert(!ret);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.code == 200);
	assert(!strcmp(hdr.reason, "OK"));
	assert(hdr.fields.nr_fields == 6);
	assert(!strcmp(hdr.fields.fields[0].key, "Content-Type"));
	assert(!strcmp(hdr.fields.fields[0].val, "text/html; charset=UTF-8"));
	assert(!strcmp(hdr.fields.fields[1].key, "X-Test-A"));
	assert(!strcmp(hdr.fields.fields[1].val, ""));
	assert(!strcmp(hdr.fields.fields[2].key, "X-Test-B"));
	assert(!strcmp(hdr.fields.fields[2].val, ""));
	assert(!strcmp(hdr.fields.fields[3].key, "X-Test-C"));
	assert(!strcmp(hdr.fields.fields[3].val, ""));
	assert(!strcmp(hdr.fields.fields[4].key, "X-Test-D"));
	assert(!strcmp(hdr.fields.fields[4].val, ""));
	assert(!strcmp(hdr.fields.fields[5].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[5].val, "keep-alive"));
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_comma_append_after_empty(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Accept: \r\n"
		"Accept:\r\n"
		"Accept: application/json\r\n"
		"Accept: text/plain\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(!ret);
	assert(!strcmp(hdr.uri, "/index.html"));
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.fields.nr_fields == 3);
	assert(!strcmp(hdr.fields.fields[0].key, "Host"));
	assert(!strcmp(hdr.fields.fields[0].val, "example.com"));
	assert(!strcmp(hdr.fields.fields[1].key, "Accept"));
	assert(!strcmp(hdr.fields.fields[1].val, "application/json, text/plain"));
	assert(!strcmp(hdr.fields.fields[2].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[2].val, "keep-alive"));
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_comma_append_after_empty(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Transfer-Encoding:                       \r\n"
		"Transfer-Encoding:\r\n"
		"Transfer-Encoding:             gzip            \r\n"
		"Transfer-Encoding: chunked\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_RES;
	ret = gwnet_http_parse_res_header(&ctx, &hdr);
	assert(!ret);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.code == 200);
	assert(!strcmp(hdr.reason, "OK"));
	assert(hdr.fields.nr_fields == 3);
	assert(!strcmp(hdr.fields.fields[0].key, "Content-Type"));
	assert(!strcmp(hdr.fields.fields[0].val, "text/html; charset=UTF-8"));
	assert(!strcmp(hdr.fields.fields[1].key, "Transfer-Encoding"));
	assert(!strcmp(hdr.fields.fields[1].val, "gzip, chunked"));
	assert(!strcmp(hdr.fields.fields[2].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[2].val, "keep-alive"));
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_invalid_comma_append(void)
{
	static const char buf[] =
		"GET /index.html HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"User-Agent: gwhttp\r\n"
		"User-Agent: gwhttp2\r\n"
		"Accept: */*\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(ret == -EINVAL);
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_invalid_comma_append(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: 1234\r\n"
		"Connection: keep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_RES;
	ret = gwnet_http_parse_res_header(&ctx, &hdr);
	assert(ret == -EINVAL);
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_with_body(void)
{
	static const char buf[] =
		"POST /submit HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"Content-Length: 27\r\n"
		"\r\n"
		"name=John+Doe&age=30";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(!ret);
	assert(!strcmp(hdr.uri, "/submit"));
	assert(hdr.method == GWNET_HTTP_METHOD_POST);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.fields.nr_fields == 3);
	assert(!strcmp(hdr.fields.fields[0].key, "Host"));
	assert(!strcmp(hdr.fields.fields[0].val, "example.com"));
	assert(!strcmp(hdr.fields.fields[1].key, "Content-Type"));
	assert(!strcmp(hdr.fields.fields[1].val, "application/x-www-form-urlencoded"));
	assert(!strcmp(hdr.fields.fields[2].key, "Content-Length"));
	assert(!strcmp(hdr.fields.fields[2].val, "27"));
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_with_body(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/plain\r\n"
		"Content-Length: 13\r\n"
		"\r\n"
		"Hello, World!";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_RES;
	ret = gwnet_http_parse_res_header(&ctx, &hdr);
	assert(!ret);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.code == 200);
	assert(!strcmp(hdr.reason, "OK"));
	assert(hdr.fields.nr_fields == 2);
	assert(!strcmp(hdr.fields.fields[0].key, "Content-Type"));
	assert(!strcmp(hdr.fields.fields[0].val, "text/plain"));
	assert(!strcmp(hdr.fields.fields[1].key, "Content-Length"));
	assert(!strcmp(hdr.fields.fields[1].val, "13"));
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_req_hdr_valid_multi_sp_trim(void)
{
	static const char buf[] =
		"GET            \t /index.html        \t       HTTP/1.1\r\n"
		"Host:             \t  \t \t example.com   \t\t\r\n"
		"User-Agent: \t\tgwhttp             \r\n"
		"Accept: \t\t\t\t*/*                                      \r\n"
		"Connection: \t      \tkeep-alive        \t\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_req_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_REQ;
	ret = gwnet_http_parse_req_header(&ctx, &hdr);
	assert(!ret);
	assert(!strcmp(hdr.uri, "/index.html"));
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.fields.nr_fields == 4);
	assert(!strcmp(hdr.fields.fields[0].key, "Host"));
	assert(!strcmp(hdr.fields.fields[0].val, "example.com"));
	assert(!strcmp(hdr.fields.fields[1].key, "User-Agent"));
	assert(!strcmp(hdr.fields.fields[1].val, "gwhttp"));
	assert(!strcmp(hdr.fields.fields[2].key, "Accept"));
	assert(!strcmp(hdr.fields.fields[2].val, "*/*"));
	assert(!strcmp(hdr.fields.fields[3].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[3].val, "keep-alive"));
	gwnet_http_req_hdr_free(&hdr);
	PRTEST_OK();
}

static void test_res_hdr_valid_multi_sp_trim(void)
{
	static const char buf[] =
		"HTTP/1.1        \t 200 OK\r\n"
		"Content-Type: \t\ttext/html; charset=UTF-8\r\n"
		"Content-Length: \t1234\r\n"
		"Connection: \t\tkeep-alive\r\n\r\n";

	struct gwnet_http_parse_hdr_ctx ctx;
	struct gwnet_http_res_hdr hdr;
	int ret;

	gwnet_http_parse_header_init(&ctx);
	ctx.buf = buf;
	ctx.buf_len = sizeof(buf) - 1;
	ctx.type = GWNET_HTTP_HDR_TYPE_RES;
	ret = gwnet_http_parse_res_header(&ctx, &hdr);
	assert(!ret);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(hdr.code == 200);
	assert(!strcmp(hdr.reason, "OK"));
	assert(hdr.fields.nr_fields == 3);
	assert(!strcmp(hdr.fields.fields[0].key, "Content-Type"));
	assert(!strcmp(hdr.fields.fields[0].val, "text/html; charset=UTF-8"));
	assert(!strcmp(hdr.fields.fields[1].key, "Content-Length"));
	assert(!strcmp(hdr.fields.fields[1].val, "1234"));
	assert(!strcmp(hdr.fields.fields[2].key, "Connection"));
	assert(!strcmp(hdr.fields.fields[2].val, "keep-alive"));
	gwnet_http_res_hdr_free(&hdr);
	PRTEST_OK();
}

void gwnet_http_run_tests(void)
{
	test_req_hdr_simple();
	test_res_hdr_simple();
	test_req_hdr_with_no_cr_line_terminator();
	test_res_hdr_with_no_cr_line_terminator();
	test_req_hdr_comma_append_simple();
	test_res_hdr_comma_append_simple();
	test_req_hdr_invalid();
	test_res_hdr_invalid();
	test_req_hdr_invalid_uri();
	test_req_hdr_invalid_method();
	test_req_hdr_invalid_version();
	test_res_hdr_invalid_version();
	test_req_hdr_invalid_hdr_fields();
	test_res_hdr_invalid_hdr_fields();
	test_req_hdr_invalid_hdr_fields_sp_before_colon();
	test_res_hdr_invalid_hdr_fields_sp_before_colon();
	test_req_hdr_invalid_duplicate_no_merge();
	test_res_hdr_invalid_duplicate_no_merge();
	test_req_hdr_val_trailing_spaces();
	test_res_hdr_val_trailing_spaces();
	test_req_hdr_val_leading_spaces();
	test_res_hdr_val_leading_spaces();
	test_req_hdr_empty_qs_with_question_mark();
	test_req_hdr_invalid_field_contains_unprintable_char();
	test_res_hdr_invalid_field_contains_unprintable_char();
	test_res_hdr_invalid_reason_contains_unprintable_char();
	test_req_hdr_incomplete();
	test_res_hdr_incomplete();
	test_req_hdr_short_recv_interruptible();
	test_res_hdr_short_recv_interruptible();
	test_req_hdr_empty_hdr_fields();
	test_res_hdr_empty_hdr_fields();
	test_req_hdr_comma_append_after_empty();
	test_res_hdr_comma_append_after_empty();
	test_req_hdr_invalid_comma_append();
	test_res_hdr_invalid_comma_append();
	test_req_hdr_with_body();
	test_res_hdr_with_body();
	test_req_hdr_valid_multi_sp_trim();
	test_res_hdr_valid_multi_sp_trim();
	printf("All tests passed!\n");
}
