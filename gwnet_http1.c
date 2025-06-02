// SPDX-License-Identifier: GPL-2.0-only
/*
 * gwnet_http1.c - HTTP/1.0 and HTTP/1.1 parser.
 *
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>

#include "gwnet_http1.h"

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

/**
 * Checks if the given HTTP header field key is one of the standard headers
 * that are allowed to appear multiple times in a message and should be
 * merged into a single comma-separated header value according to the HTTP
 * specification.
 *
 * This is used to determine whether the parser should combine multiple
 * occurrences of the specified header field into a single comma-separated
 * value.
 *
 * @param key The header field name to check (case-insensitive).
 * @param n   The length of the header field name.
 * @return    true if the header is allowed to be provided multiple times and
 *            should be merged; false otherwise.
 */
static bool field_is_comma_separated(const char *key, size_t n)
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

static int parse_hdr_req_first_line(struct gwnet_http_hdr_pctx *ctx,
				    struct gwnet_http_req_hdr *hdr)
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
	size_t i, cmpl, reml, off = 0, len = ctx->len - ctx->off;
	const char *uri, *qs, *buf = &ctx->buf[ctx->off];
	uint8_t method_code, version_code;
	uint32_t uri_len, qs_len;

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

	hdr->uri = malloc(uri_len + 1);
	if (!hdr->uri)
		return -ENOMEM;

	if (qs) {
		hdr->qs = malloc(qs_len + 1);
		if (!hdr->qs) {
			free(hdr->uri);
			hdr->uri = NULL;
			return -ENOMEM;
		}
		memcpy(hdr->qs, qs, qs_len);
		hdr->qs[qs_len] = '\0';
	}

	memcpy(hdr->uri, uri, uri_len);
	hdr->uri[uri_len] = '\0';
	hdr->method = method_code;
	hdr->version = version_code;
	ctx->off += off;
	return 0;
}

static int parse_hdr_res_first_line(struct gwnet_http_hdr_pctx *ctx,
				    struct gwnet_http_res_hdr *hdr)
{
	size_t off = 0, len = ctx->len - ctx->off, cmpl, reml, i;
	const char *reason, *buf = &ctx->buf[ctx->off], *p;
	uint8_t version_code;
	uint32_t reason_len;
	char rcode[3];
	uint16_t code;

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

	hdr->reason = malloc(reason_len + 1);
	if (!hdr->reason)
		return -ENOMEM;

	memcpy(hdr->reason, reason, reason_len);
	hdr->reason[reason_len] = '\0';
	hdr->version = version_code;
	hdr->code = code;
	ctx->off += off;
	return 0;
}

static int parse_hdr_fields(struct gwnet_http_hdr_pctx *ctx,
			    struct gwnet_http_hdr_fields *ff)
{
	size_t off = 0, len = ctx->len - ctx->off;
	const char *buf = &ctx->buf[ctx->off];
	int r;

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

		r = gwnet_http_hdr_fields_addl(ff, k, kl, v, vl);
		if (r)
			return r;

		ctx->off += off;
		if (off >= len)
			return -EAGAIN;

		buf = &ctx->buf[ctx->off];
		len = ctx->len - ctx->off;
		off = 0;
	}

	return 0;
}

int gwnet_http_hdr_pctx_init(struct gwnet_http_hdr_pctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->state = GWNET_HTTP_HDR_PARSE_ST_INIT;
	return 0;
}

void gwnet_http_hdr_pctx_free(struct gwnet_http_hdr_pctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

int gwnet_http_req_hdr_parse(struct gwnet_http_hdr_pctx *ctx,
			     struct gwnet_http_req_hdr *hdr)
{
	int r = 0;

	if (ctx->state == GWNET_HTTP_HDR_PARSE_ST_INIT)
		ctx->state = GWNET_HTTP_HDR_PARSE_ST_FIRST_LINE;

	if (!ctx->len)
		return -EAGAIN;

	if (ctx->state == GWNET_HTTP_HDR_PARSE_ST_FIRST_LINE) {
		r = parse_hdr_req_first_line(ctx, hdr);
		if (r)
			return r;
		ctx->state = GWNET_HTTP_HDR_PARSE_ST_FIELDS;
	}

	if (ctx->state == GWNET_HTTP_HDR_PARSE_ST_FIELDS) {
		r = parse_hdr_fields(ctx, &hdr->fields);
		if (r)
			return r;
		ctx->state = GWNET_HTTP_HDR_PARSE_ST_DONE;
	}

	return r;
}

int gwnet_http_res_hdr_parse(struct gwnet_http_hdr_pctx *ctx,
			     struct gwnet_http_res_hdr *hdr)
{
	int r = 0;

	if (ctx->state == GWNET_HTTP_HDR_PARSE_ST_INIT) {
		ctx->state = GWNET_HTTP_HDR_PARSE_ST_FIRST_LINE;
		memset(hdr, 0, sizeof(*hdr));
	}

	if (!ctx->len)
		return -EAGAIN;

	if (ctx->state == GWNET_HTTP_HDR_PARSE_ST_FIRST_LINE) {
		r = parse_hdr_res_first_line(ctx, hdr);
		if (r)
			return r;
		ctx->state = GWNET_HTTP_HDR_PARSE_ST_FIELDS;
	}

	if (ctx->state == GWNET_HTTP_HDR_PARSE_ST_FIELDS) {
		r = parse_hdr_fields(ctx, &hdr->fields);
		if (r)
			return r;
		ctx->state = GWNET_HTTP_HDR_PARSE_ST_DONE;
	}

	return r;
}

void gwnet_http_req_hdr_free(struct gwnet_http_req_hdr *hdr)
{
	if (!hdr)
		return;

	free(hdr->uri);
	free(hdr->qs);
	gwnet_http_hdr_fields_free(&hdr->fields);
	memset(hdr, 0, sizeof(*hdr));
}

void gwnet_http_res_hdr_free(struct gwnet_http_res_hdr *hdr)
{
	if (!hdr)
		return;

	free(hdr->reason);
	gwnet_http_hdr_fields_free(&hdr->fields);
	memset(hdr, 0, sizeof(*hdr));
}

void gwnet_http_hdr_fields_free(struct gwnet_http_hdr_fields *ff)
{
	size_t i;

	if (!ff)
		return;

	for (i = 0; i < ff->nr; i++) {
		free(ff->ff[i].key);
		free(ff->ff[i].val);
	}

	free(ff->ff);
	memset(ff, 0, sizeof(*ff));
}

int gwnet_http_hdr_fields_add(struct gwnet_http_hdr_fields *ff, const char *k,
			      const char *v)
{
	return gwnet_http_hdr_fields_addl(ff, k, strlen(k), v, strlen(v));
}

int gwnet_http_hdr_fields_addf(struct gwnet_http_hdr_fields *ff,
			       const char *k, const char *fmt, ...)
{
	va_list args1, args2;
	size_t vlen;
	char *v;
	int r;

	va_start(args1, fmt);
	va_copy(args2, args1);
	r = vsnprintf(NULL, 0, fmt, args1);
	va_end(args1);

	v = malloc(r + 1);
	if (!v) {
		r = -ENOMEM;
		goto out;
	}

	vlen = (size_t)r;
	vsnprintf(v, vlen + 1, fmt, args2);
	r = gwnet_http_hdr_fields_addl(ff, k, strlen(k), v, vlen);
	free(v);
out:
	va_end(args2);
	return r;
}

static ssize_t find_hdr_field_idx(const struct gwnet_http_hdr_fields *ff,
				  const char *k, size_t klen)
{
	size_t i;

	for (i = 0; i < ff->nr; i++) {
		struct gwnet_http_hdr_field *f = &ff->ff[i];
		if (!strncasecmp(f->key, k, klen)) {
			if (strlen(f->key) == klen)
				return i;
		}
	}

	return -ENOENT;
}

int gwnet_http_hdr_fields_addl(struct gwnet_http_hdr_fields *ff,
			       const char *k, size_t klen,
			       const char *v, size_t vlen)
{
	ssize_t idx = find_hdr_field_idx(ff, k, klen);
	struct gwnet_http_hdr_field *f;
	char *new_val;

	if (idx < 0) {
		struct gwnet_http_hdr_field *new_fields;
		char *kc, *vc;
		size_t new_size;

		kc = malloc(klen + 1);
		if (!kc)
			return -ENOMEM;

		vc = malloc(vlen + 1);
		if (!vc) {
			free(kc);
			return -ENOMEM;
		}

		new_size = (ff->nr + 1) * sizeof(*ff->ff);
		new_fields = realloc(ff->ff, new_size);
		if (!new_fields) {
			free(kc);
			free(vc);
			return -ENOMEM;
		}

		memcpy(kc, k, klen);
		memcpy(vc, v, vlen);
		kc[klen] = '\0';
		vc[vlen] = '\0';
		ff->ff = new_fields;
		f = &ff->ff[ff->nr++];
		f->key = kc;
		f->val = vc;
		return 0;
	}

	f = &ff->ff[idx];
	if (field_is_comma_separated(k, klen)) {
		size_t cur_len = strlen(f->val);
		size_t new_val_len = cur_len + vlen + 3;

		new_val = realloc(f->val, new_val_len);
		if (!new_val)
			return -ENOMEM;

		if (!cur_len) {
			memcpy(new_val, v, vlen);
			new_val[vlen] = '\0';
		} else {
			memcpy(&new_val[cur_len], ", ", 2);
			memcpy(&new_val[cur_len + 2], v, vlen);
			new_val[cur_len + 2 + vlen] = '\0';
		}

		f->val = new_val;
		return 0;
	}

	new_val = realloc(f->val, vlen + 1);
	if (!new_val)
		return -ENOMEM;

	memcpy(new_val, v, vlen);
	new_val[vlen] = '\0';
	f->val = new_val;
	return 0;
}

const char *gwnet_http_hdr_fields_get(const struct gwnet_http_hdr_fields *ff,
				      const char *k)
{
	ssize_t idx = find_hdr_field_idx(ff, k, strlen(k));
	if (idx < 0)
		return NULL;

	return ff->ff[idx].val;
}

const char *gwnet_http_hdr_fields_getl(const struct gwnet_http_hdr_fields *ff,
				       const char *k, size_t klen)
{
	ssize_t idx = find_hdr_field_idx(ff, k, klen);
	if (idx < 0)
		return NULL;

	return ff->ff[idx].val;
}

#define PRTEST_OK()				\
do {						\
	printf("Test passed: %s\n", __func__);	\
} while (0)

#define ASSERT_HDRF(f, k, v)			\
do {						\
	assert(!strcmp((f)->key, k));		\
	assert(!strcmp((f)->val, v));		\
} while (0)

static void test_req_hdr_simple(void)
{
	static const char buf[] =
		"GET /index.html?q=1&a=b HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"User-Agent: gwhttp\r\n"
		"Accept: */*\r\n"
		"Connection: keep-alive\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_req_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_req_hdr_parse(&ctx, &hdr);
	assert(!r);
	assert(ctx.off == len);
	assert(ctx.state == GWNET_HTTP_HDR_PARSE_ST_DONE);
	assert(hdr.method == GWNET_HTTP_METHOD_GET);
	assert(hdr.version == GWNET_HTTP_VER_1_1);
	assert(!strcmp(hdr.uri, "/index.html?q=1&a=b"));
	assert(!strcmp(hdr.qs, "q=1&a=b"));
	assert(hdr.fields.nr == 4);
	ASSERT_HDRF(&hdr.fields.ff[0], "Host", "example.com");
	ASSERT_HDRF(&hdr.fields.ff[1], "User-Agent", "gwhttp");
	ASSERT_HDRF(&hdr.fields.ff[2], "Accept", "*/*");
	ASSERT_HDRF(&hdr.fields.ff[3], "Connection", "keep-alive");
	gwnet_http_req_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

static void test_res_hdr_simple(void)
{
	static const char buf[] =
		"HTTP/1.1 200 OK\r\n"
		"Server: gwhttpd\r\n"
		"Date: Mon, 01 Jan 1999 00:00:00 GMT\r\n"
		"Content-Type: text/html; charset=UTF-8\r\n"
		"Content-Length: 1234\r\n"
		"Connection: close\r\n"
		"\r\n";
	static const size_t len = sizeof(buf) - 1;
	struct gwnet_http_hdr_pctx ctx;
	struct gwnet_http_res_hdr hdr;
	int r;

	r = gwnet_http_hdr_pctx_init(&ctx);
	assert(!r);
	ctx.buf = buf;
	ctx.len = len;
	r = gwnet_http_res_hdr_parse(&ctx, &hdr);
	assert(!r);
	assert(ctx.off == len);
	assert(ctx.state == GWNET_HTTP_HDR_PARSE_ST_DONE);
	assert(hdr.fields.nr == 5);
	ASSERT_HDRF(&hdr.fields.ff[0], "Server", "gwhttpd");
	ASSERT_HDRF(&hdr.fields.ff[1], "Date", "Mon, 01 Jan 1999 00:00:00 GMT");
	ASSERT_HDRF(&hdr.fields.ff[2], "Content-Type", "text/html; charset=UTF-8");
	ASSERT_HDRF(&hdr.fields.ff[3], "Content-Length", "1234");
	ASSERT_HDRF(&hdr.fields.ff[4], "Connection", "close");
	gwnet_http_res_hdr_free(&hdr);
	gwnet_http_hdr_pctx_free(&ctx);
	PRTEST_OK();
}

// int main(void)
// {
// 	test_req_hdr_simple();
// 	test_res_hdr_simple();
// 	printf("All tests passed!\n");
// 	return 0;
// }
