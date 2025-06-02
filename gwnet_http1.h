// SPDX-License-Identifier: GPL-2.0-only
/*
 * gwnet_http1.h - HTTP/1.0 and HTTP/1.1 parser.
 *
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWNET_HTTP1_H
#define GWNET_HTTP1_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

enum {
	GWNET_HTTP_HDR_TYPE_REQ	= 0,
	GWNET_HTTP_HDR_TYPE_RES	= 1,
};

enum {
	GWNET_HTTP_HDR_PARSE_ST_INIT		= 0,
	GWNET_HTTP_HDR_PARSE_ST_FIRST_LINE	= 1,
	GWNET_HTTP_HDR_PARSE_ST_FIELDS		= 2,
	GWNET_HTTP_HDR_PARSE_ST_DONE		= 3,
};

enum {
	GWNET_HTTP_HDR_ERR_NONE		= 0,
	GWNET_HTTP_HDR_ERR_MALFORMED	= 1,
	GWNET_HTTP_HDR_ERR_TOO_LONG	= 2,
	GWNET_HTTP_HDR_ERR_INTERNAL	= 100,
};

enum {
	GWNET_HTTP_VER_UNKNOWN	= 0,
	GWNET_HTTP_VER_1_0	= 1,
	GWNET_HTTP_VER_1_1	= 2,
};

enum {
	GWNET_HTTP_METHOD_UNKNOWN	= 0,
	GWNET_HTTP_METHOD_GET		= 1,
	GWNET_HTTP_METHOD_POST		= 2,
	GWNET_HTTP_METHOD_PUT		= 3,
	GWNET_HTTP_METHOD_DELETE	= 4,
	GWNET_HTTP_METHOD_HEAD		= 5,
	GWNET_HTTP_METHOD_OPTIONS	= 6,
	GWNET_HTTP_METHOD_PATCH		= 7,
	GWNET_HTTP_METHOD_TRACE		= 8,
	GWNET_HTTP_METHOD_CONNECT	= 9,
};

struct gwnet_http_hdr_field {
	char	*key;
	char	*val;
};

struct gwnet_http_hdr_fields {
	struct gwnet_http_hdr_field	*ff;
	size_t				nr;
};

struct gwnet_http_req_hdr {
	uint8_t		method;
	uint8_t		version;
	char		*uri;
	char		*qs;

	struct gwnet_http_hdr_fields fields;
};

struct gwnet_http_res_hdr {
	uint8_t		version;
	uint16_t	code;
	char		*reason;

	struct gwnet_http_hdr_fields fields;
};

struct gwnet_http_hdr_pctx {
	uint8_t		state;
	uint8_t		err;
	uint32_t	off;
	const char	*buf;
	uint64_t	len;
	uint64_t	max_len;
};

int gwnet_http_hdr_pctx_init(struct gwnet_http_hdr_pctx *ctx);
void gwnet_http_hdr_pctx_free(struct gwnet_http_hdr_pctx *ctx);
int gwnet_http_req_hdr_parse(struct gwnet_http_hdr_pctx *ctx,
			     struct gwnet_http_req_hdr *hdr);
int gwnet_http_res_hdr_parse(struct gwnet_http_hdr_pctx *ctx,
			     struct gwnet_http_res_hdr *hdr);
void gwnet_http_req_hdr_free(struct gwnet_http_req_hdr *hdr);
void gwnet_http_res_hdr_free(struct gwnet_http_res_hdr *hdr);

void gwnet_http_hdr_fields_free(struct gwnet_http_hdr_fields *ff);
int gwnet_http_hdr_fields_add(struct gwnet_http_hdr_fields *ff, const char *k,
			      const char *v);
__attribute__((__format__(printf, 3, 4)))
int gwnet_http_hdr_fields_addf(struct gwnet_http_hdr_fields *ff,
			       const char *k, const char *fmt, ...);
int gwnet_http_hdr_fields_addl(struct gwnet_http_hdr_fields *ff,
			       const char *k, size_t klen,
			       const char *v, size_t vlen);

const char *gwnet_http_hdr_fields_get(const struct gwnet_http_hdr_fields *ff,
				      const char *k);
const char *gwnet_http_hdr_fields_getl(const struct gwnet_http_hdr_fields *ff,
				       const char *k, size_t klen);

#endif /* #ifndef GWNET_HTTP1_H */
