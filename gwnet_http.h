// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWNET_HTTP_H
#define GWNET_HTTP_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "gwnet_tcp.h"

#define GWNET_HTTP_DEF_MAX_REQ_HDR_LEN	8192
#define GWNET_HTTP_DEF_MAX_REQ_BODY_LEN	(1024 * 1024 * 10)

enum {
	GWNET_HTTP_RES_TYPE_NO_CONTENT	= 0,
	GWNET_HTTP_RES_TYPE_BUF		= 1,
	GWNET_HTTP_RES_TYPE_ZERO	= 2,
};

struct gwnet_http_srv_cfg {
	struct gwnet_tcp_srv_cfg	tcp_cfg;
	uint32_t			max_req_hdr_len;
	uint64_t			max_req_body_len;
};

struct gwnet_http_hdr_pair {
	char	*key;
	char	*val;
};

struct gwnet_http_hdr {
	struct gwnet_http_hdr_pair	*pairs;
	size_t				nr_pairs;
};

struct gwnet_http_srv;
struct gwnet_http_cli;
struct gwnet_http_req;
struct gwnet_http_res;

typedef struct gwnet_http_srv gwnet_http_srv_t;
typedef int (*gwnet_http_srv_route_cb_t)(struct gwnet_http_srv *srv,
					 struct gwnet_http_cli *hc);

const char *gwnet_http_hdr_get_val(struct gwnet_http_hdr *hdr, const char *key);
int gwnet_http_hdr_addf(struct gwnet_http_hdr *hdr, const char *key,
			const char *fmt, ...);
int gwnet_http_hdr_add(struct gwnet_http_hdr *hdr, const char *key,
		       const char *val);
gwnet_http_srv_t *gwnet_http_srv_init(const struct gwnet_http_srv_cfg *cfg);
int gwnet_http_srv_run(gwnet_http_srv_t *s);
void gwnet_http_srv_free(struct gwnet_http_srv *s);
void gwnet_http_srv_set_route_cb(gwnet_http_srv_t *s,
				 gwnet_http_srv_route_cb_t cb, void *data);

struct gwnet_http_req *gwnet_http_req_get(struct gwnet_http_cli *hc);
const char *gwnet_http_req_get_uri(struct gwnet_http_req *req);
const char *gwnet_http_req_get_qs(struct gwnet_http_req *req);
const char *gwnet_http_req_get_method(struct gwnet_http_req *req);

char *gwnet_http_req_get_nc_uri(struct gwnet_http_req *req);
char *gwnet_http_req_get_nc_qs(struct gwnet_http_req *req);

struct gwnet_http_res *gwnet_http_res_get(struct gwnet_http_cli *hc);
void gwnet_http_res_set_content_type(struct gwnet_http_res *res,
				     const char *content_type);
struct gwnet_http_hdr *gwnet_http_res_get_hdr(struct gwnet_http_res *res);
void gwnet_http_res_set_code(struct gwnet_http_res *res, int code);
struct gwbuf *gwnet_http_res_get_body_buf(struct gwnet_http_res *res);

void gwnet_http_res_set_type(struct gwnet_http_res *res, int type);
void gwnet_http_res_set_zero_len(struct gwnet_http_res *res, size_t len);

#ifdef GWNET_HTTP_DEFINE_SHORT_NAMES
static inline
const char *hhdr_get_val(struct gwnet_http_hdr *hdr, const char *key)
{
	return gwnet_http_hdr_get_val(hdr, key);
}

#define hhdr_addf(hdr, key, fmt, ...) \
	gwnet_http_hdr_addf(hdr, key, fmt, ##__VA_ARGS__)

#define hhdr_add(hdr, key, val) \
	gwnet_http_hdr_add(hdr, key, val)

static inline
gwnet_http_srv_t *hserv_init(const struct gwnet_http_srv_cfg *cfg)
{
	return gwnet_http_srv_init(cfg);
}

static inline
int hserv_run(gwnet_http_srv_t *s)
{
	return gwnet_http_srv_run(s);
}

static inline
void hserv_free(gwnet_http_srv_t *s)
{
	gwnet_http_srv_free(s);
}

static inline
void hserv_set_route_cb(gwnet_http_srv_t *s,
			gwnet_http_srv_route_cb_t cb, void *data)
{
	gwnet_http_srv_set_route_cb(s, cb, data);
}

static inline
struct gwnet_http_req *hreq_get(struct gwnet_http_cli *hc)
{
	return gwnet_http_req_get(hc);
}

static inline
const char *hreq_get_uri(struct gwnet_http_req *req)
{
	return gwnet_http_req_get_uri(req);
}

static inline
const char *hreq_get_qs(struct gwnet_http_req *req)
{
	return gwnet_http_req_get_qs(req);
}

static inline
const char *hreq_get_method(struct gwnet_http_req *req)
{
	return gwnet_http_req_get_method(req);
}

static inline
char *hreq_get_nc_uri(struct gwnet_http_req *req)
{
	return gwnet_http_req_get_nc_uri(req);
}

static inline
char *hreq_get_nc_qs(struct gwnet_http_req *req)
{
	return gwnet_http_req_get_nc_qs(req);
}

static inline
struct gwnet_http_res *hres_get(struct gwnet_http_cli *hc)
{
	return gwnet_http_res_get(hc);
}

static inline
void hres_set_content_type(struct gwnet_http_res *res,
			   const char *content_type)
{
	gwnet_http_res_set_content_type(res, content_type);
}

static inline
struct gwnet_http_hdr *hres_get_hdr(struct gwnet_http_res *res)
{
	return gwnet_http_res_get_hdr(res);
}

static inline
void hres_set_code(struct gwnet_http_res *res, int code)
{
	gwnet_http_res_set_code(res, code);
}

static inline
struct gwbuf *hres_get_body_buf(struct gwnet_http_res *res)
{
	return gwnet_http_res_get_body_buf(res);
}

static inline
void hres_set_type(struct gwnet_http_res *res, int type)
{
	gwnet_http_res_set_type(res, type);
}

static inline
void hres_set_zero_len(struct gwnet_http_res *res, size_t len)
{
	gwnet_http_res_set_zero_len(res, len);
}
#endif /* #ifdef GWNET_HTTP_DEFINE_SHORT_NAMES */

#endif /* #ifndef GWNET_HTTP_H */
