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

#include <stdbool.h>

#define GWNET_HTTP_DEF_MAX_REQ_HDR_LEN	8192
#define GWNET_HTTP_DEF_MAX_REQ_BODY_LEN	(1024 * 1024 * 10)

enum {
	GWNET_HTTP_RES_TYPE_NO_CONTENT	= 0,
	GWNET_HTTP_RES_TYPE_BUF		= 1,
	GWNET_HTTP_RES_TYPE_ZERO	= 2,
	GWNET_HTTP_RES_TYPE_URANDOM	= 3,
	GWNET_HTTP_RES_TYPE_FILE	= 4,
};


enum {
	GWNET_HTTP_VER_UNKNOWN	= 0,
	GWNET_HTTP_VER_1_0	= 10,
	GWNET_HTTP_VER_1_1	= 11,
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
typedef struct gwnet_http_cli gwnet_http_cli_t;
typedef struct gwnet_http_req gwnet_http_req_t;
typedef struct gwnet_http_res gwnet_http_res_t;
typedef int (*gwnet_http_srv_route_cb_t)(struct gwnet_http_srv *srv,
					 struct gwnet_http_cli *hc);


int gwnet_http_req_get_method(gwnet_http_req_t *req);
int gwnet_http_req_get_version(gwnet_http_req_t *req);
bool gwnet_http_req_is_body_oversized(gwnet_http_req_t *req);
struct gwnet_http_hdr *gwnet_http_req_get_hdr(gwnet_http_req_t *req);
const char *gwnet_http_req_get_content_type(gwnet_http_req_t *req);
uint64_t gwnet_http_req_get_content_length(gwnet_http_req_t *req);
struct gwbuf *gwnet_http_req_get_body_buf(gwnet_http_req_t *req);
char *gwnet_http_req_get_nc_uri(gwnet_http_req_t *req);
char *gwnet_http_req_get_nc_qs(gwnet_http_req_t *req);
const char *gwnet_http_req_get_uri(gwnet_http_req_t *req);
const char *gwnet_http_req_get_qs(gwnet_http_req_t *req);
gwnet_http_res_t *gwnet_http_res_get(gwnet_http_req_t *req);
int gwnet_http_res_get_code(gwnet_http_res_t *res);
void gwnet_http_res_set_code(gwnet_http_res_t *res, int code);
const char *gwnet_http_res_get_content_type(gwnet_http_res_t *res);
void gwnet_http_res_set_content_type(gwnet_http_res_t *res,
				     const char *content_type);
void gwnet_http_res_body_set_zero(gwnet_http_res_t *res, uint64_t len);
void gwnet_http_res_body_set_urandom(gwnet_http_res_t *res, uint64_t len);
void gwnet_http_res_body_set_file(gwnet_http_res_t *res, int fd, uint64_t len);
int gwnet_http_res_body_set_file_path(gwnet_http_res_t *res, const char *path);
void gwnet_http_res_body_set_buf(gwnet_http_res_t *res, struct gwbuf *buf);
struct gwbuf *gwnet_http_res_body_get_buf(gwnet_http_res_t *res);
const char *gwnet_http_hdr_get_val(struct gwnet_http_hdr *hdr, const char *key);
char *gwnet_http_hdr_get_nc_val(struct gwnet_http_hdr *hdr, const char *key);
int gwnet_http_hdr_addf(struct gwnet_http_hdr *hdr, const char *key,
			const char *fmt, ...);
int gwnet_http_hdr_add(struct gwnet_http_hdr *hdr, const char *key,
		       const char *val);

gwnet_http_srv_t *gwnet_http_srv_init(const struct gwnet_http_srv_cfg *cfg);
int gwnet_http_srv_run(gwnet_http_srv_t *srv);
void gwnet_http_srv_stop(gwnet_http_srv_t *srv);
void gwnet_http_srv_free(gwnet_http_srv_t *srv);

#endif /* #ifndef GWNET_HTTP_H */
