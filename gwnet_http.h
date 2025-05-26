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

typedef struct gwnet_http_srv gwnet_http_srv_t;
typedef int (*gwnet_http_srv_route_cb_t)(struct gwnet_http_srv *srv,
					 struct gwnet_http_cli *hc,
					 struct gwnet_http_req *req);

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

#endif /* #ifndef GWNET_HTTP_H */
