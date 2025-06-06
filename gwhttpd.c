// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#define GWNET_HTTP_DEFINE_SHORT_NAMES
#include "gwnet_http.h"
#include "gwbuf.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#include <signal.h>

static const struct option long_opts[] = {
	{ "bind-addr",		required_argument,	NULL,	'b' },
	{ "port",		required_argument,	NULL,	'p' },
	{ "nr-workers",		required_argument,	NULL,	'n' },
	{ "reuse-addr",		required_argument,	NULL,	'r' },
	{ "reuse-port",		required_argument,	NULL,	'R' },
	{ "tcp-backlog",	required_argument,	NULL,	't' },
	{ "max-req-hdr-len",	required_argument,	NULL,	'H' },
	{ "max-req-body-len",	required_argument,	NULL,	'B' },
	{ "help",		no_argument,		NULL,	'h' },
#ifdef GWNET_HTTP1_TESTS
	{ "run-tests",		no_argument,		NULL,	1 },
#endif
	{ NULL, 0, NULL, 0 }
};
static const char short_opts[] = "b:p:n:r:R:t:H:B:h";

static const struct gwnet_http_srv_cfg default_cfg = {
	.tcp_cfg = {
		.bind_addr = "::",
		.port = 8080,
		.nr_workers = 3,
		.reuse_addr = 1,
		.reuse_port = 1,
		.tcp_backlog = 4096
	},
	.max_req_hdr_len = GWNET_HTTP_DEF_MAX_REQ_HDR_LEN,
	.max_req_body_len = GWNET_HTTP_DEF_MAX_REQ_BODY_LEN
};

static gwnet_http_srv_t *g_srv = NULL;

static void signal_handler(int sig)
{
	(void)sig;

	if (g_srv)
		gwnet_http_srv_stop(g_srv);
}

static void show_help(const char *app)
{
	const struct gwnet_tcp_srv_cfg *tc = &default_cfg.tcp_cfg;
	const struct gwnet_http_srv_cfg *hc = &default_cfg;

	printf("Usage: %s [OPTIONS]\n", app);
	printf("gwhttpd2 - A simple HTTP server\n");
	printf("\n");
	printf("Options:\n");
	printf("  -b, --bind-addr <addr>        Bind address (default: %s)\n", tc->bind_addr);
	printf("  -p, --port <port>             Port number (default: %u)\n", tc->port);
	printf("  -n, --nr-workers <num>        Number of worker threads (default: %u)\n", tc->nr_workers);
	printf("  -r, --reuse-addr <0|1>        Enable/disable SO_REUSEADDR (default: %d)\n", tc->reuse_addr);
	printf("  -R, --reuse-port <0|1>        Enable/disable SO_REUSEPORT (default: %d)\n", tc->reuse_port);
	printf("  -t, --tcp-backlog <num>       TCP backlog size (default: %d)\n", tc->tcp_backlog);
	printf("  -H, --max-req-hdr-len <len>   Maximum request header length (default: %u)\n", hc->max_req_hdr_len);
	printf("  -B, --max-req-body-len <len>  Maximum request body length (default: %llu)\n", (unsigned long long)hc->max_req_body_len);
	printf("  -h, --help                    Show this help message and exit\n");
	printf("  --run-tests                   Run tests and exit\n");
	printf("\n");
}

uint64_t atoull_kgmt(const char *str, int *err)
{
	char *endptr;
	uint64_t value = strtoull(str, &endptr, 10);

	if (endptr == str || *endptr == '\0') {
		*err = 0;
		return value;
	}

	if (*endptr == 'k' || *endptr == 'K') {
		value *= 1024;
		endptr++;
	} else if (*endptr == 'm' || *endptr == 'M') {
		value *= 1024 * 1024;
		endptr++;
	} else if (*endptr == 'g' || *endptr == 'G') {
		value *= 1024 * 1024 * 1024;
		endptr++;
	}

	if (*endptr != '\0') {
		*err = -EINVAL;
		return 0;
	}

	*err = 0;
	return value;
}

static int __parse_arg(const char *app, int c, struct gwnet_tcp_srv_cfg *tc,
		       struct gwnet_http_srv_cfg *hc)
{
	int tmp;

	switch (c) {
	case 'b':
		strncpy(tc->bind_addr, optarg, sizeof(tc->bind_addr));
		tc->bind_addr[sizeof(tc->bind_addr) - 1] = '\0';
		break;
	case 'p':
		tmp = atoi(optarg);
		if (tmp < 0 || tmp > 65535) {
			fprintf(stderr, "Error: Invalid port number: %s\n", optarg);
			return -EINVAL;
		}
		tc->port = (uint16_t)tmp;
		break;
	case 'n':
		tmp = atoi(optarg);
		if (tmp < 1 || tmp > 1024) {
			fprintf(stderr, "Error: Invalid number of workers: %s\n", optarg);
			return -EINVAL;
		}
		tc->nr_workers = (uint16_t)tmp;
		break;
	case 'r':
		if (!strcmp(optarg, "1") || !strcasecmp(optarg, "true")) {
			tc->reuse_addr = 1;
		} else if (!strcmp(optarg, "0") || !strcasecmp(optarg, "false")) {
			tc->reuse_addr = 0;
		} else {
			fprintf(stderr, "Error: Invalid reuse-addr value: %s\n", optarg);
			return -EINVAL;
		}
		break;
	case 'R':
		if (!strcmp(optarg, "1") || !strcasecmp(optarg, "true")) {
			tc->reuse_port = 1;
		} else if (!strcmp(optarg, "0") || !strcasecmp(optarg, "false")) {
			tc->reuse_port = 0;
		} else {
			fprintf(stderr, "Error: Invalid reuse-port value: %s\n", optarg);
			return -EINVAL;
		}
		break;
	case 't':
		tmp = atoi(optarg);
		if (tmp < 0 || tmp > 1024) {
			fprintf(stderr, "Error: Invalid TCP backlog: %s\n", optarg);
			return -EINVAL;
		}
		tc->tcp_backlog = tmp;
		break;
	case 'H':
		tmp = atoi(optarg);
		if (tmp < 0 || tmp > 65536) {
			fprintf(stderr, "Error: Invalid max request header length: %s\n", optarg);
			return -EINVAL;
		}
		hc->max_req_hdr_len = (uint32_t)tmp;
		break;
	case 'B':
		hc->max_req_body_len = atoull_kgmt(optarg, &tmp);
		if (tmp < 0) {
			fprintf(stderr, "Error: Invalid max request body length: %s\n", optarg);
			return -EINVAL;
		}
		break;
	case 'h':
		show_help(app);
		exit(0);
#ifdef GWNET_HTTP1_TESTS
	case 1:
		gwnet_http_run_tests();
		exit(0);
		break;
#endif
	default:
		fprintf(stderr, "Error: Unknown option: %c\n", c);
		show_help(app);
		return -EINVAL;
	}

	return 0;
}

static int parse_arg_and_init(int argc, char *argv[], gwnet_http_srv_t **srv_p)
{
	const struct sigaction sa = {
		.sa_handler = &signal_handler,
		.sa_flags = 0
	};
	struct gwnet_http_srv_cfg cfg = default_cfg;
	struct gwnet_tcp_srv_cfg *tc = &cfg.tcp_cfg;
	struct gwnet_http_srv_cfg *hc = &cfg;
	gwnet_http_srv_t *srv;
	int ret;

	while (1) {
		int c = getopt_long(argc, argv, short_opts, long_opts, NULL);
		if (c == -1)
			break;

		ret = __parse_arg(argv[0], c, tc, hc);
		if (ret < 0)
			return ret;
	}

	ret = 0;
	ret |= sigaction(SIGINT, &sa, NULL);
	ret |= sigaction(SIGTERM, &sa, NULL);
	if (ret) {
		ret = -errno;
		fprintf(stderr, "Error: Failed to set signal handlers: %s\n",
			strerror(-ret));
		return ret;
	}

	srv = gwnet_http_srv_init(&cfg);
	if (!srv) {
		fprintf(stderr, "Error: Failed to initialize HTTP server\n");
		return -ENOMEM;
	}

	*srv_p = g_srv = srv;
	return 0;
}

#if 0
struct rt_ctx {
	struct gwnet_http_srv *srv;
	struct gwnet_http_cli *hc;
	struct gwnet_http_req *req;
	struct gwnet_http_res *res;
};

static int route_hello_world(struct rt_ctx *ctx)
{
	struct gwnet_http_res *res = ctx->res;
	struct gwbuf *b = hres_get_body_buf(res);

	hres_set_content_type(res, "text/plain");
	gwnet_http_res_set_type(res, GWNET_HTTP_RES_TYPE_BUF);
	gwbuf_apfmt(b, "Hello world!\n");
	hres_set_code(res, 200);
	return 0;
}

static int route_zero(struct rt_ctx *ctx)
{
	struct gwnet_http_res *res = hres_get(ctx->hc);

	hres_set_content_type(res, "application/octet-stream");
	gwnet_http_res_set_type(res, GWNET_HTTP_RES_TYPE_ZERO);
	hres_set_zero_len(res, 1024ull * 1024 * 1024 * 30);
	hres_set_code(res, 200);
	return 0;
}

static int route_404(struct rt_ctx *ctx)
{
	struct gwnet_http_res *res = ctx->res;

	hres_set_content_type(res, "text/plain");
	gwnet_http_res_set_type(res, GWNET_HTTP_RES_TYPE_BUF);
	gwbuf_apfmt(hres_get_body_buf(res), "404 Not Found\n");
	hres_set_code(res, 404);
	return 0;
}

static int handle_route(struct gwnet_http_srv *srv, struct gwnet_http_cli *hc)
{
	struct gwnet_http_req *req = hreq_get(hc);
	struct gwnet_http_res *res = hres_get(hc);
	struct rt_ctx ctx = {
		.srv = srv,
		.hc = hc,
		.req = req,
		.res = res,
	};
	char *uri = hreq_get_nc_uri(req);

	if (!uri)
		return -EINVAL;

	uri = trim_char(uri, '/');
	if (!*uri)
		return route_hello_world(&ctx);

	if (!strcmp(uri, "zero"))
		return route_zero(&ctx);

	return route_404(&ctx);
}
#endif

int main(int argc, char *argv[])
{
	gwnet_http_srv_t *srv;
	int ret;

	ret = parse_arg_and_init(argc, argv, &srv);
	if (ret)
		return -ret;

	ret = gwnet_http_srv_run(srv);
	gwnet_http_srv_free(srv);
	return -ret;
}
