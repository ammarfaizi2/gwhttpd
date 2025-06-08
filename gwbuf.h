// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWBUF_H
#define GWBUF_H

#include <stddef.h>
#include <stdint.h>
#include <assert.h>

struct gwbuf {
	char		*buf;
	uint64_t	len;
	uint64_t	cap;
	char		*orig_buf;
};

int gwbuf_init(struct gwbuf *b, uint64_t cap);
int gwbuf_increase(struct gwbuf *b, uint64_t inc);
void gwbuf_free(struct gwbuf *b);
void gwbuf_advance(struct gwbuf *b, uint64_t len);

static inline
void gwbuf_soft_advance(struct gwbuf *b, uint64_t len)
{
	assert(len <= b->len);
	b->buf += len;
	b->len -= len;
}

void gwbuf_soft_advance_sync(struct gwbuf *b);
int gwbuf_prepare_need(struct gwbuf *b, uint64_t need);
int gwbuf_apfmt(struct gwbuf *b, const char *fmt, ...);
int gwbuf_append(struct gwbuf *b, const void *data, uint64_t len);
void gwbuf_move(struct gwbuf *dst, struct gwbuf *src);

#endif /* #ifndef GWBUF_H */
