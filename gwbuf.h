// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWBUF_H
#define GWBUF_H

#include <stddef.h>

struct gwbuf {
	char	*buf;
	size_t	len;
	size_t	cap;
};

int gwbuf_init(struct gwbuf *b, size_t cap);
int gwbuf_increase(struct gwbuf *b, size_t inc);
void gwbuf_free(struct gwbuf *b);
void gwbuf_advance(struct gwbuf *b, size_t len);
int gwbuf_set_cap(struct gwbuf *b, size_t cap);
int gwbuf_apfmt(struct gwbuf *b, const char *fmt, ...);
int gwbuf_append(struct gwbuf *b, const void *data, size_t len);

#endif /* #ifndef GWBUF_H */
