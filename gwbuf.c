
#include "gwbuf.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>

int gwbuf_init(struct gwbuf *b, size_t cap)
{
	if (cap == 0)
		cap = 1023;

	b->buf = malloc(cap + 1);
	if (!b->buf)
		return -ENOMEM;

	b->len = 0;
	b->cap = cap;
	b->buf[0] = b->buf[cap] = '\0';
	return 0;
}

int gwbuf_increase(struct gwbuf *b, size_t inc)
{
	size_t new_cap = b->cap + inc;
	char *new_buf;

	if (new_cap < b->cap)
		return -ENOMEM; // Overflow

	new_buf = realloc(b->buf, new_cap + 1);
	if (!new_buf)
		return -ENOMEM;

	b->buf = new_buf;
	b->cap = new_cap;
	b->buf[b->len] = b->buf[b->cap] = '\0';
	return 0;
}

void gwbuf_free(struct gwbuf *b)
{
	if (b->buf) {
		free(b->buf);
		b->buf = NULL;
		b->len = 0;
		b->cap = 0;
	}
}

void gwbuf_advance(struct gwbuf *b, size_t len)
{
	if (len > b->len)
		return;

	if (len == b->len) {
		gwbuf_free(b);
		return;
	}

	memmove(b->buf, b->buf + len, b->len - len);
	b->len -= len;
	b->buf[b->len] = '\0';
}

int gwbuf_set_cap(struct gwbuf *b, size_t cap)
{
	char *new_buf;

	if (cap == b->cap)
		return 0;

	new_buf = realloc(b->buf, cap + 1);
	if (!new_buf)
		return -ENOMEM;

	b->buf = new_buf;
	b->cap = cap;
	if (b->len > b->cap)
		b->len = b->cap;

	b->buf[b->len] = b->buf[b->cap] = '\0';
	return 0;
}

int gwbuf_apfmt(struct gwbuf *b, const char *fmt, ...)
{
	va_list args, args2;
	int len, ret;

	va_start(args, fmt);
	va_copy(args2, args);
	len = vsnprintf(NULL, 0, fmt, args2);
	va_end(args2);

	ret = gwbuf_increase(b, len + 1);
	if (ret < 0)
		goto out;

	ret = vsnprintf(b->buf + b->len, b->cap - b->len + 1, fmt, args);
	b->len += ret;
	b->buf[b->len] = '\0';
	ret = 0;
out:
	va_end(args);
	return ret;
}

int gwbuf_append(struct gwbuf *b, const void *data, size_t len)
{
	static const size_t base_buf = 1023;

	if (b->len + len > b->cap) {
		size_t new_cap = b->cap ? b->cap * 2 : base_buf;
		char *new_buf;

		if (new_cap < b->len + len)
			new_cap = b->len + len + base_buf;

		new_buf = realloc(b->buf, new_cap + 1);
		if (!new_buf)
			return -ENOMEM;

		b->buf = new_buf;
		b->cap = new_cap;
	}

	memcpy(b->buf + b->len, data, len);
	b->len += len;
	b->buf[b->len] = b->buf[b->cap] = '\0';
	return 0;
}

void gwbuf_move(struct gwbuf *dst, struct gwbuf *src)
{
	if (dst->buf)
		free(dst->buf);

	dst->buf = src->buf;
	dst->len = src->len;
	dst->cap = src->cap;

	src->buf = NULL;
	src->len = 0;
	src->cap = 0;
}
