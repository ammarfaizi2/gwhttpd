
#include "gwbuf.h"
#include "common.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

int gwbuf_init(struct gwbuf *b, uint64_t cap)
{
	if (!cap)
		cap = 1023ull;

	b->orig_buf = b->buf = malloc(cap + 1ull);
	if (!b->buf)
		return -ENOMEM;

	b->buf[cap] = '\0';
	b->len = 0;
	b->cap = cap;
	return 0;
}

static int gwbuf_set_cap(struct gwbuf *b, uint64_t new_cap)
{
	char *new_buf;

	new_buf = realloc(b->buf, new_cap + 1ull);
	if (!new_buf)
		return -ENOMEM;

	b->orig_buf = b->buf = new_buf;
	b->cap = new_cap;
	b->len = (b->len > new_cap) ? new_cap : b->len;
	b->buf[b->cap] = b->buf[b->len] = '\0';
	return 0;
}

__hot
int gwbuf_increase(struct gwbuf *b, uint64_t inc)
{
	if (!inc)
		return 0;

	return gwbuf_set_cap(b, b->cap + inc);
}

__hot
void gwbuf_free(struct gwbuf *b)
{
	if (!b || !b->buf || !b->orig_buf)
		return;

	free(b->orig_buf);
	memset(b, 0, sizeof(*b));
}

__hot
void gwbuf_advance(struct gwbuf *b, uint64_t len)
{
	if (len >= b->len) {
		gwbuf_free(b);
		return;
	}

	b->len -= len;
	memmove(b->buf, &b->buf[len], b->len);
	b->buf[b->len] = '\0';
}

__hot
void gwbuf_soft_advance(struct gwbuf *b, uint64_t len)
{
	assert(len <= b->len);
	b->buf += len;
	b->len -= len;
}

__hot
void gwbuf_soft_advance_sync(struct gwbuf *b)
{
	assert(b->buf >= b->orig_buf);
	assert(b->cap >= b->len);

	if (!b->len) {
		gwbuf_free(b);
		return;
	}

	memmove(b->orig_buf, b->buf, b->len);
	b->orig_buf[b->len] = '\0';
	b->buf = b->orig_buf;
}

__hot
int gwbuf_prepare_need(struct gwbuf *b, uint64_t need)
{
	uint64_t needed_len;
	uint64_t new_cap;

	if (b->orig_buf != b->buf)
		gwbuf_soft_advance_sync(b);

	if (need <= b->cap - b->len)
		return 0;

	needed_len = b->len + need;
	new_cap = (b->cap + 1ull) * 2ull;
	while (new_cap < needed_len)
		new_cap *= 2ull;

	return gwbuf_set_cap(b, new_cap);
}

__hot
int gwbuf_apfmt(struct gwbuf *b, const char *fmt, ...)
{
	va_list args, args2;
	uint64_t free_space;
	int len, ret;

	va_start(args, fmt);
	va_copy(args2, args);
	len = vsnprintf(NULL, 0, fmt, args2);
	va_end(args2);

	ret = gwbuf_prepare_need(b, len + 1);
	if (ret < 0)
		goto out;

	free_space = b->cap - b->len;
	ret = vsnprintf(&b->buf[b->len], free_space + 1ul, fmt, args);
	b->len += ret;
	ret = 0;
out:
	va_end(args);
	return ret;
}

__hot
int gwbuf_append(struct gwbuf *b, const void *data, uint64_t len)
{
	int ret;

	ret = gwbuf_prepare_need(b, len);
	if (ret < 0)
		return ret;

	memcpy(&b->buf[b->len], data, len);
	b->len += len;
	b->buf[b->len] = '\0';
	return 0;
}

__hot
void gwbuf_move(struct gwbuf *dst, struct gwbuf *src)
{
	gwbuf_free(dst);
	*dst = *src;
	memset(src, 0, sizeof(*src));
}
