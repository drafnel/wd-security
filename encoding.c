/*
 * encoding.c
 *
 * Copyright (C) 2025  Brandon Casey
 */
#include "compat.h"
#include "encoding.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <iconv.h>

static void* xmalloc (size_t sz)
{
	void *ptr = malloc(sz);
	if (!ptr) {
		perror("memory allocation failed");
		abort();
	}
	return ptr;
}

static void* xrealloc (void *ptr, size_t sz)
{
	void *nptr = realloc(ptr, sz);
	if (!nptr && sz) {
		perror("memory allocation failed");
		abort();
	}
	return nptr;
}

/*
 * Trim leading and trailing whitespace.
 */
char* strtrim (char *s) {
	char *head = s;
	size_t len;

	/* trim leading space */
	while (isspace((unsigned char)*s))
		s++;

	/* trim trailing space */
	for (len = strlen(s); len && isspace((unsigned char)s[len-1]); len--)
		;

	s[len] = '\0';

	if (head != s)
		memmove(head, s, strlen(s) + 1);

	return head;
}

char* strdup_printf (const char *fmt, ...) {
	char *s;
	int sz;
	va_list ap;

	va_start(ap, fmt);

	sz = vsnprintf(NULL, 0, fmt, ap);
	if (sz < 0) {
		perror("vnsprintf failed");
		abort();
	}
	sz++;
	s = xmalloc(sz);

	va_end(ap);

	va_start(ap, fmt);
	vsnprintf(s, sz, fmt, ap);
	va_end(ap);

	return s;
}

/*
 * Delete non-UCS-2 characters from string.
 */
size_t delete_non_ucs2le (uint8_t *s, size_t len) {
	uint8_t *h = s;
	size_t i;
	assert(len < SIZE_MAX);
	/* The range 0xD800 to 0xDFFF have a special purpose. */
	for (i = 1; i < len; i+=2, s+=2)
		if (s[1] < 0xD8 || s[1] > 0xDF) {
			*h++ = s[0];
			*h++ = s[1];
		}
	return s - h + (len - i + 1);
}

/*
 * Converts string from src_encoding to dest_encoding.  The result is
 * returned in an allocated string which must be freed.
 */
static char* convert (const char *src_encoding, const char *src, size_t slen,
		const char *dest_encoding, size_t *dlen)
{
	iconv_t cd;
	char *buf = NULL;
	char *ptr;
	size_t avail = 0;
	size_t len = 0;

	cd = iconv_open(dest_encoding, src_encoding);
	if (cd == (iconv_t)-1)
		return NULL;

	do {
		len += slen + 4;
		avail += slen + 4;
		buf = xrealloc(buf, len);
		ptr = buf + len - avail;

		if (iconv(cd, (char**)&src, &slen, &ptr, &avail) == (size_t)-1)
		{
			if (errno == E2BIG)
				continue;
			free(buf);
			iconv_close(cd);
			return NULL;
		}
	} while (slen);

	while (1) {
		if (iconv(cd, NULL, &slen, &ptr, &avail) == (size_t)-1) {
			if (errno == E2BIG) {
				len += 4;
				avail += 4;
				buf = xrealloc(buf, len);
				ptr = buf + len - avail;
				continue;
			}
			free(buf);
			iconv_close(cd);
			return NULL;
		}
		break;
	}

	if (iconv_close(cd) == -1)
		perror("iconv_close failed");

	/* *dlen will contain the number of bytes written to dest */
	*dlen = len - avail;

	return buf;
}

/*
 * Converts string from src_encoding to dest_encoding using a fixed-size
 * destination buffer.  If the string in `src` cannot be represented in
 * the new encoding within the `dest` buffer, then it will be truncated.
 */
static size_t convert_buf (const char *src_encoding, const char *src,
		size_t slen, const char *dest_encoding, char *dest, size_t dlen)
{
	iconv_t cd;
	size_t avail = dlen;

	cd = iconv_open(dest_encoding, src_encoding);
	if (cd == (iconv_t)-1)
		return (size_t)-1;

	if (iconv(cd, (char**)&src, &slen, &dest, &avail) == (size_t)-1)
	{
		if (errno != E2BIG) {
			iconv_close(cd);
			return (size_t)-1;
		}
	}

	if (iconv(cd, NULL, &slen, &dest, &avail) == (size_t)-1) {
		if (errno != E2BIG) {
			iconv_close(cd);
			return (size_t)-1;
		}
	}

	if (iconv_close(cd) == -1)
		perror("iconv_close failed");

	return dlen - avail;
}

/*
 * Convert UTF-16 LE to UTF-8
 *
 * Returns allocated string which must be freed.
 * `len` parameter is updated with length of returned string.
 *
 * Params:
 * src  pointer to UCS-2 LE bytes
 * slen  number of bytes in src to convert
 *
 * dlen number of bytes returned.
 */
char* utf16le_to_utf8 (const uint8_t *src, size_t slen, size_t *dlen)
{
	char *dest;
	dest = convert("UTF-16LE", (const char*)src, slen, "UTF-8", dlen);
	if (dest) {
		dest = xrealloc(dest, *dlen + 1);
		dest[*dlen] = '\0';
	}
	return dest;
}

/*
 * Convert UTF-8 to UTF-16 LE
 *
 * Returns allocated string which must be freed.
 * `len` parameter is updated with length of returned string.
 *
 * Params:
 * src  pointer to UTF-8 bytes
 * slen  number of bytes in src to convert
 *
 * dlen number of bytes in returned buffer.
 */
uint8_t* utf8_to_utf16le (const char *src, size_t slen, size_t *dlen)
{
	uint8_t *dest;
	dest = (uint8_t*)convert("UTF-8", src, slen, "UTF-16LE", dlen);
	if (dest) {
		assert((*dlen & 0x01) == 0);
		dest = xrealloc(dest, *dlen + 2);
		dest[*dlen] = 0;
		dest[*dlen + 1] = 0;
	}
	return dest;
}

size_t utf8_to_utf16le_buf (const char *src, size_t slen, uint8_t *dest,
		size_t dlen)
{
	return convert_buf("UTF-8", src, slen, "UTF-16LE", (char*)dest, dlen);
}
