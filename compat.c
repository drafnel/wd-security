/*
 * compat.c
 *
 * Copyright (C) 2025  Brandon Casey
 */
#include "compat.h"

#include <stdlib.h>       /* arc4random_buf */
#include <fcntl.h>        /* open */
#include <unistd.h>       /* read, close */

#ifdef HAVE_BSD_STDLIB_H
#include <bsd/stdlib.h>   /* arc4random_buf */
#endif


#ifndef HAVE_GETRANDOM
ssize_t wds_getrandom (void *buf, size_t len, unsigned flags __attribute__((unused)))
{
#ifdef HAVE_ARC4RANDOM_BUF
	arc4random_buf(buf, len);
	return (ssize_t)len;
#else
	static const char* const rnd_devices[] = { "/dev/urandom", "/dev/random", NULL };
	static const char * const *rnd_device = rnd_devices;
	for ( ; *rnd_device; rnd_device++) {
		ssize_t rd;
		int fd = open(*rnd_device, O_RDONLY);
		if (fd == -1)
			continue;

		rd = read(fd, buf, len);

		close(fd);
		return rd;
	}
	return -1;
#endif
}
#endif /* HAVE_GETRANDOM */
