/*
 * compat.c
 *
 * Copyright (C) 2025  Brandon Casey
 */
#include "compat.h"

#include <fcntl.h>        /* open */
#include <unistd.h>       /* read, close */



#ifndef HAVE_GETRANDOM
ssize_t wds_getrandom (void *buf, size_t len, unsigned flags __attribute__((unused)))
{
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
}
#endif /* HAVE_GETRANDOM */
