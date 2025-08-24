/*
 * compat.h
 *
 *   Compatibility functions.
 *
 * Copyright (C) 2025  Brandon Casey
 */
#ifndef COMPAT_H
#define COMPAT_H

#include "config.h"

#include <stddef.h>     /* size_t */
#include <sys/types.h>  /* ssize_t */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_GETRANDOM
ssize_t wds_getrandom (void *buf, size_t len, unsigned flags_unused);
#define getrandom wds_getrandom
#endif

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* COMPAT_H */
