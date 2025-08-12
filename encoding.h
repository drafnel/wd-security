/*
 *
 * Copyright (C) 2025  Brandon Casey
 */
#ifndef WDS_ENCODING_H
#define WDS_ENCODING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern char* strdup_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
extern char* strtrim (char *s);
extern size_t delete_non_ucs2le (uint8_t *s, size_t len);

extern size_t utf8_to_utf16le_buf (const char *src, size_t slen, uint8_t *dest, size_t dlen);
extern uint8_t* utf8_to_utf16le (const char *src, size_t slen, size_t *dlen);
extern char* utf16le_to_utf8 (const uint8_t *src, size_t slen, size_t *dlen);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* WDS_ENCODING_H */
