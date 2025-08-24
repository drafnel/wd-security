/*
 * wd-security-cli.c
 *
 *   Manage the password protection of external drives supported by the
 *   proprietary WD Security software.
 *
 * Copyright (C) 2025  Brandon Casey
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include "config.h"
#include "compat.h"
#include "encoding.h"
#include "wd-security.h"

#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <inttypes.h>
#include <termios.h>

#ifdef HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif

#ifdef HAVE_DECL_BLKRRPART
#include <fcntl.h>
#include <sys/ioctl.h>
#ifdef HAVE_LINUX_FS_H
#include <linux/fs.h>
#endif
#endif

/*
 * Maximum number of characters in a password necessary to maintain
 * compatibility with proprietary WD Security software.
 */
#define PASSWORD_MAX_CHARS 25
#define PASSWORD_MAX_BYTES 50
#define HINT_MAX_CHARS 101
#define HINT_MAX_BYTES 202

#define DEFAULT_ITER_TIME 2000

/* Flags for use with prompt_user() */
#define NOECHO 1

#define NSEC_PER_SEC 1000000000
#define MSEC_PER_SEC 1000
#define NSEC_PER_MSEC 1000000

#define xstr(_x) # _x
#define str(_x) xstr(_x)

#define ARRAY_LEN(_a) (sizeof(_a)/sizeof(*(_a)))


/* wdpassport-utils.py hint string */
#define WDPASSPORT_UTILS_PY_HINT "wdpassport-utils                                                                                                                                                                                          "
#define AUTO_DETECT      0x00
#define NO_DETECT        0x01
#define FORCE_WDP_UTILS  0x02

static char *progname;
static int verbose;

static void* xmalloc (size_t sz) {
	void *ptr = malloc(sz);
	if (!ptr) {
		perror("memory allocation failed");
		abort();
	}
	return ptr;
}

static void* xrealloc (void *ptr, size_t sz) {
	ptr = realloc(ptr, sz);
	if (!ptr) {
		perror("memory allocation failed");
		abort();
	}
	return ptr;
}

static void* xmemdup (const void *src, size_t len) {
	void *buf = xmalloc(len);
	memcpy(buf, src, len);
	return buf;
}

static void hexdump (FILE *fp, const uint8_t *buf, size_t len) {
	size_t i;
	if (len)
		fprintf(fp, "0x%.2" PRIx8, buf[0]);
	for (i = 1; i < len; i++)
		fprintf(fp, " 0x%.2" PRIx8, buf[i]);
}

/*
 * Re-read partition table.
 */
static int reread_part (const char *device) {
	int err;
#ifdef HAVE_DECL_BLKRRPART
	int fd = open(device, O_RDONLY);
	if (fd == -1) {
		perror("reread-part failed opening device");
		return 1;
	}
	err = ioctl(fd, BLKRRPART, NULL);
	if (err)
		perror("reread-part failed issuing BLKRRPART ioctl");
	if (close(fd))
		perror("reread-part failed closing device");
#else
	fputs("Error: don't know how to re-read partition table\n", stderr);
	err = 1;
#endif
	return err;
}

static int is_wdpassport_utils (const uint8_t *hint) {
	return !memcmp(hint, WDPASSPORT_UTILS_PY_HINT,
			strlen(WDPASSPORT_UTILS_PY_HINT));
}

/*
 * Read a file into buffer, optionally allocating buffer.
 *
 * If *bufp is not NULL, then up to *maxlen bytes will be read into the
 * buffer specified by *bufp and *maxlen will be updated to reflect the
 * number of bytes read.
 *
 * If *bufp is NULL, then a buffer large enough to hold the entire file
 * will be allocated and the file will be read into the allocated
 * buffer.  The allocated buffer will be passed back via *bufp and
 * *maxlen will be updated to reflect the size.
 *
 * Returns non-zero on error.
 */
static int read_file (const char *filename, char **bufp, size_t *maxlen) {
	FILE *fp;
	char *buf = *bufp;
	struct stat st;
	size_t len;

	fp = fopen(filename, "r");
	if (!fp) {
		perror("failed opening file");
		return 1;
	}

	if (fstat(fileno(fp), &st)) {
		perror("failed to stat file");
		fclose(fp);
		return 1;
	}

	len = *maxlen;
	if (buf) {
		if (len > (size_t)st.st_size)
			len = st.st_size;
	} else {
		if (!len || len > (size_t)st.st_size)
			len = st.st_size;
		buf = xmalloc(len);
	}

	if (fread(buf, len, 1, fp) != 1) {
		if (ferror(fp))
			perror("failed reading from file");
		else
			fputs("short read from file\n", stderr);
		if (!*bufp)
			free(buf);
		fclose(fp);
		return 1;
	}

	if (fclose(fp))
		perror("failed closing file");

	*maxlen = len;
	if (!*bufp)
		*bufp = buf;

	return 0;
}

/*
 *  Read in entire file and return in allocated buffer.
 *  *len will be updated to reflect the size of the returned buffer.
 */
static char* slirp_file (const char *filename, size_t *len) {
	char *buf = NULL;
	size_t rd = 0;

	if (!read_file(filename, &buf, &rd))
		*len = rd;

	return buf;
}

static int disable_echo (int fd, struct termios *old) {
	struct termios tios;

	if (!isatty(fd))
		return 1;

	memset(&tios, 0, sizeof(tios));

	if (tcgetattr(fd, &tios)) {
		perror("failed getting terminal attributes");
		return 1;
	}

	if (old)
		*old = tios;

	tios.c_lflag &= ~ECHO;
	tios.c_lflag |= ECHONL;

	if (tcsetattr(fd, TCSANOW, &tios)) {
		perror("failed disabling terminal echo");
		return 1;
	}

	return 0;
}

static int restore_terminal (int fd, struct termios *tios) {
	if (tcsetattr(fd, TCSANOW, tios)) {
		perror("failed restoring terminal settings");
		return 1;
	}

	return 0;
}

typedef int (*check_func_t) (const char*, size_t);
typedef ssize_t (*filter_func_t) (char**, size_t, size_t*, void*);
typedef char* (*vprompt_func_t) (size_t*, unsigned, check_func_t,
		const char*, va_list);

/*
 * Prompt user for input, optionally apply filter.
 *
 * buf should either be NULL (and len == 0), or should be a malloc'ed
 * buffer with len describing the allocated size.
 *
 * Returns:
 *   -1   error, do not continue
 *   -2   filter func failure abort
 *    X   otherwise number of bytes read from stdin or, if filter_func
 *        specified, a filter-specific value.
 *
 * filter_func should return
 *   -1   to abort
 *   -2   retry
 *        any other value means success
 */
static __attribute__((format (printf, 6, 0)))
ssize_t vprompt_user_filter (char **buf, size_t *len, unsigned flags,
		filter_func_t filter_func, void *user_data,
		const char *fmt, va_list ap)
{
	int need_restore = (flags & NOECHO);
	ssize_t nread;
	struct termios old;

	do {
		va_list cp;

		va_copy(cp, ap);
		vfprintf(stderr, fmt, cp);
		va_end(cp);

		if (need_restore)
			need_restore = !disable_echo(STDIN_FILENO, &old);

		nread = getline(buf, len, stdin);

		if (need_restore)
			restore_terminal(STDIN_FILENO, &old);

		if (nread > 0 && (*buf)[nread - 1] == '\n') {
			(*buf)[nread - 1] = '\0';
			nread--;
		} else
			putc('\n', stderr);

		if (nread == -1) {
			if (ferror(stdin))
				perror("getline failed");
		} else if (filter_func)
			nread = filter_func(buf, (size_t)nread, len, user_data);
	} while (nread == -2);

	return nread;
}

static ssize_t yesno_filter (char **buf, size_t len, size_t *sz, void *user_data)
{
	char default_ans = (char)(intptr_t)user_data;

	assert(*buf != NULL);

	if (len == 0 && default_ans) {
		*buf = xrealloc(*buf, 2);
		(*buf)[0] = default_ans;
		(*buf)[1] = '\0';
		*sz = 2;
		return 1;
	}

	if (len == 2 &&
	    tolower((unsigned char)((*buf)[0])) == 'n' &&
	    tolower((unsigned char)((*buf)[1])) == 'o')
	{
		(*buf)[0] = 'n';
		(*buf)[1] = '\0';
		return 1;
	}

	if (len == 3 &&
	    tolower((unsigned char)((*buf)[0])) == 'y' &&
	    tolower((unsigned char)((*buf)[1])) == 'e' &&
	    tolower((unsigned char)((*buf)[2])) == 's')
	{
		(*buf)[0] = 'y';
		(*buf)[1] = '\0';
		return 1;
	}

	if (len != 1)
		return -2;

	if (!strchr("YyNn", **buf))
		return -2;

	return len;
}

static __attribute__((format (printf, 2, 3)))
int prompt_yesno (char default_ans, const char *fmt, ...) {
	char *ans = NULL;
	char *nfmt;
	size_t len = 0;
	va_list ap;
	char q[] = " [y/n]> ";
	ssize_t res;
	char c = 0;

	if (default_ans) {
		char *s = strchr(q, default_ans);
		assert(s != NULL);
		*s = toupper((unsigned char)default_ans);
	}

	/* append y/n prompt (which contains no conversion specifiers)
	 * to format string */
	nfmt = xmalloc(strlen(fmt) + strlen(q) + 1);
	memcpy(nfmt, fmt, strlen(fmt));
	memcpy(nfmt + strlen(fmt), q, strlen(q) + 1);

	va_start(ap, fmt);

	res = vprompt_user_filter(&ans, &len, 0, yesno_filter,
			(void*)(intptr_t)default_ans, nfmt, ap);

	va_end(ap);

	free(nfmt);

	if (ans) {
		c = *ans;
		free(ans);
	}

	return res == 1 && (c == 'Y' || c == 'y');
}

/*
 * "check" functions return boolean indicating whether the entered
 * text passes or fails the check.
 */

static int check_noempty (const char *pw __attribute__((unused)), size_t len) {
	return !!len;
}

#define PASSWD_TOO_LONG_MSG "Password exceeds proprietary WD Security maximum (" str(PASSWORD_MAX_CHARS) " chars, " str(PASSWORD_MAX_BYTES) " UTF-16 bytes).\nKeep password?"
static int check_password (const char *pw __attribute__((unused)), size_t len) {
	/* Disallow an empty password */
	if (!len)
		return 0;

	if (len > PASSWORD_MAX_BYTES)
		if (!prompt_yesno(0, PASSWD_TOO_LONG_MSG))
			return 0;

	return 1;
}

#define HINT_TOO_LONG_MSG "Error: hint too long (max " str(HINT_MAX_CHARS) " chars, " str(HINT_MAX_BYTES) " UTF-16 bytes).\n"
static int check_hint (const char *hint __attribute__((unused)), size_t len)
{
	if (len > HINT_MAX_BYTES) {
		fputs(HINT_TOO_LONG_MSG, stderr);
		return 0;
	}
	return 1;
}

static ssize_t utf16le_filter (char **buf, size_t len, size_t *sz,
		void *user_data)
{
	uint8_t *value;
	check_func_t check_func = (check_func_t)user_data;

	assert(*buf != NULL);

	value = utf8_to_utf16le(*buf, len, &len);
	if (!value) {
		fprintf(stderr, "Error: failed converting to UTF-16LE\n");
		return -2;
	}

	if (check_func && !check_func((char*)value, len)) {
		free(value);
		return -2;
	}

	*sz = len;
	free(*buf);
	*buf = (char*)value;

	return (ssize_t)len;
}

/*
 * Prompt the user for input, convert to UTF-16LE and return in
 * allocated buffer which must be freed.
 */
static __attribute__((format (printf, 4, 0)))
char* vprompt_utf16le (size_t *len, unsigned flags, check_func_t check_func,
		const char *fmt, va_list ap)
{
	uint8_t *value = NULL;
	size_t alloc = 0;
	ssize_t res;

	res = vprompt_user_filter((char**)&value, &alloc, flags, utf16le_filter,
			check_func, fmt, ap);

	if (res < 0) {
		free(value);
		value = NULL;
		*len = 0;
	} else
		*len = (size_t)res;

	return (char*)value;
}

/*
 * Prompt the user for input, prompt again for verification, convert to
 * UTF-16LE and return in allocated buffer which must be freed.
 */
static __attribute__((format (printf, 4, 0)))
char* vprompt_utf16le2 (size_t *len, unsigned flags, check_func_t check_func,
		const char *fmt, va_list ap)
{
	const char* again = "(again) ";
	char *nfmt;
	uint8_t *pw = NULL;
	uint8_t *pw2 = NULL;
	size_t pwlen;
	size_t pw2len;

	nfmt = xmalloc(strlen(again) + strlen(fmt) + 1);
	memcpy(nfmt, again, strlen(again));
	memcpy(nfmt + strlen(again), fmt, strlen(fmt) + 1);

	do {
		va_list cp;

		if (pw)
			fprintf(stderr, "Error: values didn't match\n");

		free(pw);
		free(pw2);

		va_copy(cp, ap);
		pw = (uint8_t*)vprompt_utf16le(&pwlen, flags, check_func, fmt,
				cp);
		va_end(cp);

		if (!pw) {
			pw2 = NULL;
			break;
		}

		va_copy(cp, ap);
		pw2 = (uint8_t*)vprompt_utf16le(&pw2len, flags, NULL, nfmt, cp);
		va_end(cp);

		if (!pw2) {
			free(pw);
			pw = NULL;
			pwlen = 0;
			break;
		}
	} while (pwlen != pw2len || memcmp(pw, pw2, pwlen));

	free(pw2);
	free(nfmt);

	if (len)
		*len = pwlen;

	return (char*)pw;
}

/*
 * Load value from file, argument, or prompt the user, all optionally.
 */
static __attribute__((format (printf, 7, 0)))
uint8_t* vload_or_prompt (size_t *len, const char *filename, const char *arg,
		check_func_t check_func, vprompt_func_t vprompt_func,
		unsigned flags, const char* fmt, va_list ap)
{
	uint8_t *val = NULL;

	if (filename) {
		val = (uint8_t*)slirp_file(filename, len);
		if (!val) {
			fprintf(stderr, "Error: failed reading from file "
					"\"%s\"\n", filename);
			return NULL;
		}
	} else if (arg) {
		if (check_func && !check_func(arg, strlen(arg)))
			return NULL;
		val = utf8_to_utf16le(arg, strlen(arg), len);
		if (!val) {
			fputs("Error: failed converting string to UTF-16LE\n",
					stderr);
			return NULL;
		}
	} else if (vprompt_func) {
		val = (uint8_t*)vprompt_func(len, flags, check_func, fmt, ap);
	}

	return val;
}

static __attribute__((format (printf, 7, 8)))
uint8_t* load_or_prompt (size_t *len, const char *filename, const char *str,
		check_func_t check_func, vprompt_func_t vprompt_func,
		unsigned flags, const char* fmt, ...)
{
	uint8_t *val = NULL;
	va_list ap;

	va_start(ap, fmt);

	val = vload_or_prompt(len, filename, str, check_func, vprompt_func,
			flags, fmt, ap);

	va_end(ap);

	return val;
}

/*
 * Get password from file, argument, or prompt the user.
 *
 * Returns allocated buffer which must be freed.
 */
static uint8_t* get_password (size_t *len, const char *filename,
		const char *str, const uint8_t *hint, size_t hlen, int verify,
		int do_checks, const char* prompt)
{
	char *new_p = NULL;
	uint8_t *pw;
	check_func_t check_func = do_checks ? check_password : check_noempty;

	if (hint) {
		char *h;
		if (!is_wdpassport_utils(hint)) {
			size_t sz;
			h = utf16le_to_utf8(hint, hlen, &sz);
		} else
			h = strndup((const char*)hint, hlen);
		if (h) {
			h = strtrim(h);
			if (*h)
				new_p = strdup_printf("%s (hint: %s)> ",
						prompt, h);
			free(h);
		}
	}

	if (!new_p)
		new_p = strdup_printf("%s> ", prompt);

	if (verify)
		pw = load_or_prompt(len, filename, str, check_func,
				vprompt_utf16le2, NOECHO, "%s", new_p);
	else
		pw = load_or_prompt(len, filename, str, check_func,
				vprompt_utf16le, NOECHO, "%s", new_p);

	free(new_p);

	return pw;
}

static uint8_t* get_salt (size_t *salt_bytes, const char *salt_file,
		const char *salt_arg)
{
	return load_or_prompt(salt_bytes, salt_file, salt_arg, NULL, NULL,
			0, NULL);
}

static uint8_t* get_hint (size_t *hint_bytes, const char* hint_arg,
		const char *prompt)
{
	return load_or_prompt(hint_bytes, NULL, hint_arg, check_hint,
			vprompt_utf16le, 0, "%s", prompt);
}

static int fill_random (uint8_t *buf, size_t count, int ucs2only) {
	size_t need = count;

	/* if ucs2only is set, then buffer should always have an
	 * even-numbered size */
	assert(!ucs2only || (count & 0x01) == 0);

	do {
		ssize_t got = getrandom(buf + count - need, need, 0);
		if (got < 0) {
			perror("getrandom() failed");
			return 1;
		}
		if (ucs2only) {
			/* make it an even-number */
			got &= ~1;
			/* remove bytes that are not legal UCS2 characters */
			got -= delete_non_ucs2le(buf + count - need, got);
		}

		assert(got >= 0);

		need -= (size_t)got;
	} while (need);

	return 0;
}

static int write_drive_label (wds_handle *wds, const char *label_arg) {
	struct wds_handy_store_user_block ub;
	size_t len;
	int err;

	len = utf8_to_utf16le_buf(label_arg, strlen(label_arg), ub.label,
			sizeof(ub.label));
	if (len == (size_t)-1) {
		fputs("Error: failed converting label to UTF-16\n", stderr);
		return 1;
	}

	memset(ub.label + len, 0, sizeof(ub.label) - len);

	if (!len) /* clear user block */
		err = wds_write_handy_store_user_block(wds, NULL);
	else
		err = wds_write_handy_store_user_block(wds, &ub);
	if (err) {
		fprintf(stderr, "Error: failed writing label: %s\n",
				wds_strerror(err));
		return 1;
	}

	return 0;
}

static int write_password_hint (wds_handle *wds, const char *hint_arg) {
	struct wds_handy_store_security_block sb;
	size_t len;
	int new_block = 0;
	int err;

	err = wds_read_handy_store_security_block(wds, &sb);
	if (err == WD_SECURITY_ESIG || err == WD_SECURITY_ECHKSUM) {
		/* failed to read hint, but ESIG/ECHKSUM just means
		 * the security block wasn't valid (i.e. missing),
		 * continue, using the default salt/iterations */
		memcpy(sb.salt, WD_SECURITY_DEFAULT_SALT, sizeof(sb.salt));
		sb.iterations = WD_SECURITY_DEFAULT_ITERATIONS;
		new_block = 1;
	} else if (err) {
		fprintf(stderr, "Error: failed reading security block: %s\n",
				wds_strerror(err));
		return 1;
	}

	len = utf8_to_utf16le_buf(hint_arg, strlen(hint_arg), sb.hint,
			sizeof(sb.hint));
	if (len == (size_t)-1) {
		fputs("Error: failed converting hint to UTF-16\n", stderr);
		return 1;
	}

	memset(sb.hint + len, 0, sizeof(sb.hint) - len);

	/* Avoid writing an empty hint if there is currently no security
	 * block */
	if (len || !new_block) {
		err = wds_write_handy_store_security_block(wds, &sb);
		if (err) {
			fprintf(stderr, "Error: failed writing hint: %s\n",
					wds_strerror(err));
			return 1;
		}
	}

	return 0;
}

/*
 * Generate a new Handy Store Security Block, allowing overrides for the
 * salt and iterations, but within the bounds to maintain compatibility
 * with proprietary WD Security software.
 *
 * That means that the salt must be 8-bytes and will be padded with nul
 * bytes or truncated if necessary, and iterations must be able to be
 * represented by an unsigned 32-bit integer.
 *
 * salt_file   if specified, then at-most 8-bytes will be read and used
 *             as the salt as-is without any conversion.  If fewer than
 *             8-bytes are available, then it will be padded to 8-bytes.
 * salt_arg    UTF-8 string, will be converted to UTF-16LE and truncated
 *             or padded to 8-bytes as necessary.
 *
 * iterations  if non-zero, then will be clamped to UINT32_MAX and used
 *             as the iterations field.
 *
 * hint_arg    UTF-8 string, will be converted to UTF-16LE and truncated
 *             if necessary.
 *
 * If neither salt_file or salt_arg is specified (i.e. both specified
 * as NULL), then a new random salt will be generated.
 *
 * If iterations is zero, then a value will be calculated so that the
 * generation of a KEK takes approximately iter_time milliseconds.
 *
 * If hint is NULL, then any hint existing in the security block will be
 * reused unless it matches the wdpassport-utils.py signature, in which
 * case it will be cleared.
 */
static int gen_security_block (struct wds_handy_store_security_block *sb,
		const char *salt_file, const char *salt_arg,
		unsigned long iterations, const char *hint_arg,
		unsigned iter_time)
{
	if (hint_arg) {
		size_t len = utf8_to_utf16le_buf(hint_arg, strlen(hint_arg),
			sb->hint, sizeof(sb->hint));
		if (len == (size_t)-1) {
			fputs("Error: failed converting hint to UTF-16\n",
					stderr);
			return 1;
		}

		memset(sb->hint + len, 0, sizeof(sb->hint) - len);
	} else if (is_wdpassport_utils(sb->hint)) {
		/* preserve hint unless it's the wdpassport-utils.py hint */
		memset(sb->hint, 0, sizeof(sb->hint));
	}

	if (salt_file) {
		size_t len = sizeof(sb->salt);
		if (read_file(salt_file, (char**)&sb->salt, &len)) {
			fprintf(stderr, "Error: failed reading salt from "
					"file \"%s\"\n", salt_file);
			return 1;
		}
		memset(sb->salt + len, 0, sizeof(sb->salt) - len);
	} else if (salt_arg) {
		size_t len = utf8_to_utf16le_buf(salt_arg, strlen(salt_arg),
			sb->salt, sizeof(sb->salt));
		if (len == (size_t)-1) {
			fputs("Error: failed converting salt to UTF-16\n",
					stderr);
			return 1;
		}

		if (len < sizeof(sb->salt)) {
			fputs("Warning: padding salt with zeroes\n", stderr);
			memset(sb->salt + len, 0, sizeof(sb->salt) - len);
		}
	} else {
		if (fill_random(sb->salt, sizeof(sb->salt), 1))
			return 1;
	}

	if (!iterations) {
		uint8_t kek[WD_SECURITY_KEK_MAX_BYTES];
#ifdef _POSIX_MONOTONIC_CLOCK
		clockid_t clockid = CLOCK_MONOTONIC;
#else
		clockid_t clockid = CLOCK_REALTIME;
#endif
		struct timespec ts_start;
		struct timespec ts_end;
		struct timespec elapsed;
		int err;

		iterations = 1000000;

		if (clock_gettime(clockid, &ts_start)) {
			perror("clock_gettime failed");
			return 1;
		}

		err = wds_generate_kek(sb->salt, sizeof(sb->salt), NULL, 0,
				iterations, kek);

		if (clock_gettime(clockid, &ts_end)) {
			perror("clock_gettime failed");
			return 1;
		}

		if (err) {
			fprintf(stderr, "Error: failed timing KEK generation: "
					"%s\n", wds_strerror(err));
			return 1;
		}

		elapsed.tv_sec = ts_end.tv_sec - ts_start.tv_sec;
		if (ts_end.tv_nsec < ts_start.tv_nsec) {
			elapsed.tv_sec--;
			elapsed.tv_nsec = ts_end.tv_nsec +
				(NSEC_PER_SEC - ts_start.tv_nsec);
		} else {
			/* add 1 nanosecond just to ensure it's never zero */
			elapsed.tv_nsec = ts_end.tv_nsec - ts_start.tv_nsec + 1;
		}

		while (elapsed.tv_nsec >= NSEC_PER_SEC) {
			elapsed.tv_sec++;
			elapsed.tv_nsec -= NSEC_PER_SEC;
		}

		if (verbose)
			fprintf(stderr, "Performed %lu hash iterations in %"
					PRIdMAX ".%09" PRIdMAX " secs.\n",
					iterations,
					(intmax_t)elapsed.tv_sec,
					(intmax_t)elapsed.tv_nsec);

		iterations = iter_time /
			(elapsed.tv_sec * MSEC_PER_SEC +
			 (double)elapsed.tv_nsec / NSEC_PER_MSEC) *
			iterations + 1.;

		if (verbose)
			fprintf(stderr, "Calculated iterations: %ld\n",
					iterations);

		if (iterations < WD_SECURITY_DEFAULT_ITERATIONS)
			iterations = WD_SECURITY_DEFAULT_ITERATIONS;
	}

	if (iterations > UINT32_MAX) {
		fprintf(stderr, "Warning: clamping iterations "
				"(%lu -> %" PRIu32 ")\n",
				iterations, UINT32_MAX);
		iterations = UINT32_MAX;
	}

	sb->iterations = iterations;

	return 0;
}

/*
 * Load Handy Store Security Block
 *
 * If device does not support Handy Store, or if the Security Block is
 * missing, then populate the returned wds_handy_store_security_block
 * with the default WD Security parameters.
 *
 * If detect_wdputils is non-zero, then detect whether the Security
 * Block was written by wdpassport-utils.py and munge the salt as
 * necessary.
 */
static void read_security_block_nofail (wds_handle *wds,
		struct wds_handy_store_security_block *sb,
		int detect_wdputils)
{
	if (wds_read_handy_store_security_block(wds, sb)) {
		memcpy(sb->salt, WD_SECURITY_DEFAULT_SALT, sizeof(sb->salt));
		sb->iterations = WD_SECURITY_DEFAULT_ITERATIONS;
		memset(sb->hint, 0, sizeof(sb->hint));
	} else if (detect_wdputils == FORCE_WDP_UTILS ||
		   (detect_wdputils == AUTO_DETECT &&
		    is_wdpassport_utils(sb->hint))) {
		/*
		 * The wdpassport-utils.py script stores the salt in the
		 * Handy Store Security Block as an ASCII string, but
		 * then when preparing the KEK, it drops the odd-indexed
		 * characters and converts the remaining characters to
		 * UTF-16 to generate the final salt.  Since the
		 * even-indexed bytes are ASCII, we can convert this to
		 * UTF-16LE as simply as...
		 */
		sb->salt[1] = sb->salt[3] = sb->salt[5] = sb->salt[7] = 0;
	}
}

/*
 * Get iterations and salt from the Handy Store Security Block,
 * allowing overrides for the salt and iterations with no restrictions.
 *
 * salt_file   if specified, then the entire file will be read and used
 *             as the salt as-is without any conversion.
 * salt_arg    UTF-8 string, will be converted to UTF-16LE.
 *
 * iterations  if non-zero, then it will be used as the iterations
 *             field.
 *
 * If neither salt_file or salt_arg is specified (i.e. both specified
 * as NULL), then the salt value stored in the Handy Store Security
 * Block will be used.
 *
 * If iterations is zero, then the iterations value stored in the Handy
 * Store Security Block will be used.
 */
static int get_iterations_salt (
		const struct wds_handy_store_security_block *sb,
		const char *salt_file, const char *salt_arg, uint8_t **salt,
		size_t *salt_bytes, unsigned long *iterations)
{
	if (salt_file || salt_arg) {
		*salt = get_salt(salt_bytes, salt_file, salt_arg);
		if (!*salt)
			return 1;
	}

	if (!(salt_file || salt_arg) || !*iterations) {
		if (!(salt_file || salt_arg)) {
			*salt = xmemdup(sb->salt, sizeof(sb->salt));
			*salt_bytes = sizeof(sb->salt);
		}

		if (!*iterations)
			*iterations = sb->iterations;
	}

	return 0;
}

static void status_cmd_usage (FILE *fp, const char *name) {
	fprintf(fp, "usage: %s %s [--help] [OPTIONS] <device>\n",
			progname, name);
}

static void status_cmd_help (const char *name) {
	status_cmd_usage(stdout, name);
	printf("\n"
	       "Show encryption status of <device>\n"
	       "\n"
	       "OPTIONS\n"
	       "--is-locked  suppress normal output and exit with zero status\n"
	       "             if locked, non-zero otherwise.\n"
	       "--verbose    increase verbosity\n"
	       "--help       this text\n"
	       "\n");
}

static int status_cmd (int argc, char * const argv[]) {
	const char *devpath;
	wds_handle *wds;
	struct wds_encryption_status *es;
	int is_locked = 0;
	int opt;
	int err;
	const struct option long_options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "is-locked", no_argument, NULL, 'l' },
		{ NULL, 0, 0, 0 }
	};

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hvl", long_options, NULL)) != -1)
	{
		switch (opt) {
		case 'h':
			status_cmd_help(argv[0]);
			return 0;
		case 'v':
			verbose++;
			break;
		case 'l':
			is_locked = 1;
			break;
		case '?':
			status_cmd_usage(stderr, argv[0]);
			return 1;
		}
	}

	if (argc - optind != 1) {
		status_cmd_usage(stderr, argv[0]);
		return 1;
	}

	devpath = argv[optind++];

	wds = wds_open(devpath, NULL, &err);
	if (!wds) {
		fprintf(stderr, "Error: failed opening device: %s\n",
				wds_strerror(err));
		return 1;
	}

	es = wds_get_status(wds, &err);

	wds_close(wds);

	if (!es) {
		fprintf(stderr, "Error: failed getting device status: %s\n",
				wds_strerror(err));
		return 1;
	}

	if (is_locked) {
		if (es->status == WD_SECURITY_STATUS_LOCKED)
			return 0;
		return 1;
	}

	printf("   Status: (0x%.2" PRIx8 ") %s\n"
	       "   Cipher: (0x%.2" PRIx8 ") %s\n",
	       es->status, wds_status_to_string(es->status),
	       es->cipher, wds_cipher_to_string(es->cipher));

	if (verbose) {
		int i;
		printf(" KEK Size: %" PRIu16 " Bytes\n"
		       "Erase SYN: 0x%.2" PRIx8 "%.2" PRIx8 "%.2" PRIx8 "%.2" PRIx8 "\n"
		       "  Ciphers: %" PRIu8 "\n",
		       es->kek_size,
		       es->reset_syn[0],
		       es->reset_syn[1],
		       es->reset_syn[2],
		       es->reset_syn[3],
		       es->num_ciphers);
		for (i = 0; i < es->num_ciphers; i++)
			printf("Cipher[%d]: (0x%.2" PRIx8 ") %s\n",
					i, es->ciphers[i],
					wds_cipher_to_string(es->ciphers[i]));
	}

	free(es);

	return 0;
}

static int show_handy_capacity (FILE *fp, struct wds_handle *wds) {
	struct wds_handy_capacity hc;
	int err;

	err = wds_read_handy_capacity(wds, &hc);
	if (err) {
		fprintf(stderr, "Error: failed getting Handy Capacity: %s\n",
				wds_strerror(err));
		return 1;
	}

	fprintf(fp, "Last Block: %" PRIu32 "\n"
		    "Block Size: %" PRIu32 "\n"
	            "  Xfer Max: %" PRIu16 "\n",
		    hc.last_block,
		    hc.length,
		    hc.max_xfer_len);

	return 0;
}

static int show_handy_store_security_block (FILE *fp, struct wds_handle *wds,
		int detect_wdputils)
{
	struct wds_handy_store_security_block sb;
	int err;

	err = wds_read_handy_store_security_block(wds, &sb);

	if (err == WD_SECURITY_ESIG || err == WD_SECURITY_ECHKSUM) {
		fprintf(fp, "No Handy Store Security Block\n");
	} else if (err) {
		fprintf(stderr, "Error: failed getting Handy Store Security "
				"Block: %s\n", wds_strerror(err));
		return 1;
	} else if (detect_wdputils == FORCE_WDP_UTILS ||
		   (detect_wdputils == AUTO_DETECT &&
		    is_wdpassport_utils(sb.hint)))
	{
		size_t salt_len = sizeof(sb.salt);
		char *salt;

		fprintf(stderr, "Warning: Security Block created by "
				"wdpassport-utils.py, enabling quirks.\n");

		sb.salt[1] = sb.salt[3] = sb.salt[5] = sb.salt[7] = 0;
		salt = utf16le_to_utf8(sb.salt, salt_len, &salt_len);
		fprintf(fp, " Password Salt: ");
		if (salt)
			fprintf(fp, "\"%s\" ", salt);
		hexdump(fp, sb.salt, sizeof(sb.salt));
		fprintf(fp, "\n"
			    " Password Hint: \"%.*s\"\n"
		            "Iteration Rnds: %" PRIu32 "\n",
			    (int)sizeof(sb.hint), (char*)sb.hint,
			    sb.iterations);
		free(salt);
	} else {
		size_t salt_len = sizeof(sb.salt);
		size_t hint_len = sizeof(sb.hint);
		char *salt = utf16le_to_utf8(sb.salt, salt_len, &salt_len);
		char *hint = utf16le_to_utf8(sb.hint, hint_len, &hint_len);
		fprintf(fp, " Password Salt: ");
		if (salt)
			fprintf(fp, "\"%s\" ", salt);
		hexdump(fp, sb.salt, sizeof(sb.salt));
		fprintf(fp, "\n Password Hint: \"%s\"\n", hint ? hint : "");
		fprintf(fp, "Iteration Rnds: %" PRIu32 "\n", sb.iterations);
		free(hint);
		free(salt);
	}

	return 0;
}

static int show_handy_store_user_block (FILE *fp, struct wds_handle *wds) {
	struct wds_handy_store_user_block ub;
	int err;

	err = wds_read_handy_store_user_block(wds, &ub);

	if (err == WD_SECURITY_ESIG || err == WD_SECURITY_ECHKSUM) {
		fprintf(fp, "No Handy Store User Block\n");
	} else if (err) {
		fprintf(stderr, "Error: failed getting Handy Store User "
				"Block: %s\n", wds_strerror(err));
		return 1;
	} else {
		size_t label_len = sizeof(ub.label);
		char *label = utf16le_to_utf8(ub.label, label_len, &label_len);
		fprintf(fp, "   Drive Label: \"%s\"\n", label ? label : "");
		free(label);
	}

	return 0;
}

static void handy_store_cmd_usage (FILE *fp, const char *name) {
	fprintf(fp, "usage: %s %s [--help] [OPTIONS] <device>\n",
			progname, name);
}

static void handy_store_cmd_help (const char *name) {
	handy_store_cmd_usage(stdout, name);
	printf("\n"
	       "Show or manipulate the Handy Store of <device>\n"
	       "\n"
	       "The proprietary WD Security software stores encryption parameters\n"
	       "in special sectors on the drive called the Handy Store.  The\n"
	       "first two blocks are named the Security Block and the User Block.\n"
	       "\n"
	       "Security Block\n"
	       "--------------\n"
	       "Stores the password hint, as well as the salt and number of\n"
	       "iteration rounds used to generate the Key Encryption Key (KEK).\n"
	       "\n"
	       "User Block\n"
	       "----------\n"
	       "Stores a drive label.\n"
	       "\n"
	       "OPTIONS\n"
	       "--capacity         show capacity\n"
	       "--set-label        set the drive label\n"
	       "--set-hint         set the password hint\n"
	       "--no-wdp-utils     don't detect wdpassport-utils.py\n"
	       "--wdp-utils        force wdpassport-utils.py quirks\n"
	       "--verbose          increase verbosity\n"
	       "--help             this text\n"
	       "\n");
}

static int handy_store_cmd (int argc, char * const argv[]) {
	const char *devpath;
	wds_handle *wds;
	int err;
	int opt;
	int detect_wdputils = AUTO_DETECT;
	int show_capacity = 0;
	const struct option long_options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "capacity", no_argument, NULL, 'C' },
		{ "set-label", required_argument, NULL, 'L' },
		{ "set-hint", required_argument, NULL, 'H' },
		{ "no-wdp-utils", no_argument, NULL, 'N' },
		{ "wdp-utils", no_argument, NULL, 'W' },
		{ NULL, 0, 0, 0 }
	};
	const char *label_arg = NULL;
	const char *hint_arg = NULL;

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hvCNWL:H:", long_options, NULL)) != -1)
	{
		switch (opt) {
		case 'h':
			handy_store_cmd_help(argv[0]);
			return 0;
		case 'v':
			verbose++;
			break;
		case 'C':
			show_capacity = 1;
			break;
		case 'L':
			label_arg = optarg;
			break;
		case 'H':
			hint_arg = optarg;
			break;
		case 'N':
			detect_wdputils = NO_DETECT;
			break;
		case 'W':
			detect_wdputils = FORCE_WDP_UTILS;
			break;
		case '?':
			handy_store_cmd_usage(stderr, argv[0]);
			return 1;
		}
	}

	if (argc - optind != 1) {
		handy_store_cmd_usage(stderr, argv[0]);
		return 1;
	}

	devpath = argv[optind++];

	wds = wds_open(devpath, NULL, &err);
	if (!wds) {
		fprintf(stderr, "Error: failed opening device: %s\n",
				wds_strerror(err));
		return 1;
	}

	if (show_capacity) {
		err = show_handy_capacity(stdout, wds);
	} else if (hint_arg || label_arg) {
		if (hint_arg) {
			printf("Writing password hint to Handy Store Security "
			       "Block...");
			fflush(stdout);
			if (write_password_hint(wds, hint_arg)) {
				fprintf(stderr, "FAILED\n");
				err = 1;
			} else
				printf("done.\n");
		}

		if (label_arg) {
			printf("Writing drive label to Handy Store User "
			       "Block...");
			fflush(stdout);
			if (write_drive_label(wds, label_arg)) {
				fprintf(stderr, "FAILED\n");
				err = 1;
			} else
				printf("done.\n");
		}
	} else {
		err = show_handy_store_security_block(stdout, wds,
				detect_wdputils);
		if (!err)
			err = show_handy_store_user_block(stdout, wds);
	}

	wds_close(wds);

	return err;
}

static int unlock (wds_handle *wds, const uint8_t *salt, size_t salt_bytes,
		const uint8_t* pw, size_t pw_bytes, unsigned long iterations)
{
	struct wds_encryption_status* es;
	uint8_t kek[WD_SECURITY_KEK_MAX_BYTES];
	uint16_t kek_bytes;
	int err;

	err = wds_generate_kek(salt, salt_bytes, pw, pw_bytes, iterations, kek);
	if (err) {
		fprintf(stderr, "failed generating KEK: %s\n",
				wds_strerror(err));
		return 1;
	}

	es = wds_get_status(wds, &err);
	if (!es) {
		fprintf(stderr, "failed getting status: %s\n", wds_strerror(err));
		return 1;
	}

	if (es->kek_size > WD_SECURITY_KEK_MAX_BYTES) {
		fprintf(stderr, "KEK size (%" PRIu16 ") is unsupported (max %u)",
				es->kek_size, WD_SECURITY_KEK_MAX_BYTES);
		free(es);
		return 1;
	}

	kek_bytes = es->kek_size;

	free(es);

	err = wds_unlock_kek(wds, kek, kek_bytes);
	if (err) {
		fprintf(stderr, "Error: failed unlocking drive: %s\n",
				wds_strerror(err));
		return 1;
	}

	return 0;
}

static void unlock_cmd_usage (FILE *fp, const char *name) {
	fprintf(fp, "usage: %s %s [--help] [OPTIONS] <device>\n",
			progname, name);
}

static void unlock_cmd_help (const char *name) {
	unlock_cmd_usage(stdout, name);
	printf("\n"
	       "Prompt for password and unlock <device>.  The password will be\n"
	       "converted to UTF-16LE encoding to be compatible with the\n"
	       "proprietary WD Security software.\n"
	       "\n"
	       "OPTIONS\n"
	       "--password <pw>      unlock password.  Will be converted to\n"
	       "                     UTF-16LE.\n"
	       "--key-file <file>    use contents of file as password.  The\n"
	       "                     entire file will be read and used as-is\n"
	       "                     for the password.\n"
	       "--salt <salt>        password salt.  Will be converted to\n"
	       "                     UTF-16LE.  Overrides Handy Store.\n"
	       "--salt-file <file>   use contents of file as password salt.\n"
	       "                     The entire file will be read and used\n"
	       "                     as-is for the password salt.  Overrides\n"
	       "                     Handy Store.\n"
	       "--iterations <num>   number of hash iterations to perform.\n"
	       "                     Overrides Handy Store.\n"
	       "--write-handy-store  write salt/iterations to Handy Store\n"
	       "--rescan             reread partition table after unlock\n"
	       "--no-wdp-utils       don't detect wdpassport-utils.py\n"
	       "--wdp-utils          force wdpassport-utils.py quirks\n"
	       "--verbose            increase verbosity\n"
	       "--help               this text\n"
	       "\n");
}

static int unlock_cmd (int argc, char * const argv[]) {
	struct wds_handy_store_security_block sb;
	const char *devpath;
	wds_handle *wds;
	const char *key_file = NULL;
	const char *pw_arg = NULL;
	const char *salt_file = NULL;
	const char *salt_arg = NULL;
	unsigned long iterations = 0;
	uint8_t *pw = NULL;
	size_t pw_bytes = 0;
	uint8_t *salt;
	size_t salt_bytes = 0;
	int do_checks = 1;
	int do_rescan = 0;
	int write_handy_store = 0;
	int err;
	int opt;
	int detect_wdputils = AUTO_DETECT;
	const struct option long_options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "password", required_argument, NULL, 'p' },
		{ "key-file", required_argument, NULL, 'd' },
		{ "salt", required_argument, NULL, 's' },
		{ "salt-file", required_argument, NULL, 'S' },
		{ "iterations", required_argument, NULL, 'i' },
		{ "write-handy-store", no_argument, NULL, 'w' },
		{ "no-wdp-utils", no_argument, NULL, 'N' },
		{ "wdp-utils", no_argument, NULL, 'W' },
		{ "rescan", no_argument, NULL, 'R' },
		{ NULL, 0, 0, 0 }
	};

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hvp:Rd:s:S:i:wNW", long_options,
					NULL)) != -1)
	{
		switch (opt) {
		case 'h':
			unlock_cmd_help(argv[0]);
			return 0;
		case 'v':
			verbose++;
			break;
		case 'd':
			key_file = optarg;
			break;
		case 'p':
			pw_arg = optarg;
			break;
		case 'R':
			do_rescan = 1;
			break;
		case 's':
			salt_arg = optarg;
			break;
		case 'S':
			salt_file = optarg;
			break;
		case 'i':
			iterations = strtoul(optarg, NULL, 0);
			break;
		case 'w':
			write_handy_store = 1;
			break;
		case 'N':
			detect_wdputils = NO_DETECT;
			break;
		case 'W':
			detect_wdputils = FORCE_WDP_UTILS;
			break;
		case '?':
			unlock_cmd_usage(stderr, argv[0]);
			return 1;
		}
	}

	if (argc - optind != 1) {
		unlock_cmd_usage(stderr, argv[0]);
		return 1;
	}

	devpath = argv[optind++];

	wds = wds_open(devpath, NULL, &err);
	if (!wds) {
		fprintf(stderr, "Error: failed opening device: %s\n",
				wds_strerror(err));
		return 1;
	}

	read_security_block_nofail(wds, &sb, detect_wdputils);

	pw = get_password(&pw_bytes, key_file, pw_arg,
			sb.hint, sizeof(sb.hint), 0, do_checks,
			"Enter password");
	if (!pw) {
		wds_close(wds);
		return 1;
	}

	if (get_iterations_salt(&sb, salt_file, salt_arg, &salt, &salt_bytes,
		&iterations))
	{
		free(pw);
		return 1;
	}

	err = unlock(wds, salt, salt_bytes, pw, pw_bytes, iterations);
	if (!err && write_handy_store) {
		if (salt_bytes != sizeof(sb.salt)) {
			fprintf(stderr, "Error: salt is not 8-bytes, cannot"
					"write to Handy Store\n");
			err = 1;
		} else if (iterations > UINT32_MAX) {
			fprintf(stderr, "Error: iterations is too large "
					"to write to Handy Store\n");
			err = 1;
		} else {
			memcpy(sb.salt, salt, salt_bytes);

			sb.iterations = iterations;

			if (is_wdpassport_utils(sb.hint))
				memset(sb.hint, 0, sizeof(sb.hint));

			err = wds_write_handy_store_security_block(wds, &sb);
			if (err) {
				fprintf(stderr, "Error: failed writing new "
						"Security Block: %s\n",
						wds_strerror(err));
			}
		}
	}

	free(salt);

	wds_close(wds);

	if (!err) {
		printf("Successfully unlocked drive\n");
		if (do_rescan)
			err = reread_part(devpath);
	}

	return !!err;
}

static int changepw (wds_handle *wds, const uint8_t *salt, size_t salt_bytes,
		unsigned long iterations, uint8_t *opw, size_t opw_bytes,
		uint8_t *npw, size_t npw_bytes, uint16_t kek_size)
{
	uint8_t okekbuf[WD_SECURITY_KEK_MAX_BYTES];
	uint8_t nkekbuf[WD_SECURITY_KEK_MAX_BYTES];
	uint8_t *okek = okekbuf;
	uint8_t *nkek = nkekbuf;
	int err;

	if (kek_size > WD_SECURITY_KEK_MAX_BYTES) {
		fprintf(stderr, "KEK size (%" PRIu16 ") is unsupported "
				"(max %u)\n",
				kek_size, WD_SECURITY_KEK_MAX_BYTES);
		return 1;
	}

	if (opw) {
		err = wds_generate_kek(salt, salt_bytes, opw, opw_bytes,
				iterations, okek);
		if (err) {
			fprintf(stderr, "failed generating old KEK: %s\n",
					wds_strerror(err));
			return 1;
		}
	} else
		okek = NULL;

	if (npw) {
		err = wds_generate_kek(salt, salt_bytes, npw, npw_bytes,
				iterations, nkek);
		if (err) {
			fprintf(stderr, "failed generating new KEK: %s\n",
					wds_strerror(err));
			return 1;
		}
	} else
		nkek = NULL;

	err = wds_changepw_kek(wds, okek, nkek, kek_size);
	if (err) {
		fprintf(stderr, "failed changing password: %s\n",
				wds_strerror(err));
		return 1;
	}

	return 0;
}

static void changepw_cmd_usage (FILE *fp, const char *name) {
	fprintf(fp, "usage: %s %s [--help] [OPTIONS] <devpath>\n",
			progname, name);
}

static void changepw_cmd_help (const char *name) {
	changepw_cmd_usage(stdout, name);
	printf("\n"
	       "Prompt for password(s) and enable/disable/change encryption\n"
	       "status of <device>.  The password(s) will be converted to\n"
	       "UTF16-LE to be compatible with the proprietary WD Security\n"
	       "software.\n"
	       "\n"
	       "OPTIONS\n"
	       "--disable-protection   disable password protection\n"
	       "--no-clear             don't clear Handy Store Security Block\n"
	       "                       when disabling password protection.\n"
	       "--password <pw>        current password.  Will be converted to\n"
	       "                       UTF-16LE.\n"
	       "--key-file <file>      use contents of file as password.  The\n"
	       "                       entire file will be read and used as-is\n"
	       "                       for the password.\n"
	       "--new-password <pw>    new password.  Will be converted to\n"
	       "                       UTF-16LE.\n"
	       "--new-key-file <file>  use contents of file as new password.\n"
	       "                       The entire file will be read and used\n"
	       "                       as-is for the password.\n"
	       "--hint <hint>          set new password hint\n"
	       "--salt <salt>          password salt.  Will be converted to\n"
	       "                       UTF-16LE.  If enabling password protection\n"
	       "                       then will be truncated or zero-padded\n"
	       "                       to 8-bytes after converting to UTF-16LE\n"
	       "                       if necessary.  Otherwise full value\n"
	       "                       overrides Handy Store.\n"
	       "--salt-file <file>     use contents of file as password salt.\n"
	       "                       If enabling password protection, then\n"
	       "                       8-bytes will be read, zero-padding if\n"
	       "                       necessary.  Otherwise the entire file\n"
	       "                       will be read and used as-is for the\n"
	       "                       password salt.  Overrides Handy Store.\n"
	       "--iterations <num>     number of hash iterations to perform.\n"
	       "                       Clamped to 32-bits if enabling password\n"
	       "                       protection.  Overrides Handy Store.\n"
	       "--iter-time <ms>       milliseconds for hash iteration rounds\n"
	       "                       (default: " str(DEFAULT_ITER_TIME) ")\n"
	       "--no-wdp-utils         don't detect wdpassport-utils.py\n"
	       "--wdp-utils            force wdpassport-utils.py quirks\n"
	       "--verbose              increase verbosity\n"
	       "--help                 this text\n"
	       "\n");
}

static int changepw_cmd (int argc, char * const argv[]) {
	const char *devpath;
	wds_handle *wds;
	struct wds_encryption_status *es;
	struct wds_handy_store_security_block sb;
	const char *hint_arg = NULL;
	const char *key_file = NULL;
	const char *pw_arg = NULL;
	const char *nkey_file = NULL;
	const char *npw_arg = NULL;
	const char *salt_file = NULL;
	const char *salt_arg = NULL;
	uint8_t *opw = NULL;
	uint8_t *npw = NULL;
	size_t opw_len = 0;
	size_t npw_len = 0;
	uint8_t *salt = NULL;
	size_t salt_bytes = 0;
	unsigned long iterations = 0;
	int disable_protection = 0;
	int clear_sec_block = 1;
	int do_checks = 1;
	unsigned iter_time = DEFAULT_ITER_TIME;
	uint16_t key_size;
	int detect_wdputils = AUTO_DETECT;
	int hint_dirty = 0;
	int err;
	int opt;
	const struct option long_options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "disable-protection", no_argument, NULL, 'X' },
		{ "no-clear", no_argument, NULL, 'C' },
		{ "password", required_argument, NULL, 'p' },
		{ "new-password", required_argument, NULL, 'P' },
		{ "key-file", required_argument, NULL, 'd' },
		{ "new-key-file", required_argument, NULL, 'D' },
		{ "hint", required_argument, NULL, 'H' },
		{ "salt", required_argument, NULL, 's' },
		{ "salt-file", required_argument, NULL, 'S' },
		{ "iterations", required_argument, NULL, 'i' },
		{ "iter-time", required_argument, NULL, 'I'},
		{ "no-wdp-utils", no_argument, NULL, 'N' },
		{ "wdp-utils", no_argument, NULL, 'W' },
		{ NULL, 0, 0, 0 }
	};

	optind = 1;
	while ((opt = getopt_long(argc, argv, "hH:i:I:d:D:p:P:s:S:vCXNW",
					long_options, NULL)) != -1)
	{
		switch (opt) {
		case 'h':
			changepw_cmd_help(argv[0]);
			return 0;
		case 'v':
			verbose++;
			break;
		case 'X':
			disable_protection = 1;
			break;
		case 'C':
			clear_sec_block = 0;
			break;
		case 'H':
			hint_arg = optarg;
			break;
		case 'd':
			key_file = optarg;
			break;
		case 'D':
			nkey_file = optarg;
			break;
		case 'p':
			pw_arg = optarg;
			break;
		case 'P':
			npw_arg = optarg;
			break;
		case 's':
			salt_arg = optarg;
			break;
		case 'S':
			salt_file = optarg;
			break;
		case 'i':
			iterations = strtoul(optarg, NULL, 0);
			break;
		case 'I':
			iter_time = strtoul(optarg, NULL, 0);
			break;
		case 'N':
			detect_wdputils = NO_DETECT;
			break;
		case 'W':
			detect_wdputils = FORCE_WDP_UTILS;
			break;
		case '?':
			changepw_cmd_usage(stderr, argv[0]);
			return 1;
		}
	}

	if (argc - optind != 1) {
		changepw_cmd_usage(stderr, argv[0]);
		return 1;
	}

	devpath = argv[optind++];

	wds = wds_open(devpath, NULL, &err);
	if (!wds) {
		fprintf(stderr, "Error: failed opening device %s: %s\n",
				devpath, wds_strerror(err));
		return 1;
	}

	es = wds_get_status(wds, &err);
	if (!es) {
		fprintf(stderr, "Error: failed getting encryption status of "
				"device %s: %s\n", devpath,
				wds_strerror(err));
		wds_close(wds);
		return 1;
	}

	read_security_block_nofail(wds, &sb, detect_wdputils);

	if (es->status == WD_SECURITY_STATUS_UNLOCKED) {
		opw = get_password(&opw_len, key_file, pw_arg,
				sb.hint, sizeof(sb.hint), 0, do_checks,
				"Enter current password");
		if (!opw) {
			free(es);
			wds_close(wds);
			return 1;
		}
	}

	if (!disable_protection) {
		size_t len = 0;
		uint8_t *h;

		npw = get_password(&npw_len, nkey_file, npw_arg,
				NULL, 0, 1, do_checks, "Enter new password");
		if (!npw) {
			free(opw);
			free(es);
			wds_close(wds);
			return 1;
		}

		h = get_hint(&len, hint_arg, "Enter password hint> ");
		if (h) {
			assert(len <= sizeof(sb.hint));

			h = xrealloc(h, sizeof(sb.hint));
			memset(h + len, 0, sizeof(sb.hint) - len);

			if (memcmp(sb.hint, h, sizeof(sb.hint))) {
				memcpy(sb.hint, h, sizeof(sb.hint));
				hint_dirty = 1;
			}

			free(h);
		}
		hint_arg = NULL;
	}

	/*
	 * Not Protected -> Protected (set password)
	 * 1. Write Security Block
	 *    - Use salt if supplied, otherwise generate one.
	 *    - Use iterations if supplied, otherwise calculate one.
	 *    - Use hint if supplied, otherwise retain existing hint.
	 *    - Impose restrictions on salt/iterations
	 *      - salt is 8 bytes
	 *      - iterations is <= UINT32_MAX
	 * 2. Set password
	 *
	 * Protected -> Not Protected (clear password)
	 * 1. Disable password (this validates current password)
	 *    - Read Security Block, display hint
	 *    - Allow salt/iterations to override security block.
	 * 2. Clear Security Block
	 *    - Ignore hint if supplied.
	 *
	 * Protected -> Protected (change password)
	 * 1. Change password (validates current/new password)
	 *    - Read Security Block, display hint
	 *    - Reuse existing Security Block (if present)
	 *    - Allow salt/iterations to override security block.
	 * 2. If hint is supplied, update security block with new hint,
	 *    retaining existing salt and iterations values.  If
	 *    security block is missing, write one with the default
	 *    parameters.
	 */

	if (es->status == WD_SECURITY_STATUS_NOPASSWD && npw) {
		/*
		 * Not Protected -> Protected
		 *
		 *   Generate new security block.
		 */
		if (gen_security_block(&sb, salt_file, salt_arg, iterations,
				hint_arg, iter_time))
		{
			fprintf(stderr, "Error: failed generating Handy Store "
					"Security Block\n");
			assert(opw == NULL);
			free(npw);
			free(es);
			wds_close(wds);
			return 1;
		}

		err = wds_write_handy_store_security_block(wds, &sb);
		if (err) {
			fprintf(stderr, "Error: failed writing Handy Store "
					"Security Block: %s\n",
					wds_strerror(err));
			assert(opw == NULL);
			free(npw);
			free(es);
			wds_close(wds);
			return 1;
		}

		/* clear salt_XXX/iterations so that they won't be used
		 * again below when we call get_iterations_salt(). */
		salt_file = NULL;
		salt_arg = NULL;
		iterations = 0;
		hint_dirty = 0;
	}

	key_size = es->kek_size;

	free(es);

	if (get_iterations_salt(&sb, salt_file, salt_arg, &salt, &salt_bytes,
				&iterations))
	{
		free(npw);
		free(opw);
		wds_close(wds);
		return 1;
	}

	err = changepw(wds, salt, salt_bytes, iterations, opw, opw_len, npw,
			npw_len, key_size);
	if (err) {
		free(npw);
		free(opw);
		wds_close(wds);
		return 1;
	} else if (disable_protection) {
		/*
		 * Protected -> Not Protected
		 *
		 *   Clear Security Block
		 */
		if (clear_sec_block) {
			err = wds_write_handy_store_security_block(wds, NULL);
			if (err)
				fprintf(stderr, "Error: failed clearing Handy "
						"Store Security Block: %s\n",
						wds_strerror(err));
		}
	} else if (hint_dirty) {
		/*
		 * Protected -> Protected
		 *
		 *   Update hint only.
		 *
		 * sb contains either the old, possibly default, contents of
		 * the Security Block (i.e. *not* overriden by salt or
		 * iterations specified on the command line) and the new hint.
		 */
		err = wds_write_handy_store_security_block(wds, &sb);
		if (err)
			fprintf(stderr, "Error: failed writing hint to Handy "
					"Store Security Block: %s\n",
					wds_strerror(err));
	}

	free(npw);
	free(opw);
	wds_close(wds);

	return !!err;
}

static int erase_drive (wds_handle *wds, uint8_t reset_syn[4],
		uint16_t key_size, const char *keyfile, uint8_t cipher,
		unsigned combine)
{
	uint8_t *key;
	int err = 0;

	key = xmalloc(key_size);

	if (keyfile) {
		size_t rd_bytes = key_size;

		if (read_file(keyfile, (char**)&key, &rd_bytes)) {
			free(key);
			return 1;
		}

		if (rd_bytes != key_size) {
			fprintf(stderr, "Error: key file contains fewer bytes "
					"than required (%" PRIu16 "B).\n",
					key_size);
			free(key);
			return 1;
		}
	} else {
		if (fill_random(key, key_size, 0)) {
			fprintf(stderr, "Error: failed creating encryption key\n");
			free(key);
			return 1;
		}
	}

	err = wds_erase(wds, reset_syn, key, key_size, cipher, combine);
	if (err)
		fprintf(stderr, "Error: failed erasng device: %s\n",
				wds_strerror(err));

	free(key);

	return err;
}

static void erase_cmd_usage (FILE *fp, const char *name) {
	fprintf(fp, "usage: %s %s [--help] [OPTIONS] <device>\n",
			progname, name);
}

static void erase_cmd_help (const char *name) {
	erase_cmd_usage(stdout, name);
	printf("\n"
	       "Erase <device> by changing Device Encryption Key (DEK)\n"
	       "\n"
	       "CAUTION: all information that exists on device will become\n"
	       "         lost and completely unrecoverable.\n"
	       "\n"
	       "OPTIONS\n"
	       "--no-clear         don't clear Handy Store Security Block\n"
	       "--cipher <name>    specify cipher by name\n"
	       "--cipher-id <id>   specify cipher by id\n"
	       "--combine          request mixing key with on-device RNG\n"
	       "--key-file <file>  use contents of file as encryption key.\n"
	       "                   <key-size> bytes will be read from file and\n"
	       "                   used as-is for the encryption key.\n"
	       "--key-size <num>   force encryption key size (bytes)\n"
	       "--verbose          increase verbosity\n"
	       "--help             this text\n"
	       "\n");
}

static int erase_cmd(int argc, char * const argv[]) {
	const char *devpath;
	struct wds_encryption_status *es;
	wds_handle *wds;
	const char *cipher_name = NULL;
	const char *keyfile = NULL;
	unsigned combine = 0;
	int clear_sec_block = 1;
	uint16_t key_size = 0;
	uint8_t cipher = (uint8_t)-1;
	int key_size_set = 0;
	int err = 0;
	int opt;
	const struct option long_options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "no-clear", no_argument, NULL, 'N' },
		{ "cipher", required_argument, NULL, 'c' },
		{ "cipher-id", required_argument, NULL, 'I' },
		{ "combine", no_argument, NULL, 'C' },
		{ "key-file", required_argument, NULL, 'd' },
		{ "key-size", required_argument, NULL, 'l' },
		{ NULL, 0, 0, 0 }
	};

	optind = 1;
	while ((opt = getopt_long(argc, argv, "Nhc:I:Cd:l:v", long_options, NULL)) != -1) {
		switch (opt) {
			unsigned long ul_tmp;
		case 'h':
			erase_cmd_help(argv[0]);
			return 0;
		case 'v':
			verbose++;
			break;
		case 'c':
			cipher_name = optarg;
			break;
		case 'I':
			ul_tmp = strtoul(optarg, NULL, 0);
			if (ul_tmp > UINT8_MAX) {
				erase_cmd_usage(stderr, argv[0]);
				fputs("Error: cipher-id out-of-range\n", stderr);
				return 1;
			}
			cipher = ul_tmp;
			break;
		case 'C':
			combine = 1;
			break;
		case 'd':
			keyfile = optarg;
			break;
		case 'l':
			ul_tmp = strtoul(optarg, NULL, 0);
			if (ul_tmp > UINT16_MAX) {
				erase_cmd_usage(stderr, argv[0]);
				fputs("Error: key-size out-of-range\n", stderr);
				return 1;
			}
			key_size = ul_tmp;
			key_size_set = 1;
			break;
		case 'N':
			clear_sec_block = 0;
			break;
		case '?':
			erase_cmd_usage(stderr, argv[0]);
			return 1;
		}
	}

	if (argc - optind != 1) {
		erase_cmd_usage(stderr, argv[0]);
		return 1;
	}

	devpath = argv[optind++];

	if (cipher == (uint8_t)-1 && cipher_name) {
		cipher = wds_string_to_cipher(cipher_name);
		if (cipher == (uint8_t)-1) {
			fprintf(stderr, "Error: unrecognized cipher \"%s\".  "
					"Use the `status` sub-command to see "
					"the list of ciphers supported by the "
					"device.\n",
					cipher_name);
			return 1;
		}
	}

	wds = wds_open(devpath, NULL, &err);
	if (!wds) {
		fprintf(stderr, "Error: failed opening device %s: %s\n",
				devpath, wds_strerror(err));
		return 1;
	}

	es = wds_get_status(wds, &err);
	if (!es) {
		fprintf(stderr, "Error: failed to get status: %s\n",
				wds_strerror(err));
		wds_close(wds);
		return 1;
	}

	if (cipher == (uint8_t)-1) {
		cipher = es->cipher;
		if (cipher == WD_SECURITY_CIPHER_NONE) {
			unsigned i;
			for (i = 0; i < es->num_ciphers; i++)
				if (es->ciphers[i] != WD_SECURITY_CIPHER_NONE) {
					cipher = es->ciphers[i];
					break;
				}
		}
	}

	if (!key_size_set)
		/* FDE requires that key length be zero */
		if (cipher != WD_SECURITY_CIPHER_FDE)
			key_size = es->kek_size;


	if (prompt_yesno('n', "Erasing device using the following parameters:\n"
			    "    Cipher: 0x%" PRIx8 " (%s)\n"
			    "  Key size: %" PRIu16 "\n"
			    "  %sCombine key with on-device RNG\n"
			    "Continue?",
			    cipher, wds_cipher_to_string(cipher),
			    key_size, combine ? "" : "Do not "))
	{
		err = erase_drive(wds, es->reset_syn, key_size, keyfile, cipher,
				combine);
		if (!err && clear_sec_block) {
			printf("Clearing Handy Store Security Block...\n");
			err = wds_write_handy_store_security_block(wds, NULL);
			if (err) {
				fprintf(stderr, "Error: failed clearing "
						"Handy Store Security Block: "
						"%s\n", wds_strerror(err));
			}
		}
	} else
		printf("Aborted.\n");

	free(es);
	wds_close(wds);

	return !!err;
}

static int version (int argc __attribute__((unused)), char * const argv[] __attribute__((unused)))
{
	puts(PACKAGE_STRING);
	return 0;
}

static int help (int argc, char * const argv[]);

static const struct {
	const char *name;
	int (*func) (int, char* const *);
	const char *desc;
} subcmd[] = {
	{ "status", status_cmd, "show encryption status" },
	{ "unlock", unlock_cmd, "unlock device" },
	{ "change-pw", changepw_cmd, "change or set password" },
	{ "erase", erase_cmd, "erase device" },
	{ "handy-store", handy_store_cmd, "show/manipulate Handy Store" },
	{ "version", version, "version information" },
	{ "help", help, "this text" }
};

static void usage (FILE *fp) {
	size_t i;

	fprintf(fp, "usage: %s [--help] %s", progname, subcmd[0].name);
	for (i = 1; i < ARRAY_LEN(subcmd) - 3; i++)
		fprintf(fp, "|%s", subcmd[i].name);
	fprintf(fp, " ...\n");
}

static int help (int argc, char * const argv[]) {
	int width_max = 0;
	size_t i;

	if (argc > 1) {
		for (i = 0; i < ARRAY_LEN(subcmd); i++)
			if (!strcmp(argv[1], subcmd[i].name)) {
				char * const tmpargv[] = {
					argv[1],
					"--help",
					NULL
				};
				return subcmd[i].func(2, tmpargv);
			}
	}

	usage(stdout);
	printf("\n"
	       "Manage password protection of external drives supported by\n"
	       "the proprietary WD Security software.\n"
	       "\n"
	       "Sub-commands:\n");
	for (i = 0; i < ARRAY_LEN(subcmd); i++) {
		int width = (int)strlen(subcmd[i].name);
		if (width > width_max)
			width_max = width;
	}
	for (i = 0; i < ARRAY_LEN(subcmd); i++)
		printf(" %*s  %s\n", -width_max, subcmd[i].name, subcmd[i].desc);
	printf("\n");

	return 0;
}

int main (int argc, char *argv[]) {
	const char* cmd;
	int opt;
	const struct option long_options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "version", no_argument, NULL, 'V' },
		{ NULL, 0, 0, 0 }
	};
	size_t i;

	progname = strrchr(argv[0], '/');
	if (progname)
		progname++;
	else
		progname = argv[0];

	optind = 1;
	while ((opt = getopt_long(argc, argv, "+hvV", long_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			return help(argc - optind + 1, argv + optind - 1);
		case 'v':
			verbose++;
			break;
		case 'V':
			return version(argc - optind + 1, argv + optind - 1);
		case '?':
			usage(stderr);
			exit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		usage(stderr);
		exit(EXIT_FAILURE);
	}

	cmd = argv[0];

	for (i = 0; i < ARRAY_LEN(subcmd); i++)
		if (!strcmp(cmd, subcmd[i].name))
			return subcmd[i].func(argc, argv);

	usage(stderr);
	fprintf(stderr, "Error: unknown sub-command \"%s\"\n", cmd);

	exit(EXIT_FAILURE);
}
