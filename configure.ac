#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([WD-Security], [m4_esyscmd_s(sh ./GEN-VERSION.sh -n)], [drafnel@gmail.com])
AC_CONFIG_SRCDIR([wd-security.c])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([foreign])

# GCC 64-bit
: ${CFLAGS="-W -Wall -O2"}

# Checks for programs.
AC_PROG_CC

dnl Prepare for future Autoconf macro to request 64-bit time_t??
dnl See https://github.com/autotools-mirror/autoconf/blob/master/NEWS
m4_ifdef([AC_SYS_YEAR2038], [AC_SYS_YEAR2038],
	 [AC_MSG_WARN([unable to check for 64-bit time support])])
AC_SYS_LARGEFILE

# Checks for libraries.

# openssl crypto libraries for AES-256 hash
AC_CHECK_LIB([crypto], [EVP_MD_fetch], [],
	     [AC_CHECK_LIB([crypto], [EVP_sha256], [],
	     [AC_MSG_ERROR([unable to find usable crypto library])])])

# Try to use getrandom, then arc4random, then internal impl.
AC_SEARCH_LIBS([getrandom], [c], [],
	       [AC_SEARCH_LIBS([arc4random_buf], [c bsd], [], [])])

AC_SEARCH_LIBS([iconv], [c], [],
	       [AC_MSG_ERROR([unable to find iconv])])

AC_SEARCH_LIBS([clock_gettime], [c rt], [],
	       [AC_MSG_ERROR([unable to find clock_gettime])])

# Checks for header files.
AC_HEADER_ASSERT

AC_CHECK_HEADERS([endian.h fcntl.h linux/fs.h openssl/crypto.h openssl/evp.h scsi/scsi.h scsi/sg.h stddef.h stdlib.h string.h sys/ioctl.h sys/random.h unistd.h])

AS_IF([test "x$ac_cv_search_arc4random_buf" != "x" -a \
       "x$ac_cv_search_arc4random_buf" != "xno"],
      [AC_CHECK_FUNCS([arc4random_buf])
       AC_CHECK_HEADERS([bsd/stdlib.h])])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_C_FLEXIBLE_ARRAY_MEMBER
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

AC_CHECK_DECLS([BLKRRPART], [], [], [[#include <linux/fs.h>]])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([EVP_MD_fetch EVP_sha256 getrandom iconv memset strchr strrchr strtof strtoul])


AC_CONFIG_FILES([Makefile])
AC_OUTPUT
