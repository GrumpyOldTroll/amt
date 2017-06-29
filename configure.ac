#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(amt, 0.1.4, jholland@akamai.com)
AC_CONFIG_SRCDIR([relay/main.c])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB
AC_CONFIG_HEADERS([include/config.h])

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h paths.h stddef.h stdint.h stdlib.h string.h strings.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([bzero gettimeofday memset socket strchr strdup strerror strncasecmp strtol])

AC_CHECK_LIB([event], [event_init])
AC_CHECK_LIB([md], [MD5Init], [], [ my_want_md5=yes ])
AM_CONDITIONAL([WANT_MD5], [test "$my_want_md5" = yes])

AC_CONFIG_FILES([Makefile
                 include/Makefile
                 libhmac/Makefile
                 libmd5/Makefile
                 libmem/Makefile
                 libpatricia/Makefile
                 libprefix/Makefile
                 libshared/Makefile
                 relay/Makefile
                 gateway/Makefile
                 doc/Makefile
                 test_hmac/Makefile
                 test_patricia/Makefile])
AC_OUTPUT
