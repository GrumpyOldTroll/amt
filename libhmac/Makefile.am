noinst_LIBRARIES = libhmac.a
libhmac_a_SOURCES = hmac.c hmac.h
if WANT_MD5
MD5_INCLUDES = -I$(top_builddir)/libmd5
endif
AM_CPPFLAGS = -Werror -Wall $(MD5_INCLUDES)
