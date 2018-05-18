if WANT_MD5
MD5_INCLUDES = -I$(top_builddir)/libmd5
MD5_LIBS = $(top_builddir)/libmd5/libmd5.a
endif

bin_PROGRAMS = amtrelayd
amtrelayd_SOURCES = main.c config.c recv.c tree.c tree.h relay.h
amtrelayd_LDADD = $(top_builddir)/libhmac/libhmac.a $(top_builddir)/libpatricia/libpatricia.a $(top_builddir)/libprefix/libprefix.a $(top_builddir)/libshared/libshared.a $(top_builddir)/libmem/libmem.a $(MD5_LIBS)
AM_CPPFLAGS = -D_GNU_SOURCE -D_DEFAULT_SOURCE -Werror -Wall -I$(top_builddir)/include -I$(top_builddir)/libmem -I$(top_builddir)/libhmac -I$(top_builddir)/libpatricia -I$(top_builddir)/libprefix -I$(top_builddir)/libshared $(MD5_INCLUDES)

# _GNU_SOURCE is because of in6_pktinfo, with workaround from:
# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=45257
# However, this seems like a legit bug because in6_pktinfo is not
# gnu-specific, as in https://tools.ietf.org/html/rfc3542#section-15
# --jake 2017-06-14
