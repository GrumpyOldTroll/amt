if WANT_MD5
MD5_INCLUDES = -I$(top_builddir)/libmd5
MD5_LIBS = $(top_builddir)/libmd5/libmd5.a
endif
bin_PROGRAMS = amtrelayd
amtrelayd_SOURCES = main.c recv.c tree.c tree.h relay.h
amtrelayd_LDADD = $(top_builddir)/libhmac/libhmac.a $(top_builddir)/libpatricia/libpatricia.a $(top_builddir)/libprefix/libprefix.a $(top_builddir)/libsum/libsum.a $(top_builddir)/libmem/libmem.a $(MD5_LIBS)
AM_CPPFLAGS = -D_BSD_SOURCE -Werror -Wall -I$(top_builddir)/include -I$(top_builddir)/libmem -I$(top_builddir)/libhmac -I$(top_builddir)/libpatricia -I$(top_builddir)/libprefix -I$(top_builddir)/libsum $(MD5_INCLUDES)
