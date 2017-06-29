bin_PROGRAMS = amtgwd
amtgwd_SOURCES = gw_main.c gw_config.c gw_if.c gw_udp.c gw_sock.c gw_tun.c gw.h
amtgwd_LDADD = $(top_builddir)/libshared/libshared.a $(top_builddir)/libprefix/libprefix.a $(top_builddir)/libmem/libmem.a
AM_CPPFLAGS = -Werror -Wall -I$(top_builddir)/include -I$(top_builddir)/libshared -I$(top_builddir)/libprefix
