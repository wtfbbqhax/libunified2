bin_PROGRAMS = u2dump u2split u2csv u2pcap

u2dump_SOURCES	= u2dump.c
u2csv_SOURCES	= u2csv.c
u2split_SOURCES = u2split.c
u2pcap_SOURCES	= u2pcap.c

# library inclusion
u2dump_LDADD	= ../libunified2/libunified2.la
u2csv_LDADD		= ../libunified2/libunified2.la
u2split_LDADD	= ../libunified2/libunified2.la
u2pcap_LDADD	= ../libunified2/libunified2.la





AM_CFLAGS = -Wall -Werror -I$(top_srcdir)/include
