# As suggested by libtoolize
ACLOCAL_AMFLAGS = -I config

AM_CFLAGS = -Wall -Werror

WARNING_CFLAGS = -Wall -Wformat -W -Werror
WARNING_CXXFLAGS = -fvisibility-inlines-hidden


# PROGRAMS
##################################################
noinst_PROGRAMS = src/udp_server

src_udp_server_SOURCES = src/udp_server.cpp
src_udp_server_CXXFLAGS = $(OLA_CFLAGS)
src_udp_server_LDADD = $(OLA_LIBS)
