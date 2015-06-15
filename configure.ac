#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([laughing-tribble], [0.0.1], [])
AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([config])
AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects foreign])
AC_LANG_PUSH([C++])

AC_PROG_CXX
AM_PROG_AR

LT_INIT
AC_PROG_LIBTOOL

# pkg-config
PKG_PROG_PKG_CONFIG
AS_IF([test -z "$PKG_CONFIG"],
      [AC_MSG_ERROR([Missing pkg-config, please install it])])

# OLA
PKG_CHECK_MODULES(
  OLA,
  [libola],
  [],
  [AC_MSG_ERROR([Missing OLA, please install])])

# Output
#####################################################
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo \
"-------------------------------------------------------
${PACKAGE_NAME} Version ${PACKAGE_VERSION}

Prefix: '${prefix}'
Compiler: '${CXX} ${CXXFLAGS} ${CPPFLAGS}'
Linker: '${LD} ${LDFLAGS} ${LIBS}'

Now type 'make'
-------------------------------------------------------"
