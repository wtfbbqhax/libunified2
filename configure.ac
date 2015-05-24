#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([libunified2], [0.0.7], [https://github.com/wtfbbqhax/libunified2/issues/new])
AC_CONFIG_SRCDIR([include/unified2.h])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_RANLIB
LT_INIT
AC_PROG_LIBTOOL

# Checks for libraries.

  
# Check operating system specifics
case "$host" in
    *-apple*)
    AC_DEFINE([MACOS], [1], [Define if MacOS])
    ;;

    *-linux*)
    AC_DEFINE([LINUX], [1], [Define if Linux])
    ;;
esac


# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([memset strdup strerror])

AC_CONFIG_FILES([Makefile
                 include/Makefile
                 src/Makefile
                 src/apps/Makefile
                 src/libunified2/Makefile])
AC_OUTPUT
