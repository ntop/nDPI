#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_CONFIG_MACRO_DIR([m4])
m4_define([v_maj], [2])
m4_define([v_min], [9])
m4_define([v_mic], [0])
m4_define([project_version], [v_maj.v_min.v_mic])

AC_PREREQ([2.69])
AC_INIT([libndpi], [project_version])
AC_USE_SYSTEM_EXTENSIONS

AM_PROG_AR
LT_INIT([shared static])
AM_INIT_AUTOMAKE([foreign subdir-objects -Wall -Werror])

LT_LIB_M

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_CC_STDC
AC_LANG_WERROR
AX_PTHREAD
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

AC_CONFIG_SRCDIR([src/lib/ndpi_main.c])

if test -d ".git"; then :
     GIT_TAG=`git log -1 --format=%h`
     GIT_DATE=`git log -1 --format=%cd`
     #
     # On CentOS 6 `git rev-list HEAD --count` does not work
     # 
     #
     GIT_NUM=`git log --pretty=oneline | wc -l | tr -d '[[:space:]]'`
     GIT_RELEASE="project_version-${GIT_NUM}-${GIT_TAG}"
else
     GIT_RELEASE="project_version"
     GIT_DATE=`date`
fi

AC_DEFINE_UNQUOTED(NDPI_GIT_RELEASE, ["${GIT_RELEASE}"], [nDPI version])

# Checks for libraries.
AC_ARG_WITH([hyperscan], AS_HELP_STRING([--with-hyperscan, [Enable nDPI build with Intel Hyperscan]]))
AS_IF([test "x$with_hyperscan" != "xno"], [
	PKG_CHECK_MODULES(HYPERSCAN, [hs], [HAVE_HS=1], [HAVE_HS=0]
		AC_MSG_WARN([Intel Hyperscan not found]))
])
AC_SEARCH_LIBS([pcap_open_live], [pcap], [], [AC_MSG_ERROR([unable to find libpcap])])

dnl> https://github.com/json-c/json-c
AC_ARG_ENABLE([json-c],
    AS_HELP_STRING([--disable-json-c], [Disable json-c support]))
AS_IF([test "x$enable_json_c" != "xno"], [
       PKG_CHECK_MODULES(JSON_C, [json-c], AC_DEFINE(HAVE_JSON_C, 1, [json-c found]), [AC_MSG_ERROR([unable to find json-c])])
])

AC_ARG_WITH([dpdk], AS_HELP_STRING([--with-dpdk], [Enable nDPI example build with DPDK]))
AS_IF([test "x$with_dpdk" = "xyes"], [
        PKG_CHECK_MODULES(DPDK, [libdpdk], AC_DEFINE(HAVE_DPDK, 1, [dpdk found]),
                AC_MSG_WARN([unable to find dpdk]))
])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stddef.h stdint.h stdlib.h string.h strings.h sys/param.h sys/socket.h sys/time.h unistd.h])

AC_ARG_ENABLE([debug-messages],
    AS_HELP_STRING([--enable-debug-messages], [Define NDPI_ENABLE_DEBUG_MESSAGES=1]), [
	AC_DEFINE(NDPI_ENABLE_DEBUG_MESSAGES, 1, [Enable ndpi_debug_messages]) ])

AC_CHECK_LIB(pthread, pthread_setaffinity_np, AC_DEFINE_UNQUOTED(HAVE_PTHREAD_SETAFFINITY_NP, 1, [libc has pthread_setaffinity_np]))

AC_CONFIG_FILES([Makefile example/Makefile src/lib/Makefile src/include/ndpi_define.h libndpi.pc tests/Makefile])
AC_CONFIG_HEADERS([src/include/ndpi_config.h])

AC_OUTPUT
