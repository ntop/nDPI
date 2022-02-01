AC_INIT([libndpi], [4.2.0])

AC_CONFIG_AUX_DIR([.])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_PREFIX_DEFAULT(/usr)

EXTRA_TARGETS="example tests tests/unit tests/dga"
AC_ARG_WITH(only-libndpi,  AS_HELP_STRING([--with-only-libndpi], [Build only libndpi (no examples, tests etc)]))
AS_IF([test "${with_only_libndpi+set}" = set],[
  EXTRA_TARGETS=""
])

AC_ARG_WITH(sanitizer,     AS_HELP_STRING([--with-sanitizer], [Build with support for address, undefined and leak sanitizer]))
AC_ARG_ENABLE(fuzztargets, AS_HELP_STRING([--enable-fuzztargets], [Enable fuzz targets]),[enable_fuzztargets=$enableval],[enable_fuzztargets=no])
AS_IF([test "x$enable_fuzztargets" = "xyes"], [BUILD_FUZZTARGETS=1], [BUILD_FUZZTARGETS=0])
AM_CONDITIONAL([BUILD_FUZZTARGETS], [test "x$enable_fuzztargets" = "xyes"])

AS_IF([test "${with_sanitizer+set}" = set],[
  CFLAGS="${CFLAGS} -g3 -O0 -fsanitize=address -fsanitize=undefined -fno-sanitize=alignment -fsanitize=leak -fno-omit-frame-pointer"
  LDFLAGS="${LDFLAGS} -fsanitize=address -fsanitize=undefined -fno-sanitize=alignment -fsanitize=leak"
])

LT_INIT
LT_LIB_M
PKG_PROG_PKG_CONFIG

SYSTEM=`uname -s`
if test $SYSTEM = "Darwin"; then
dnl>  AC_PROG_CC(clang gcc)
  AM_PROG_CC_C_O(clang gcc)
  AC_PROG_CXX(clang++ g++)
  AC_PROG_CC_STDC(clang gcc)
else
  AC_PROG_CC_C_O
  AC_PROG_CXX
  AC_PROG_CC_STDC
fi

dnl> Can't iuse AM_PROG_AR because not all of our Makefiles are automake (yet?)
AC_CHECK_TOOL(AR, ar, [false])

AC_LANG_WERROR

NDPI_MAJOR=`echo "${PACKAGE_VERSION}" | cut -d . -f 1`
NDPI_MINOR=`echo "${PACKAGE_VERSION}" | cut -d . -f 2`
NDPI_PATCH=`echo "${PACKAGE_VERSION}" | cut -d . -f 3`
NDPI_VERSION_SHORT="$NDPI_MAJOR.$NDPI_MINOR.$NDPI_PATCH"

AC_DEFINE_UNQUOTED(NDPI_MAJOR_RELEASE, "${NDPI_MAJOR}", [nDPI major release])
AC_DEFINE_UNQUOTED(NDPI_MINOR_RELEASE, "${NDPI_MINOR}", [nDPI minor release])
AC_DEFINE_UNQUOTED(NDPI_PATCH_LEVEL,   "${NDPI_PATCH}", [nDPI patch level])

# .git as directory in a cloned repo
# .git as file in submodule based integration
if test -d ".git" || test -f ".git" ; then :
     GIT_TAG=`git log -1 --format=%h`
     GIT_DATE=`git log -1 --format=%cd`
     #
     # On CentOS 6 `git rev-list HEAD --count` does not work
     #
     #
     GIT_NUM=`git log --pretty=oneline | wc -l | tr -d '[[:space:]]'`
     GIT_RELEASE="${PACKAGE_VERSION}-${GIT_NUM}-${GIT_TAG}"

     A=`git log src/include/ndpi_typedefs.h|wc -l`
     B=`git log src/include/ndpi_protocol_ids.h|wc -l`
     C=`git log src/include/ndpi_api.h.in|wc -l`
     NDPI_API_VERSION=$((A+B+C))
else
     GIT_RELEASE="${PACKAGE_VERSION}"
     GIT_DATE=`date -u -r CHANGELOG.md`
     if test -z "$SOURCE_DATE_EPOCH" ; then :
         SOURCE_DATE_EPOCH=`date +%s`
     fi
     NDPI_API_VERSION=`echo $SOURCE_DATE_EPOCH | cut -c7-10`
fi

NDPI_API_VERSION=`echo $NDPI_API_VERSION | sed 's/^0*//'`

echo "Setting API version to $NDPI_API_VERSION"

AC_DEFINE_UNQUOTED(NDPI_GIT_RELEASE, "${GIT_RELEASE}", [GIT Release])
AC_DEFINE_UNQUOTED(NDPI_GIT_DATE, "${GIT_DATE}", [Last GIT change])

if ! test "${with_only_libndpi+set}" = set; then :
    dnl> used by json-c for unit tests
    PKG_CHECK_MODULES([JSONC], [json-c], [JSONC_LIBS="${pkg_cv_JSONC_LIBS}" JSONC_CFLAGS="${pkg_cv_JSONC_CFLAGS}"])
    AC_CHECK_LIB([json-c], [json_object_put], [], [
        AC_MSG_WARN([JSON-C not available. Disabled unit test.])
        JSONC_LIBS=""
        JSONC_CFLAGS=""
        EXTRA_TARGETS="example tests tests/dga"
    ])
    AX_PTHREAD([],[
        AC_MSG_WARN([POSIX Threads not available. Building library only.])
        JSONC_LIBS=""
        JSONC_CFLAGS=""
        EXTRA_TARGETS=""
    ])
fi

LIBS="$LIBS $JSONC_LIBS"
CFLAGS="-W -Wall -Wno-unused-parameter -Wno-unused-function $CFLAGS $JSONC_CFLAGS"

AC_CHECK_HEADERS([netinet/in.h stdint.h stdlib.h string.h unistd.h math.h float.h])
AC_CHECK_LIB([m], [sqrt], [], [LIBM="-lm"])
AC_CHECK_LIB([rrd], [rrd_fetch_r], [LIBRRD=-lrrd])

if test "x$ac_cv_lib_rrd_rrd_fetch_r" = xyes; then :
   AC_DEFINE_UNQUOTED(HAVE_RRDTOOL, "1", [rrdtool is present])
   EXTRA_TARGETS="$EXTRA_TARGETS rrdtool"
fi

ADDITIONAL_LIBS="$LIBRRD $LIBM"
PCAP_HOME=$HOME/PF_RING/userland

DPDK_TARGET=
AC_MSG_CHECKING([DPDK (used by ndpiReader)])
if test -d $HOME/DPDK; then :
      AC_MSG_RESULT(yes)
     DPDK_TARGET=dpdk
else
     AC_MSG_RESULT([no (missing $HOME/DPDK)])
fi

if ! test -d $PCAP_HOME; then :
     PCAP_HOME=`pwd`/../../PF_RING/userland
fi
SHORT_MACHINE=`uname -m | cut -b1-3`
if test $SHORT_MACHINE = "arm"; then
     LIBNUMA=""
else
     AC_CHECK_LIB([numa], [numa_available], [LIBNUMA="-lnuma"])
fi

MACHINE=`uname -m`

CUSTOM_NDPI=

if test -d ../nDPI-custom; then :
   CUSTOM_NDPI="-DCUSTOM_NDPI_PROTOCOLS"
   AC_MSG_RESULT([Compiling with custom nDPI protocols])
fi

if test -d ../ndpi-pro; then :
   with_maxminddb=1
fi

case "$host" in
   *-*-mingw32*|*-*-msys)
      PCAP_INC=""
      PCAP_LIB=""
      case "$host" in
        x86_64-*)
          BUILD_MINGW_X64=1
        ;;
        i686-*)
        ;;
        *)
          AC_MSG_ERROR([Unsupported MingW cross compiler.])
        ;;
      esac
      CFLAGS="${CFLAGS}"
      LIBS="${LIBS} -lws2_32"
      BUILD_MINGW=1
      ;;
   *)
      if test -f $PCAP_HOME/libpcap/libpcap.a; then :
         echo "Using libpcap from $PCAP_HOME"
         PCAP_INC="-I $PCAP_HOME/libpcap"
	 PFRING_LIB=
	 if test -f $PCAP_HOME/lib/libpfring.a; then :
   	   PFRING_LIB=$PCAP_HOME/lib/libpfring.a
	 fi
	 
         PCAP_LIB="$PCAP_HOME/libpcap/libpcap.a $PFRING_LIB $LIBNUMA `$PCAP_HOME/lib/pfring_config --libs`"
         AC_CHECK_LIB([rt], [clock_gettime],   [PCAP_LIB="$PCAP_LIB -lrt"])
         AC_CHECK_LIB([nl], [nl_handle_alloc], [PCAP_LIB="$PCAP_LIB -lnl"])
         # The dlopen() function is in libdl on GLIBC-based systems
         # and in the C library for *BSD systems
         AC_CHECK_LIB([dl], [dlopen],   [DL_LIB="-ldl"],[AC_CHECK_LIB([c],
                            [dlopen],   [DL_LIB="-lc"],
                            [AC_MSG_ERROR([unable to find the dlopen(), dlsym() functions]) ]) ])
      elif test "${with_only_libndpi+set}" != set; then :
         AC_CHECK_LIB([pcap], [pcap_open_live], [PCAP_LIB="-lpcap"])
         if test $ac_cv_lib_pcap_pcap_open_live = "no"; then :
            AC_MSG_ERROR([Missing libpcap(-dev) library required to compile the example application.])
         fi
      fi
      ;;
esac

AC_ARG_ENABLE([debug-messages],
    AS_HELP_STRING([--enable-debug-messages], [Define NDPI_ENABLE_DEBUG_MESSAGES=1]), [
	AC_DEFINE(NDPI_ENABLE_DEBUG_MESSAGES, 1, [Enable ndpi_debug_messages]) ])

AS_IF([test "x$enable_fuzztargets" = "xyes"], [
    AC_PROG_CXX
    AC_LANG_PUSH(C++)
    tmp_saved_flags=$[]_AC_LANG_PREFIX[]FLAGS
    AX_CHECK_COMPILE_FLAG([-fsanitize=fuzzer],,
        [AC_MSG_ERROR([--enable-fuzztargets requires -fsanitize=fuzzer which is only supported by LLVM])],
        [-Werror])
    AS_IF([test "x$LIB_FUZZING_ENGINE" = "x"], [
        LIB_FUZZING_ENGINE=-fsanitize=fuzzer
        AC_SUBST(LIB_FUZZING_ENGINE)
    ])
    _AC_LANG_PREFIX[]FLAGS="$[]_AC_LANG_PREFIX[]FLAGS $LIB_FUZZING_ENGINE"
    AC_MSG_CHECKING([whether $CXX accepts $LIB_FUZZING_ENGINE])
    AC_LINK_IFELSE([AC_LANG_SOURCE([[
#include <sys/types.h>
extern "C" int LLVMFuzzerTestOneInput(const unsigned char *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput(const unsigned char *Data, size_t Size) {
(void)Data;
(void)Size;
return 0;
}
        ]])],
        [ AC_MSG_RESULT(yes)
          has_sanitizefuzzer=yes],
        [ AC_MSG_RESULT(no) ]
    )
    _AC_LANG_PREFIX[]FLAGS=$tmp_saved_flags
    AC_LANG_POP()
])
AM_CONDITIONAL([HAS_FUZZLDFLAGS], [test "x$has_sanitizefuzzer" = "xyes"])

AC_CHECK_LIB(pthread, pthread_setaffinity_np, AC_DEFINE_UNQUOTED(HAVE_PTHREAD_SETAFFINITY_NP, 1, [libc has pthread_setaffinity_np]))

dnl> GCRYPT
GCRYPT_ENABLED=1
AC_ARG_ENABLE([gcrypt],
  [AS_HELP_STRING([--disable-gcrypt], [Avoid compiling with libgcrypt/libgpg-error, even if they are present. QUIC sub-classification may be missing])],
  [GCRYPT_ENABLED=0],
  [AC_CHECK_LIB(gcrypt, gcry_cipher_checktag)])
AS_IF([test ${GCRYPT_ENABLED} -eq 1], [
  if test "x$ac_cv_lib_gcrypt_gcry_cipher_checktag" = xyes; then :
    ADDITIONAL_LIBS="${ADDITIONAL_LIBS} -lgcrypt"
  else
    $as_unset ac_cv_lib_gcrypt_gcry_cipher_checktag
    AC_CHECK_LIB(gpg-error, gpg_strerror_r)
    AC_CHECK_LIB(gcrypt, gcry_cipher_checktag)
    if test "x$ac_cv_lib_gcrypt_gcry_cipher_checktag" = xyes -a "x$ac_cv_lib_gpg_error_gpg_strerror_r" = xyes; then :
      ADDITIONAL_LIBS="${ADDITIONAL_LIBS} -lgcrypt -lgpg-error"
    else
      GCRYPT_ENABLED=0
    fi
  fi
])

dnl> PCRE
PCRE_ENABLED=0
AC_ARG_WITH(pcre,          [  --with-pcre        Enable nDPI build with libpcre])
if test "${with_pcre+set}" = set; then :
  AC_CHECK_LIB(pcre, pcre_compile, AC_DEFINE_UNQUOTED(HAVE_PCRE, 1, [libpcre(-dev) is present]))
  if test "x$ac_cv_lib_pcre_pcre_compile" = xyes; then :
    ADDITIONAL_LIBS="${ADDITIONAL_LIBS} -lpcre"
    PCRE_ENABLED=1
  fi
fi

dnl> GeoIP
AC_ARG_WITH(maxminddb,          [  --with-maxminddb        Enable nDPI build with libmaxminddb])
if test "${with_maxminddb+set}" = set; then :
  AC_CHECK_LIB([maxminddb], [MMDB_lookup_sockaddr])
  AC_HAVE_HEADERS(maxminddb.h)
  if test ".${ac_cv_lib_maxminddb_MMDB_lookup_sockaddr}" = ".yes" && test ".${ac_cv_header_maxminddb_h}" = ".yes"; then
    ADDITIONAL_LIBS="${ADDITIONAL_LIBS} -lmaxminddb"
    AC_DEFINE_UNQUOTED(HAVE_MAXMINDDB, 1, [MaxMind DB support])
  fi
fi

dnl> Curl
dnl> AC_CHECK_LIB([curl], [curl_easy_perform])
dnl> if test ${ac_cv_lib_curl_curl_easy_perform} = "no"; then
dnl>    echo "Please install libcurl4-openssl-dev (http://curl.haxx.se/) in order to enable curl support"
dnl> else
dnl>   ADDITIONAL_LIBS="${ADDITIONAL_LIBS} -lcurl"
dnl>   AC_DEFINE_UNQUOTED(HAVE_CURL, 1, [curl is present])
dnl> fi

AC_CONFIG_FILES([Makefile example/Makefile example/Makefile.dpdk tests/Makefile tests/unit/Makefile tests/performance/Makefile tests/dga/Makefile rrdtool/Makefile libndpi.pc src/include/ndpi_define.h src/lib/Makefile python/Makefile fuzz/Makefile src/include/ndpi_api.h])
AC_CONFIG_FILES([tests/do.sh], [chmod +x tests/do.sh])
AC_CONFIG_HEADERS(src/include/ndpi_config.h)
AC_SUBST(GIT_RELEASE)
AC_SUBST(NDPI_MAJOR)
AC_SUBST(NDPI_MINOR)
AC_SUBST(NDPI_PATCH)
AC_SUBST(NDPI_VERSION_SHORT)
AC_SUBST(PCAP_INC)
AC_SUBST(PCAP_LIB)
AC_SUBST(ADDITIONAL_LIBS)
AC_SUBST(DL_LIB)
AC_SUBST(DPDK_TARGET)
AC_SUBST(HAVE_PTHREAD_SETAFFINITY_NP)
AC_SUBST(CUSTOM_NDPI)
AC_SUBST(NDPI_API_VERSION)
AC_SUBST(EXTRA_TARGETS)
AC_SUBST(BUILD_MINGW)
AC_SUBST(BUILD_MINGW_X64)
AC_SUBST(BUILD_FUZZTARGETS)
AC_SUBST(JSONC_CFLAGS)
AC_SUBST(JSONC_LIBS)
AC_SUBST(GCRYPT_ENABLED)
AC_SUBST(PCRE_ENABLED)
AC_OUTPUT
