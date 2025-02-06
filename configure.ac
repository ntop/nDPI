AC_INIT([libndpi],[4.13.0])

AC_CONFIG_AUX_DIR([.])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_PREFIX_DEFAULT(/usr)

EXTRA_TARGETS="example tests tests/dga"
AC_ARG_WITH(only-libndpi, AS_HELP_STRING([--with-only-libndpi], [Build only libndpi (no examples, tests etc)]))
AS_IF([test "${with_only_libndpi+set}" = set],[
  EXTRA_TARGETS=""
])

PWD=`pwd`


AC_ARG_WITH(sanitizer, AS_HELP_STRING([--with-sanitizer], [Build with support for address, undefined and leak sanitizer]))
AC_ARG_WITH(thread-sanitizer, AS_HELP_STRING([--with-thread-sanitizer], [Build with support for thread sanitizer]))
AC_ARG_WITH(memory-sanitizer, AS_HELP_STRING([--with-memory-sanitizer], [Build with support for memory sanitizer]))
AC_ARG_WITH(macos-memory-sanitizer, AS_HELP_STRING([--with-macos-memory-sanitizer], [Build with support for memory sanitizer macOS]))
AC_ARG_ENABLE(fuzztargets, AS_HELP_STRING([--enable-fuzztargets], [Enable fuzz targets]),[enable_fuzztargets=$enableval],[enable_fuzztargets=no])
AC_ARG_ENABLE(gprof, AS_HELP_STRING([--enable-gprof], [Enable CPU/HEAP profiling with gperftools]),[enable_gprof=$enableval],[enable_gprof=no])
AC_ARG_ENABLE(code-coverage, AS_HELP_STRING([--enable-code-coverage], [Generate Code Coverage report]))
AC_ARG_WITH(local-libgcrypt, AS_HELP_STRING([--with-local-libgcrypt], [Build with libgcrypt (if present) instead of the enclosed gcrypt light]))
AC_ARG_ENABLE(tls-sigs, AS_HELP_STRING([--enable-tls-sigs], [Enable TLS Client signature algorithm dissection. Rarely used, but requires significantly more memory.]))
AC_ARG_ENABLE(npcap, AS_HELP_STRING([--disable-npcap], [msys2 only: Disable linkage against the wpcap/npcap import library in windows/WpdPack/Lib.]))
AC_ARG_WITH(nbpf-path, AS_HELP_STRING([--with-nbpf-path], [nBPF library custom path; default: ${PWD}/../PF_RING/userland/nbpf]),[NBPF_HOME=$withval],[NBPF_HOME=${PWD}/../PF_RING/userland/nbpf])
AC_ARG_WITH(lto-and-gold-linker, AS_HELP_STRING([--with-lto-and-gold-linker], [Build with LTO and Gold linker]))
AC_ARG_ENABLE(debug-build, AS_HELP_STRING([--enable-debug-build], [Enable debug build (`-g` flag)]),[enable_debugbuild=$enableval],[enable_debugbuild=no])
AC_ARG_ENABLE(global-context-support, AS_HELP_STRING([--disable-global-context-support], [Disable support for global context. No external dependency on libpthread]))
AC_ARG_ENABLE(memory-track-origins, AS_HELP_STRING([--disable-memory-track-origins], [Don't add -fsanitize-memory-track-origins flag when compiling with MASAN support. Useful for faster CI]))

NDPI_CFLAGS="${NDPI_CFLAGS} -D_DEFAULT_SOURCE=1 -D_GNU_SOURCE=1"

AS_IF([test "x$enable_fuzztargets" = "xyes"], [
  BUILD_FUZZTARGETS=1
  NDPI_CFLAGS="${NDPI_CFLAGS} -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
], [BUILD_FUZZTARGETS=0])
AM_CONDITIONAL([BUILD_FUZZTARGETS], [test "x$enable_fuzztargets" = "xyes"])

AS_IF([test "x$enable_debugbuild" = "xyes"], [
  NDPI_CFLAGS="${NDPI_CFLAGS} -g"
])

AS_IF([test "${with_sanitizer+set}" = set -a "${with_thread_sanitizer+set}" = set],[
  AC_MSG_ERROR([Configure options `--with-sanitizer' and `--with_thread_sanitizer' can not used at the same time.])
])
AS_IF([test "${with_sanitizer+set}" = set -a "${with_memory_sanitizer+set}" = set],[
  AC_MSG_ERROR([Configure options `--with-sanitizer' and `--with_memory_sanitizer' can not used at the same time.])
])
AS_IF([test "${with_thread_sanitizer+set}" = set -a "${with_memory_sanitizer+set}" = set],[
  AC_MSG_ERROR([Configure options `--with_thread_sanitizer' and `--with_memory_sanitizer' can not used at the same time.])
])
AS_IF([test "${with_sanitizer+set}" = set -o "${with_thread_sanitizer+set}" = set -o "${with_memory_sanitizer+set}" = set],[
  NDPI_CFLAGS="${NDPI_CFLAGS} -O0 -g3"
],[
  dnl>  Oss-fuzz doesn't really like any optimizaton flags don't set by itself
  AS_IF([test "x$enable_fuzztargets" != "xyes"], [NDPI_CFLAGS="${NDPI_CFLAGS} -O2"])
])
AS_IF([test "${with_sanitizer+set}" = set -o "${with_thread_sanitizer+set}" = set -o "${with_memory_sanitizer+set}" = set],[
  AS_IF([test "x$enable_gprof" = "xyes"], [
    AC_MSG_ERROR([Configure options `--with-sanitizer' / `--with_thread_sanitizer' / `--with_memory_sanitizer' can not used together with `--enable-gprof'.])
  ])
])

AS_IF([test "${with_sanitizer+set}" = set],[
  NDPI_CFLAGS="${NDPI_CFLAGS} -fsanitize=address -fsanitize=undefined -fsanitize=leak -fno-omit-frame-pointer"
  NDPI_LDFLAGS="${NDPI_LDFLAGS} -fsanitize=address -fsanitize=undefined -fsanitize=leak"
  #Sanitizers should work on any compilers that we support (or that we test on CI, at least)
  #Exception: "-fsanitize=alignment" is not supported in gcc 4.9
  AX_CHECK_COMPILE_FLAG([-fno-sanitize=alignment], [
    NDPI_CFLAGS="${NDPI_CFLAGS} -fno-sanitize=alignment"
    NDPI_LDFLAGS="${NDPI_LDFLAGS} -fno-sanitize=alignment"
  ])
])

AS_IF([test "${with_thread_sanitizer+set}" = set],[
  NDPI_CFLAGS="${NDPI_CFLAGS} -fsanitize=thread -fno-omit-frame-pointer"
  NDPI_LDFLAGS="${NDPI_LDFLAGS} -fsanitize=thread"
])

AS_IF([test "${with_memory_sanitizer+set}" = set],[
  NDPI_CFLAGS="${NDPI_CFLAGS} -fsanitize=memory -fno-omit-frame-pointer"
  AS_IF([test "x$enable_memory_track_origins" != "xno"], [
    NDPI_CFLAGS="${NDPI_CFLAGS} -fsanitize-memory-track-origins"
  ])
  NDPI_LDFLAGS="${NDPI_LDFLAGS} -fsanitize=memory"
])

AS_IF([test "${with_macos_memory_sanitizer+set}" = set],[
  NDPI_CFLAGS="${NDPI_CFLAGS} -fsanitize=address -fno-omit-frame-pointer -fsanitize=signed-integer-overflow -fno-sanitize-recover=address"
  NDPI_LDFLAGS="${NDPI_LDFLAGS} -fsanitize=address"
])

AS_IF([test "x${enable_code_coverage}" = "xyes"],[
  NDPI_CFLAGS="${NDPI_CFLAGS} -fprofile-arcs -ftest-coverage"
  NDPI_LDFLAGS="${NDPI_LDFLAGS} --coverage"
])

AS_IF([test "${enable_npcap+set}" = set],[DISABLE_NPCAP=1],[DISABLE_NPCAP=0])

LT_INIT
LT_LIB_M
PKG_PROG_PKG_CONFIG

AC_PROG_CC
AC_PROG_CPP_WERROR
AC_C_INLINE

SYSTEM=`uname -s`
if test $SYSTEM = "Darwin"; then
dnl>  AC_PROG_CC(clang gcc)
  AM_PROG_CC_C_O(clang gcc)
  AC_PROG_CXX(clang++ g++)
else
  AC_PROG_CC_C_O
  AC_PROG_CXX
fi

dnl> Can't iuse AM_PROG_AR because not all of our Makefiles are automake (yet?)
AC_CHECK_TOOL(AR, ar, [false])

AC_LANG_WERROR

AC_MSG_CHECKING([whether roaring v3 works])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
	    #if __has_include (<stdio.h>)
	    #endif
	    ]])],
	    [
	      AC_MSG_RESULT([yes])
	      ],
	      [
	        AC_MSG_RESULT([no])
		  AC_DEFINE_UNQUOTED(USE_ROARING_V2, "1", [Use CRoaring 2.1.x])
  ])

GCC_VERSION=`gcc --version | cut -d ' ' -f 3 | head -1|cut -d '.' -f 1`
if test "${GCC_VERSION}" == "version" ; then
  GCC_VERSION=`gcc --version | cut -d ' ' -f 4 | head -1|cut -d '.' -f 1`
fi

if test "${GCC_VERSION}" -lt "7" ; then
 AC_DEFINE_UNQUOTED(USE_ROARING_V2, "1", [Use CRoaring 2.1.x])
fi


NDPI_MAJOR=`echo "${PACKAGE_VERSION}" | cut -d . -f 1`
NDPI_MINOR=`echo "${PACKAGE_VERSION}" | cut -d . -f 2`
NDPI_PATCH=`echo "${PACKAGE_VERSION}" | cut -d . -f 3`
NDPI_VERSION_SHORT="$NDPI_MAJOR.$NDPI_MINOR.$NDPI_PATCH"

AC_DEFINE_UNQUOTED(NDPI_MAJOR_RELEASE, "${NDPI_MAJOR}", [nDPI major release])
AC_DEFINE_UNQUOTED(NDPI_MINOR_RELEASE, "${NDPI_MINOR}", [nDPI minor release])
AC_DEFINE_UNQUOTED(NDPI_PATCH_LEVEL,   "${NDPI_PATCH}", [nDPI patch level])

# .git as directory in a cloned repo
# .git as file in submodule based integration
if test -d ".git" || test -r ".git"; then
     GIT_TAG=`git log -1 --abbrev=7 --format=%h`
     GIT_DATE=`git log -1 --abbrev=7 --format=%cd`
     #
     # On CentOS 6 `git rev-list HEAD --count` does not work
     #
     #
     GIT_NUM=`git log --pretty=oneline | wc -l | tr -d '[[:space:]]'`
     GIT_RELEASE="${PACKAGE_VERSION}-${GIT_NUM}-${GIT_TAG}"

     A=`git log src/include/ndpi_typedefs.h|wc -l`
     B=`git log src/include/ndpi_protocol_ids.h|wc -l`
     C=`git log src/include/ndpi_api.h|wc -l`
     NDPI_API_VERSION=$((A+B+C))
else
     GIT_RELEASE="${PACKAGE_VERSION}"
     GIT_DATE=`date -u -r CHANGELOG.md`
     if test -z "$SOURCE_DATE_EPOCH" ; then :
         SOURCE_DATE_EPOCH=`date +%s`
     fi
     NDPI_API_VERSION=$((SOURCE_DATE_EPOCH % 65536))
fi

AS_IF([test "x${NDPI_API_VERSION}" = "x"],[
  AC_MSG_WARN([Could not get NDPI_API_VERSION, defaulting to 0.])
  NDPI_API_VERSION=0
])
echo "Setting API version to ${NDPI_API_VERSION}"

AC_DEFINE_UNQUOTED(NDPI_GIT_RELEASE, "${GIT_RELEASE}", [GIT Release])
AC_DEFINE_UNQUOTED(NDPI_GIT_DATE, "${GIT_DATE}", [Last GIT change])

NDPI_CFLAGS="-W -Wall -Wno-address-of-packed-member ${NDPI_CFLAGS}"

dnl> MacOS brew.sh
HOMEBREW_DIR=/opt/homebrew
if test -d $HOMEBREW_DIR; then
 # On latest macOS versions on M* archs, some (all?) libraries are not installed
 # "system-wide" anymore.
 NDPI_CFLAGS="${NDPI_CFLAGS} -I ${HOMEBREW_DIR}/include"
 NDPI_LDFLAGS="${NDPI_LDFLAGS} -L ${HOMEBREW_DIR}/lib"

 # While updating NDPI_CFLAGS/NDPI_LDFLAGS is obvious, we need to update
 # CFLAGS/LDFLAGS as well, because only these variables are used internally by
 # autoconf to check for libraries.
 # The core reason is likely that internally in our Makefiles we use
 # NDPI_CFLAGS/NDPI_LDFLAGS instead of the standard CFLAGS/LDFLAGS
 # See: 7c19de49047a5731f3107ff17854e9afe839cc61 for details
 CFLAGS="${CFLAGS} -I ${HOMEBREW_DIR}/include"
 LDFLAGS="${LDFLAGS} -L ${HOMEBREW_DIR}/lib"
fi

if ! test "${with_only_libndpi+set}" = set; then :
    dnl> used by json-c for unit tests
    PKG_CHECK_MODULES([JSONC], [json-c], [
        AC_DEFINE(HAVE_LIBJSON_C, 1, [libjson-c is present])
        JSONC_LIBS="${pkg_cv_JSONC_LIBS}"
        JSONC_CFLAGS="${pkg_cv_JSONC_CFLAGS}"
    ], [AC_MSG_WARN([JSON-C not available. Disabled unit test.])])
    AC_CHECK_LIB([json-c], [json_object_put], [
        EXTRA_TARGETS="$EXTRA_TARGETS tests/unit"
        build_unittests=yes
    ],[
        AC_MSG_WARN([JSON-C not available. Disabled unit test.])
        JSONC_LIBS=""
        JSONC_CFLAGS=""
    ])
    dnl> AX_PTHREAD test does not work along with MingW/MSYS anymore
    case "$host" in
      *-*-mingw32*|*-*-msys)
      ;;
      *)
        AX_PTHREAD([],[
            AC_MSG_WARN([POSIX Threads not available. Building library only.])
            JSONC_LIBS=""
            JSONC_CFLAGS=""
            EXTRA_TARGETS=""
        ])
      ;;
    esac
fi
AM_CONDITIONAL([BUILD_UNITTESTS], [test "x$build_unittests" = "xyes"])

HANDLE_TLS_SIGS="//"
AS_IF([test "x${enable_tls_sigs}" = "xyes"],[
  HANDLE_TLS_SIGS=""
])

AS_IF([test "${with_lto_and_gold_linker+set}" = set], [
       NDPI_CFLAGS="${NDPI_CFLAGS} -flto -fuse-ld=gold -Wno-unused-command-line-argument"
       NDPI_LDFLAGS="${NDPI_LDFLAGS} ${NDPI_CFLAGS}"
])

AC_CHECK_HEADERS([netinet/in.h stdint.h stdlib.h string.h unistd.h math.h float.h])
AC_CHECK_LIB([m], [sqrt], [], [LIBM="-lm"])
AC_CHECK_LIB([rrd], [rrd_fetch_r], [LIBRRD=-lrrd])

if test "x$ac_cv_lib_rrd_rrd_fetch_r" = xyes; then :
   AC_DEFINE_UNQUOTED(HAVE_RRDTOOL, "1", [rrdtool is present])
   EXTRA_TARGETS="$EXTRA_TARGETS rrdtool"
fi

GLOBAL_CONTEXT_ENABLED=0
AS_IF([test "x$enable_global_context_support" != "xno"], [
  AC_CHECK_LIB([pthread], [pthread_mutex_init])
  NDPI_CFLAGS="${NDPI_CFLAGS} -DUSE_GLOBAL_CONTEXT"
  GLOBAL_CONTEXT_ENABLED=1
])

ADDITIONAL_INCS=
ADDITIONAL_LIBS="$LIBM"
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

NBPF_ENABLED=0
AC_MSG_CHECKING([PF_RING nBPF ($NBPF_HOME)])
LIBNBPF=${NBPF_HOME}/libnbpf.a
if test -f ${LIBNBPF}; then :
   ADDITIONAL_LIBS="${ADDITIONAL_LIBS} ${LIBNBPF}"
   ADDITIONAL_INCS="${ADDITIONAL_INCS} -I${NBPF_HOME}"
   AC_DEFINE_UNQUOTED(HAVE_NBPF, "1", [PF_RING nBPF is present])
   AC_MSG_RESULT(yes)
   NBPF_ENABLED=1
else
   AC_MSG_RESULT(no)
fi

CUSTOM_NDPI=
if test -d ../nDPI-custom; then :
   CUSTOM_NDPI="-DCUSTOM_NDPI_PROTOCOLS"
   AC_MSG_RESULT([Compiling with custom nDPI protocols])
fi

case "$host" in
   *-*-mingw32*|*-*-msys)
      PCAP_INC=""
      PCAP_LIB=""
      case "$host" in
        x86_64-*)
          BUILD_MINGW_X64=1
          NDPI_LDFLAGS="${NDPI_LDFLAGS} -L/mingw64/lib"
        ;;
        i686-*)
          NDPI_LDFLAGS="${NDPI_LDFLAGS} -L/mingw32/lib"
        ;;
        *)
          AC_MSG_ERROR([Unsupported MingW cross compiler.])
        ;;
      esac
      NDPI_CFLAGS="-D__USE_MINGW_ANSI_STDIO -D__STDC_FORMAT_MACROS ${NDPI_CFLAGS}"
      LIBS="${LIBS} -lws2_32"
      BUILD_MINGW=1
      EXE_SUFFIX=".exe"
      AS_IF([test "${enable_npcap+set}" != set && test "${with_only_libndpi+set}" != set],,
            [PKG_CHECK_MODULES([PCAP], [libpcap], [PCAP_LIB="" PCAP_INC="${pkg_cv_PCAP_CFLAGS}"])
             AC_CHECK_LIB([pcap], [pcap_open_live],, [AC_MSG_ERROR([Missing msys2/mingw libpcap library. Install it with `pacman -S mingw-w64-x86_64-libpcap' (msys2).])])])
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
      EXE_SUFFIX=""
      AS_IF([test "${enable_npcap+set}" = set],AC_MSG_ERROR([--disable-npcap does only work with msys2/mingw CCs]))
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

GPROF_ENABLED=0
AS_IF([test "x$enable_gprof" = "xyes"], [
    PKG_CHECK_MODULES([PROFILER], [libprofiler],,[
        AC_MSG_ERROR([libprofiler not available. Required for profiling support.])
    ])
    PKG_CHECK_MODULES([TCMALLOC], [libtcmalloc],,[
        AC_MSG_ERROR([libtcmalloc not available. Required for profiling support.])
    ])
    GPROF_ENABLED=1
    GPROF_LIBS="-ltcmalloc_and_profiler"
    GPROF_CFLAGS="-g3 -fvisibility=default -fno-omit-frame-pointer ${pkg_cv_PROFILER_CFLAGS} ${pkg_cv_TCMALLOC_CFLAGS}"
])

AC_CHECK_LIB(pthread, pthread_setaffinity_np, AC_DEFINE_UNQUOTED(HAVE_PTHREAD_SETAFFINITY_NP, 1, [libc has pthread_setaffinity_np]))

dnl> libgcrypt (external)
USE_HOST_LIBGCRYPT=0
AS_IF([test "${with_local_libgcrypt+set}" = set],[
  USE_HOST_LIBGCRYPT=1
  AC_CHECK_LIB(gpg-error, gpg_strerror_r, [], AC_MSG_ERROR([libgpg-error required (because of --with-local-libgcrypt) but not found or too old.]))
  AC_CHECK_LIB(gcrypt, gcry_cipher_checktag, [], AC_MSG_ERROR([libgcrypt required (because of --with-local-libgcrypt) but not found or too old.]))
  ADDITIONAL_LIBS="${ADDITIONAL_LIBS} -lgcrypt -lgpg-error"
  AC_DEFINE_UNQUOTED(USE_HOST_LIBGCRYPT, 1, [Use locally installed libgcrypt instead of builtin gcrypt-light])
])

dnl> PCRE2
PCRE2_ENABLED=0
AC_ARG_WITH(pcre2, AS_HELP_STRING([--with-pcre2], [Enable nDPI build with libpcre2]))
if test "${with_pcre2+set}" = set; then :
  AC_CHECK_LIB(pcre2-8, pcre2_compile_8, AC_DEFINE_UNQUOTED(HAVE_PCRE2, 1, [libpcre2(-dev) is present]))
  if test "x$ac_cv_lib_pcre2_8_pcre2_compile_8" = xyes; then :
    ADDITIONAL_LIBS="${ADDITIONAL_LIBS} -lpcre2-8"
    PCRE2_ENABLED=1
  fi
fi

dnl> GeoIP
AC_ARG_WITH(maxminddb, AS_HELP_STRING([--with-maxminddb], [Enable nDPI build with libmaxminddb]))
if test "${with_maxminddb+set}" = set; then :
  AC_CHECK_LIB([maxminddb], [MMDB_lookup_sockaddr])
  AC_CHECK_HEADERS([maxminddb.h])
  if test ".${ac_cv_lib_maxminddb_MMDB_lookup_sockaddr}" = ".yes" && test ".${ac_cv_header_maxminddb_h}" = ".yes"; then
    ADDITIONAL_LIBS="${ADDITIONAL_LIBS} -lmaxminddb"
    AC_DEFINE_UNQUOTED(HAVE_MAXMINDDB, 1, [MaxMind DB support])
  fi
fi

AC_DEFINE_UNQUOTED(NDPI_BASE_DIR, "${PWD}", [nDPI base directory])

dnl> Curl
dnl> AC_CHECK_LIB([curl], [curl_easy_perform])
dnl> if test ${ac_cv_lib_curl_curl_easy_perform} = "no"; then
dnl>    echo "Please install libcurl4-openssl-dev (http://curl.haxx.se/) in order to enable curl support"
dnl> else
dnl>   ADDITIONAL_LIBS="${ADDITIONAL_LIBS} -lcurl"
dnl>   AC_DEFINE_UNQUOTED(HAVE_CURL, 1, [curl is present])
dnl> fi

AC_CONFIG_FILES([Makefile example/Makefile example/Makefile.dpdk tests/Makefile tests/unit/Makefile tests/performance/Makefile tests/dga/Makefile rrdtool/Makefile influxdb/Makefile libndpi.pc src/include/ndpi_define.h src/lib/Makefile fuzz/Makefile doc/Doxyfile.cfg])
AC_CONFIG_FILES([tests/do.sh], [chmod +x tests/do.sh])
AC_CONFIG_HEADERS(src/include/ndpi_config.h)
AC_SUBST(GIT_RELEASE)
AC_SUBST(NDPI_MAJOR)
AC_SUBST(NDPI_MINOR)
AC_SUBST(NDPI_PATCH)
AC_SUBST(NDPI_VERSION_SHORT)
AC_SUBST(PCAP_INC)
AC_SUBST(PCAP_LIB)
AC_SUBST(LIBRRD)
AC_SUBST(ADDITIONAL_INCS)
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
AC_SUBST(GPROF_CFLAGS)
AC_SUBST(GPROF_LIBS)
AC_SUBST(GPROF_ENABLED)
AC_SUBST(USE_HOST_LIBGCRYPT)
AC_SUBST(PCRE2_ENABLED)
AC_SUBST(NBPF_ENABLED)
AC_SUBST(GLOBAL_CONTEXT_ENABLED)
AC_SUBST(HANDLE_TLS_SIGS)
AC_SUBST(DISABLE_NPCAP)
AC_SUBST(EXE_SUFFIX)
AC_SUBST(NDPI_CFLAGS)
AC_SUBST(NDPI_LDFLAGS)
AC_SUBST(NDPI_BASE_DIR)
AC_OUTPUT
