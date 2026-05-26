AC_INIT([libndpi],[5.1.0])

AC_CONFIG_AUX_DIR([.])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign subdir-objects parallel-tests])

AC_PREFIX_DEFAULT(/usr)

EXTRA_TARGETS="example tests tests/dga"
AC_ARG_WITH(only-libndpi, AS_HELP_STRING([--with-only-libndpi], [Build only libndpi (no examples, tests etc)]))
AS_IF([test "${with_only_libndpi+set}" = set],[
  EXTRA_TARGETS=""
])


AC_ARG_WITH(sanitizer, AS_HELP_STRING([--with-sanitizer], [Build with support for address, undefined and leak sanitizer]))
AC_ARG_WITH(thread-sanitizer, AS_HELP_STRING([--with-thread-sanitizer], [Build with support for thread sanitizer]))
AC_ARG_WITH(memory-sanitizer, AS_HELP_STRING([--with-memory-sanitizer], [Build with support for memory sanitizer]))
AC_ARG_WITH(macos-memory-sanitizer, AS_HELP_STRING([--with-macos-memory-sanitizer], [Build with support for memory sanitizer macOS]))
AC_ARG_ENABLE(fuzztargets, AS_HELP_STRING([--enable-fuzztargets], [Enable fuzz targets]),[enable_fuzztargets=$enableval],[enable_fuzztargets=no])
AC_ARG_ENABLE(gprof, AS_HELP_STRING([--enable-gprof], [Enable CPU/HEAP profiling with gperftools]),[enable_gprof=$enableval],[enable_gprof=no])
AC_ARG_ENABLE(code-coverage, AS_HELP_STRING([--enable-code-coverage], [Generate Code Coverage report]))
AC_ARG_WITH(local-libgcrypt, AS_HELP_STRING([--with-local-libgcrypt], [Build with libgcrypt (if present) instead of the enclosed gcrypt light]))
AC_ARG_ENABLE(npcap, AS_HELP_STRING([--disable-npcap], [msys2 only: Disable linkage against the wpcap/npcap import library in windows/WpdPack/Lib.]))
AC_ARG_WITH(nbpf-path, AS_HELP_STRING([--with-nbpf-path], [nBPF library custom path; default: ${srcdir}/../PF_RING/userland/nbpf]),[NBPF_HOME=$withval],[NBPF_HOME="`cd ${srcdir}/../PF_RING/userland/nbpf 2>/dev/null && pwd || echo ${srcdir}/../PF_RING/userland/nbpf`"])
AC_ARG_WITH(libpcap, AS_HELP_STRING([--with-libpcap=PATH], [Linux only: Custom path to libpcap installation]),[LIBPCAP_PATH=$withval],[LIBPCAP_PATH=""])
AC_ARG_WITH(lto-and-gold-linker, AS_HELP_STRING([--with-lto-and-gold-linker], [Build with LTO and Gold linker]))
AC_ARG_ENABLE(debug-build, AS_HELP_STRING([--enable-debug-build], [Enable debug build (`-g` flag)]),[enable_debugbuild=$enableval],[enable_debugbuild=no])
AC_ARG_ENABLE(plugin-support, AS_HELP_STRING([--disable-plugin-support], [Disable plugin system]))
AC_ARG_ENABLE(global-context-support, AS_HELP_STRING([--disable-global-context-support], [Disable support for global context. No external dependency on libpthread]))
AC_ARG_ENABLE(memory-track-origins, AS_HELP_STRING([--disable-memory-track-origins], [Don't add -fsanitize-memory-track-origins flag when compiling with MASAN support. Useful for faster CI]))
AC_ARG_ENABLE(old-croaring, AS_HELP_STRING([--enable-old-croaring], [Always use old croaring version, instead of try to auto-detect if v4 works. Useful with old compilers]),[enable_oldcroaring=$enableval],[enable_oldcroaring=no])
AC_ARG_ENABLE(usdt-probes, AS_HELP_STRING([--enable-usdt-probes], [Enable USDT/DTrace static tracing probes]),[enable_usdt_probes=$enableval],[enable_usdt_probes=no])

AS_IF([test "x$enable_usdt_probes" = "xyes"], [
  AC_CHECK_HEADER([sys/sdt.h], [
    AC_DEFINE([HAVE_USDT], [1], [Define if USDT probes are enabled])
  ], [
    AC_MSG_ERROR([--enable-usdt-probes requires sys/sdt.h (install systemtap-sdt-dev)])
  ])
])

#These two variables are not supposed to be set/changed by the user:
#he should use standard CFLAGS/LDFLAGS, instead
NDPI_CFLAGS="-D_DEFAULT_SOURCE=1 -D_GNU_SOURCE=1"
NDPI_LDFLAGS=""

AS_IF([test "x$enable_fuzztargets" = "xyes"], [
  BUILD_FUZZTARGETS=1
  NDPI_CFLAGS="${NDPI_CFLAGS} -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
], [BUILD_FUZZTARGETS=0])
AM_CONDITIONAL([BUILD_FUZZTARGETS], [test "x$enable_fuzztargets" = "xyes"])

AS_IF([test "x$enable_debugbuild" = "xyes"], [
  NDPI_CFLAGS="${NDPI_CFLAGS} -g"
])

AS_IF([test "${with_sanitizer+set}" = set -a "${with_thread_sanitizer+set}" = set],[
  AC_MSG_ERROR([Configure options `--with-sanitizer' and `--with-thread-sanitizer' can not used at the same time.])
])
AS_IF([test "${with_sanitizer+set}" = set -a "${with_memory_sanitizer+set}" = set],[
  AC_MSG_ERROR([Configure options `--with-sanitizer' and `--with-memory-sanitizer' can not used at the same time.])
])
AS_IF([test "${with_thread_sanitizer+set}" = set -a "${with_memory_sanitizer+set}" = set],[
  AC_MSG_ERROR([Configure options `--with-thread-sanitizer' and `--with-memory-sanitizer' can not used at the same time.])
])
AS_IF([test "${with_sanitizer+set}" = set -o "${with_thread_sanitizer+set}" = set -o "${with_memory_sanitizer+set}" = set],[
  NDPI_CFLAGS="${NDPI_CFLAGS} -O0 -g3"
])
AS_IF([test "${with_sanitizer+set}" = set -o "${with_thread_sanitizer+set}" = set -o "${with_memory_sanitizer+set}" = set],[
  AS_IF([test "x$enable_gprof" = "xyes"], [
    AC_MSG_ERROR([Configure options `--with-sanitizer' / `--with-thread-sanitizer' / `--with-memory-sanitizer' can not used together with `--enable-gprof'.])
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

AC_PATH_PROG([FILECMD], [file])
AC_PATH_PROG([MANIFEST_TOOL], [mt], [:])
LT_INIT
LT_LIB_M

# Ensure at least one library type is enabled
AS_IF([test "x${enable_shared}" = "xno" -a "x${enable_static}" = "xno"],[
  AC_MSG_ERROR([Cannot disable both shared and static libraries. At least one must be enabled.])
])

# Fuzz targets require static library
AS_IF([test "x${enable_fuzztargets}" = "xyes" -a "x${enable_static}" = "xno"],[
  AC_MSG_ERROR([--enable-fuzztargets requires static library. Cannot use with --disable-static.])
])

# Detect build and host system for cross-compilation support
# Must be called early, before AC_PROG_CC
AC_CANONICAL_HOST

PKG_PROG_PKG_CONFIG

# Prefer clang on Darwin if user didn't explicitly set CC.
# Must be done before AC_PROG_CC so the preference takes effect.
case "$host_os" in
  darwin*)
    : ${CC:=clang}
    : ${CXX:=clang++}
    ;;
esac

AC_PROG_CC
AC_C_INLINE

case "$host_os" in
  darwin*)
    AM_PROG_CC_C_O
    AC_PROG_CXX
    ;;
  *)
    AC_PROG_CC_C_O
    AC_PROG_CXX
    ;;
esac

# Warn when cross-compiling without proper sysroot/pkg-config setup.
# PKG_PROG_PKG_CONFIG uses AC_PATH_TOOL so it finds ${host}-pkg-config,
# but PKG_CONFIG_SYSROOT_DIR / PKG_CONFIG_LIBDIR must still be set for
# the target sysroot. Build-host paths (Homebrew, DPDK, PCAP_HOME with
# PF_RING) are also silently wrong for the target in this case.
AS_IF([test "$cross_compiling" = yes], [
  AC_MSG_WARN([Cross-compiling: build=$build -> host=$host])
  AS_IF([test -z "$PKG_CONFIG_SYSROOT_DIR" -a -z "$PKG_CONFIG_LIBDIR"], [
    AC_MSG_WARN([PKG_CONFIG_SYSROOT_DIR and PKG_CONFIG_LIBDIR are not set.])
    AC_MSG_WARN([pkg-config may query the build host instead of the target sysroot.])
    AC_MSG_WARN([Set PKG_CONFIG_SYSROOT_DIR and PKG_CONFIG_LIBDIR for correct library detection.])
  ])
  AC_MSG_WARN([Build-host paths (Homebrew, DPDK, PCAP_HOME with PF_RING) may not apply to the target.])
])

dnl> Can't use AM_PROG_AR because not all of our Makefiles are automake (yet?)
AC_CHECK_TOOL(AR, ar, [false])
AC_CHECK_TOOL([RANLIB], [ranlib], [:])

# Set OS_TYPE for Makefiles based on host system
case "$host_os" in
  darwin*)
    OS_TYPE="Darwin"
    ;;
  mingw*|msys*)
    OS_TYPE="Windows_NT"
    ;;
  *)
    OS_TYPE="Unix"
    ;;
esac
AC_SUBST(OS_TYPE)

if test "x$OS_TYPE" = "xDarwin"; then
   NDPI_CFLAGS="${NDPI_CFLAGS} -fno-color-diagnostics -fPIE"
   NDPI_LDFLAGS="${NDPI_LDFLAGS} -fno-color-diagnostics -fPIE"
fi

#We should use latest croaring version, but with old compilers we need to
#fallback to old/legacy code
AS_IF([test "x${enable_oldcroaring}" = "xyes"], [
  NDPI_CFLAGS="${NDPI_CFLAGS} -DUSE_OLD_ROARING"
  USE_OLD_ROARING=yes
  echo "Using old croaring (forced by user)"
], [
  # Test if the compiler supports C11 atomics (required by roaring v4)
  # Roaring v4 requires __STDC_VERSION__ >= 201112L and working C11 atomics
  AC_MSG_CHECKING([whether C compiler supports C11 atomics for roaring v4])
  AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
    #include <stdatomic.h>
    #if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L
    #error "C11 not supported"
    #endif
    #if defined(__STDC_NO_ATOMICS__)
    #error "C11 atomics not supported"
    #endif
    typedef _Atomic(unsigned int) test_atomic_t;
    int main() {
      test_atomic_t val = 0;
      atomic_fetch_add_explicit(&val, 1, memory_order_relaxed);
      return atomic_load_explicit(&val, memory_order_relaxed);
    }
  ]])], [
    AC_MSG_RESULT(yes)
    echo "Using croaring v4 (autodetect: C11 atomics available)"
  ], [
    AC_MSG_RESULT(no)
    NDPI_CFLAGS="${NDPI_CFLAGS} -DUSE_OLD_ROARING"
    USE_OLD_ROARING=yes
    echo "Using old croaring (autodetect: C11 atomics not available)"
  ])
])


NDPI_MAJOR=`echo "${PACKAGE_VERSION}" | cut -d . -f 1`
NDPI_MINOR=`echo "${PACKAGE_VERSION}" | cut -d . -f 2`
NDPI_PATCH=`echo "${PACKAGE_VERSION}" | cut -d . -f 3`
NDPI_VERSION_SHORT="$NDPI_MAJOR.$NDPI_MINOR.$NDPI_PATCH"

AC_DEFINE_UNQUOTED(NDPI_MAJOR_RELEASE, "${NDPI_MAJOR}", [nDPI major release])
AC_DEFINE_UNQUOTED(NDPI_MINOR_RELEASE, "${NDPI_MINOR}", [nDPI minor release])
AC_DEFINE_UNQUOTED(NDPI_PATCH_LEVEL,   "${NDPI_PATCH}", [nDPI patch level])

# .git as directory in a cloned repo
# .git as file in submodule based integration
# Improved git detection with better error handling
if test -d "${srcdir}/.git" || test -r "${srcdir}/.git"; then
     # Check if git command is available
     if command -v git >/dev/null 2>&1; then
          GIT_TAG=`cd ${srcdir} && git log -1 --abbrev=7 --format=%h 2>/dev/null || echo "unknown"`
          GIT_DATE=`cd ${srcdir} && git log -1 --abbrev=7 --format=%cd 2>/dev/null || date -u`
          #
          # On CentOS 6 `git rev-list HEAD --count` does not work
          #
          #
          GIT_NUM=`cd ${srcdir} && git log --pretty=oneline 2>/dev/null | wc -l | tr -d '[[:space:]]'`

          # Fallback to 0 if git commands failed
          if test -z "${GIT_NUM}" || test "${GIT_NUM}" = "0"; then
               GIT_NUM="0"
               AC_MSG_WARN([Could not determine git commit count, using 0])
          fi

          GIT_RELEASE="${PACKAGE_VERSION}-${GIT_NUM}-${GIT_TAG}"

          A=`cd ${srcdir} && git log src/include/ndpi_typedefs.h 2>/dev/null|wc -l`
          B=`cd ${srcdir} && git log src/include/ndpi_protocol_ids.h 2>/dev/null|wc -l`
          C=`cd ${srcdir} && git log src/include/ndpi_api.h 2>/dev/null|wc -l`
          NDPI_API_VERSION=$((A+B+C))
     else
          AC_MSG_WARN([Git repository detected but git command not found])
          GIT_RELEASE="${PACKAGE_VERSION}"
          GIT_TAG="nogit"
          GIT_DATE=`date -u`
          # Use SOURCE_DATE_EPOCH or current timestamp for reproducible builds
          if test -z "$SOURCE_DATE_EPOCH" ; then :
               SOURCE_DATE_EPOCH=`date +%s`
          fi
          NDPI_API_VERSION=$((SOURCE_DATE_EPOCH % 65536))
     fi
else
     GIT_RELEASE="${PACKAGE_VERSION}"
     GIT_TAG="tarball"
     # Better fallback for GIT_DATE when not in git repo
     if test -f "${srcdir}/CHANGELOG.md"; then
          GIT_DATE=`stat -c '%y' "${srcdir}/CHANGELOG.md" 2>/dev/null || \
                    stat -f '%Sm' "${srcdir}/CHANGELOG.md" 2>/dev/null || \
                    date -u`
     else
          GIT_DATE=`date -u`
          AC_MSG_WARN([CHANGELOG.md not found, using current date])
     fi
     # Use SOURCE_DATE_EPOCH for reproducible builds, with better fallback
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

NDPI_CFLAGS="-W -Wall -Wextra -Wno-address-of-packed-member ${NDPI_CFLAGS}"

dnl> MacOS brew.sh
HOMEBREW_DIR=/opt/homebrew
if test -d "$HOMEBREW_DIR" && test "$cross_compiling" != yes; then
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
    dnl > RRD (optional dependency)
    AC_CHECK_LIB([rrd], [rrd_fetch_r], [LIBRRD=-lrrd], [
        AC_MSG_WARN([librrd not found. RRDtool support will be disabled.])
        AC_MSG_WARN([Install librrd-dev or rrdtool-devel to enable RRDtool integration.])
    ])
    if test "x$ac_cv_lib_rrd_rrd_fetch_r" = xyes; then :
        AC_DEFINE_UNQUOTED(HAVE_RRDTOOL, "1", [rrdtool is present])
        EXTRA_TARGETS="$EXTRA_TARGETS rrdtool"
    fi
fi
AM_CONDITIONAL([BUILD_UNITTESTS], [test "x$build_unittests" = "xyes"])

AS_IF([test "${with_lto_and_gold_linker+set}" = set], [
       NDPI_CFLAGS="${NDPI_CFLAGS} -flto -fuse-ld=gold -Wno-unused-command-line-argument"
       NDPI_LDFLAGS="${NDPI_LDFLAGS} ${NDPI_CFLAGS}"
])

AC_CHECK_HEADERS([netinet/in.h stdint.h stdlib.h string.h unistd.h math.h float.h])
AC_CHECK_LIB([m], [sqrt], [], [LIBM="-lm"])

GLOBAL_CONTEXT_ENABLED=0
AS_IF([test "x$enable_global_context_support" != "xno"], [
  AC_CHECK_LIB([pthread], [pthread_mutex_init])
  NDPI_CFLAGS="${NDPI_CFLAGS} -DUSE_GLOBAL_CONTEXT"
  GLOBAL_CONTEXT_ENABLED=1
])

PLUGINS_ENABLED=1
AS_IF([test "x$enable_plugin_support" = "xno"], [
  PLUGINS_ENABLED=0
])
AS_IF([test "x${enable_shared}" = "xno"],[
  AC_MSG_WARN([plugins require shared library.])
  PLUGINS_ENABLED=0
])

ADDITIONAL_INCS="${ADDITIONAL_INCS}"
ADDITIONAL_LIBS="${ADDITIONAL_LIBS}"
PCAP_HOME=$HOME/PF_RING/userland

DPDK_TARGET=
AC_MSG_CHECKING([DPDK (used by ndpiReader)])
if test -d "$HOME/DPDK"; then :
      AC_MSG_RESULT(yes)
     DPDK_TARGET=dpdk
else
     AC_MSG_RESULT([no (missing $HOME/DPDK)])
fi

if ! test -d "$PCAP_HOME"; then :
     PCAP_HOME=${srcdir}/../../PF_RING/userland
fi

AC_CHECK_LIB([numa], [numa_available], [LIBNUMA="-lnuma"], [
    AC_MSG_WARN([libnuma not found. NUMA optimizations will be disabled.])
    AC_MSG_WARN([Install libnuma-dev or numactl-devel for better performance on NUMA systems.])
])

# Set MACHINE from host_cpu for compatibility with existing code
MACHINE="$host_cpu"
AC_SUBST(MACHINE)

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
if test -d ${srcdir}/../nDPI-custom; then :
   CUSTOM_NDPI="-DCUSTOM_NDPI_PROTOCOLS"
   AC_MSG_RESULT([Compiling with custom nDPI protocols])
fi

case "$host" in
   *-*-mingw32*|*-*-msys)
      PCAP_INC=""
      PCAP_LIB=""
      PLUGINS_ENABLED=0
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
      if test -n "$LIBPCAP_PATH"; then :
         echo "Using custom libpcap from $LIBPCAP_PATH"
         PCAP_INC="-I $LIBPCAP_PATH/include"

         dnl> Check for libpcap in custom path (prefer static library)
         if test -f "$LIBPCAP_PATH/lib/libpcap.a"; then :
            PCAP_LIB="$LIBPCAP_PATH/lib/libpcap.a"
            echo "  Found static library: $LIBPCAP_PATH/lib/libpcap.a"
         elif test -f "$LIBPCAP_PATH/lib64/libpcap.a"; then :
            PCAP_LIB="$LIBPCAP_PATH/lib64/libpcap.a"
            echo "  Found static library: $LIBPCAP_PATH/lib64/libpcap.a"
         elif test -f "$LIBPCAP_PATH/lib/libpcap.so"; then :
            PCAP_LIB="-L$LIBPCAP_PATH/lib -lpcap"
            echo "  Found shared library: $LIBPCAP_PATH/lib/libpcap.so"
         elif test -f "$LIBPCAP_PATH/lib/libpcap.dylib"; then :
            PCAP_LIB="-L$LIBPCAP_PATH/lib -lpcap"
            echo "  Found shared library: $LIBPCAP_PATH/lib/libpcap.dylib"
         else
            AC_MSG_ERROR([libpcap not found in specified path: $LIBPCAP_PATH. Please check that libpcap is installed in this location with lib/ and include/ subdirectories.])
         fi

         dnl> Try to get additional dependencies from pkg-config if available
         if test -f "$LIBPCAP_PATH/lib/pkgconfig/libpcap.pc"; then :
            ax_save_pkg_config_path="$PKG_CONFIG_PATH"
            export PKG_CONFIG_PATH="$LIBPCAP_PATH/lib/pkgconfig:$PKG_CONFIG_PATH"
            PKG_CHECK_MODULES([PCAP_DEPS], [libpcap], [
               PCAP_PRIVATE_LIBS=`"$PKG_CONFIG" --libs --static libpcap | sed "s|-L$LIBPCAP_PATH/lib *||" | sed 's|-lpcap *||'`
               PCAP_LIB="$PCAP_LIB $PCAP_PRIVATE_LIBS"
               echo "  Added dependencies from pkg-config: $PCAP_PRIVATE_LIBS"
            ], [
               echo "  Warning: Could not get dependencies from pkg-config, using defaults"
            ])
            PKG_CONFIG_PATH="$ax_save_pkg_config_path"
            export PKG_CONFIG_PATH
         fi
      elif test -f $PCAP_HOME/libpcap/libpcap.a; then :
         echo "Using libpcap from $PCAP_HOME"
         PCAP_INC="-I $PCAP_HOME/libpcap"
	 PFRING_LIB=
	 if test -f $PCAP_HOME/lib/libpfring.a; then :
   	   PFRING_LIB=$PCAP_HOME/lib/libpfring.a
	 fi
	 
         PFRING_CONFIG_LIBS=""
         AS_IF([test -x "$PCAP_HOME/lib/pfring_config"], [
           PFRING_CONFIG_LIBS=`"$PCAP_HOME/lib/pfring_config" --libs 2>/dev/null`
         ])
         PCAP_LIB="$PCAP_HOME/libpcap/libpcap.a $PFRING_LIB $LIBNUMA $PFRING_CONFIG_LIBS"
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

dnl> PCRE2 (optional dependency)
PCRE2_ENABLED=0
AC_ARG_WITH(pcre2, AS_HELP_STRING([--with-pcre2], [Enable nDPI build with libpcre2]))
if test "${with_pcre2+set}" = set; then :
  AC_CHECK_LIB(pcre2-8, pcre2_compile_8, [
    AC_DEFINE_UNQUOTED(HAVE_PCRE2, 1, [libpcre2(-dev) is present])
  ], [
    AC_MSG_WARN([libpcre2-8 not found. PCRE2 support requested but unavailable.])
    AC_MSG_WARN([Install libpcre2-dev to enable advanced pattern matching features.])
  ])

 if test "x$ac_cv_lib_pcre2_8_pcre2_compile_8" = xyes; then :
   ADDITIONAL_LIBS="${ADDITIONAL_LIBS} -lpcre2-8"
   PCRE2_ENABLED=1
 fi
fi

dnl> GeoIP (optional dependency)
AC_ARG_WITH(maxminddb, AS_HELP_STRING([--with-maxminddb], [Enable nDPI build with libmaxminddb]))
if test "${with_maxminddb+set}" = set; then :
  AC_CHECK_LIB([maxminddb], [MMDB_lookup_sockaddr], [], [
    AC_MSG_WARN([libmaxminddb not found. GeoIP support requested but unavailable.])
    AC_MSG_WARN([Install libmaxminddb-dev to enable geographic IP lookups.])
  ])
  AC_CHECK_HEADERS([maxminddb.h], [], [
    AC_MSG_WARN([maxminddb.h header not found.])
  ])
  if test ".${ac_cv_lib_maxminddb_MMDB_lookup_sockaddr}" = ".yes" && test ".${ac_cv_header_maxminddb_h}" = ".yes"; then
    ADDITIONAL_LIBS="${ADDITIONAL_LIBS} -lmaxminddb"
    AC_DEFINE_UNQUOTED(HAVE_MAXMINDDB, 1, [MaxMind DB support])
  fi
fi

AS_IF([test "x${PLUGINS_ENABLED}" = "x1"], [
  AC_DEFINE_UNQUOTED(HAVE_PLUGINS, "1", [plugins are supported])
  AC_CHECK_LIB([dl], [dlopen], [LIBDL="-ldl"])
])
AM_CONDITIONAL([PLUGINS_ENABLED], [test "x${PLUGINS_ENABLED}" = "x1"])

dnl> Add base system libraries last (lowest-level dependencies)
dnl> This ensures proper linking order: high-level libs -> low-level libs
ADDITIONAL_LIBS="${ADDITIONAL_LIBS} $LIBM $LIBDL"

AC_CONFIG_FILES([Makefile example/Makefile example/Makefile.dpdk tests/Makefile tests/unit/Makefile tests/performance/Makefile tests/dga/Makefile rrdtool/Makefile influxdb/Makefile libndpi.pc libndpi-uninstalled.pc src/include/ndpi_define.h src/lib/Makefile src/lib/plugins/Makefile fuzz/Makefile doc/Doxyfile.cfg utils/Makefile])
AC_CONFIG_FILES([tests/do.sh], [chmod +x tests/do.sh])
AC_CONFIG_FILES([tests/do-dga.sh], [chmod +x tests/do-dga.sh])
AC_CONFIG_FILES([tests/do-unit.sh], [chmod +x tests/do-unit.sh])
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
AC_SUBST(PLUGINS_ENABLED)
AC_SUBST(DISABLE_NPCAP)
AC_SUBST(EXE_SUFFIX)
AC_SUBST(NDPI_CFLAGS)
AC_SUBST(NDPI_LDFLAGS)
AC_SUBST(enable_shared)
AC_SUBST(enable_static)
AC_OUTPUT

dnl> ========================================================================
dnl> Configuration Summary
dnl> ========================================================================

dnl> Build summary message dynamically
SUMMARY="
========================================================================
nDPI Configuration Summary
========================================================================

Package Information:
  Version:                 ${PACKAGE_VERSION} (${GIT_RELEASE})
  API Version:             ${NDPI_API_VERSION}
  Git Date:                ${GIT_DATE}

Installation Paths:
  Prefix:                  ${prefix}
  Exec prefix:             ${exec_prefix}
  Library path:            ${libdir}
  Include path:            ${includedir}
  Binary path:             ${bindir}

Build Configuration:
  Host system:             ${host}
  C Compiler:              ${CC}
  C++ Compiler:            ${CXX}"

AS_IF([test "x${enable_debugbuild}" = "xyes"],
  [SUMMARY="${SUMMARY}
  Debug build:             enabled (-g)"],
  [SUMMARY="${SUMMARY}
  Debug build:             disabled"])

AS_IF([test "${with_sanitizer+set}" = set],
  [SUMMARY="${SUMMARY}
  Sanitizers:              address, undefined, leak"],
  [AS_IF([test "${with_thread_sanitizer+set}" = set],
    [SUMMARY="${SUMMARY}
  Sanitizers:              thread"],
    [AS_IF([test "${with_memory_sanitizer+set}" = set],
      [SUMMARY="${SUMMARY}
  Sanitizers:              memory"],
      [AS_IF([test "${with_macos_memory_sanitizer+set}" = set],
        [SUMMARY="${SUMMARY}
  Sanitizers:              macOS memory"],
        [SUMMARY="${SUMMARY}
  Sanitizers:              none"])])])])

AS_IF([test "x${enable_code_coverage}" = "xyes"],
  [SUMMARY="${SUMMARY}
  Code coverage:           enabled"],
  [SUMMARY="${SUMMARY}
  Code coverage:           disabled"])

AS_IF([test "${with_lto_and_gold_linker+set}" = set],
  [SUMMARY="${SUMMARY}
  LTO + Gold linker:       enabled"],
  [SUMMARY="${SUMMARY}
  LTO + Gold linker:       disabled"])

AS_IF([test "x${enable_shared}" = "xyes"],
  [SUMMARY="${SUMMARY}
  Shared library:          enabled"],
  [SUMMARY="${SUMMARY}
  Shared library:          disabled"])

AS_IF([test "x${enable_static}" = "xyes"],
  [SUMMARY="${SUMMARY}
  Static library:          enabled"],
  [SUMMARY="${SUMMARY}
  Static library:          disabled"])

AS_IF([test "x${DPDK_TARGET}" = "xdpdk"],
  [SUMMARY="${SUMMARY}
  DPDK support:            enabled"],
  [SUMMARY="${SUMMARY}
  DPDK support:            disabled"])

AS_IF([test "x${GPROF_ENABLED}" = "x1"],
  [SUMMARY="${SUMMARY}
  gperftools profiling:    enabled"],
  [SUMMARY="${SUMMARY}
  gperftools profiling:    disabled"])

SUMMARY="${SUMMARY}

Core Features:"

AS_IF([test "x${PCRE2_ENABLED}" = "x1"],
  [SUMMARY="${SUMMARY}
  PCRE2:                   enabled"],
  [SUMMARY="${SUMMARY}
  PCRE2:                   disabled"])

AS_IF([test "x${NBPF_ENABLED}" = "x1"],
  [SUMMARY="${SUMMARY}
  nBPF:                    enabled (${NBPF_HOME})"],
  [SUMMARY="${SUMMARY}
  nBPF:                    disabled"])

AS_IF([test "x${USE_HOST_LIBGCRYPT}" = "x1"],
  [SUMMARY="${SUMMARY}
  Crypto library:          external libgcrypt"],
  [SUMMARY="${SUMMARY}
  Crypto library:          built-in gcrypt-light"])

AS_IF([test "x${GLOBAL_CONTEXT_ENABLED}" = "x1"],
  [SUMMARY="${SUMMARY}
  Global context:          enabled (with pthread)"],
  [SUMMARY="${SUMMARY}
  Global context:          disabled"])

AS_IF([test "x${PLUGINS_ENABLED}" = "x1"],
  [SUMMARY="${SUMMARY}
  Plugins:                 enabled"],
  [SUMMARY="${SUMMARY}
  Plugins:                 disabled"])

AS_IF([test "x${enable_oldcroaring}" = "xyes"],
  [SUMMARY="${SUMMARY}
  CRoaring version:        legacy (forced)"],
  [AS_IF([test "x${USE_OLD_ROARING}" != "xyes"],
    [SUMMARY="${SUMMARY}
  CRoaring version:        v4 (C11 atomics)"],
    [SUMMARY="${SUMMARY}
  CRoaring version:        legacy (autodetected)"])])

AS_IF([test "x${CUSTOM_NDPI}" = "x-DCUSTOM_NDPI_PROTOCOLS"],
  [SUMMARY="${SUMMARY}
  Custom protocols:        yes (../nDPI-custom)"],
  [SUMMARY="${SUMMARY}
  Custom protocols:        no"])

AS_IF([test "x${enable_usdt_probes}" = "xyes"],
  [SUMMARY="${SUMMARY}
  USDT probes:             enabled"],
  [SUMMARY="${SUMMARY}
  USDT probes:             disabled"])

SUMMARY="${SUMMARY}

Optional Dependencies:"

AS_IF([test "x${ac_cv_lib_maxminddb_MMDB_lookup_sockaddr}" = "xyes" -a "x${ac_cv_header_maxminddb_h}" = "xyes"],
  [SUMMARY="${SUMMARY}
  MaxMindDB (GeoIP):       yes"],
  [SUMMARY="${SUMMARY}
  MaxMindDB (GeoIP):       no"])

AS_IF([test "x${ac_cv_lib_json_c_json_object_put}" = "xyes"],
  [SUMMARY="${SUMMARY}
  JSON-C:                  yes"],
  [SUMMARY="${SUMMARY}
  JSON-C:                  no"])

AS_IF([test "x${ac_cv_lib_rrd_rrd_fetch_r}" = "xyes"],
  [SUMMARY="${SUMMARY}
  RRDtool:                 yes"],
  [SUMMARY="${SUMMARY}
  RRDtool:                 no"])

AS_IF([test "x${LIBNUMA}" = "x-lnuma"],
  [SUMMARY="${SUMMARY}
  libnuma:                 yes"],
  [SUMMARY="${SUMMARY}
  libnuma:                 no"])

SUMMARY="${SUMMARY}

Build Targets:"

AS_IF([test "x${EXTRA_TARGETS}" = "x"],
  [SUMMARY="${SUMMARY}
  Library only:            yes
  Application examples:    no"],
  [SUMMARY="${SUMMARY}
  Library only:            no
  Application examples:    yes"])

AS_IF([test "x${build_unittests}" = "xyes"],
  [SUMMARY="${SUMMARY}
  Unit tests:              yes"],
  [SUMMARY="${SUMMARY}
  Unit tests:              no"])

AS_IF([test "x${enable_fuzztargets}" = "xyes"],
  [SUMMARY="${SUMMARY}
  Fuzz targets:            yes"],
  [SUMMARY="${SUMMARY}
  Fuzz targets:            no"])

SUMMARY="${SUMMARY}

Compiler Flags:
  CFLAGS:                  ${CFLAGS}
  NDPI_CFLAGS:             ${NDPI_CFLAGS}
  LDFLAGS:                 ${LDFLAGS}
  NDPI_LDFLAGS:            ${NDPI_LDFLAGS}
  Additional libs:         ${ADDITIONAL_LIBS}
  PCAP_INC:                ${PCAP_INC}
  PCAP_LIB:                ${PCAP_LIB}

========================================================================
Configuration complete. Now run 'make' to build nDPI.
========================================================================"

AC_MSG_NOTICE([${SUMMARY}])
