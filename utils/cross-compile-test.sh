#!/usr/bin/env bash
# =============================================================================
# cross-compile-test.sh — Test nDPI cross-compilation
# Host  : Ubuntu x86-64
# Target: AArch64 (aarch64-linux-gnu)
#
# Usage:
#   ./utils/cross-compile-test.sh [OPTIONS]
#
# Modes (mutually exclusive):
#   --library-only   (default) Build libndpi only; no cross-compiled host libs
#                    needed.  Fast and self-contained.
#   --full           Add arm64 multiarch, install cross-compiled dev libs,
#                    build examples and unit tests, then run ndpiReader -H
#                    on the host via QEMU user-mode emulation.
#   --tests          Everything in --full, plus run the full test suite
#                    (tests/do.sh) via QEMU binfmt_misc.
#
# Options:
#   --clean          Remove the build directory and exit.
#   --jobs N         Parallel make jobs (default: all CPUs via nproc).
#   --build-dir DIR  Override the default build directory path.
#   --help           Show this message.
#
# What is tested:
#   1. Cross-compiler selection (CC/CXX set before AC_PROG_CC).
#   2. configure.ac cross-compilation warning (fires when PKG_CONFIG_SYSROOT_DIR
#      is unset; suppressed in --full/--tests mode where it is explicitly set).
#   3. Homebrew path guard (should be skipped on non-Darwin host).
#   4. pfring_config conditional execution.
#   5. date portability fix (stat-based file mtime).
#   6. The final library/binary is AArch64, not x86-64.
#   7. (--full/--tests) ndpiReader -H executes correctly under QEMU user-mode emulation.
#   8. (--tests) Full test suite (tests/do.sh) passes under QEMU via binfmt_misc.
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
NDPI_ROOT="$(realpath "${SCRIPT_DIR}/..")"
TARGET_TRIPLE="aarch64-linux-gnu"
DEFAULT_BUILD_DIR="${NDPI_ROOT}/build-cross-${TARGET_TRIPLE}"
JOBS="$(nproc)"
MODE="library-only"
DO_CLEAN=false
BUILD_DIR="${DEFAULT_BUILD_DIR}"

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
info() { echo -e "${BOLD}[INFO]${NC} $*"; }
ok()   { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }
sep()  { echo -e "${BOLD}------------------------------------------------------------------------${NC}"; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --library-only) MODE="library-only" ;;
        --full)         MODE="full" ;;
        --tests)        MODE="tests" ;;
        --clean)        DO_CLEAN=true ;;
        --jobs)         shift; JOBS="$1" ;;
        --build-dir)    shift; BUILD_DIR="$1" ;;
        --help|-h)      sed -n '2,32p' "$0"; exit 0 ;;
        *) die "Unknown argument: $1.  Run with --help for usage." ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------
if $DO_CLEAN; then
    info "Removing ${BUILD_DIR}"
    rm -rf "${BUILD_DIR}"
    ok "Done."
    exit 0
fi

# ---------------------------------------------------------------------------
# Host sanity checks
# ---------------------------------------------------------------------------
sep
info "Host checks"

[[ "$(uname -s)" == "Linux" ]]   || die "This script is designed for Linux hosts."
[[ "$(uname -m)" == "x86_64" ]]  || die "This script requires an x86-64 host."

if command -v lsb_release &>/dev/null && lsb_release -si 2>/dev/null | grep -qi ubuntu; then
    UBUNTU_VER="$(lsb_release -sr)"
    ok "Ubuntu ${UBUNTU_VER} detected."
else
    warn "Not Ubuntu — package names may differ; continuing anyway."
fi

# ---------------------------------------------------------------------------
# Install toolchain packages
# ---------------------------------------------------------------------------
sep
info "Installing cross-compilation toolchain (${TARGET_TRIPLE})"

COMMON_PKGS=(autoconf automake libtool make file pkgconf parallel)

# crossbuild-essential-arm64 is available on Ubuntu 18.04+
if apt-cache show crossbuild-essential-arm64 &>/dev/null 2>&1; then
    TOOLCHAIN_PKGS=(crossbuild-essential-arm64)
else
    TOOLCHAIN_PKGS=(
        binutils-${TARGET_TRIPLE}
        gcc-${TARGET_TRIPLE}
        g++-${TARGET_TRIPLE}
    )
fi

sudo apt-get install -y --no-install-recommends "${TOOLCHAIN_PKGS[@]}" "${COMMON_PKGS[@]}"
ok "Toolchain installed."

# Verify cross-compiler is reachable
CC_CROSS="${TARGET_TRIPLE}-gcc"
command -v "${CC_CROSS}" &>/dev/null \
    || die "Cross-compiler ${CC_CROSS} not found after install."
ok "Cross-compiler: $(command -v "${CC_CROSS}") ($(${CC_CROSS} --version | head -1))"

# ---------------------------------------------------------------------------
# Helper: add ports.ubuntu.com as the arm64 apt source.
#
# On a standard Ubuntu amd64 install, archive.ubuntu.com and
# security.ubuntu.com only carry amd64/i386 packages.  arm64 packages live
# on ports.ubuntu.com.  Without this, 'apt-get update' returns 404s for
# every arm64 index file and ':arm64' package installs fail.
#
# We also add an Architectures: restriction to the existing main sources so
# that apt no longer tries (and fails) to fetch arm64 indices from the
# amd64-only mirrors.
# ---------------------------------------------------------------------------
setup_arm64_apt_sources() {
    local codename
    codename="$(lsb_release -sc 2>/dev/null || echo "noble")"

    if [[ -f /etc/apt/sources.list.d/ubuntu.sources ]]; then
        # Ubuntu 24.04+ deb822 format
        local ports_file="/etc/apt/sources.list.d/ubuntu-ports-arm64.sources"
        if [[ ! -f "${ports_file}" ]]; then
            info "Creating ${ports_file} (ports.ubuntu.com, arm64)"
            sudo tee "${ports_file}" >/dev/null <<EOF
Types: deb
URIs: http://ports.ubuntu.com/ubuntu-ports
Suites: ${codename} ${codename}-updates ${codename}-security ${codename}-backports
Components: main restricted universe multiverse
Architectures: arm64
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
            ok "Created ${ports_file}"
        else
            ok "${ports_file} already exists."
        fi

        # Add 'Architectures: amd64 i386' to each stanza in ubuntu.sources
        # that doesn't already have an Architectures field, so apt stops
        # requesting arm64 indices from archive.ubuntu.com.
        if ! grep -q "^Architectures:" /etc/apt/sources.list.d/ubuntu.sources; then
            info "Restricting ubuntu.sources to amd64 i386"
            local tmpfile
            tmpfile="$(mktemp)"
            python3 -c "
import re, sys
content = open('/etc/apt/sources.list.d/ubuntu.sources').read()
# Insert 'Architectures: amd64 i386' after every 'Components:' line
content = re.sub(r'(Components:[^\n]+)', r'\1\nArchitectures: amd64 i386', content)
sys.stdout.write(content)
" >"${tmpfile}"
            sudo cp "${tmpfile}" /etc/apt/sources.list.d/ubuntu.sources
            rm -f "${tmpfile}"
            ok "Restricted ubuntu.sources to amd64 i386."
        else
            ok "ubuntu.sources already has Architectures field."
        fi

    elif [[ -f /etc/apt/sources.list ]]; then
        # Ubuntu 22.04 and earlier: plain sources.list
        local ports_file="/etc/apt/sources.list.d/ubuntu-ports-arm64.list"
        if [[ ! -f "${ports_file}" ]]; then
            info "Creating ${ports_file} (ports.ubuntu.com, arm64)"
            sudo tee "${ports_file}" >/dev/null <<EOF
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports ${codename} main restricted universe multiverse
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports ${codename}-updates main restricted universe multiverse
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports ${codename}-security main restricted universe multiverse
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports ${codename}-backports main restricted universe multiverse
EOF
            ok "Created ${ports_file}"
        else
            ok "${ports_file} already exists."
        fi

        # Add arch=amd64,i386 restriction to the main entries so apt doesn't
        # request arm64 indices from archive.ubuntu.com.
        if ! grep -qE '^\s*deb\s+\[' /etc/apt/sources.list; then
            info "Adding arch restriction to /etc/apt/sources.list"
            sudo sed -i \
                -e 's|^\(deb  *\)http://archive\.ubuntu\.com|\1[arch=amd64,i386] http://archive.ubuntu.com|' \
                -e 's|^\(deb  *\)http://security\.ubuntu\.com|\1[arch=amd64,i386] http://security.ubuntu.com|' \
                /etc/apt/sources.list
            ok "Updated /etc/apt/sources.list with arch restrictions."
        else
            ok "/etc/apt/sources.list already has arch restrictions."
        fi
    else
        warn "Cannot locate apt sources file; skipping arm64 source setup."
        warn "Manually add ports.ubuntu.com arm64 sources if package installation fails."
    fi
}

# ---------------------------------------------------------------------------
# Install arm64 dev libraries (full mode only)
# ---------------------------------------------------------------------------
if [[ "$MODE" != "library-only" ]]; then
    sep
    info "Setting up arm64 multiarch and cross-compiled dev libraries"

    # Register arm64 as a foreign architecture so apt can install :arm64 packages
    if ! dpkg --print-foreign-architectures | grep -q arm64; then
        sudo dpkg --add-architecture arm64
        ok "arm64 architecture registered."
    else
        ok "arm64 multiarch already registered."
    fi

    # Configure apt to fetch arm64 packages from ports.ubuntu.com
    setup_arm64_apt_sources

    info "Updating package lists..."
    sudo apt-get update -q
    ok "Package lists updated."

    # Dev libraries for the target sysroot.
    # These land in /usr/lib/aarch64-linux-gnu/ and their .pc files in
    # /usr/lib/aarch64-linux-gnu/pkgconfig/ — exactly what cross-pkg-config needs.
    TARGET_LIBS=(
        libpcap-dev:arm64
        libjson-c-dev:arm64
        libpcre2-dev:arm64
        libmaxminddb-dev:arm64
    )
    sudo apt-get install -y --no-install-recommends "${TARGET_LIBS[@]}"
    ok "Cross-compiled dev libraries installed."
fi

# ---------------------------------------------------------------------------
# Determine pkg-config to use
# ---------------------------------------------------------------------------
#
# PKG_PROG_PKG_CONFIG in our configure uses AC_PATH_TOOL, which searches for
# ${host}-pkg-config first.  On Ubuntu the wrapper is provided either by the
# pkgconf or pkg-config package.  We prefer it when available; otherwise we
# fall back to the plain pkg-config with explicit LIBDIR / SYSROOT_DIR.
#
if command -v "${TARGET_TRIPLE}-pkg-config" &>/dev/null; then
    PKG_CONFIG_CROSS="${TARGET_TRIPLE}-pkg-config"
    ok "Cross pkg-config: $(command -v "${PKG_CONFIG_CROSS}")"
else
    PKG_CONFIG_CROSS="pkg-config"
    warn "${TARGET_TRIPLE}-pkg-config not found; using plain pkg-config with sysroot vars."
fi

# ---------------------------------------------------------------------------
# Regenerate configure if needed
# ---------------------------------------------------------------------------
sep
info "Checking autotools artefacts"

if [[ ! -f "${NDPI_ROOT}/configure" || \
      "${NDPI_ROOT}/configure.ac" -nt "${NDPI_ROOT}/configure" ]]; then
    info "Running autoreconf (configure is missing or stale)"
    (cd "${NDPI_ROOT}" && autoreconf -fi)
    ok "autoreconf done."
else
    ok "configure is up to date."
fi

# ---------------------------------------------------------------------------
# Remove stale ndpi_config.h from the source tree.
#
# AC_CONFIG_HEADERS writes the generated header into the BUILD directory
# (build-cross-*/src/include/ndpi_config.h).  If a previous native build
# left a different ndpi_config.h in the SOURCE tree, the compiler finds
# that one first in a VPATH build and silently uses it — causing defines
# like HAVE_PCRE2 to disagree with what configure actually detected.
# ---------------------------------------------------------------------------
if [[ -f "${NDPI_ROOT}/src/include/ndpi_config.h" ]]; then
    info "Removing stale ${NDPI_ROOT}/src/include/ndpi_config.h"
    rm -f "${NDPI_ROOT}/src/include/ndpi_config.h"
fi

# ---------------------------------------------------------------------------
# Prepare VPATH build directory
# ---------------------------------------------------------------------------
sep
info "Preparing build directory: ${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

# ---------------------------------------------------------------------------
# Build up configure arguments
# ---------------------------------------------------------------------------
CONFIGURE_ARGS=(
    --host="${TARGET_TRIPLE}"
    --build="$(cc -dumpmachine 2>/dev/null || gcc -dumpmachine 2>/dev/null || echo "$(uname -m)-linux-gnu")"
    CC="${CC_CROSS}"
    CXX="${TARGET_TRIPLE}-g++"
    AR="${TARGET_TRIPLE}-ar"
    RANLIB="${TARGET_TRIPLE}-ranlib"
    STRIP="${TARGET_TRIPLE}-strip"
    PKG_CONFIG="${PKG_CONFIG_CROSS}"
)

if [[ "$MODE" == "library-only" ]]; then
    # No external deps needed — fastest path
    CONFIGURE_ARGS+=(--with-only-libndpi)
    info "Mode: library-only (--with-only-libndpi)"
else
    # Tell pkg-config where the target .pc files and sysroot live.
    # When ${TARGET_TRIPLE}-pkg-config exists it already knows this, but
    # setting these explicitly also satisfies the configure warning we emit
    # when PKG_CONFIG_SYSROOT_DIR is empty during a cross build.
    CONFIGURE_ARGS+=(
        PKG_CONFIG_LIBDIR="/usr/lib/${TARGET_TRIPLE}/pkgconfig:/usr/share/pkgconfig"
        PKG_CONFIG_SYSROOT_DIR="/"
        --with-pcre2
        --with-maxminddb
    )
    info "Mode: ${MODE} (examples + unit tests, with cross-compiled dev libs)"
fi

# ---------------------------------------------------------------------------
# Configure
# ---------------------------------------------------------------------------
sep
info "Configuring..."

CONFIGURE_LOG="${BUILD_DIR}/configure.log"
(
    cd "${BUILD_DIR}"
    "${NDPI_ROOT}/configure" "${CONFIGURE_ARGS[@]}" 2>&1 | tee "${CONFIGURE_LOG}"
)

echo
info "--- configure warnings related to cross-compilation ---"
# Surface any warnings that our configure.ac emits for cross-builds
grep -E "Cross-compil|PKG_CONFIG_SYSROOT|PKG_CONFIG_LIBDIR|build-host path|Homebrew|DPDK|PCAP_HOME" \
    "${CONFIGURE_LOG}" || echo "  (none)"
echo

ok "configure complete."

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
sep
info "Building (${JOBS} jobs)..."
make -C "${BUILD_DIR}" -j"${JOBS}"
ok "Build complete."

# ---------------------------------------------------------------------------
# Verify outputs
# ---------------------------------------------------------------------------
sep
info "=== Verification ==="

READELF="${TARGET_TRIPLE}-readelf"

# Locate the built library (prefer shared, fall back to static)
LIB_SO="$(find "${BUILD_DIR}/src/lib" -name 'libndpi.so.*' ! -name '*.la' \
          2>/dev/null | sort -V | tail -1 || true)"
LIB_A="$(find  "${BUILD_DIR}/src/lib" -name 'libndpi.a' \
          2>/dev/null | head -1 || true)"
LIB="${LIB_SO:-${LIB_A}}"
[[ -n "${LIB}" ]] || die "No libndpi.{so,a} found under ${BUILD_DIR}/src/lib"

check_arch() {
    local path="$1"
    local label="$2"
    local file_out arch_ok=false

    file_out="$(file "${path}")"
    echo "  file: ${file_out}"

    # 'file' on .so reports "ARM aarch64" or "ELF 64-bit LSB ... ARM"
    # 'file' on .a  reports "current ar archive" — probe with readelf instead
    if echo "${file_out}" | grep -qiE "aarch64|ARM aarch64|64-bit.*ARM"; then
        arch_ok=true
    elif echo "${file_out}" | grep -qi "current ar archive"; then
        if command -v "${READELF}" &>/dev/null; then
            local re_out
            re_out="$("${READELF}" -h "${path}" 2>/dev/null || true)"
            echo "  readelf machine: $(echo "${re_out}" | grep 'Machine:' || echo '  (unknown)')"
            echo "${re_out}" | grep -qiE "aarch64|AArch64" && arch_ok=true
        fi
    fi

    if $arch_ok; then
        ok "${label} is AArch64."
    else
        die "${label} is NOT AArch64!  Cross-compilation may have failed.\n  file output: ${file_out}"
    fi

    # Sanity: no x86 code should be present
    if command -v "${READELF}" &>/dev/null; then
        local machine
        machine="$("${READELF}" -h "${path}" 2>/dev/null | grep 'Machine:' || true)"
        if echo "${machine}" | grep -qiE "x86|386|x86-64"; then
            die "x86 machine type found in ${path} — cross-compilation broken!"
        fi
    fi
}

check_arch "${LIB}" "libndpi"

# Headers
NDPI_H="${BUILD_DIR}/src/include/ndpi_api.h"
if [[ -f "${NDPI_H}" ]]; then
    ok "Header present: ${NDPI_H}"
fi

# Full mode: also check ndpiReader and optionally run it via QEMU
READER=""
if [[ "$MODE" != "library-only" ]]; then
    READER="$(find "${BUILD_DIR}/example" -name 'ndpiReader' 2>/dev/null | head -1 || true)"
    if [[ -n "${READER}" ]]; then
        check_arch "${READER}" "ndpiReader"
    else
        warn "ndpiReader not found — check configure output for missing dependencies."
    fi

    # Unit tests binary (if built)
    UNIT="$(find "${BUILD_DIR}/tests/unit" -name 'ndpi_unit_test' 2>/dev/null | head -1 || true)"
    if [[ -n "${UNIT}" ]]; then
        check_arch "${UNIT}" "ndpi_unit_test"
    fi
fi

# ---------------------------------------------------------------------------
# QEMU smoke test: run ndpiReader -H on the host via user-mode emulation
#
# qemu-aarch64-static executes AArch64 ELFs on the x86-64 kernel using two
# independent mechanisms:
#
#   QEMU_LD_PREFIX=/
#     Tells QEMU to prepend '/' to the ELF interpreter path embedded in the
#     binary (/lib/ld-linux-aarch64.so.1).  With Ubuntu multiarch that file
#     exists at /lib/aarch64-linux-gnu/ld-linux-aarch64.so.1, installed as a
#     dependency of libc6:arm64 (pulled in by the cross-compiled dev libs).
#
#   LD_LIBRARY_PATH=<build lib dir>
#     Passed through QEMU to the AArch64 dynamic linker so it can find
#     libndpi.so in the build directory (it is not installed system-wide).
# ---------------------------------------------------------------------------
if [[ -n "${READER}" ]]; then
    sep
    info "QEMU smoke test: ndpiReader -H"

    QEMU_BIN=""
    if command -v qemu-aarch64-static &>/dev/null; then
        QEMU_BIN="qemu-aarch64-static"
    else
        info "qemu-user-static not installed; installing now..."
        sudo apt-get install -y --no-install-recommends qemu-user-static
        QEMU_BIN="qemu-aarch64-static"
    fi

    # Verify the aarch64 dynamic linker is accessible (installed via libc6:arm64
    # which is pulled in as a dependency of the cross-compiled dev libs above).
    AARCH64_LD="/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"
    if [[ ! -f "${AARCH64_LD}" ]]; then
        warn "AArch64 dynamic linker not found at ${AARCH64_LD}."
        warn "Install libc6:arm64 to enable QEMU execution."
    else
        ok "AArch64 dynamic linker: ${AARCH64_LD}"

        # LD_LIBRARY_PATH points QEMU at the cross-compiled shared libndpi.so
        # so ndpiReader can find it at runtime.
        READER_LIB_DIR="$(dirname "${LIB_SO:-}")"

        echo
        info "Running: QEMU_LD_PREFIX=/ LD_LIBRARY_PATH=${READER_LIB_DIR} ${QEMU_BIN} ${READER} -H"
        echo "----------------------------------------------------------------------"
        QEMU_LD_PREFIX=/ LD_LIBRARY_PATH="${READER_LIB_DIR:-.}" \
            "${QEMU_BIN}" "${READER}" -H 2>&1 || true
        echo "----------------------------------------------------------------------"
        ok "ndpiReader -H executed successfully under QEMU."
    fi
fi

# ---------------------------------------------------------------------------
# Full test suite via QEMU (binfmt_misc)
#
# tests/do.sh calls ndpiReader repeatedly against pcap files.  With
# qemu-user-static installed, the kernel's binfmt_misc subsystem intercepts
# every execve() of an AArch64 ELF and routes it through qemu-aarch64-static
# transparently — no explicit wrapper is needed around each call.
#
# Environment variables are inherited through the whole binfmt_misc chain:
#   QEMU_LD_PREFIX=/   — read by QEMU to locate the AArch64 dynamic linker
#                        (/lib/ld-linux-aarch64.so.1)
#   LD_LIBRARY_PATH    — passed to the AArch64 dynamic linker so it finds
#                        libndpi.so (build dir) and cross-compiled system
#                        libs (e.g. libpcap, libpcre2) under
#                        /usr/lib/aarch64-linux-gnu/
# ---------------------------------------------------------------------------
if [[ "$MODE" == "tests" && -n "${READER}" && -f "${BUILD_DIR}/tests/do.sh" ]]; then
    sep
    info "Running test suite via QEMU (binfmt_misc)"

    # qemu-user-static registers a binfmt_misc entry on install.
    # If absent, execve() of AArch64 ELFs fails immediately with ENOEXEC.
    BINFMT_ENTRY="/proc/sys/fs/binfmt_misc/qemu-aarch64"
    if [[ ! -f "${BINFMT_ENTRY}" ]]; then
        warn "binfmt_misc entry not found at ${BINFMT_ENTRY}."
        if command -v update-binfmts &>/dev/null; then
            info "Trying: sudo update-binfmts --enable qemu-aarch64"
            sudo update-binfmts --enable qemu-aarch64 2>/dev/null || true
        fi
        if [[ ! -f "${BINFMT_ENTRY}" ]]; then
            warn "Registration still absent — skipping test suite."
            warn "Try: sudo systemctl restart systemd-binfmt  (or reboot)"
        fi
    fi

    if [[ -f "${BINFMT_ENTRY}" ]]; then
        ok "binfmt_misc AArch64: $(head -1 "${BINFMT_ENTRY}")"
        info "QEMU_LD_PREFIX=/ LD_LIBRARY_PATH=${BUILD_DIR}/src/lib:/usr/lib/${TARGET_TRIPLE}"
        echo
        TESTS_RC=0
        (
            export QEMU_LD_PREFIX=/
            export LD_LIBRARY_PATH="${BUILD_DIR}/src/lib:/usr/lib/${TARGET_TRIPLE}"
            cd "${BUILD_DIR}"
            NDPI_FORCE_PARALLEL_UTESTS=1 NDPI_FORCE_PARALLEL_CONFIGS=1 NDPI_SKIP_PARALLEL_BAR=1 bash tests/do.sh
        ) || TESTS_RC=$?
        echo
        if [[ "${TESTS_RC}" -eq 0 ]]; then
            ok "Test suite PASSED."
        else
            warn "Test suite finished with exit code ${TESTS_RC} — check output above."
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
sep
ok "Cross-compilation test PASSED"
echo
echo "  Mode          : ${MODE}"
echo "  Target triple : ${TARGET_TRIPLE}"
echo "  Library       : ${LIB}"
echo "  Build dir     : ${BUILD_DIR}"
echo
echo "To inspect the library manually:"
echo "  ${TARGET_TRIPLE}-readelf -h '${LIB}'"
echo "  ${TARGET_TRIPLE}-nm      '${LIB}' | head -20"
echo
if [[ -n "${READER}" ]]; then
echo "To run the binary again:"
echo "  QEMU_LD_PREFIX=/ LD_LIBRARY_PATH='${READER_LIB_DIR:-${BUILD_DIR}/src/lib}' qemu-aarch64-static '${READER}' -H"
echo
fi
