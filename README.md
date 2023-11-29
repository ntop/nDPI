![ntop][ntopng_logo] ![ntop][ntop_logo]
# nDPI

[![Build Status](https://img.shields.io/github/actions/workflow/status/ntop/nDPI/build.yml?branch=dev&logo=github)](https://github.com/ntop/nDPI/actions?query=workflow%3ABuild)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/ndpi.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:ndpi)

## What is nDPI ?

nDPI® is an open source LGPLv3 library for deep-packet inspection. Based on OpenDPI it includes ntop extensions. We have tried to push them into the OpenDPI source tree but nobody answered emails so we have decided to create our own source tree

A generic FAQ about nDPI® is available [here](https://github.com/ntop/nDPI/blob/dev/doc/FAQ.md)

### How To Compile nDPI

In order to compile this project do

- ./autogen.sh
- make

To compile the library w/o any tools or tests:

- ./autogen.sh --with-only-libndpi
- make

To run tests do additionally:

- ./tests/do.sh # Generate and check for diff's in PCAP files
- ./tests/do-unit.sh # Run unit tests
- ./tests/do-dga.sh # Run DGA detection test

or run all with: `make check`

Please note that the (minimal) pre-requisites for compilation include:
- GNU tools (autoconf automake libtool pkg-config gettext flex bison)
- GNU C compiler (gcc) or Clang

On Debian/Ubuntu systems do:
- sudo apt-get install build-essential git gettext flex bison libtool autoconf automake pkg-config libpcap-dev libjson-c-dev libnuma-dev libpcre2-dev libmaxminddb-dev librrd-dev

On Arch Linux:
- sudo pacman -S gcc git gettext flex bison libtool autoconf automake pkg-config libpcap json-c numactl pcre2 libmaxminddb rrdtool

On FreeBSD:
- sudo pkg install gcc git gettext flex bison libtool autoconf automake devel/pkgconf gmake libpcap json-c pcre2 libmaxminddb rrdtool

Remember to use `gmake` and not `make` on FreeBSD

On MacOS:
- brew install coreutils gcc git gettext flex bison libtool autoconf automake pkg-config libpcap json-c pcre2 libmaxminddb rrdtool

On Windows:

There are three supported ways to build nDPI:

1. MSYS2 (assuming [MSYS2](https://www.msys2.org/) already installed):
  - msys2 -c "pacman --noconfirm -S --needed --overwrite '\*' git mingw-w64-x86\_64-toolchain automake1.16 automake-wrapper autoconf libtool make mingw-w64-x86\_64-json-c mingw-w64-x86\_64-crt-git mingw-w64-x86\_64-pcre2 mingw-w64-x86\_64-libpcap"

2. Mingw-w64

3. Visual Studio (see `windows/nDPI.sln`)

Note: All Windows versions require [npcap](https://npcap.com/#download) with WinPcap compatibility mode enabled.

### How To Build The Documentation

- pip install --upgrade pip
- pip install -r doc/requirements.txt
- make doc

Use the builtin python3 webserver to view documentation:
- make doc-view

### How To Add A New Protocol Dissector

The entire procedure of adding new protocols in detail:

1. Add new protocol together with its unique ID to: `src/include/ndpi_protocol_ids.h`
2. Create a new protocol in: `src/lib/protocols/`
3. Variables to be kept for the duration of the entire flow (as state variables) need to be placed in: `src/include/ndpi_typedefs.h` in `ndpi_flow_tcp_struct` (for TCP only), `ndpi_flow_udp_struct` (for UDP only), or `ndpi_flow_struct` (for both).
4. Add a new entry for the search function for the new protocol in: `src/include/ndpi_protocols.h`
5. Choose (do not change anything) a selection bitmask from: `src/include/ndpi_define.h`
6. Set protocol default ports in `ndpi_init_protocol_defaults` in: `src/lib/ndpi_main.c`
7. Be sure to have nBPF support, cloning `PF_RING` in the same directory where you cloned `nDPI`: `git clone https://github.com/ntop/PF_RING/ && cd PF_RING/userland/nbpf && ./configure && make`
8. From the `nDPI` root directory, `./autogen.sh --with-pcre2` (nBPF and PCRE2 are usually optional, but they are needed to run/update *all* the unit tests)
9. `make`
10. `make check`
11. Update the documentation, adding this new protocol to `doc/protocols.rst`

### How to use nDPI to Block Selected Traffic

You can use nDPI to selectively block selected Internet traffic by embedding it onto an application (remember that nDPI is just a library). Both [ntopng](https://github.com/ntop/ntopng) and [nProbe cento](http://www.ntop.org/products/netflow/nprobe-cento/) can do this.

### nDPI Paper Citation

- Deri, Luca, et al. [nDPI: Open-source high-speed deep packet inspection](http://luca.ntop.org/nDPI.pdf) 2014 International Wireless Communications and Mobile Computing Conference (IWCMC). IEEE, 2014.

### Videos and Presentations

- [Using nDPI for Monitoring and Security](https://archive.fosdem.org/2021/schedule/event/nemondpi/)
- [Network Traffic Classification for Cybersecurity and Monitoring](https://fosdem.org/2022/schedule/event/using_ndpi_to_efficiently_classify_network_traffic/)

### nDPI-Related Projects

- [nfstream](https://github.com/aouinizied/nfstream)
- [nDPId](https://github.com/utoni/nDPId)

### DISCLAIMER

While we do our best to detect network protocols, we cannot guarantee that our software is error free and 100% accurate in protocol detection. Please make sure that you respect the privacy of users and you have proper authorization to listen, capture and inspect network traffic.

nDPI is a registered trademark in the US and EU.

[ntopng_logo]: https://camo.githubusercontent.com/0f789abcef232035c05e0d2e82afa3cc3be46485/687474703a2f2f7777772e6e746f702e6f72672f77702d636f6e74656e742f75706c6f6164732f323031312f30382f6e746f706e672d69636f6e2d313530783135302e706e67

[ntop_logo]: https://camo.githubusercontent.com/58e2a1ecfff62d8ecc9d74633bd1013f26e06cba/687474703a2f2f7777772e6e746f702e6f72672f77702d636f6e74656e742f75706c6f6164732f323031352f30352f6e746f702e706e67
