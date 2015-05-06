This directory contains a modified version of OpenDPI which
includes ntop extensions. I have tried to push them into the
OpenDPI source tree but nobody in answering emails so I have
decided to create my own source tree

==========

In order to compile this library do

# ./autogen.sh
# ./configure
# make

Please note that the pre-requisites for compilation include:
- GNU tools (autogen, automake, autoconf, libtool)
- GNU C compiler (gcc)

==========

The entire procedure of adding new protocols in detail:

1. Add new protocol together with its unique ID to:
src/include/ndpi_protocols_osdpi.h

2. Create a new protocol in:
src/lib/protocols/

3. Variables to be kept for the duration of the entire flow (as state variables) needs to be placed in:
/include/ndpi_structs.h
in ndpi_flow_tcp_struct (for TCP only), ndpi_flow_udp_struct (for UDP only), or ndpi_flow_struct (for both).

4. Add a new entry for the search function for the new protocol in:
src/include/ndpi_protocols.h

5. Choose (do not change anything) a selection bitmask from:
src/include/ndpi_define.h

6. Add a new entry in ndpi_set_protocol_detection_bitmask2 in:
src/lib/ndpi_main.c

7. Set protocol default ports in ndpi_init_protocol_defaults in:
src/lib/ndpi_main.c

8. Add the new protocol file to:
src/lib/Makefile.am

9.  ./autogen.sh
10. ./configure
11. make

==========

If you want to distribute a source tar file of nDPI do:

# make dist

--------------------------
April 2015 - ntop 