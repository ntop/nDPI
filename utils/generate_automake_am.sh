#!/usr/bin/env sh
#
# This script is used for automatic generation of src/Makefile.am and fuzz/Makefile.am
# That way it is not necessary anymore to use wildcard *.c includes.
# Automake does not support it: https://www.gnu.org/software/automake/manual/html_node/Wildcards.html
#
# This script should run everytime a new *.c file should be part of the library.
#

set -e

MYDIR="$(realpath "$(dirname "${0}")")"

generate_src_am()
{
    # enumerate all *.c sources below src/ with a max. depth of three
    cd "${MYDIR}/../src"
    C_INCLUDES_GEN=$(find include -iname "*.h.in" | sort)
    C_INCLUDES_PRV=$(find lib lib/protocols lib/third_party/include -maxdepth 1 -iname "*.h" -o -iname "*.c.inc" | sort)
    C_INCLUDES=$(find include -iname "*.h" | sort)
    C_SOURCES=$(find lib -maxdepth 3 -iname "*.c" | sort)
    C_THIRD_PARTY_HLL_SOURCES=$(find lib/third_party/src/hll -iname "*.c" | sort)

    # extra dist source files (required by nDPI through #include)
    printf '%s' 'EXTRA_DIST =' >Makefile.am

    # HLL sources
    for src in ${C_THIRD_PARTY_HLL_SOURCES}; do
        printf ' \\\n\t%s' "${src}" >>Makefile.am
    done

    # private headers
    for inc in ${C_INCLUDES_PRV}; do
        printf ' \\\n\t%s' "${inc}" >>Makefile.am
    done
    printf '\n\n' >>Makefile.am

    printf '%s\n\n' 'includendpidir = $(includedir)/ndpi' >>Makefile.am

    printf '%s' 'includendpi_HEADERS =' >>Makefile.am

    # generated headers
    for inc in ${C_INCLUDES_GEN}; do
        printf ' \\\n\t%s' "${inc%.in}" >>Makefile.am
    done

    # headers
    for inc in ${C_INCLUDES}; do
        SKIP_INC=0
        for check_inc in ${C_INCLUDES_GEN}; do
            test "x${inc}.in" != "x${check_inc}" || SKIP_INC=1
        done
        test ${SKIP_INC} -eq 0 || continue
        printf ' \\\n\t%s' "${inc}" >>Makefile.am
    done
    printf '\n\n' >>Makefile.am

    # libtool init
    printf '%s\n\n' 'lib_LTLIBRARIES = libndpi.la' >>Makefile.am
    printf '%s'     'libndpi_la_SOURCES =' >>Makefile.am

    # add all *.c files found to SOURCES
    for src in ${C_SOURCES}; do
        printf ' \\\n\t%s' "${src}" >>Makefile.am
    done
    printf '\n\n' >>Makefile.am

    # libtool CFLAGS / LDFLAGS
cat >>Makefile.am <<EOF
libndpi_la_CFLAGS = \\
	-fPIC -DPIC \\
	-I\$(top_srcdir)/src/include \\
	-I\$(top_srcdir)/src/lib \\
	-I\$(top_srcdir)/src/lib/third_party/include \\
	-DNDPI_LIB_COMPILATION \\
	-Wall \\
	@CUSTOM_NDPI@

# Remember that libtool's semantic versioning is different from nDPI's versioning!
# See: https://www.gnu.org/software/libtool/manual/html_node/Libtool-versioning.html
libndpi_la_LDFLAGS = -version-info @NDPI_MAJOR@:@NDPI_MINOR@:@NDPI_PATCH@

check:
	cppcheck --template='{file}:{line}:{severity}:{message}' --quiet --enable=all --force \\
		-Iinclude \\
		-I\$(top_srcdir)/src/include \\
		-I\$(top_srcdir)/src/lib \\
		-I\$(top_srcdir)/src/lib/third_party/include \\
		\$(top_srcdir)/src/lib/*.c \$(top_srcdir)/src/lib/protocols/*.
EOF
    cd "${MYDIR}"
}

generate_fuzz_am()
{
    # enumerate all *.pcap files in tests/pcap/
    cd "${MYDIR}/../tests/pcap"
    PCAP_FILES=$(find . -iname "*.pcap" -o -iname "*.pcapng" | sort)
    cd "${MYDIR}"

    cd "${MYDIR}/../fuzz"
cat >Makefile.am <<EOF
bin_PROGRAMS = fuzz_process_packet fuzz_ndpi_reader fuzz_ndpi_reader_with_main

BUILD_SRC=../src
BUILD_EXAMPLE=../example

fuzz_process_packet_SOURCES = fuzz_process_packet.c
fuzz_process_packet_CFLAGS = -I\$(top_srcdir)/example -I\$(top_srcdir)/src/include -I\$(BUILD_SRC)/include
fuzz_process_packet_LDADD = \$(BUILD_SRC)/.libs/libndpi.a
fuzz_process_packet_LDFLAGS = \$(LIBS)
if HAS_FUZZLDFLAGS
fuzz_process_packet_CFLAGS += \$(LIB_FUZZING_ENGINE)
fuzz_process_packet_LDFLAGS += \$(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_process_packet_LINK=\$(LIBTOOL) \$(AM_V_lt) --tag=CC \$(AM_LIBTOOLFLAGS) \\
	\$(LIBTOOLFLAGS) --mode=link \$(CXX) \$(AM_CXXFLAGS) \$(CXXFLAGS) \\
	\$(fuzz_process_packet_LDFLAGS) \$(LDFLAGS) -o \$@

fuzz_ndpi_reader_SOURCES = fuzz_ndpi_reader.c
fuzz_ndpi_reader_CFLAGS = -I\$(top_srcdir)/example -I\$(top_srcdir)/src/include -I\$(BUILD_SRC)/include
fuzz_ndpi_reader_LDADD = \$(BUILD_EXAMPLE)/libndpiReader.a \$(BUILD_SRC)/.libs/libndpi.a
fuzz_ndpi_reader_LDFLAGS = \$(PCAP_LIB) \$(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ndpi_reader_CFLAGS += \$(LIB_FUZZING_ENGINE)
fuzz_ndpi_reader_LDFLAGS += \$(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ndpi_reader_LINK=\$(LIBTOOL) \$(AM_V_lt) --tag=CC \$(AM_LIBTOOLFLAGS) \\
	\$(LIBTOOLFLAGS) --mode=link \$(CXX) \$(AM_CXXFLAGS) \$(CXXFLAGS) \\
	\$(fuzz_ndpi_reader_LDFLAGS) \$(LDFLAGS) -o \$@

fuzz_ndpi_reader_with_main_SOURCES = fuzz_ndpi_reader.c
fuzz_ndpi_reader_with_main_CFLAGS = -I\$(top_srcdir)/example -I\$(top_srcdir)/src/include -I\$(BUILD_SRC)/include -DBUILD_MAIN
fuzz_ndpi_reader_with_main_LDADD = \$(BUILD_SRC)/.libs/libndpi.a
fuzz_ndpi_reader_with_main_LDFLAGS = \$(BUILD_EXAMPLE)/libndpiReader.a \$(PCAP_LIB) \$(LIBS)
# force usage of CXX for linker
fuzz_ndpi_reader_with_main_LINK=\$(LIBTOOL) \$(AM_V_lt) --tag=CC \$(AM_LIBTOOLFLAGS) \\
	\$(LIBTOOLFLAGS) --mode=link \$(CXX) \$(AM_CXXFLAGS) \$(CXXFLAGS) \\
	\$(fuzz_ndpi_reader_with_main_LDFLAGS) \$(LDFLAGS) -o \$@

EOF

    printf '%s\n%s\n%s' \
        '# required for Google oss-fuzz' \
        '# see https://github.com/google/oss-fuzz/tree/master/projects/ndpi' \
        'TESTPCAPS =' >>Makefile.am

    # pcap files in tests/pcap/
    for pcap in ${PCAP_FILES}; do
        printf ' \\\n\t%s' "${pcap}" >>Makefile.am
    done
    printf '\n\n' >>Makefile.am

    printf '%s\n%s\n' \
        'fuzz_ndpi_reader_seed_corpus.zip: $(TESTPCAPS)' \
        '	zip -r fuzz_ndpi_reader_seed_corpus.zip $(TESTPCAPS)' >>Makefile.am

    cd "${MYDIR}"
}

generate_src_am
generate_fuzz_am
