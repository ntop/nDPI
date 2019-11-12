bin_PROGRAMS = fuzz_process_packet

fuzz_process_packet_SOURCES = fuzz_process_packet.c
fuzz_process_packet_LDFLAGS = ../src/lib/libndpi.a
if HAS_FUZZLDFLAGS
    fuzz_process_packet_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_process_packet_SOURCES += # onefile.c
endif
# force usage of CXX for linker
fuzz_process_packet_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_process_packet_LDFLAGS) $(LDFLAGS) -o $@
