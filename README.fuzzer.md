## Compiling nDPI with Fuzzer

- Install the latest clang (sudo apt-get install clang-18)
- Export environamental variables to prefer clang over g++ (of installed)
  - export CC=/usr/bin/clang-18
  - export CPP=/usr/bin/clang-cpp-18
  - export CXX=/usr/bin/clang++-18
  - export LD=/usr/bin/ld.lld-18
- Run autogen.sh
  - ./autogen.sh --with-sanitizer --enable-fuzztargets 


## Testing nDPI with ClusterFuzz Artifacts
- Download the artifact (example clusterfuzz-testcase-fuzz_process_packet-4992218834796544)
- Run nDPI against the artifact
  - Example: ./fuzz/fuzz_process_packet clusterfuzz-testcase-fuzz_process_packet-4992218834796544 

The output is the error report
```
  ./fuzz/fuzz_process_packet /tmp/clusterfuzz-testcase-fuzz_process_packet-4992218834796544 
  AddressSanitizer:DEADLYSIGNAL
  =================================================================
  ==11590==ERROR: AddressSanitizer: SEGV on unknown address 0x61a100000087 (pc 0x00000056e6a4 bp 0x7ffd624fa170 sp 0x7ffd624fa090 T0)
  ==11590==The signal is caused by a READ memory access.
      #0 0x56e6a4 in quic_len /home/deri/nDPI/src/lib/protocols/quic.c:203:12
      #1 0x575d6b in decrypt_initial_packet /home/deri/nDPI/src/lib/protocols/quic.c:993:16
      #2 0x571776 in get_clear_payload /home/deri/nDPI/src/lib/protocols/quic.c:1302:21
      #3 0x56f149 in ndpi_search_quic /home/deri/nDPI/src/lib/protocols/quic.c:1658:19
      #4 0x503935 in check_ndpi_detection_func /home/deri/nDPI/src/lib/ndpi_main.c:4683:6
      #5 0x5056fb in check_ndpi_udp_flow_func /home/deri/nDPI/src/lib/ndpi_main.c:4742:10
      #6 0x505152 in ndpi_check_flow_func /home/deri/nDPI/src/lib/ndpi_main.c:4775:12
      #7 0x5174cf in ndpi_detection_process_packet /home/deri/nDPI/src/lib/ndpi_main.c:5545:15
      #8 0x4c709b in LLVMFuzzerTestOneInput /home/deri/nDPI/fuzz/fuzz_process_packet.c:30:3
      #9 0x4c7640 in main /home/deri/nDPI/fuzz/fuzz_process_packet.c:90:17
      #10 0x7f888e5dabf6 in __libc_start_main /build/glibc-S9d2JN/glibc-2.27/csu/../csu/libc-start.c:310
      #11 0x41c399 in _start (/home/deri/nDPI/fuzz/fuzz_process_packet+0x41c399)

  AddressSanitizer can not provide additional info.
  SUMMARY: AddressSanitizer: SEGV /home/deri/nDPI/src/lib/protocols/quic.c:203:12 in quic_len
  ==11590==ABORTING
```
