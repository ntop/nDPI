#include "ndpi_api.h"
#include "fuzz_common_code.h"
#include "reader_util.h"

#include <stdint.h>
#include <stdio.h>
#include "fuzzer/FuzzedDataProvider.h"

extern u_int8_t enable_doh_dot_detection;

char *_debug_protocols;
int nDPI_LogLevel = 0;
u_int32_t current_ndpi_memory = 0, max_ndpi_memory = 0;
u_int8_t enable_protocol_guess = 1, enable_payload_analyzer = 0;
u_int8_t enable_flow_stats = 0;
u_int8_t human_readeable_string_len = 5;
u_int8_t max_num_udp_dissected_pkts = 16 /* 8 is enough for most protocols, Signal requires more */, max_num_tcp_dissected_pkts = 80 /* due to telnet */;
ndpi_init_prefs init_prefs = ndpi_track_flow_payload | ndpi_enable_ja3_plus | ndpi_enable_tcp_ack_payload_heuristic;
int enable_malloc_bins = 0;
int malloc_size_stats = 0;
int max_malloc_bins = 14;
struct ndpi_bin malloc_bins; /* unused */

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  ndpi_workflow *w;
  struct ndpi_workflow_prefs prefs;
  pcap_t *pcap_handle;
  ndpi_serialization_format serialization_format;
  NDPI_PROTOCOL_BITMASK enabled_bitmask;
  ndpi_risk flow_risk;
  const u_char *pkt;
  struct pcap_pkthdr *header;
  int r, rc;
  char errbuf[PCAP_ERRBUF_SIZE];
  FILE *fd;
  u_int8_t debug_protos_index;
  const char *strs[] = { "all",
			 "dns,quic",
			 "+dns:-quic",
			 "all;-http",
			 "foo",
			 "openvpn",
			 "+bar;-foo",
			 NULL,
			 "http;bar" };


  /* Data structure: 8 bytes header for random values + pcap file */
  if(size < 8)
    return 0; 

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  prefs.decode_tunnels = fuzzed_data.ConsumeBool();
  prefs.quiet_mode = fuzzed_data.ConsumeBool();
  prefs.ignore_vlanid = fuzzed_data.ConsumeBool();
  prefs.num_roots = fuzzed_data.ConsumeIntegral<u_int8_t>();
  if(prefs.num_roots == 0)
    prefs.num_roots = 1;
  prefs.max_ndpi_flows = fuzzed_data.ConsumeIntegral<u_int8_t>();

  serialization_format = static_cast<ndpi_serialization_format>(fuzzed_data.ConsumeIntegralInRange(1, 4));

  debug_protos_index = fuzzed_data.ConsumeIntegralInRange(0,  static_cast<int>(sizeof(strs) / sizeof(char *) - 1));
  _debug_protocols = ndpi_strdup(strs[debug_protos_index]);

  /* byte8 is still unused */

  enable_doh_dot_detection = 1;

  fd = buffer_to_file(data + 8, size - 8);
  if(fd == NULL) {
    ndpi_free(_debug_protocols);
    return 0;
  }

  pcap_handle = pcap_fopen_offline(fd, errbuf);
  if(pcap_handle == NULL) {
    fclose(fd);
    ndpi_free(_debug_protocols);
    return 0;
  }
  if(ndpi_is_datalink_supported(pcap_datalink(pcap_handle)) == 0) {
    pcap_close(pcap_handle);
    ndpi_free(_debug_protocols);
    return 0;
  }

  w = ndpi_workflow_init(&prefs, pcap_handle, 1, serialization_format);
  if(w) {
    NDPI_BITMASK_SET_ALL(enabled_bitmask);
    rc = ndpi_set_protocol_detection_bitmask2(w->ndpi_struct, &enabled_bitmask);
    if(rc == 0) {
      ndpi_finalize_initialization(w->ndpi_struct);

      header = NULL;
      r = pcap_next_ex(pcap_handle, &header, &pkt);
      while (r > 0) {
        ndpi_workflow_process_packet(w, header, pkt, &flow_risk);
        r = pcap_next_ex(pcap_handle, &header, &pkt);
      }
    }

    ndpi_workflow_free(w);
  }
  pcap_close(pcap_handle);

  ndpi_free(_debug_protocols);

  return 0;
}
