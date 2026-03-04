#include "ndpi_api.h"
#include "fuzz_common_code.h"
#include "reader_util.h"

#include <stdint.h>
#include <stdio.h>
#include "fuzzer/FuzzedDataProvider.h"


u_int8_t enable_doh_dot_detection = 0;
u_int8_t enable_payload_analyzer = 0;
u_int8_t enable_flow_stats = 0;
u_int8_t human_readeable_string_len = 5;
u_int8_t max_num_udp_dissected_pkts = 16 /* 8 is enough for most protocols, Signal requires more */, max_num_tcp_dissected_pkts = 80 /* due to telnet */;
int alloc_size_stats = 0;
FILE *fingerprint_fp = NULL;
char const *addr_dump_path = "/tmp/";
int monitoring_enabled = 0;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  ndpi_workflow *w;
  struct ndpi_global_context *g_ctx;
  struct ndpi_workflow_prefs prefs;
  pcap_t *pcap_handle;
  ndpi_serialization_format serialization_format;
  ndpi_risk flow_risk;
  struct ndpi_flow_info *flow = NULL; /* unused */
  const u_char *pkt;
  struct pcap_pkthdr *header;
  int r;
  char errbuf[PCAP_ERRBUF_SIZE];
  FILE *fd;


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

  /* byte8 is still unused */

  enable_doh_dot_detection = 1;

  fd = buffer_to_file(data + 8, size - 8);
  if(fd == NULL) {
    return 0;
  }

  pcap_handle = pcap_fopen_offline(fd, errbuf);
  if(pcap_handle == NULL) {
    fclose(fd);
    return 0;
  }
  if(ndpi_is_datalink_supported(pcap_datalink(pcap_handle)) == 0) {
    pcap_close(pcap_handle);
    return 0;
  }

  g_ctx = ndpi_global_init();

  w = ndpi_workflow_init(&prefs, pcap_handle, 1, serialization_format, g_ctx);
  if(w) {
    ndpi_finalize_initialization(w->ndpi_struct);

    if(ndpi_stats_init(&w->stats, ndpi_get_num_protocols(w->ndpi_struct))) {
      header = NULL;

      r = pcap_next_ex(pcap_handle, &header, &pkt);
      while (r > 0) {
        ndpi_workflow_process_packet(w, header, pkt, &flow_risk, &flow);
        r = pcap_next_ex(pcap_handle, &header, &pkt);
      }

      ndpi_stats_reset(&w->stats);
    }
    ndpi_workflow_free(w);
  }
  pcap_close(pcap_handle);

  ndpi_global_deinit(g_ctx);

  return 0;
}
