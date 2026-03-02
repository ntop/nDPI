#include "ndpi_api.h"
#include "ndpi_private.h"
#include "fuzz_common_code.h"

static struct ndpi_detection_module_struct *ndpi_struct = NULL;
static struct ndpi_flow_struct ndpi_flow;
struct ndpi_iphdr iph;
#ifdef STUN_TCP
struct ndpi_tcphdr tcph;
#else
struct ndpi_udphdr udph;
#endif

static char *path = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;

  path = dirname(strdup(*argv[0])); /* No errors; no free! */
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  u_int16_t app_proto; /* unused */
  struct ndpi_packet_struct *packet;
  ndpi_protocol_category_t category;

  if (ndpi_struct == NULL) {
    fuzz_init_detection_module(&ndpi_struct, NULL, path);
  }

  packet = &ndpi_struct->packet;
  packet->payload = data;
  packet->payload_packet_len = size;
#ifndef STUN_TCP
  packet->udp = &udph;
#else
  packet->tcp = &tcph;
#endif
  packet->iph = &iph; /* IPv4 only */

  is_stun(ndpi_struct, &ndpi_flow, &app_proto, &category);
  return 0;
}
