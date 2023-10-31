#define NDPI_LIB_COMPILATION

#include "ndpi_api.h"
#include "fuzz_common_code.h"

static struct ndpi_detection_module_struct *ndpi_struct = NULL;
static struct ndpi_flow_struct ndpi_flow;
#ifdef STUN_TCP
struct ndpi_tcphdr tcph;
#else
struct ndpi_udphdr udph;
#endif

extern int is_stun(struct ndpi_detection_module_struct *ndpi_struct,
                   struct ndpi_flow_struct *flow,
                   u_int16_t *app_proto);


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  u_int16_t app_proto; /* unused */
  struct ndpi_packet_struct *packet;

  if (ndpi_struct == NULL) {
    fuzz_init_detection_module(&ndpi_struct);
  }

  packet = &ndpi_struct->packet;
  packet->payload = data;
  packet->payload_packet_len = size;
#ifndef STUN_TCP
  packet->udp = &udph;
#else
  packet->tcp = &tcph;
#endif

  is_stun(ndpi_struct, &ndpi_flow, &app_proto);
  return 0;
}
