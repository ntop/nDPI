/*
 * fuzz_dns_parse
 *
 * What it tests:
 *   DNS query / answer RR walking in src/lib/protocols/dns.c. Calls
 *   ndpi_search_dns() directly with a synthesised packet_struct so the
 *   dissector is reached without depending on ndpi_detection_process_packet()
 *   and the full flow state machine. Exercises attacker-controlled uint16
 *   counts (num_queries, num_answers, authority_rrs, additional_rrs) and the
 *   name-compression pointer loops.
 *
 * Expected input format:
 *   Raw DNS payload (starts with the 12-byte ndpi_dns_packet_header prefix).
 *   The last byte is consumed as a selector:
 *     bit 0 -> TCP vs UDP framing
 *     bit 1 -> MDNS port (5353) vs DNS port (53)
 */

#include "ndpi_api.h"
#include "ndpi_private.h"
#include "fuzz_common_code.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static struct ndpi_detection_module_struct *ndpi_struct = NULL;
static struct ndpi_flow_struct *ndpi_flow = NULL;
static struct ndpi_iphdr iph;
static struct ndpi_udphdr udph;
static struct ndpi_tcphdr tcph;

static char *path = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  path = dirname(strdup(*argv[0])); /* No errors; no free! */
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct ndpi_packet_struct *packet;
  uint8_t selector;
  int is_tcp, is_mdns;
  uint16_t port;

  if (ndpi_struct == NULL) {
    fuzz_init_detection_module(&ndpi_struct, NULL, path);
    ndpi_flow = ndpi_calloc(1, sizeof(struct ndpi_flow_struct));

    memset(&iph, 0, sizeof(iph));
    iph.version = 4;
    iph.ihl = 5;
    iph.saddr = htonl(0x0A000001);
    iph.daddr = htonl(0x0A000002);
  }

  if (size < 1)
    return 0;

  fuzz_set_alloc_callbacks_and_seed(size);

  selector = data[size - 1];
  is_tcp  = selector & 0x01;
  is_mdns = (selector & 0x02) ? 1 : 0;
  port    = is_mdns ? 5353 : 53;

  packet = &ndpi_struct->packet;
  packet->payload = data;
  packet->payload_packet_len = (u_int16_t)size;
  packet->iph = &iph;
  packet->iphv6 = NULL;

  if (is_tcp) {
    memset(&tcph, 0, sizeof(tcph));
    tcph.source = htons(port);
    tcph.dest = htons(port);
    packet->tcp = &tcph;
    packet->udp = NULL;
    iph.protocol = 6;
  } else {
    memset(&udph, 0, sizeof(udph));
    udph.source = htons(port);
    udph.dest = htons(port);
    packet->udp = &udph;
    packet->tcp = NULL;
    iph.protocol = 17;
  }

  memset(ndpi_flow, 0, sizeof(struct ndpi_flow_struct));
  ndpi_flow->l4_proto = is_tcp ? IPPROTO_TCP : IPPROTO_UDP;

  ndpi_search_dns(ndpi_struct, ndpi_flow);
  ndpi_free_flow_data(ndpi_flow);

  return 0;
}
