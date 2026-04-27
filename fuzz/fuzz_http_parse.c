/*
 * fuzz_http_parse
 *
 * What it tests:
 *   HTTP dissector (ndpi_search_http_tcp) in src/lib/protocols/http.c. Calls
 *   the parser directly with a synthesised packet_struct so the header
 *   extractors (Host, User-Agent, Content-Type, Referer), chunked/transfer
 *   handling, URL/URI walking, WebSocket upgrade, and URL-decode helpers are
 *   reached without relying on the full ndpi_detection_process_packet() flow
 *   state machine.
 *
 * Expected input format:
 *   Raw TCP payload bytes (e.g. "GET / HTTP/1.1\r\nHost: x\r\n\r\n").
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
static struct ndpi_tcphdr tcph;

static char *path = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  path = dirname(strdup(*argv[0])); /* No errors; no free! */
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct ndpi_packet_struct *packet;

  if (ndpi_struct == NULL) {
    fuzz_init_detection_module(&ndpi_struct, NULL, path);
    ndpi_flow = ndpi_calloc(1, sizeof(struct ndpi_flow_struct));

    memset(&iph, 0, sizeof(iph));
    iph.version = 4;
    iph.ihl = 5;
    iph.protocol = 6; /* TCP */
    iph.saddr = htonl(0x0A000001);
    iph.daddr = htonl(0x0A000002);

    memset(&tcph, 0, sizeof(tcph));
    tcph.source = htons(80);
    tcph.dest = htons(80);
  }

  fuzz_set_alloc_callbacks_and_seed(size);

  packet = &ndpi_struct->packet;

  /* Reset lines info */
  memset(packet, '\0', sizeof(*packet));

  packet->payload = data;
  packet->payload_packet_len = (u_int16_t)size;
  packet->iph = &iph;
  packet->iphv6 = NULL;
  packet->tcp = &tcph;
  packet->udp = NULL;

  memset(ndpi_flow, 0, sizeof(struct ndpi_flow_struct));
  ndpi_flow->l4_proto = IPPROTO_TCP;

  ndpi_search_http_tcp(ndpi_struct, ndpi_flow);
  ndpi_free_flow_data(ndpi_flow);

  return 0;
}
