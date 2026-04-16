/*
 * fuzz_http_parse
 *
 * What it tests:
 *   HTTP dissection path reached from ndpi_detection_process_packet() for a
 *   TCP flow on port 80. Exercises ndpi_search_http_tcp and its header
 *   extractors (Host, User-Agent, Content-Type, Referer), chunked/transfer
 *   handling, URL/URI walking, WebSocket upgrade, and the URL-decode helpers.
 *
 * Expected input format:
 *   Raw TCP payload bytes (e.g. "GET / HTTP/1.1\r\nHost: x\r\n\r\n"). The
 *   harness wraps the fuzz data in a synthetic IPv4 + TCP packet with src/dst
 *   port 80 so the HTTP dissector fires via the port hint.
 */

#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define IPV4_HDR_LEN 20
#define TCP_HDR_LEN  20
#define MAX_PKT      (64 * 1024)

static struct ndpi_detection_module_struct *ndpi_info_mod = NULL;
static char *path = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  path = dirname(strdup(*argv[0]));
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static uint8_t pkt[MAX_PKT];
  struct ndpi_flow_struct flow;
  size_t payload_len, total_len;
  uint16_t ip_len;

  if (ndpi_info_mod == NULL)
    fuzz_init_detection_module(&ndpi_info_mod, NULL, path);

  if (size > MAX_PKT - IPV4_HDR_LEN - TCP_HDR_LEN)
    size = MAX_PKT - IPV4_HDR_LEN - TCP_HDR_LEN;
  payload_len = size;
  total_len = IPV4_HDR_LEN + TCP_HDR_LEN + payload_len;

  memset(pkt, 0, IPV4_HDR_LEN + TCP_HDR_LEN);

  /* IPv4 header: version=4, ihl=5, proto=6 (TCP) */
  pkt[0] = 0x45;
  ip_len = htons((uint16_t)total_len);
  memcpy(&pkt[2], &ip_len, 2);
  pkt[8] = 64;   /* ttl */
  pkt[9] = 6;    /* TCP */
  {
    uint32_t saddr = htonl(0x0A000001);
    uint32_t daddr = htonl(0x0A000002);
    memcpy(&pkt[12], &saddr, 4);
    memcpy(&pkt[16], &daddr, 4);
  }

  /* TCP header: src/dst port 80; data offset = 5 (20 bytes) */
  {
    uint16_t sport = htons(80), dport = htons(80);
    memcpy(&pkt[IPV4_HDR_LEN + 0], &sport, 2);
    memcpy(&pkt[IPV4_HDR_LEN + 2], &dport, 2);
  }
  pkt[IPV4_HDR_LEN + 12] = 0x50;   /* data offset = 5 */
  pkt[IPV4_HDR_LEN + 13] = 0x18;   /* flags = PSH | ACK */

  if (payload_len > 0)
    memcpy(&pkt[IPV4_HDR_LEN + TCP_HDR_LEN], data, payload_len);

  memset(&flow, 0, SIZEOF_FLOW_STRUCT);
  ndpi_detection_process_packet(ndpi_info_mod, &flow, pkt,
                                (unsigned short)total_len, 0, NULL);
  ndpi_detection_giveup(ndpi_info_mod, &flow);
  ndpi_free_flow_data(&flow);

  return 0;
}
