/*
 * fuzz_dns_parse
 *
 * What it tests:
 *   DNS query / answer RR walking in src/lib/protocols/dns.c. Reaches
 *   process_queries() / process_answers() and the name-compression parser.
 *   Exercises attacker-controlled uint16 counts (num_queries, num_answers,
 *   authority_rrs, additional_rrs) and name-pointer loops.
 *
 * Expected input format:
 *   Raw DNS payload (starts with the 12-byte ndpi_dns_packet_header prefix).
 *   The harness wraps the fuzz data in a synthetic IPv4 + UDP packet with
 *   src/dst port 53 and feeds it to ndpi_detection_process_packet() so the
 *   DNS dissector is selected by the port hint.
 */

#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define IPV4_HDR_LEN 20
#define UDP_HDR_LEN  8
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
  uint16_t ip_len, udp_len;

  if (ndpi_info_mod == NULL)
    fuzz_init_detection_module(&ndpi_info_mod, NULL, path);

  if (size > MAX_PKT - IPV4_HDR_LEN - UDP_HDR_LEN)
    size = MAX_PKT - IPV4_HDR_LEN - UDP_HDR_LEN;
  payload_len = size;
  total_len = IPV4_HDR_LEN + UDP_HDR_LEN + payload_len;

  memset(pkt, 0, IPV4_HDR_LEN + UDP_HDR_LEN);

  /* IPv4 header: version=4, ihl=5, proto=17 (UDP) */
  pkt[0] = 0x45;
  ip_len = htons((uint16_t)total_len);
  memcpy(&pkt[2], &ip_len, 2);
  pkt[8] = 64;   /* ttl */
  pkt[9] = 17;   /* UDP */
  {
    uint32_t saddr = htonl(0x0A000001);
    uint32_t daddr = htonl(0x0A000002);
    memcpy(&pkt[12], &saddr, 4);
    memcpy(&pkt[16], &daddr, 4);
  }

  /* UDP header: src/dst port 53 */
  {
    uint16_t sport = htons(53), dport = htons(53);
    memcpy(&pkt[IPV4_HDR_LEN + 0], &sport, 2);
    memcpy(&pkt[IPV4_HDR_LEN + 2], &dport, 2);
  }
  udp_len = htons((uint16_t)(UDP_HDR_LEN + payload_len));
  memcpy(&pkt[IPV4_HDR_LEN + 4], &udp_len, 2);

  if (payload_len > 0)
    memcpy(&pkt[IPV4_HDR_LEN + UDP_HDR_LEN], data, payload_len);

  memset(&flow, 0, SIZEOF_FLOW_STRUCT);
  ndpi_detection_process_packet(ndpi_info_mod, &flow, pkt,
                                (unsigned short)total_len, 0, NULL);
  ndpi_detection_giveup(ndpi_info_mod, &flow);
  ndpi_free_flow_data(&flow);

  return 0;
}
