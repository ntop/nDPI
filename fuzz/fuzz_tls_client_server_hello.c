/*
 * fuzz_tls_client_server_hello
 *
 * What it tests:
 *   processClientServerHello() — the TLS / DTLS / QUIC-in-TLS ClientHello &
 *   ServerHello parser in src/lib/protocols/tls.c. Exercises handshake framing,
 *   version selection, session_id walking, cipher lists, extensions (SNI, ALPN,
 *   supported_versions, supported_groups, sig_algs, ESNI/ECH), and JA3/JA4
 *   fingerprint computation.
 *
 * Expected input format:
 *   Raw bytes of a TLS handshake record body (starting with handshake_type byte
 *   — 0x01 ClientHello or 0x02 ServerHello, followed by 24-bit length).
 *   The last byte is consumed as a selector:
 *     bit 0  -> TCP (TLS) vs UDP (DTLS)
 *     bit 1  -> quic_version = 0 vs v1 (drives the QUIC-carried CH path)
 *     bit 2  -> IPv4 vs IPv6 framing
 */

#include "ndpi_api.h"
#include "ndpi_private.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>

static struct ndpi_tcphdr tcph;
static struct ndpi_udphdr udph;
static struct ndpi_iphdr iph;
static struct ndpi_ipv6hdr iphv6;

static struct ndpi_detection_module_struct *ndpi_struct = NULL;
static struct ndpi_flow_struct *ndpi_flow = NULL;

static char *path = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  path = dirname(strdup(*argv[0]));
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct ndpi_packet_struct *packet;
  uint8_t selector;
  int is_udp, is_quic, is_ipv6;
  uint32_t quic_version;

  if (ndpi_struct == NULL) {
    fuzz_init_detection_module(&ndpi_struct, NULL, path);
    ndpi_flow = ndpi_calloc(1, sizeof(struct ndpi_flow_struct));
  }

  if (size < 4)
    return 0;

  fuzz_set_alloc_callbacks_and_seed(size);

  selector = data[size - 1];
  is_udp  = selector & 0x01;
  is_quic = (selector & 0x02) ? 1 : 0;
  is_ipv6 = (selector & 0x04) ? 1 : 0;

  quic_version = is_quic ? 0x00000001u : 0u;

  packet = &ndpi_struct->packet;
  packet->payload = data;
  packet->payload_packet_len = (u_int16_t)size;

  packet->iph   = is_ipv6 ? NULL : &iph;
  packet->iphv6 = is_ipv6 ? &iphv6 : NULL;
  if (is_udp) {
    packet->tcp = NULL;
    packet->udp = &udph;
  } else {
    packet->tcp = &tcph;
    packet->udp = NULL;
  }

  memset(ndpi_flow, 0, sizeof(struct ndpi_flow_struct));
  ndpi_flow->detected_protocol_stack[0] = NDPI_PROTOCOL_TLS;
  ndpi_flow->l4_proto = is_udp ? IPPROTO_UDP : IPPROTO_TCP;
  if (is_quic)
    ndpi_flow->protos.tls_quic.quic_version = quic_version;

  processClientServerHello(ndpi_struct, ndpi_flow, quic_version);
  ndpi_free_flow_data(ndpi_flow);

  return 0;
}
