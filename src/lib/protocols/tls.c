/*
 * tls.c - TLS/TLS/DTLS dissector
 *
 * Copyright (C) 2016-26 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TLS

#include "ndpi_api.h"
#include "ndpi_md5.h"
#include "ndpi_sha1.h"
#include "ndpi_sha256.h"
#include "ndpi_encryption.h"
#include "ndpi_private.h"

//#define JA4R_DECIMAL 1

static void ndpi_search_tls_wrapper(struct ndpi_detection_module_struct *ndpi_struct,
				    struct ndpi_flow_struct *flow);

// #define DEBUG_TLS_MEMORY       1
// #define DEBUG_TLS              1
// #define DEBUG_TLS_BLOCKS       1
// #define DEBUG_CERTIFICATE_HASH

// #define DEBUG_HEURISTIC

// #define DEBUG_JA 1

/* #define DEBUG_FINGERPRINT      1 */
/* #define DEBUG_ENCRYPTED_SNI    1 */

/* **************************************** */

/*
  JA3
  https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967

  JA4
  https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
*/

#define JA_STR_LEN        1024

union ndpi_ja_info {
  ndpi_tls_client_info client;
  ndpi_tls_server_info server;
};

/*
  NOTE

  How to view the certificate fingerprint
  1. Using wireshark save the certificate on certificate.bin file as explained
  in https://security.stackexchange.com/questions/123851/how-can-i-extract-the-certificate-from-this-pcap-file

  2. openssl x509 -inform der -in certificate.bin -text > certificate.der
  3. openssl x509 -noout -fingerprint -sha1 -inform pem -in certificate.der
  SHA1 Fingerprint=15:9A:76....

  $ shasum -a 1 www.grc.com.bin
  159a76.....
*/

#define NDPI_MAX_TLS_REQUEST_SIZE 10000
#define TLS_THRESHOLD             34387200 /* Threshold for certificate validity                                */
#define TLS_LIMIT_DATE            1598918400 /* From 01/09/2020 TLS certificates lifespan is limited to 13 months */


static void ndpi_int_tls_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					struct ndpi_flow_struct *flow);

/* **************************************** */

static bool str_contains_digit(char *str) {
  u_int i = 0;

  for(i=0; (str[i] != '.') && (str[i] != '\0'); i++) {
    if(isdigit(str[i]))
      return(true);
  }

  return(false);
}

/* **************************************** */

/* TODO: rename */
static int keep_extra_dissection_tcp(struct ndpi_detection_module_struct *ndpi_struct,
                                     struct ndpi_flow_struct *flow) {
  if(ndpi_struct->cfg.tls_max_num_blocks_to_analyze > 0)
    return(1); /* Process as much TLS blocks as the max packet number */

  /* Common path: found handshake on both directions */
  if(
     (flow->tls_quic.certificate_processed == 1 && flow->protos.tls_quic.client_hello_processed)

     /* Application Data on both directions: handshake already ended (did we miss it?) */
     || (flow->l4.tcp.tls.app_data_seen[0] == 1 && flow->l4.tcp.tls.app_data_seen[1] == 1)

     /* Handshake on one direction and Application Data on the other */
     || ((flow->protos.tls_quic.client_hello_processed && flow->l4.tcp.tls.app_data_seen[!flow->protos.tls_quic.ch_direction] == 1) ||
	 (flow->protos.tls_quic.server_hello_processed && flow->l4.tcp.tls.app_data_seen[flow->protos.tls_quic.ch_direction] == 1))
     ) {
    return 0;
  }

  /* Non-warning alert */
  if(flow->tls_quic.alert)
    return 0;

  /* Are we interested only in the (sub)-classification? */

  if(/* Subclassification */
     flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN &&
     /* No metadata from SH or certificate */
     !ndpi_struct->cfg.tls_alpn_negotiated_enabled &&
     !ndpi_struct->cfg.tls_cipher_enabled &&
     !ndpi_struct->cfg.tls_sha1_fingerprint_enabled &&
     !ndpi_struct->cfg.tls_cert_server_names_enabled &&
     !ndpi_struct->cfg.tls_cert_validity_enabled &&
     !ndpi_struct->cfg.tls_cert_issuer_enabled &&
     !ndpi_struct->cfg.tls_cert_subject_enabled &&
     !ndpi_struct->cfg.tls_browser_enabled &&
     !ndpi_struct->cfg.tls_ja3s_fingerprint_enabled &&
     /* No flow risks from SH or certificate: we should have disabled all
        metadata needed for flow risks, so we should not need to explicitly
        check them */
     /* Ookla aggressiveness has no impact here because it is evaluated only
        without sub-classification */
     /* TLS heuristics */
     (ndpi_struct->cfg.tls_heuristics == 0 || is_flow_addr_informative(flow))) {
    return 0;
  }

  return 1;
}

/* **************************************** */

/* Heuristic to detect proxied/obfuscated TLS flows, based on
   https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting.
   Main differences between the paper and our implementation:
    * only Mahalanobis Distance, no Chi-squared Test
    * instead of 3-grams, we use 4-grams, always starting from the Client -> Server direction
    * consecutive packets in the same direction always belong to the same burst/flight

   Core idea:
    * the packets/bytes distribution of a TLS handshake is quite unique
    * this fingerprint is still detectable if the handshake is
      encrypted/proxied/obfuscated
*/

struct tls_obfuscated_heuristic_set {
  u_int8_t stage;
  u_int32_t bytes[4];
  u_int32_t pkts[4];
};

struct tls_obfuscated_heuristic_state {
  u_int8_t num_pkts;

  /* Burst/flight: consecutive packets in the same direction.
   * Set: packet/bytes distribution of 4 consecutive bursts (always starting from C->S),
          i.e. a 4-grams (using the paper terminology)
   * We have up tp 2 sets contemporarily active.
   * At the first pkt of a new C->S flight, we close the oldest set and open a new one */
  struct tls_obfuscated_heuristic_set sets[2];
};

static int check_set(struct ndpi_detection_module_struct* ndpi_struct,
                     struct tls_obfuscated_heuristic_set *set)
{
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  struct ndpi_packet_struct* packet = &ndpi_struct->packet;
#endif

  /* Model: TLS 1.2; Firefox; No session resumption/0rtt */
  const float i_s_tls_12[4 * 4] = { 0.000292421113167604, 4.43677617831228E-07, -5.69966093492813E-05, -2.18124698406311E-06,
                                    4.43677617831228E-07, 5.98954952745268E-07, -3.59798436724817E-07, 5.71638172955893E-07,
                                    -5.69966093492813E-05, -3.59798436724817E-07, 0.00076893788148309, 2.22278496185964E-05,
                                    -2.18124698406311E-06, 5.71638172955893E-07, 2.22278496185964E-05, 5.72770077086287E-05 };
  const float average_tls_12[4] = { 212.883690341977, 4514.71195039459, 107.770762871101, 307.580232995115 };
  const float distance_tls_12 = 3.5;

  /* Model: TLS 1.3; Firefox; No session resumption/0rtt; no PQ; ECH(-grease) enabled */
  const float i_s_tls_13[4 * 4] = { 3.08030337925007E-05, 1.16179172096944E-07, 1.05356744968627E-07, 3.8862884355278E-08,
                                    1.16179172096944E-07, 6.93179117519316E-07, 2.77413220880937E-08, -3.63723200682445E-09,
                                    1.05356744968627E-07, 2.77413220880937E-08, 1.0260950589675E-06, -1.08769813590053E-08,
                                    3.88628843552779E-08, -3.63723200682445E-09, -1.08769813590053E-08,	8.63307792288604E-08 };
  const float average_tls_13[4] = { 640.657378447541, 4649.30338356554, 448.408302530566, 1094.2013079329};
  const float distance_tls_13 = 3.0;

  /* Model: TLS 1.2/1.3; Chrome; No session resumption/0rtt; PQ; ECH(-grease) enabled */
  const float i_s_chrome[4 * 4] = { 6.72374390966642E-06, -2.32109583941723E-08, 6.67140014394388E-08, 1.2526322628285E-08,
                                    -2.32109583941723E-08, 5.64668947932086E-07, 4.58963631972597E-08, 6.41254684791958E-09,
                                    6.67140014394388E-08, 4.58963631972597E-08, 6.04057768431344E-07, -9.1507432597718E-10,
                                    1.2526322628285E-08, 6.41254684791958E-09, -9.1507432597718E-10, 1.01184796635481E-07 };
  const float average_chrome[4] = { 1850.43045387994, 4903.07735480722, 785.25280624695, 1051.22303562714 };
  const float distance_chrome = 3.0;

  /* TODO: * ECH/PQ are still under development/deployment -> re-evaluate these models
           * Session resumptions/0rtt
	   * Non-web traffic */

  /* This is the only logic about pkts distributions.
     ClientHello shoudn't be splitted in too many fragments: usually 1; 2 with PQ */
  if(set->pkts[0] > 3) {
    NDPI_LOG_DBG2(ndpi_struct, "TLS-Obf-Heur: too many pkts in the first burst %d\n", set->pkts[0]);
    return 0;
  }

  if(ndpi_mahalanobis_distance(set->bytes, 4, average_chrome, i_s_chrome) < distance_chrome ||
     /* To avoid false positives: we didn't find TLS 1.3 CH smaller than 517 */
     (set->bytes[0] >= 517 && ndpi_mahalanobis_distance(set->bytes, 4, average_tls_13, i_s_tls_13) < distance_tls_13) ||
     ndpi_mahalanobis_distance(set->bytes, 4, average_tls_12, i_s_tls_12) < distance_tls_12) {

    NDPI_LOG_DBG(ndpi_struct, "TLS-Obf-Heur: md %f %f %f [%d/%d/%d/%d %d/%d/%d/%d] TCP? %d\n",
                 ndpi_mahalanobis_distance(set->bytes, 4, average_tls_12, i_s_tls_12),
                 ndpi_mahalanobis_distance(set->bytes, 4, average_tls_13, i_s_tls_13),
                 ndpi_mahalanobis_distance(set->bytes, 4, average_chrome, i_s_chrome),
                 set->pkts[0], set->pkts[1], set->pkts[2], set->pkts[3],
                 set->bytes[0], set->bytes[1], set->bytes[2], set->bytes[3],
                 !!packet->tcp);
    return 1;
  }

  return 0;
}

/* **************************************** */

static int tls_obfuscated_heur_search(struct ndpi_detection_module_struct* ndpi_struct,
                                      struct ndpi_flow_struct* flow) {
  struct ndpi_packet_struct* packet = &ndpi_struct->packet;
  struct tls_obfuscated_heuristic_state *state = flow->tls_quic.obfuscated_heur_state;
  struct tls_obfuscated_heuristic_set *set;
  int i, j;
  int is_tls_in_tls_heur = 0;
  int byte_overhead;

  /* Stages:
     0: Unused/Start
     1: C->S : burst 1
     2: S->C : burst 2
     3: C->S : burst 3
     4: S->C : burst 4
     5: C->S : End
  */

  if(!state)
    return 1; /* Exclude */

  if(packet->payload_packet_len == 0)
    return 0; /* Continue */

  NDPI_LOG_DBG2(ndpi_struct, "TLS-Obf-Heur: num_pkts %d\n", state->num_pkts);

  if(flow->extra_packets_func &&
     (flow->detected_protocol_stack[0] == NDPI_PROTOCOL_TLS ||
      flow->detected_protocol_stack[1] == NDPI_PROTOCOL_TLS)) /* TLS-in-TLS heuristic */
    is_tls_in_tls_heur = 1;

  /* We try to keep into account the overhead (header/padding/mac/iv/nonce) of the
     external layers (i.e. above the TLS hanshake we are trying to detect) */
  if(is_tls_in_tls_heur == 1) {
    /* According to https://datatracker.ietf.org/doc/html/draft-mattsson-uta-tls-overhead-01
       the average packet overhead for TLS is 29 bytes.
       TODO: this draft is OLD and about TLS 1.2
       Looking at real traffic, we found that we can have TLS packets 24 bytes long
    */
    byte_overhead = 24;
  } else {
    /* The paper says that the overhead is usually quite small
       ["typically ranging between 20 to 60 bytes"], without any citations.
       From the tests, it seams that we can ignore it */
    byte_overhead = 0;
  }

  if(packet->payload_packet_len < byte_overhead) {
    NDPI_LOG_DBG2(ndpi_struct, "TLS-Obf-Heur: packet too small. Stop.\n");
    return 1; /* Exclude */
  }

  if(is_tls_in_tls_heur == 1) {
    /* We usually stop processing TLS handshake (and switch to this extra dissection
       data path) after the FIRST Change-Cipher message. However, for this
       heuristic, we need to ignore all packets before a Change-Cipher is sent in the
       same direction */
    if(current_pkt_from_client_to_server(ndpi_struct, flow) &&
       flow->tls_quic.change_cipher_from_client == 0) {
      if(packet->payload[0] == 0x14) {
        NDPI_LOG_DBG2(ndpi_struct, "TLS-Obf-Heur: Change-Cipher from client\n");
        flow->tls_quic.change_cipher_from_client = 1;
      }
      NDPI_LOG_DBG2(ndpi_struct, "TLS-Obf-Heur: skip\n");
      return 0; /* Continue */
    }
    if(current_pkt_from_server_to_client(ndpi_struct, flow) &&
       flow->tls_quic.change_cipher_from_server == 0) {
      if(packet->payload[0] == 0x14) {
        flow->tls_quic.change_cipher_from_server = 1;
        NDPI_LOG_DBG2(ndpi_struct, "TLS-Obf-Heur: Change-Cipher from server\n");
      }
      NDPI_LOG_DBG2(ndpi_struct, "TLS-Obf-Heur: skip\n");
      return 0; /* Continue */
    }
  }

  if(state->num_pkts++ > ndpi_struct->cfg.tls_heuristics_max_packets) {
    NDPI_LOG_DBG2(ndpi_struct, "TLS-Obf-Heur: too many pkts. Stop\n");
    return 1; /* Exclude */
  }

  /* Update active sets */
  for(i = 0; i < 2; i ++) {
    set = &state->sets[i];
    switch(set->stage) {
    case 0:
      /* This happen only at the beginning of the heuristic: after the first pkt
         of the third (absolute) burst, we always have both sets used */
      if(i == 0 || state->sets[0].stage == 3) {
        if(current_pkt_from_client_to_server(ndpi_struct, flow)) {
          NDPI_LOG_DBG2(ndpi_struct, "TLS-Obf-Heur: open set %d\n", i);
          set->stage = 1;
          break;
	} else {
          /* First packet should be always from client.
	     This shortcut makes detection harder if, before the obfuscated TLS hanshake
	     there is random traffic */
          return 1; /* Exclude */
	}
      }
      continue;
    case 1:
      if(current_pkt_from_server_to_client(ndpi_struct, flow))
        set->stage = 2;
      break;
    case 2:
      if(current_pkt_from_client_to_server(ndpi_struct, flow))
        set->stage = 3;
      break;
    case 3:
      if(current_pkt_from_server_to_client(ndpi_struct, flow))
        set->stage = 4;
      break;
    case 4:
      if(current_pkt_from_client_to_server(ndpi_struct, flow))
        set->stage = 5;
      break;
    /* We cant have 5 here */
    }

    if(set->stage != 5) {
      set->bytes[set->stage - 1] += (packet->payload_packet_len - byte_overhead);
      set->pkts[set->stage - 1] += 1;
    }

    NDPI_LOG_DBG2(ndpi_struct, "TLS-Obf-Heur: set %d stage %d bytes %d/%d/%d/%d pkts %d/%d/%d/%d\n",
                  i, set->stage,
                  set->bytes[0], set->bytes[1], set->bytes[2], set->bytes[3],
                  set->pkts[0], set->pkts[1], set->pkts[2], set->pkts[3]);

    /* Check completed set */
    if(set->stage == 5) {
      NDPI_LOG_DBG2(ndpi_struct, "TLS-Obf-Heur: set %d completed\n", i);
      if(check_set(ndpi_struct, set)) {
        /* Heuristic match */

        return 2; /* Found */
      } else {
        /* Close this set and open a new one... */
        set->stage = 1;
        set->bytes[0] = packet->payload_packet_len - byte_overhead;
        set->pkts[0] = 1;
	for(j = 1; j < 4; j++) {
          set->bytes[j] = 0;
          set->pkts[j] = 0;
        }
        NDPI_LOG_DBG2(ndpi_struct, "TLS-Obf-Heur: set %d closed and reused\n", i);
      }
    }
  }

  return 0; /* Continue */
}

/* **************************************** */

static int tls_obfuscated_heur_search_again(struct ndpi_detection_module_struct* ndpi_struct,
					    struct ndpi_flow_struct* flow) {
  int rc;

  NDPI_LOG_DBG2(ndpi_struct, "TLS-Obf-Heur: extra dissection\n");

  rc = tls_obfuscated_heur_search(ndpi_struct, flow);
  if(rc == 0)
    return 1; /* Keep working */
  if(rc == 2) {
    NDPI_LOG_DBG(ndpi_struct, "TLS-Obf-Heur: found!\n");

    /* Right now, if an heuritic matches, we set the classification/risk.
       TODO: avoid false positives!
       Some ideas:
        * try to identify the servers: we wait for multiple sessions to the same server,
          before to start marking the flows to that address
        * consider the number of burst after TLS handshake (see Fig 8 paper) */

    if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TLS, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI_AGGRESSIVE);
      ndpi_set_risk(ndpi_struct, flow, NDPI_OBFUSCATED_TRAFFIC, "Obfuscated TLS traffic");
    } else {
      flow->confidence = NDPI_CONFIDENCE_DPI_AGGRESSIVE; /* Update the value */
      if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_TLS ||
         flow->detected_protocol_stack[1] == NDPI_PROTOCOL_TLS)
        ndpi_set_risk(ndpi_struct, flow, NDPI_OBFUSCATED_TRAFFIC, "Obfuscated TLS-in-TLS traffic");
      else
        ndpi_set_risk(ndpi_struct, flow, NDPI_OBFUSCATED_TRAFFIC, "Obfuscated TLS-in-HTTP-WebSocket traffic");
    }

    ndpi_master_app_protocol proto;
    proto.master_protocol = ndpi_get_master_proto(ndpi_struct, flow);
    proto.app_protocol = NDPI_PROTOCOL_UNKNOWN;
    flow->category = get_proto_category(ndpi_struct, proto);
    flow->breed = get_proto_breed(ndpi_struct, proto);
  }
  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow); /* Not necessary in extra-dissection data path,
                                                but we need it with the plain heuristic */
  return 0; /* Stop */
}

/* **************************************** */

void switch_extra_dissection_to_tls_obfuscated_heur(struct ndpi_detection_module_struct* ndpi_struct,
                                                    struct ndpi_flow_struct* flow)
{
  NDPI_LOG_DBG(ndpi_struct, "Switching to TLS Obfuscated heuristic\n");

  if(flow->tls_quic.obfuscated_heur_state == NULL)
    flow->tls_quic.obfuscated_heur_state = ndpi_calloc(1, sizeof(struct tls_obfuscated_heuristic_state));
  else /* If state has been already allocated (because of NDPI_HEURISTICS_TLS_OBFUSCATED_PLAIN) reset it */
    memset(flow->tls_quic.obfuscated_heur_state, '\0', sizeof(struct tls_obfuscated_heuristic_state));

  /* "* 2" to take into account ACKs. The "real" check is performend against
     "tls_heuristics_max_packets" in tls_obfuscated_heur_search, as expected */
  flow->max_extra_packets_to_check = ndpi_struct->cfg.tls_heuristics_max_packets * 2;
  flow->extra_packets_func = tls_obfuscated_heur_search_again;
}

/* **************************************** */

static int ndpi_search_tls_memory(const u_int8_t *payload,
				  u_int16_t payload_len,
				  u_int32_t seq,
				  message_t *message) {
  u_int avail_bytes;

#ifdef DEBUG_TLS_MEMORY
  printf("[TLS Mem] Handling TLS flow [payload_len: %u][buffer_len: %u]\n",
	 payload_len,
	 message->buffer_len);
#endif

  if(message->buffer == NULL) {
    /* Allocate buffer */
    message->buffer_len = 2048, message->buffer_used = 0;
    message->buffer = (u_int8_t*)ndpi_malloc(message->buffer_len);

    if(message->buffer == NULL)
      return -1;

#ifdef DEBUG_TLS_MEMORY
    printf("[TLS Mem] Allocating %u buffer\n", message->buffer_len);
#endif
  }

  avail_bytes = message->buffer_len - message->buffer_used;

  if(avail_bytes < payload_len) {
    u_int new_len = message->buffer_len + payload_len - avail_bytes + 1;
    void *newbuf  = ndpi_realloc(message->buffer, new_len);
    if(!newbuf) return -1;

#ifdef DEBUG_TLS_MEMORY
    printf("[TLS Mem] Enlarging %u -> %u buffer\n", message->buffer_len, new_len);
#endif

    message->buffer = (u_int8_t*)newbuf;
    message->buffer_len = new_len;
    avail_bytes = message->buffer_len - message->buffer_used;
  }

  if(payload_len > 0 && avail_bytes >= payload_len) {
    u_int8_t ok = 0;

    if(message->next_seq != 0) {
      if(seq == message->next_seq)
	ok = 1;
    } else
      ok = 1;

    if(ok) {
      memcpy(&message->buffer[message->buffer_used],
	     payload, payload_len);

      message->buffer_used += payload_len;
#ifdef DEBUG_TLS_MEMORY
      printf("[TLS Mem] Copied data to buffer [%u/%u bytes][tcp_seq: %u][next: %u]\n",
	     message->buffer_used, message->buffer_len,
	     seq,
	     seq + payload_len);
#endif

      message->next_seq = seq + payload_len;
    } else {
#ifdef DEBUG_TLS_MEMORY
      printf("[TLS Mem] Skipping packet [%u bytes][tcp_seq: %u][expected next: %u]\n",
	     message->buffer_len,
	     seq,
	     message->next_seq);
#endif
    }
  }
  return 0;
}

/* **************************************** */

static void cleanupServerName(char *buffer, u_int buffer_len) {
  u_int i;

  /* Now all lowecase */
  for(i=0; i<buffer_len; i++)
    buffer[i] = tolower(buffer[i]);
}

/* **************************************** */

/*
  Return code
  -1: error (buffer too short)
  0: OK but buffer is not human readeable (so something went wrong)
  1: OK
*/
static int extractRDNSequence(struct ndpi_packet_struct *packet,
			      u_int offset, char *buffer, u_int buffer_len,
			      char *rdnSeqBuf, u_int *rdnSeqBuf_offset,
			      u_int rdnSeqBuf_len,
			      const char *label) {
  u_int8_t str_len, is_printable = 1;
  char *str;
  u_int len;

  if(*rdnSeqBuf_offset >= rdnSeqBuf_len) {
#ifdef DEBUG_TLS
    printf("[TLS] %s() [buffer capacity reached][%u]\n",
           __FUNCTION__, rdnSeqBuf_len);
#endif
    return -1;
  }
  if((offset+4) >= packet->payload_packet_len)
    return(-1);

  str_len = packet->payload[offset+4];

  // packet is truncated... further inspection is not needed
  if((offset+4+str_len) >= packet->payload_packet_len)
    return(-1);

  str = (char*)&packet->payload[offset+5];

  len = (u_int)ndpi_min(str_len, buffer_len-1);
  strncpy(buffer, str, len);
  buffer[len] = '\0';

  // check string is printable
  is_printable = ndpi_normalize_printable_string(buffer, len);

  if(is_printable) {
    int rc = ndpi_snprintf(&rdnSeqBuf[*rdnSeqBuf_offset],
			   rdnSeqBuf_len-(*rdnSeqBuf_offset),
			   "%s%s=%s", (*rdnSeqBuf_offset > 0) ? ", " : "",
			   label, buffer);

    if(rc > 0 && ((u_int)rc > rdnSeqBuf_len-(*rdnSeqBuf_offset)))
      return -1; /* Truncated; not enough buffer */
    if(rc > 0)
      (*rdnSeqBuf_offset) += rc;
  }

  return(is_printable);
}

/* **************************************** */

static u_int64_t make_tls_cert_key(struct ndpi_packet_struct *packet, int is_from_client)
{
  u_int64_t key;

  /* Server ip/port */
  if(packet->iphv6 == NULL) {
    if(packet->tcp) {
      if(is_from_client)
        key = ((u_int64_t)packet->iph->daddr << 32) | packet->tcp->dest;
      else
        key = ((u_int64_t)packet->iph->saddr << 32) | packet->tcp->source;
    } else {
      if(is_from_client)
        key = ((u_int64_t)packet->iph->daddr << 32) | packet->udp->dest;
      else
        key = ((u_int64_t)packet->iph->saddr << 32) | packet->udp->source;
    }
  } else {
    if(packet->tcp) {
      if(is_from_client)
        key = (ndpi_quick_hash64((const char *)&packet->iphv6->ip6_dst, 16) << 16) | packet->tcp->dest;
      else
        key = (ndpi_quick_hash64((const char *)&packet->iphv6->ip6_src, 16) << 16) | packet->tcp->source;
    } else {
      if(is_from_client)
        key = (ndpi_quick_hash64((const char *)&packet->iphv6->ip6_dst, 16) << 16) | packet->udp->dest;
      else
        key = (ndpi_quick_hash64((const char *)&packet->iphv6->ip6_src, 16) << 16) | packet->udp->source;
    }
  }

  return key;
}

/* **************************************** */

static void checkTLSSubprotocol(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow,
				int is_from_client) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  if(ndpi_struct->cfg.tls_subclassification_enabled &&
     flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN) {
    /* Subprotocol not yet set */

    if(ndpi_struct->tls_cert_cache) {
      u_int16_t cached_proto;
      u_int64_t key;

      key = make_tls_cert_key(packet, is_from_client);

      if(ndpi_lru_find_cache(ndpi_struct->tls_cert_cache, key,
			     &cached_proto, 0 /* Don't remove it as it can be used for other connections */,
			     ndpi_get_current_time(flow))) {
        ndpi_master_app_protocol proto;

	ndpi_set_detected_protocol(ndpi_struct, flow, cached_proto, ndpi_get_master_proto(ndpi_struct, flow), NDPI_CONFIDENCE_DPI_CACHE);
	proto.master_protocol = ndpi_get_master_proto(ndpi_struct, flow);
	proto.app_protocol = cached_proto;
	flow->category = get_proto_category(ndpi_struct, proto);
	flow->breed = get_proto_breed(ndpi_struct, proto);
	ndpi_check_subprotocol_risk(ndpi_struct, flow, cached_proto);
	ndpi_unset_risk(ndpi_struct, flow, NDPI_NUMERIC_IP_HOST);
      }
    }
  }
}

/* **************************************** */

/* See https://blog.catchpoint.com/2017/05/12/dissecting-tls-using-wireshark/ */
void processCertificateElements(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow,
				u_int16_t p_offset, u_int16_t certificate_len) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t num_found = 0;
  int32_t i;
  char buffer[64] = { '\0' }, rdnSeqBuf[2048];
  u_int rdn_len = 0;

  rdnSeqBuf[0] = '\0';

#ifdef DEBUG_TLS
  printf("[TLS] %s() [offset: %u][certificate_len: %u]\n", __FUNCTION__, p_offset, certificate_len);
#endif

  /* Check after handshake protocol header (5 bytes) and message header (4 bytes) */
  for(i = p_offset; i < certificate_len - 2; i++) {
    /*
      See https://www.ibm.com/support/knowledgecenter/SSFKSJ_7.5.0/com.ibm.mq.sec.doc/q009860_.htm
      for X.509 certificate labels
    */
    if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x03)) {
      /* Common Name */
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "CN");
      if(rc == -1) break;

#ifdef DEBUG_TLS
      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Common Name", buffer);
#endif
    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x06)) {
      /* Country */
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "C");
      if(rc == -1) break;

#ifdef DEBUG_TLS
      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Country", buffer);
#endif
    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x07)) {
      /* Locality */
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "L");
      if(rc == -1) break;

#ifdef DEBUG_TLS
      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Locality", buffer);
#endif
    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x08)) {
      /* State or Province */
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "ST");
      if(rc == -1) break;

#ifdef DEBUG_TLS
      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "State or Province", buffer);
#endif
    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x0a)) {
      /* Organization Name */
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "O");
      if(rc == -1) break;

#ifdef DEBUG_TLS
      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Organization Name", buffer);
#endif

    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x0b)) {
      /* Organization Unit */
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "OU");
      if(rc == -1) break;

#ifdef DEBUG_TLS
      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Organization Unit", buffer);
#endif
    } else if((packet->payload[i] == 0x30) && (packet->payload[i+1] == 0x1e) && (packet->payload[i+2] == 0x17)) {
      /* Certificate Validity */
      u_int offset = i+4;

      if(num_found == 0) {
	num_found++;

#ifdef DEBUG_TLS
	printf("[TLS] %s() IssuerDN [%s]\n", __FUNCTION__, rdnSeqBuf);
#endif

	if(rdn_len && (flow->protos.tls_quic.issuerDN == NULL) &&
	   ndpi_struct->cfg.tls_cert_issuer_enabled) {
	  flow->protos.tls_quic.issuerDN = ndpi_strdup(rdnSeqBuf);
	  if(ndpi_normalize_printable_string(rdnSeqBuf, rdn_len) == 0) {
	    if(is_flowrisk_info_enabled(ndpi_struct, NDPI_INVALID_CHARACTERS)) {
	      char str[64];
	      snprintf(str, sizeof(str), "Invalid issuerDN %s", flow->protos.tls_quic.issuerDN);
	      ndpi_set_risk(ndpi_struct, flow, NDPI_INVALID_CHARACTERS, str);
	    } else {
	      ndpi_set_risk(ndpi_struct, flow, NDPI_INVALID_CHARACTERS, NULL);
	    }
	  }
	}

	rdn_len = 0; /* Reset buffer */
      }

      if(i + 3 < certificate_len &&
	 (offset+packet->payload[i+3]) < packet->payload_packet_len &&
	 ndpi_struct->cfg.tls_cert_validity_enabled) {
	char utcDate[32];
        u_int8_t len = packet->payload[i+3];

#ifdef DEBUG_TLS
	u_int j;

	printf("[CERTIFICATE] notBefore [len: %u][", len);
	for(j=0; j<len; j++) printf("%c", packet->payload[i+4+j]);
	printf("]\n");
#endif

	if(len < (sizeof(utcDate)-1)) {
	  struct tm utc;
	  utc.tm_isdst = -1; /* Not set by strptime */

	  strncpy(utcDate, (const char*)&packet->payload[i+4], len);
	  utcDate[len] = '\0';

	  /* 141021000000Z */
	  if(strptime(utcDate, "%y%m%d%H%M%SZ", &utc) != NULL) {
	    flow->protos.tls_quic.notBefore = timegm(&utc);
#ifdef DEBUG_TLS
	    printf("[CERTIFICATE] notBefore %u [%s]\n",
		   flow->protos.tls_quic.notBefore, utcDate);
#endif
	  }
	}

	offset += len;

	if((offset+1) < packet->payload_packet_len) {
	  len = packet->payload[offset+1];

	  offset += 2;

	  if((offset+len) < packet->payload_packet_len) {
	    u_int32_t time_sec = packet->current_time_ms / 1000;
#ifdef DEBUG_TLS
	    u_int j;

	    printf("[CERTIFICATE] notAfter [len: %u][", len);
	    for(j=0; j<len; j++) printf("%c", packet->payload[offset+j]);
	    printf("]\n");
#endif

	    if(len < (sizeof(utcDate)-1)) {
	      struct tm utc;
	      utc.tm_isdst = -1; /* Not set by strptime */

	      strncpy(utcDate, (const char*)&packet->payload[offset], len);
	      utcDate[len] = '\0';

	      /* 141021000000Z */
	      if(strptime(utcDate, "%y%m%d%H%M%SZ", &utc) != NULL) {
		flow->protos.tls_quic.notAfter = timegm(&utc);
#ifdef DEBUG_TLS
		printf("[CERTIFICATE] notAfter %u [%s]\n",
		       flow->protos.tls_quic.notAfter, utcDate);
#endif
	      }
	    }

	    if(flow->protos.tls_quic.notBefore > TLS_LIMIT_DATE)
	      if((flow->protos.tls_quic.notAfter-flow->protos.tls_quic.notBefore) > TLS_THRESHOLD) {
	        if(is_flowrisk_info_enabled(ndpi_struct, NDPI_TLS_CERT_VALIDITY_TOO_LONG)) {
	          char str[64];

		  snprintf(str, sizeof(str), "TLS Cert lasts %u days",
			   (flow->protos.tls_quic.notAfter-flow->protos.tls_quic.notBefore) / 86400);

		  ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_CERT_VALIDITY_TOO_LONG, str); /* Certificate validity longer than 13 months */
	        } else {
	          ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_CERT_VALIDITY_TOO_LONG, NULL);
	        }
	      }

	    if((time_sec < flow->protos.tls_quic.notBefore) || (time_sec > flow->protos.tls_quic.notAfter)) {
	      if(is_flowrisk_info_enabled(ndpi_struct, NDPI_TLS_CERTIFICATE_EXPIRED)) {
	        char str[96], b[32], e[32];
	        struct tm result;
	        time_t theTime;

	        theTime = flow->protos.tls_quic.notBefore;
	        strftime(b, sizeof(b), "%d/%b/%Y %H:%M:%S", ndpi_gmtime_r(&theTime, &result));

	        theTime = flow->protos.tls_quic.notAfter;
	        strftime(e, sizeof(e), "%d/%b/%Y %H:%M:%S", ndpi_gmtime_r(&theTime, &result));

	        snprintf(str, sizeof(str), "%s - %s", b, e);
	        ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_CERTIFICATE_EXPIRED, str); /* Certificate expired */
	      } else {
	        ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_CERTIFICATE_EXPIRED, NULL);
	      }
	    } else if((time_sec > flow->protos.tls_quic.notBefore)
		      && (time_sec > (flow->protos.tls_quic.notAfter - (ndpi_struct->cfg.tls_certificate_expire_in_x_days * 86400)))) {
	      if(is_flowrisk_info_enabled(ndpi_struct, NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE)) {
	        char str[96], b[32], e[32];
	        struct tm result;
	        time_t theTime;

	        theTime = flow->protos.tls_quic.notBefore;
	        strftime(b, sizeof(b), "%d/%b/%Y %H:%M:%S", ndpi_gmtime_r(&theTime, &result));

	        theTime = flow->protos.tls_quic.notAfter;
	        strftime(e, sizeof(e), "%d/%b/%Y %H:%M:%S", ndpi_gmtime_r(&theTime, &result));

	        snprintf(str, sizeof(str), "%s - %s", b, e);
	        ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE, str); /* Certificate almost expired */
	      } else {
	        ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE, NULL);
	      }
	    }
	  }
	}
      }
    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x1d) && (packet->payload[i+2] == 0x11)) {
      /* Organization OID: 2.5.29.17 (subjectAltName) */
      u_int8_t matched_name = 0;

      /* If the client hello was not observed or the requested name was missing, there is no need to trigger an alert */
      if(flow->host_server_name[0] == '\0')
	matched_name = 1;

#ifdef DEBUG_TLS
      printf("******* [TLS] Found subjectAltName\n");
#endif

      i += 3 /* skip the initial patten 55 1D 11 */;

      /* skip the first type, 0x04 == BIT STRING, and jump to it's length */
      if(i < packet->payload_packet_len && packet->payload[i] == 0x04) i++; else i += 4; /* 4 bytes, with the last byte set to 04 */

      if(i < packet->payload_packet_len) {
	i += (packet->payload[i] & 0x80) ? (packet->payload[i] & 0x7F) : 0; /* skip BIT STRING length */
	if(i < packet->payload_packet_len) {
	  i += 2; /* skip the second type, 0x30 == SEQUENCE, and jump to it's length */
	  if(i < packet->payload_packet_len) {
	    i += (packet->payload[i] & 0x80) ? (packet->payload[i] & 0x7F) : 0; /* skip SEQUENCE length */
	    i++;

	    while(i < packet->payload_packet_len) {
	      u_int8_t general_name_type = packet->payload[i];

	      if((general_name_type == 0x81)    /* rfc822Name */
		 || (general_name_type == 0x82) /* dNSName    */
		 || (general_name_type == 0x87) /* ipAddress  */
		 )
		{
		  if((i < (packet->payload_packet_len - 1))
		     && ((i + packet->payload[i + 1] + 2) < packet->payload_packet_len)) {
		    u_int8_t len = packet->payload[i + 1];
		    char dNSName[256];
		    u_int16_t dNSName_len;

		    i += 2;

		    /* The check "len > sizeof(dNSName) - 1" will be always false. If we add it,
		       the compiler is smart enough to detect it and throws a warning */
		    if((len == 0 /* Looks something went wrong */)
		       || ((i+len) > packet->payload_packet_len))
		      break;

		    if(general_name_type == 0x87) {
		      if(len == 4 /* IPv4 */) {
			ndpi_snprintf(dNSName, sizeof(dNSName), "%u.%u.%u.%u",
				      packet->payload[i] & 0xFF,
				      packet->payload[i+1] & 0xFF,
				      packet->payload[i+2] & 0xFF,
				      packet->payload[i+3] & 0xFF);
		      } else if(len == 16 /* IPv6 */) {
			struct in6_addr addr = *(struct in6_addr *)&packet->payload[i];
			inet_ntop(AF_INET6, &addr, dNSName, sizeof(dNSName));
		      } else {
			/* Is that possibile? Better safe than sorry */
			dNSName[0] = '\0';
		      }
		    } else {
		      strncpy(dNSName, (const char*)&packet->payload[i], len);
		      dNSName[len] = '\0';
		    }

		    dNSName_len = strlen(dNSName);
		    cleanupServerName(dNSName, dNSName_len);

#if DEBUG_TLS
		    printf("[TLS] dNSName %s [%s][len: %u][leftover: %d]\n", dNSName,
			   flow->host_server_name, len,
			   packet->payload_packet_len-i-len);
#endif

		    /*
		      We cannot use ndpi_is_valid_hostname() as we can have wildcards
		      here that will create false positives
		    */
		    if(ndpi_normalize_printable_string(dNSName, dNSName_len) == 0) {
		      ndpi_set_risk(ndpi_struct, flow, NDPI_INVALID_CHARACTERS, dNSName);

		      /* This looks like an attack */
		      ndpi_set_risk(ndpi_struct, flow, NDPI_POSSIBLE_EXPLOIT, "Invalid dNSName name");
		    }

		    if(matched_name == 0) {
#if DEBUG_TLS
		      printf("[TLS] Trying to match '%s' with '%s'\n",
			     flow->host_server_name, dNSName);
#endif

		      if(dNSName[0] == '*') {
			char * label = strstr(flow->host_server_name, &dNSName[1]);

			if(label != NULL) {
			  char * first_dot = strchr(flow->host_server_name, '.');

			  if((first_dot == NULL) || (first_dot <= label)) {
			    matched_name = 1;
			  }
			}
		      } else if(strcmp(flow->host_server_name, dNSName) == 0) {
			matched_name = 1;
		      }
		    }

		    if(ndpi_struct->cfg.tls_cert_server_names_enabled) {
                      if(flow->protos.tls_quic.server_names == NULL) {
                        flow->protos.tls_quic.server_names = ndpi_strdup(dNSName);
                        flow->protos.tls_quic.server_names_len = strlen(dNSName);
                      } else if((u_int16_t)(flow->protos.tls_quic.server_names_len + dNSName_len + 1) > flow->protos.tls_quic.server_names_len) {
                        u_int16_t newstr_len = flow->protos.tls_quic.server_names_len + dNSName_len + 1;
                        char *newstr = (char*)ndpi_realloc(flow->protos.tls_quic.server_names,
                                                           newstr_len + 1);

                        if(newstr) {
                          flow->protos.tls_quic.server_names = newstr;
                          flow->protos.tls_quic.server_names[flow->protos.tls_quic.server_names_len] = ',';
                          strncpy(&flow->protos.tls_quic.server_names[flow->protos.tls_quic.server_names_len+1],
                                  dNSName, dNSName_len+1);
                          flow->protos.tls_quic.server_names[newstr_len] = '\0';
                          flow->protos.tls_quic.server_names_len = newstr_len;
                        }
                      }
		    }

		    if(ndpi_struct->cfg.tls_subclassification_enabled &&
		       !flow->protos.tls_quic.subprotocol_detected &&
		       !flow->tls_quic.from_rdp) { /* No (other) sub-classification; we will have TLS.RDP anyway */
		      if(ndpi_match_hostname_protocol(ndpi_struct, flow, ndpi_get_master_proto(ndpi_struct, flow), dNSName, dNSName_len)) {
			flow->protos.tls_quic.subprotocol_detected = 1;
		        ndpi_unset_risk(ndpi_struct, flow, NDPI_NUMERIC_IP_HOST);
		      }
		    }

		    i += len;
		  } else {
		    char buf[32];

		    snprintf(buf, sizeof(buf), "Unknown extension %02X", general_name_type);
#if DEBUG_TLS
		    printf("[TLS] Leftover %u bytes", packet->payload_packet_len - i);
#endif
		    ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_SUSPICIOUS_EXTENSION, buf);
		    break;
		  }
		} else {
		break;
	      }
	    } /* while */

	    if(!matched_name) {
	      if(is_flowrisk_info_enabled(ndpi_struct, NDPI_TLS_CERTIFICATE_MISMATCH)) {
	        char str[128];

	        snprintf(str, sizeof(str), "%s vs %s", flow->host_server_name, flow->protos.tls_quic.server_names);
	        ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_CERTIFICATE_MISMATCH, str); /* Certificate mismatch */
	      } else {
	        ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_CERTIFICATE_MISMATCH, NULL); /* Certificate mismatch */
	      }
	    }
	  }
	}
      }
    }
  } /* for */

  if(rdn_len && (flow->protos.tls_quic.subjectDN == NULL)) {
    if(ndpi_struct->cfg.tls_cert_subject_enabled)
      flow->protos.tls_quic.subjectDN = ndpi_strdup(rdnSeqBuf);

    if(ndpi_struct->cfg.tls_subclassification_enabled &&
       flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN) {
      /* No idea what is happening behind the scenes: let's check the certificate */
      u_int32_t val;
      int rc = ndpi_match_string_value(ndpi_struct->tls_cert_subject_automa.ac_automa,
				       rdnSeqBuf, strlen(rdnSeqBuf), &val);

      if(rc == 0) {
	/* Match found */
	u_int16_t proto_id = (u_int16_t)val;
	ndpi_master_app_protocol proto;

	ndpi_set_detected_protocol(ndpi_struct, flow, proto_id, ndpi_get_master_proto(ndpi_struct, flow), NDPI_CONFIDENCE_DPI);
	proto.master_protocol = ndpi_get_master_proto(ndpi_struct, flow);
	proto.app_protocol = proto_id;
	flow->category = get_proto_category(ndpi_struct, proto);
	flow->breed = get_proto_breed(ndpi_struct, proto);
	ndpi_check_subprotocol_risk(ndpi_struct, flow, proto_id);
	ndpi_unset_risk(ndpi_struct, flow, NDPI_NUMERIC_IP_HOST);

	if(ndpi_struct->tls_cert_cache) {
	  u_int64_t key = make_tls_cert_key(packet, 0 /* from the server */);

	  ndpi_lru_add_to_cache(ndpi_struct->tls_cert_cache, key, proto_id, ndpi_get_current_time(flow));
	}
      }
    }
  }

  if(flow->protos.tls_quic.subjectDN && flow->protos.tls_quic.issuerDN
     && (!strcmp(flow->protos.tls_quic.subjectDN, flow->protos.tls_quic.issuerDN))) {
    /* Last resort: we check if this is a trusted issuerDN */
    if(ndpi_check_issuerdn_risk_exception(ndpi_struct, flow->protos.tls_quic.issuerDN))
      return; /* This is a trusted DN */

    if(!flow->protos.tls_quic.webrtc)
      ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_SELFSIGNED_CERTIFICATE, flow->protos.tls_quic.subjectDN);
  }

#if DEBUG_TLS
  printf("[TLS] %s() SubjectDN [%s]\n", __FUNCTION__, rdnSeqBuf);
#endif
}

/* **************************************** */

static void tls_match_ja4(struct ndpi_detection_module_struct *ndpi_struct,
			  struct ndpi_flow_struct *flow) {
  if(ndpi_struct->ja4_custom_protos != NULL) {
    u_int64_t proto_id;
    ndpi_list *extra_data = NULL;

    /* This protocol has been defined in protos.txt-like files */
    if(ndpi_hash_find_entry_extra(ndpi_struct->ja4_custom_protos,
				  flow->protos.tls_quic.ja4_client,
				  NDPI_ARRAY_LENGTH(flow->protos.tls_quic.ja4_client) - 1,
				  &proto_id, &extra_data) != 0)
      return; /* Not found */
    else
      proto_id = ndpi_compare_flow_tls_blocks(ndpi_struct, flow, extra_data, proto_id);

    if(proto_id != NDPI_PROTOCOL_UNKNOWN)
      ndpi_set_detected_protocol(ndpi_struct, flow, proto_id,
				 ndpi_get_master_proto(ndpi_struct, flow),
				 NDPI_CONFIDENCE_CUSTOM_RULE);
  }

  if(ndpi_struct->malicious_ja4_hashmap != NULL) {
    u_int16_t rc1 = ndpi_hash_find_entry(ndpi_struct->malicious_ja4_hashmap,
					 flow->protos.tls_quic.ja4_client,
					 NDPI_ARRAY_LENGTH(flow->protos.tls_quic.ja4_client) - 1,
					 NULL);

    if(rc1 == 0)
      ndpi_set_risk(ndpi_struct, flow, NDPI_MALICIOUS_FINGERPRINT,
		    flow->protos.tls_quic.ja4_client);
  }
}

/* **************************************** */

/* See https://blog.catchpoint.com/2017/05/12/dissecting-tls-using-wireshark/ */
int processCertificate(struct ndpi_detection_module_struct *ndpi_struct,
		       struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  int is_dtls = packet->udp || flow->stun.maybe_dtls; /* No certificate with QUIC */
  u_int32_t certificates_length, length = (packet->payload[1] << 16) + (packet->payload[2] << 8) + packet->payload[3];
  u_int32_t certificates_offset = 7 + (is_dtls ? 8 : 0);
  u_int8_t num_certificates_found = 0;

#ifdef DEBUG_TLS
  printf("[TLS] %s() [payload_packet_len=%u][direction: %u][%02X %02X %02X %02X %02X %02X...]\n",
	 __FUNCTION__, packet->payload_packet_len,
	 packet->packet_direction,
	 packet->payload[0], packet->payload[1], packet->payload[2],
	 packet->payload[3], packet->payload[4], packet->payload[5]);
#endif

  if((packet->payload_packet_len != (length + 4 + (is_dtls ? 8 : 0))) || (packet->payload[1] != 0x0) ||
     certificates_offset >= packet->payload_packet_len) {
    ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, "Unvalid lenght");
    return(-1); /* Invalid length */
  }

  certificates_length = (packet->payload[certificates_offset - 3] << 16) +
    (packet->payload[certificates_offset - 2] << 8) +
    packet->payload[certificates_offset - 1];

  if((packet->payload[certificates_offset - 3] != 0x0) || ((certificates_length+3) != length)) {
    ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, "Invalid certificate offset");
    return(-2); /* Invalid length */
  }

  /* Now let's process each individual certificates */
  while(certificates_offset < certificates_length) {
    u_int32_t certificate_len = (packet->payload[certificates_offset] << 16) + (packet->payload[certificates_offset+1] << 8) + packet->payload[certificates_offset+2];

    /* Invalid lenght */
    if((certificate_len == 0)
       || (packet->payload[certificates_offset] != 0x0)
       || ((certificates_offset+certificate_len) > (4+certificates_length+(is_dtls ? 8 : 0)))) {
#ifdef DEBUG_TLS
      printf("[TLS] Invalid length [certificate_len: %u][certificates_offset: %u][%u vs %u]\n",
	     certificate_len, certificates_offset,
	     (certificates_offset+certificate_len),
	     certificates_length);
#endif
      break;
    }

    certificates_offset += 3;
#ifdef DEBUG_TLS
    printf("[TLS] Processing %u bytes certificate [%02X %02X %02X]\n",
	   certificate_len,
	   packet->payload[certificates_offset],
	   packet->payload[certificates_offset+1],
	   packet->payload[certificates_offset+2]);
#endif

    if(num_certificates_found++ == 0) /* Dissect only the first certificate that is the one we care */ {

#ifdef DEBUG_CERTIFICATE_HASH
      {
	u_int32_t i;

	for(i=0;i<certificate_len;i++)
	  printf("%02X ", packet->payload[certificates_offset+i]);

	printf("\n");
      }
#endif

      /* For SHA-1 we take into account only the first certificate and not all of them */
      if(ndpi_struct->cfg.tls_sha1_fingerprint_enabled) {
        SHA1_CTX srv_cert_fingerprint_ctx ;

	SHA1Init(&srv_cert_fingerprint_ctx);
	SHA1Update(&srv_cert_fingerprint_ctx,
                   &packet->payload[certificates_offset],
                   certificate_len);

        SHA1Final(flow->protos.tls_quic.sha1_certificate_fingerprint, &srv_cert_fingerprint_ctx);

        flow->protos.tls_quic.fingerprint_set = 1;

        uint8_t * sha1 = flow->protos.tls_quic.sha1_certificate_fingerprint;
        const size_t sha1_siz = sizeof(flow->protos.tls_quic.sha1_certificate_fingerprint);
        char sha1_str[20 /* sha1_siz */ * 2 + 1];
        static const char hexalnum[] = "0123456789ABCDEF";
        size_t i;
        for (i = 0; i < sha1_siz; ++i) {
          u_int8_t lower = (sha1[i] & 0x0F);
          u_int8_t upper = (sha1[i] & 0xF0) >> 4;
          sha1_str[i*2] = hexalnum[upper];
          sha1_str[i*2 + 1] = hexalnum[lower];
        }
        sha1_str[sha1_siz * 2] = '\0';

#ifdef DEBUG_TLS
        printf("[TLS] SHA-1: %s\n", sha1_str);
#endif

        if(ndpi_struct->malicious_sha1_hashmap != NULL) {
          u_int16_t rc1 = ndpi_hash_find_entry(ndpi_struct->malicious_sha1_hashmap, sha1_str, sha1_siz * 2, NULL);

          if(rc1 == 0)
            ndpi_set_risk(ndpi_struct, flow, NDPI_MALICIOUS_SHA1_CERTIFICATE, sha1_str);
        }
      }

      processCertificateElements(ndpi_struct, flow, certificates_offset, certificate_len);
    }

    certificates_offset += certificate_len;
  }

  return(1);
}

/* **************************************** */

static void handleTLSBlockStat(struct ndpi_detection_module_struct *ndpi_struct,
			       struct ndpi_flow_struct *flow, bool *same_packet,
			       u_int8_t record_type, u_int8_t handshake_type,
			       u_int16_t block_len) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  if(flow->l4_proto == IPPROTO_TCP &&
     ndpi_struct->cfg.tls_max_num_blocks_to_analyze != 0) {
    if(flow->l4.tcp.tls.tls_blocks == NULL) {
      u_int len = sizeof(struct ndpi_tls_block) * ndpi_struct->cfg.tls_max_num_blocks_to_analyze;

      flow->l4.tcp.tls.tls_blocks = (struct ndpi_tls_block *)ndpi_malloc(len);
    }

    if((flow->l4.tcp.tls.tls_blocks != NULL)
       && (flow->l4.tcp.tls.num_tls_blocks < ndpi_struct->cfg.tls_max_num_blocks_to_analyze)) {

      int32_t blen;
      u_int32_t tdelta;
      u_int16_t enc_block_type;

      enc_block_type = ndpi_encode_tls_block_type(record_type, handshake_type);
      blen = block_len;

      if(flow->l4.tcp.tls.last_tls_block_time_ms)
        tdelta = ndpi_struct->packet.current_time_ms - flow->l4.tcp.tls.last_tls_block_time_ms;
      else
        tdelta = 0;

      if(packet->packet_direction == 1 /* srv -> cli */) blen *= -1;

      flow->l4.tcp.tls.tls_blocks[flow->l4.tcp.tls.num_tls_blocks].len = blen,
         flow->l4.tcp.tls.tls_blocks[flow->l4.tcp.tls.num_tls_blocks].msec_delta =
        (tdelta > 0xFFFF) ?  0xFFFF : (u_int16_t)tdelta,
        flow->l4.tcp.tls.tls_blocks[flow->l4.tcp.tls.num_tls_blocks].same_pkt = same_packet ? 1 : 0;
      flow->l4.tcp.tls.tls_blocks[flow->l4.tcp.tls.num_tls_blocks++].block_type = enc_block_type;

      flow->l4.tcp.tls.last_tls_block_time_ms = ndpi_struct->packet.current_time_ms;
    }
  }
  if(*same_packet == false)
    *same_packet = true;
}

/* **************************************** */

static int processHandshakeTLSBlock(struct ndpi_detection_module_struct *ndpi_struct,
				    struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  int ret;
  int is_dtls = packet->udp || flow->stun.maybe_dtls;
  u_int8_t handshake_type = packet->payload[0];

#ifdef DEBUG_TLS
  printf("[TLS] Processing block %u\n", packet->payload[0]);
#endif

  switch(handshake_type) {
  case 0x01: /* Client Hello */
    if((flow->l4.tcp.three_way_handshake.syn_time != 0) /* Check only if 3WH was observed */
       && (flow->l4.tcp.three_way_handshake.ack_time != 0)
       ) {
      u_int64_t tdiff_ms = packet->current_time_ms - flow->l4.tcp.three_way_handshake.ack_time;

      if((tdiff_ms > 3000 /* 3 sec */) && (!ndpi_isset_risk(flow, NDPI_SLOW_DOS))) {
	char buf[64];

	snprintf(buf, sizeof(buf), "Slow TLS Request: %.1f sec", tdiff_ms/1000.);
	ndpi_set_risk(ndpi_struct, flow, NDPI_SLOW_DOS, buf);
      }
    }

    flow->protos.tls_quic.client_hello_processed = 1;
    flow->protos.tls_quic.ch_direction = packet->packet_direction;
    processClientServerHello(ndpi_struct, flow, 0);
    ndpi_int_tls_add_connection(ndpi_struct, flow);

#ifdef DEBUG_TLS
    printf("*** TLS [version: %02X][Client Hello]\n",
	   flow->protos.tls_quic.ssl_version);
#endif

    checkTLSSubprotocol(ndpi_struct, flow, packet->payload[0] == 0x01);
    break;

  case 0x02: /* Server Hello */
    flow->protos.tls_quic.server_hello_processed = 1;
    flow->protos.tls_quic.ch_direction = !packet->packet_direction;
    processClientServerHello(ndpi_struct, flow, 0);
    ndpi_int_tls_add_connection(ndpi_struct, flow);

#ifdef DEBUG_TLS
    printf("*** TLS [version: %02X][Server Hello]\n",
	   flow->protos.tls_quic.ssl_version);
#endif

    if(!is_dtls && flow->protos.tls_quic.ssl_version >= 0x0304 /* TLS 1.3 */)
      flow->tls_quic.certificate_processed = 1; /* No Certificate with TLS 1.3+ */

    if(is_dtls && flow->protos.tls_quic.ssl_version == 0xFEFC /* DTLS 1.3 */)
      flow->tls_quic.certificate_processed = 1; /* No Certificate with DTLS 1.3+ */

    checkTLSSubprotocol(ndpi_struct, flow, packet->payload[0] == 0x01);
    break;

  case 0x0b: /* Certificate */
    /* Important: populate the tls union fields only after
     * ndpi_int_tls_add_connection has been called */
    if(flow->protos.tls_quic.client_hello_processed ||
       flow->protos.tls_quic.server_hello_processed) {
      /* Only certificates from the server */
      if(flow->protos.tls_quic.ch_direction != packet->packet_direction) {
        ret = processCertificate(ndpi_struct, flow);
        if(ret != 1) {
#ifdef DEBUG_TLS
          printf("[TLS] Error processing certificate: %d\n", ret);
#endif
        }
      } else {
#ifdef DEBUG_TLS
        printf("[TLS] Certificate from client. Ignoring it\n");
#endif
      }
      flow->tls_quic.certificate_processed = 1;
    }
    break;
  }

  return(0);
}

/* **************************************** */

static void ndpi_looks_like_tls(struct ndpi_detection_module_struct *ndpi_struct,
                                struct ndpi_flow_struct *flow) {
  if(flow->fast_callback_protocol_id == NDPI_PROTOCOL_UNKNOWN)
    flow->fast_callback_protocol_id = ndpi_get_master_proto(ndpi_struct, flow);
}

/* **************************************** */

static int check_tls_type_and_version(const u_int8_t *buf, u_int16_t buf_len)
{
  /* Valid TLS Content Types:
     https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5 */
  if(buf_len >= 1 &&
     !(buf[0] >= 20 && buf[0] <= 26))
    return 0;

  /* Valid version in Record Layer
     "Earlier versions of the TLS specification were not fully clear on what the record layer version
     number (TLSPlaintext.version) should contain when sending ClientHello (i.e., before it is known
     which version of the protocol will be employed). Thus, TLS servers compliant with this
     specification MUST accept any value {03,XX} as the record layer version number for ClientHello."
  */
  if(buf_len >=2 && buf[1] != 0x03)
    return 0;

  return 1; /* ok */
}

/* **************************************** */

int ndpi_search_tls_tcp(struct ndpi_detection_module_struct *ndpi_struct,
                        struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int8_t something_went_wrong = 0;
  message_t *message;
  bool same_packet = false;

  if(packet->tcp == NULL)
    return 0; /* Error -> stop (this doesn't seem to be TCP) */

#ifdef DEBUG_TLS_MEMORY
  printf("[TLS Mem] ndpi_search_tls_tcp() Processing new packet [payload_packet_len: %u][Dir: %u]\n",
	 packet->payload_packet_len, packet->packet_direction);
#endif

  /* This function is also called by "extra dissection" data path. Unfortunately,
     generic "extra function" code doesn't honour protocol bitmask.
     TODO: handle that in ndpi_main.c for all the protocols */
  if(packet->payload_packet_len == 0 ||
     packet->tcp_retransmission) {
#ifdef DEBUG_TLS_MEMORY
    printf("[TLS Mem] Ack or retransmission %d/%d. Skip\n",
           packet->payload_packet_len, packet->tcp_retransmission);
#endif
    return 1; /* Keep working */
  }

  message = &flow->tls_quic.message[packet->packet_direction];
  if(ndpi_search_tls_memory(packet->payload,
			    packet->payload_packet_len, ntohl(packet->tcp->seq),
			    message) == -1)
    return 0; /* Error -> stop */

  while(!something_went_wrong) {
    u_int32_t len;
    u_int16_t p_len;
    const u_int8_t *p;
    u_int8_t content_type;

    if(message->buffer_used < 5)
      break;

    if(!check_tls_type_and_version(message->buffer, message->buffer_used)) {
#ifdef DEBUG_TLS_MEMORY
      printf("[TLS Mem] Invalid record type/version");
#endif
      something_went_wrong = 1;
      break;
    }

    len = (message->buffer[3] << 8) + message->buffer[4] + 5;

    if(len > message->buffer_used) {
#ifdef DEBUG_TLS_MEMORY
      printf("[TLS Mem] Not enough TLS data [%u < %u][%02X %02X %02X %02X %02X]\n",
	     len, message->buffer_used,
	     message->buffer[0],
	     message->buffer[1],
	     message->buffer[2],
	     message->buffer[3],
	     message->buffer[4]);
#endif
      break;
    }

#ifdef DEBUG_TLS_MEMORY
    printf("[TLS Mem] Processing %u bytes message\n", len);
#endif

    content_type = message->buffer[0];

    if(content_type != 0x16)
      handleTLSBlockStat(ndpi_struct, flow, &same_packet, content_type, 0, len - 5);

    /* Overwriting packet payload */
    p = packet->payload;
    p_len = packet->payload_packet_len; /* Backup */

    if(content_type == 0x14 /* Change Cipher Spec */) {
      if(len == 6 &&
         message->buffer[1] == 0x03 && /* TLS >= 1.0 */
         ((message->buffer[3] << 8) + (message->buffer[4])) == 1) {
#ifdef DEBUG_TLS
        printf("[TLS] Change Cipher Spec\n");
#endif
        if(current_pkt_from_client_to_server(ndpi_struct, flow))
          flow->tls_quic.change_cipher_from_client = 1;
        else
          flow->tls_quic.change_cipher_from_server = 1;

        ndpi_int_tls_add_connection(ndpi_struct, flow);
        flow->l4.tcp.tls.app_data_seen[packet->packet_direction] = 1;
        /* Further data is encrypted so we are not able to parse it without
           errors and without setting `something_went_wrong` variable */

	if(ndpi_struct->cfg.tls_max_num_blocks_to_analyze == 0) {
	  /*
	    In case of TLS blocks analysis we want to analize all the blocks
	    whereas in "standard" mode we can use this shortcut and break
	  */
	  break;
	}
      }
    } else if(content_type == 0x15 /* Alert */) {
      /* https://techcommunity.microsoft.com/t5/iis-support-blog/ssl-tls-alert-protocol-and-the-alert-codes/ba-p/377132 */
#ifdef DEBUG_TLS
      printf("[TLS] *** TLS ALERT ***\n");
#endif

      flow->tls_quic.alert = 1;

      /* Basic heuristic to tell if the alert is encrypted or not */
      if(len == 7 &&
         (message->buffer[5] == 1 ||
          message->buffer[5] == 2)) {
	u_int8_t alert_level = message->buffer[5];

	if(alert_level == 2 /* Warning (1), Fatal (2) */)
	  ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_FATAL_ALERT, "Found fatal TLS alert");
	else
	  flow->tls_quic.alert = 0;
      }

      u_int16_t const alert_len = ntohs(*(u_int16_t const *)&message->buffer[3]);
      if(alert_len == (u_int32_t)message->buffer_used - 5)
	ndpi_int_tls_add_connection(ndpi_struct, flow);
    } else if(content_type == 0x16 /* Handshake */) {
      /* Split the element in blocks */
      u_int32_t processed = 5;

      if(len >= 9) {
        while((processed+4) <= len) {
          const u_int8_t *block = (const u_int8_t *)&message->buffer[processed];
          u_int32_t block_len   = (block[1] << 16) + (block[2] << 8) + block[3];

          if((current_pkt_from_client_to_server(ndpi_struct, flow) &&
              flow->tls_quic.change_cipher_from_client == 1) ||
             (!current_pkt_from_client_to_server(ndpi_struct, flow) &&
              flow->tls_quic.change_cipher_from_server == 1)) {
#ifdef DEBUG_TLS_MEMORY
            printf("[TLS Mem] Encrypted Handshake msg. Skip\n");
#endif

            handleTLSBlockStat(ndpi_struct, flow, &same_packet, 0x16, 0, len - 5);

	    /* We don't have block len, so ignore the entire record */
            processed += len - 5;
            break;
          }

          if(/* (block_len == 0) || */ /* Note blocks can have zero lenght */
             (block_len > len) || ((block[1] != 0x0))) {
            something_went_wrong = 1;
            break;
          }

          packet->payload = block;
          packet->payload_packet_len = ndpi_min(block_len+4, message->buffer_used);

          if((processed+packet->payload_packet_len) > len) {
            something_went_wrong = 1;
            break;
          }

          handleTLSBlockStat(ndpi_struct, flow, &same_packet, 0x16, block[0], block_len);

	  processHandshakeTLSBlock(ndpi_struct, flow);
          ndpi_looks_like_tls(ndpi_struct, flow);

          processed += packet->payload_packet_len;
        }
      }
    } else if(content_type == 0x17 /* Application Data */) {
      u_int32_t block_len   = (message->buffer[3] << 8) + (message->buffer[4]);

      /* Let's do a quick check to make sure this really looks like TLS */
      if(block_len < 16384 /* Max TLS block size */)
	ndpi_looks_like_tls(ndpi_struct, flow);

      if(block_len == (u_int32_t)message->buffer_used - 5)
	ndpi_int_tls_add_connection(ndpi_struct, flow);

      /* If we have seen Application Data blocks in both directions, it means
	 we are after the handshake. Stop extra processing */
      flow->l4.tcp.tls.app_data_seen[packet->packet_direction] = 1;
      if(flow->l4.tcp.tls.app_data_seen[!packet->packet_direction] == 1)
	flow->tls_quic.certificate_processed = 1;
    }

    packet->payload = p;
    packet->payload_packet_len = p_len; /* Restore */
    message->buffer_used -= len;

    if(message->buffer_used > 0)
      memmove(message->buffer, &message->buffer[len], message->buffer_used);
    else
      break;

#ifdef DEBUG_TLS_MEMORY
    printf("[TLS Mem] Left memory buffer %u bytes\n", message->buffer_used);
#endif
  }

#ifdef DEBUG_TLS_MEMORY
  printf("[TLS] Eval if keep going [%p][blocks:%d/%d][wrong:%d]\n",
         flow->extra_packets_func,
         flow->l4.tcp.tls.num_tls_blocks, ndpi_struct->cfg.tls_max_num_blocks_to_analyze,
         something_went_wrong);
#endif

  if(something_went_wrong
     || ((ndpi_struct->cfg.tls_max_num_blocks_to_analyze > 0)
	 && (flow->l4.tcp.tls.num_tls_blocks == ndpi_struct->cfg.tls_max_num_blocks_to_analyze))
     || ((ndpi_struct->cfg.tls_max_num_blocks_to_analyze == 0)
	 && (!keep_extra_dissection_tcp(ndpi_struct, flow)))
     ) {
#ifdef DEBUG_TLS_BLOCKS
    printf("*** [TLS Block] No more blocks\n");
#endif
    /* An ookla flow? */
    if((ndpi_struct->cfg.ookla_aggressiveness & NDPI_AGGRESSIVENESS_OOKLA_TLS) && /* Feature enabled */
       (!something_went_wrong &&
        flow->tls_quic.certificate_processed == 1 &&
        flow->protos.tls_quic.client_hello_processed == 1 &&
        flow->protos.tls_quic.server_hello_processed == 1) && /* TLS handshake found without errors */
       flow->detected_protocol_stack[0] == NDPI_PROTOCOL_TLS && /* No IMAPS/FTPS/... */
       flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN && /* No sub-classification */
       ntohs(flow->s_port) == 8080 && /* Ookla port */
       ookla_search_into_cache(ndpi_struct, flow)) {
      NDPI_LOG_INFO(ndpi_struct, "found ookla (cache over TLS)\n");
      /* Even if a LRU cache is involved, NDPI_CONFIDENCE_DPI_AGGRESSIVE seems more
         suited than NDPI_CONFIDENCE_DPI_CACHE */
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OOKLA, NDPI_PROTOCOL_TLS, NDPI_CONFIDENCE_DPI_AGGRESSIVE);

      tls_match_ja4(ndpi_struct, flow);
      flow->extra_packets_func = NULL;

      return(0); /* That's all */
    /* Loook for TLS-in-TLS */
    } else if((ndpi_struct->cfg.tls_heuristics & NDPI_HEURISTICS_TLS_OBFUSCATED_TLS) && /* Feature enabled */
              (!something_went_wrong &&
               flow->tls_quic.certificate_processed == 1 &&
               flow->protos.tls_quic.client_hello_processed == 1 &&
               flow->protos.tls_quic.server_hello_processed == 1) && /* TLS handshake found without errors */
               flow->tls_quic.from_opportunistic_tls == 0 && /* No from plaintext Mails or FTP */
              !is_flow_addr_informative(flow) /* The proxy server is likely hosted on some cloud providers */ ) {
      switch_extra_dissection_to_tls_obfuscated_heur(ndpi_struct, flow);
      return(1);
    } else {
      tls_match_ja4(ndpi_struct, flow);

      flow->extra_packets_func = NULL;
      return(0); /* That's all */
    }
  } else
    return(1);
}

/* **************************************** */

int is_dtls(const u_int8_t *buf, u_int32_t buf_len, u_int32_t *block_len) {
  if(buf_len <= 13)
    return 0;

  if((buf[0] != 0x16 && buf[0] != 0x14 && buf[0] != 0x17 && buf[0] != 0x15) || /* Handshake, change-cipher-spec, Application-Data, Alert */
     !((buf[1] == 0xfe && buf[2] == 0xff) || /* Versions */
       (buf[1] == 0xfe && buf[2] == 0xfd) ||
       (buf[1] == 0xfe && buf[2] == 0xfc) ||
       (buf[1] == 0x01 && buf[2] == 0x00))) {
#ifdef DEBUG_TLS
    printf("[TLS] DTLS invalid block 0x%x or old version 0x%x-0x%x-0x%x\n",
           buf[0], buf[1], buf[2], buf[3]);
#endif
    return 0;
  }
  *block_len = ntohs(*((u_int16_t*)&buf[11]));
#ifdef DEBUG_TLS
  printf("[TLS] DTLS block len: %d\n", *block_len);
#endif
  if(*block_len == 0 || (*block_len + 12 >= buf_len)) { /* We might have multiple DTLS records */
#ifdef DEBUG_TLS
    printf("[TLS] DTLS invalid block len %d (buf_len %d)\n",
           *block_len, buf_len);
#endif
    return 0;
  }
  return 1;
}

/* **************************************** */

/* NOTE: this function supports both TCP and UDP */
static int ndpi_search_dtls(struct ndpi_detection_module_struct *ndpi_struct,
			       struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int32_t handshake_len, handshake_frag_off, handshake_frag_len;
  u_int16_t p_len, processed;
  const u_int8_t *p;
  u_int8_t no_dtls = 0, change_cipher_found = 0;
  message_t *message = NULL;

#ifdef DEBUG_TLS
  printf("[TLS] %s()\n", __FUNCTION__);
#endif

  /* Overwriting packet payload */
  p = packet->payload, p_len = packet->payload_packet_len; /* Backup */

  /* Split the element in blocks */
  processed = 0;
  while(processed + 13 < p_len) {
    u_int32_t block_len;
    const u_int8_t *block = (const u_int8_t *)&p[processed];

    if(!is_dtls(block, p_len, &block_len)) {
      no_dtls = 1;
      break;
    }

    /* We process only handshake msgs */
    if(block[0] == 0x16) {
      if(processed + block_len + 13 > p_len) {
#ifdef DEBUG_TLS
        printf("[TLS] DTLS invalid len %d %d %d\n", processed, block_len, p_len);
#endif
        no_dtls = 1;
        break;
      }
      /* TODO: handle (certificate) fragments */
      if(block_len > 24) {
        handshake_len = (block[14] << 16) + (block[15] << 8) + block[16];
        handshake_frag_off = (block[19] << 16) + (block[20] << 8) + block[21];
        handshake_frag_len = (block[22] << 16) + (block[23] << 8) + block[24];
        message = &flow->tls_quic.message[packet->packet_direction];


#ifdef DEBUG_TLS
        printf("[TLS] DTLS frag off %d len %d\n", handshake_frag_off, handshake_frag_len);
#endif

	if((handshake_len + 12) == block_len) {
          packet->payload = &block[13];
          packet->payload_packet_len = block_len;
          processHandshakeTLSBlock(ndpi_struct, flow);
	} else if(handshake_len + 12 > block_len) {
	  int rc;

#ifdef DEBUG_TLS
          printf("[TLS] DTLS fragment off %d len %d\n", handshake_frag_off, handshake_frag_len);
#endif
          if(handshake_frag_len + 12 > block_len) {
#ifdef DEBUG_TLS
            printf("[TLS] DTLS fragment invalid len %d + 12 > %d\n", handshake_frag_len, block_len);
#endif
            no_dtls = 1;
            break;
	  }

          if(handshake_frag_off == 0) {
            rc = ndpi_search_tls_memory(&block[13],
					handshake_frag_len + 12,
					handshake_frag_off, message);
	  } else {
            rc = ndpi_search_tls_memory(&block[13 + 12],
					handshake_frag_len,
					handshake_frag_off + 12, message);
	  }
	  if(rc == -1) {
            no_dtls = 1;
            break;
	  }
#ifdef DEBUG_TLS
          printf("[TLS] DTLS reassembled len %d vs %d\n",
                 message->buffer_used, handshake_len + 12);
#endif

          if(handshake_len + 12 == message->buffer_used) {
            packet->payload = message->buffer;
            packet->payload_packet_len = message->buffer_used;
            processHandshakeTLSBlock(ndpi_struct, flow);

            ndpi_free(message->buffer);
            memset(message, '\0', sizeof(*message));
            message = NULL;
          } else {
            /* No break, next fragments might be in the same packet */
          }

        } else {
#ifdef DEBUG_TLS
          printf("[TLS] DTLS invalid handshake_len %d, %d\n",
                 handshake_len, block_len);
#endif
          no_dtls = 1;
          break;
        }
      }
    } else if(block[0] == 0x14) {
      /* Change-cipher-spec: any subsequent block might be encrypted */
#ifdef DEBUG_TLS
      printf("[TLS] Change-cipher-spec\n");
#endif
      change_cipher_found = 1;
      processed += block_len + 13;
      flow->tls_quic.certificate_processed = 1; /* Fake, to avoid extra dissection */
      break;
    } else if(block[0] == 0x15 /* Alert */) {
#ifdef DEBUG_TLS
      printf("[TLS] TLS Alert\n");
#endif

      if(block_len == 2) {
       u_int8_t alert_level = block[13];

       if(alert_level == 2 /* Warning (1), Fatal (2) */)
         ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_FATAL_ALERT, "Found fatal TLS alert");
      }
    } else {
#ifdef DEBUG_TLS
      printf("[TLS] Application Data\n");
#endif
      processed += block_len + 13;
      /* DTLS mid session: no need to further inspect the flow */
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DTLS, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);

      ndpi_master_app_protocol proto;
      proto.master_protocol = ndpi_get_master_proto(ndpi_struct, flow);
      proto.app_protocol = NDPI_PROTOCOL_UNKNOWN;
      flow->category = get_proto_category(ndpi_struct, proto);
      flow->breed = get_proto_breed(ndpi_struct, proto);

      flow->tls_quic.certificate_processed = 1; /* Fake, to avoid extra dissection */
      break;
    }

    processed += block_len + 13;
  }

  if(processed != p_len && message == NULL /* No pending reassembler */) {
#ifdef DEBUG_TLS
    printf("[TLS] DTLS invalid processed len %d/%d (%d)\n", processed, p_len, change_cipher_found);
#endif
    if(!change_cipher_found)
      no_dtls = 1;
  }

  packet->payload = p;
  packet->payload_packet_len = p_len; /* Restore */

  if(no_dtls || change_cipher_found || flow->tls_quic.certificate_processed) {
    return(0); /* That's all */
  } else {
    return(1); /* Keep working */
  }
}

/* **************************************** */

static void tlsInitExtraPacketProcessing(struct ndpi_detection_module_struct *ndpi_struct,
					 struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  /* At most 12 packets should almost always be enough to find the server certificate if it's there.
     Exception: DTLS traffic with fragments, retransmissions and STUN packets */
  flow->max_extra_packets_to_check = ((packet->udp != NULL) ? 20 : 12) + (ndpi_struct->cfg.tls_max_num_blocks_to_analyze*4);
  flow->extra_packets_func = (packet->udp != NULL) ? ndpi_search_dtls : ndpi_search_tls_tcp;
}

/* **************************************** */

void switch_extra_dissection_to_tls(struct ndpi_detection_module_struct *ndpi_struct,
				    struct ndpi_flow_struct *flow)
{
#ifdef DEBUG_TLS
  printf("Switching to TLS extra dissection\n");
#endif

  /* Reset reassemblers */
  if(flow->tls_quic.message[0].buffer)
    ndpi_free(flow->tls_quic.message[0].buffer);
  memset(&flow->tls_quic.message[0], '\0', sizeof(flow->tls_quic.message[0]));
  if(flow->tls_quic.message[1].buffer)
    ndpi_free(flow->tls_quic.message[1].buffer);
  memset(&flow->tls_quic.message[1], '\0', sizeof(flow->tls_quic.message[1]));

  flow->tls_quic.from_opportunistic_tls = 1;

  tlsInitExtraPacketProcessing(ndpi_struct, flow);
}

/* **************************************** */

void switch_to_tls(struct ndpi_detection_module_struct *ndpi_struct,
		   struct ndpi_flow_struct *flow, int first_time)
{
#ifdef DEBUG_TLS
  printf("Switching to TLS\n");
#endif

  if(first_time) {
    /* Reset reassemblers */
    if(flow->tls_quic.message[0].buffer)
      ndpi_free(flow->tls_quic.message[0].buffer);
    memset(&flow->tls_quic.message[0], '\0', sizeof(flow->tls_quic.message[0]));
    if(flow->tls_quic.message[1].buffer)
      ndpi_free(flow->tls_quic.message[1].buffer);
    memset(&flow->tls_quic.message[1], '\0', sizeof(flow->tls_quic.message[1]));

    /* We will not check obfuscated heuristic (anymore) because we have been
       called from the STUN code, but we need to clear the previous state
       (if any) to trigger "standard" TLS/DTLS code */
    if(flow->tls_quic.obfuscated_heur_state) {
      ndpi_free(flow->tls_quic.obfuscated_heur_state);
      flow->tls_quic.obfuscated_heur_state = NULL;
    }
  }

  ndpi_search_tls_wrapper(ndpi_struct, flow);
}

/* **************************************** */

static void tls_subclassify_by_alpn(struct ndpi_detection_module_struct *ndpi_struct,
				    struct ndpi_flow_struct *flow) {
  /* Right now we have only one rule so we can keep it trivial */

  size_t alpns_len = strlen(flow->protos.tls_quic.advertised_alpns);
  if(alpns_len > NDPI_STATICSTRING_LEN("anydesk/") &&
     strncmp(flow->protos.tls_quic.advertised_alpns, "anydesk/", NDPI_STATICSTRING_LEN("anydesk/")) == 0) {
#ifdef DEBUG_TLS
    printf("Matching ANYDESK via alpn\n");
#endif
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ANYDESK,
			       ndpi_get_master_proto(ndpi_struct, flow), NDPI_CONFIDENCE_DPI);
    flow->protos.tls_quic.subprotocol_detected = 1;
  } else if ((alpns_len > NDPI_STATICSTRING_LEN("/yamux/") &&
              strncmp(flow->protos.tls_quic.advertised_alpns, "/yamux/", NDPI_STATICSTRING_LEN("/yamux/")) == 0) ||
             (alpns_len >= NDPI_STATICSTRING_LEN("libp2p") &&
              strncmp(flow->protos.tls_quic.advertised_alpns, "libp2p", NDPI_STATICSTRING_LEN("libp2p")) == 0))
  {
#ifdef DEBUG_TLS
    printf("Matching LIBP2P via alpn\n");
#endif
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_LIBP2P,
                               ndpi_get_master_proto(ndpi_struct, flow), NDPI_CONFIDENCE_DPI);
    flow->protos.tls_quic.subprotocol_detected = 1;
  }
}

/* **************************************** */

static void tlsCheckUncommonALPN(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow,
				 char *alpn_start) {
  char * comma_or_nul = alpn_start;

  do {
    size_t alpn_len;

    comma_or_nul = strchr(comma_or_nul, ',');

    if(comma_or_nul == NULL)
      comma_or_nul = alpn_start + strlen(alpn_start);

    alpn_len = comma_or_nul - alpn_start;

    if(!is_a_common_alpn(ndpi_struct, alpn_start, alpn_len)) {
      if(is_flowrisk_info_enabled(ndpi_struct, NDPI_TLS_UNCOMMON_ALPN)) {
        char str[64];
        size_t str_len;

#ifdef DEBUG_TLS
        printf("TLS uncommon ALPN found: %.*s\n", (int)alpn_len, alpn_start);
#endif

        str[0] = '\0';
        str_len = ndpi_min(alpn_len, sizeof(str));
        if(str_len > 0) {
          strncpy(str, alpn_start, str_len);
          str[str_len - 1] = '\0';
        }

        ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_UNCOMMON_ALPN, str);
      } else {
        ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_UNCOMMON_ALPN, NULL);
      }
      break;
    }

    alpn_start = comma_or_nul + 1;
  } while (*(comma_or_nul++) != '\0');
}

/* **************************************** */

static void ndpi_int_tls_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					struct ndpi_flow_struct *flow) {
  u_int32_t protocol;

#if DEBUG_TLS
  printf("[TLS] %s()\n", __FUNCTION__);
#endif

  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_RDP) {
    /* RDP over TLS */
    ndpi_set_detected_protocol(ndpi_struct, flow,
			       NDPI_PROTOCOL_RDP, NDPI_PROTOCOL_TLS, NDPI_CONFIDENCE_DPI);
    return;
  }

  if((flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) ||
     (flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN)) {
    if(!flow->extra_packets_func)
      tlsInitExtraPacketProcessing(ndpi_struct, flow);

    return;
  }

  protocol = ndpi_get_master_proto(ndpi_struct, flow);

  ndpi_set_detected_protocol(ndpi_struct, flow, protocol, protocol, NDPI_CONFIDENCE_DPI);
  /* We don't want to ovewrite STUN extra dissection, if enabled */
  if(!flow->extra_packets_func)
    tlsInitExtraPacketProcessing(ndpi_struct, flow);
}

/* **************************************** */

static void checkExtensions(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct * const flow, int is_dtls,
                            u_int16_t extension_id, u_int16_t extension_len,
			    u_int16_t extension_payload_offset) {
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  if((extension_payload_offset + extension_len) > packet->payload_packet_len) {
#ifdef DEBUG_TLS
      printf("[TLS] extension length exceeds remaining packet length: %u > %u.\n",
	     extension_len, packet->payload_packet_len - extension_payload_offset);
#endif
      ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_SUSPICIOUS_EXTENSION, "Invalid extension len");
      return;
    }

  /* see: https://www.wireshark.org/docs/wsar_html/packet-tls-utils_8h_source.html */
  static u_int16_t const allowed_non_iana_extensions[] = {
      /* 65486 ESNI is suspicious nowadays */ 13172 /* NPN - Next Proto Neg */,
      30032 /* Channel ID */, 65445 /* QUIC transport params */,
      /* GREASE extensions */
      2570, 6682, 10794, 14906, 19018, 23130, 27242,
      31354, 35466, 39578, 43690, 47802, 51914, 56026,
      60138, 64250,
      /* Groups */
      1035, 10794, 16696, 23130, 31354, 35466, 51914,
      /* Ciphers */
      102, 129, 52243, 52244, 57363, 65279, 65413,
      /* ALPS */
      17513, 17613
  };
  size_t const allowed_non_iana_extensions_size = sizeof(allowed_non_iana_extensions) /
    sizeof(allowed_non_iana_extensions[0]);

  /* see: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml */
  /* 65281 renegotiation_info, 65037 ECH */
  if(extension_id > 59 && extension_id != 65281 && extension_id != 65037)
    {
      u_int8_t extension_found = 0;
      size_t i;

      for (i = 0; i < allowed_non_iana_extensions_size; ++i) {
	if(allowed_non_iana_extensions[i] == extension_id) {
	  extension_found = 1;
	  break;
	}
      }

      if(extension_found == 0) {
#ifdef DEBUG_TLS
        printf("[TLS] suspicious extension id: %u\n", extension_id);
#endif

        if(is_flowrisk_info_enabled(ndpi_struct, NDPI_TLS_SUSPICIOUS_EXTENSION)) {
	  char str[64];

	  snprintf(str, sizeof(str), "Extn id %u", extension_id);
	  ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_SUSPICIOUS_EXTENSION, str);
        } else {
          ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_SUSPICIOUS_EXTENSION, NULL);
        }
	return;
      }
    }

  /* Check for DTLS-only extensions. */
  if(is_dtls == 0)
    {
      if(extension_id == 53 || extension_id == 54)
	{
#ifdef DEBUG_TLS
          printf("[TLS] suspicious DTLS-only extension id: %u\n", extension_id);
#endif

          if(is_flowrisk_info_enabled(ndpi_struct, NDPI_TLS_SUSPICIOUS_EXTENSION)) {
	    char str[64];

	    snprintf(str, sizeof(str), "Extn id %u", extension_id);
	    ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_SUSPICIOUS_EXTENSION, str);
          } else {
            ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_SUSPICIOUS_EXTENSION, NULL);
          }
	  return;
	}
    }
}

/* **************************************** */

static int u_int16_t_cmpfunc(const void * a, const void * b) { return(*(u_int16_t*)a - *(u_int16_t*)b); }

static bool is_grease_version(u_int16_t version) {
  switch(version) {
  case 0x0a0a:
  case 0x1a1a:
  case 0x2a2a:
  case 0x3a3a:
  case 0x4a4a:
  case 0x5a5a:
  case 0x6a6a:
  case 0x7a7a:
  case 0x8a8a:
  case 0x9a9a:
  case 0xaaaa:
  case 0xbaba:
  case 0xcaca:
  case 0xdada:
  case 0xeaea:
  case 0xfafa:
    return(true);

  default:
    return(false);
  }
}

/* **************************************** */

bool skipTLSextension(struct ndpi_detection_module_struct *ndpi_struct,
		      u_int16_t extension_id)  {
  if((extension_id == 0x0 /* SNI */) && ndpi_struct->cfg.tls_ndpifp_ignore_sni_extension)
    return(true);

  if(ndpi_struct->cfg.tls_ja_ignore_ephemeral_extensions) {
    switch(extension_id) {
    case 0x23: /* session ticket - RFC 9149 */
    case 0x29: /* pre-shared key - RFC 8446 */
    case 0x15: /* padding        - RFC 7685 */
      /* Noisy extensions */
    case 0x2b: /* Supported TLS versions    */
    case 0x0a: /* Supported groups          */
      return(true);
    }
  }

  return(false);
}

/* **************************************** */

static void ndpi_fill_version_str(char *ja_str,
				  u_int16_t tls_handshake_version) {
  switch(tls_handshake_version) {
  case 0x0304: /* TLS 1.3 = “13” */
    ja_str[1] = '1';
    ja_str[2] = '3';
    break;

  case 0x0303: /* TLS 1.2 = “12” */
    ja_str[1] = '1';
    ja_str[2] = '2';
    break;

  case 0x0302: /* TLS 1.1 = “11” */
    ja_str[1] = '1';
    ja_str[2] = '1';
    break;

  case 0x0301: /* TLS 1.0 = “10” */
    ja_str[1] = '1';
    ja_str[2] = '0';
    break;
  case 0x0300: /* SSL 3.0 = “s3” */
    ja_str[1] = 's';
    ja_str[2] = '3';
    break;

  case 0x0002: /* SSL 2.0 = “s2” */
    ja_str[1] = 's';
    ja_str[2] = '2';
    break;

  case 0xFEFF: /* DTLS 1.0 = “d1” */
    ja_str[1] = 'd';
    ja_str[2] = '1';
    break;

  case 0xFEFD: /* DTLS 1.2 = “d2” */
    ja_str[1] = 'd';
    ja_str[2] = '2';
    break;
  case 0xFEFC: /* DTLS 1.3 = “d3” */
    ja_str[1] = 'd';
    ja_str[2] = '3';
    break;

  default:
    ja_str[1] = '0';
    ja_str[2] = '0';
    break;
  }
}

/* **************************************** */

static void ndpi_compute_ja4(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow,
			     u_int32_t quic_version,
			     union ndpi_ja_info *ja) {
  u_int8_t tmp_str[JA_STR_LEN], tmp_ndpi_str[512];
  u_int tmp_str_len, tmp_ndpi_str_len = 0, num_extn, num_ndpi_extn;
  u_int8_t sha_hash[NDPI_SHA256_BLOCK_SIZE];
  u_int16_t ja_str_len, i, ja_offset;
  int rc;
  u_int16_t tls_handshake_version = ja->client.tls_handshake_version;
  char * const ja_str = &flow->protos.tls_quic.ja4_client[0];
  char * const ja_ndpi_str = &flow->protos.tls_quic.ja4_ndpi_client[0];
  const u_int16_t ja_max_len = sizeof(flow->protos.tls_quic.ja4_client);
  bool is_dtls = ((flow->l4_proto == IPPROTO_UDP) && (quic_version == 0)) || flow->stun.maybe_dtls;
  int ja4_r_len = 0;
  char ja4_r[1024];

  /*
    Compute JA4 TLS/QUIC client

    https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md

    (QUIC=”q”, DTLS="d" or TCP=”t”)
    (2 character TLS version)
    (SNI=”d” or no SNI=”i”)
    (2 character count of ciphers)
    (2 character count of extensions)
    (first and last characters of first ALPN extension value)
    _
    (sha256 hash of the list of cipher hex codes sorted in hex order, truncated to 12 characters)
    _
    (sha256 hash of (the list of extension hex codes sorted in hex order)
    _
    (the list of signature algorithms), truncated to 12 characters)
  */
  ja_str[0] = is_dtls ? 'd' : ((quic_version != 0) ? 'q' : 't');

  for(i=0; i<ja->client.num_supported_versions; i++) {
    if((!is_grease_version(ja->client.supported_version[i]))
       && (tls_handshake_version < ja->client.supported_version[i]))
      tls_handshake_version = ja->client.supported_version[i];
  }

  ndpi_fill_version_str(ja_str, tls_handshake_version);

  /* Check if SNI extension exists at all */
  if(flow->host_server_name[0] == '\0') {
    ja_str[3] = 'i';  /* No SNI extension */
  } else if(ndpi_isset_risk(flow, NDPI_NUMERIC_IP_HOST)) {
    ja_str[3] = 'i';  /* SNI contains IP address */
  } else {
    ja_str[3] = 'd';  /* SNI contains domain name */
  }
  ja_str_len = 4;

  /* JA4_a */
  /* first + last character of the ALPN string (or '0' if missing) */
  char alpn_first = (ja->client.alpn[0] != '\0') ? ja->client.alpn[0] : '0';
  char alpn_last  = ja->client.alpn_original_last;  /* Use original last character before null terminator */

#ifdef DEBUG_JA
  size_t alpn_len = strlen(ja->client.alpn);
  printf("[JA4 DEBUG] ALPN string: '%s' (len=%zu)\n", ja->client.alpn, alpn_len);
  printf("[JA4 DEBUG] First='%c', Last='%c'\n", alpn_first, alpn_last);
#endif

  rc = ndpi_snprintf(&ja_str[ja_str_len], ja_max_len - ja_str_len,
		     "%02u%02u%c%c_",
		     ndpi_min(99, ja->client.num_ciphers),
		     ndpi_min(99, ja->client.num_tls_extensions),
		     alpn_first, alpn_last);
  if((rc > 0) && (ja_str_len + rc < JA_STR_LEN)) ja_str_len += rc;

  /* Sort ciphers and extensions */
  qsort(&ja->client.cipher, ja->client.num_ciphers, sizeof(u_int16_t), u_int16_t_cmpfunc);
  qsort(&ja->client.tls_extension, ja->client.num_tls_extensions, sizeof(u_int16_t), u_int16_t_cmpfunc);

  tmp_str_len = 0;
  for(i=0; i<ja->client.num_ciphers; i++) {
#ifdef JA4R_DECIMAL
    rc = snprintf(&ja4_r[ja4_r_len], sizeof(ja4_r)-ja4_r_len, "%s%u", (i > 0) ? "," : "", ja->client.cipher[i]);
    if(rc > 0) ja4_r_len += rc;
#endif
    rc = ndpi_snprintf((char *)&tmp_str[tmp_str_len], JA_STR_LEN-tmp_str_len, "%s%04x",
		       (i > 0) ? "," : "", ja->client.cipher[i]);
    if((rc > 0) && (tmp_str_len + rc < JA_STR_LEN)) tmp_str_len += rc; else break;
  }

#ifndef JA4R_DECIMAL
  ja_str[ja_str_len] = 0;
  i = snprintf(&ja4_r[ja4_r_len], sizeof(ja4_r)-ja4_r_len, "%s", ja_str); if(i > 0) ja4_r_len += i;

  tmp_str[tmp_str_len] = 0;
  i = snprintf(&ja4_r[ja4_r_len], sizeof(ja4_r)-ja4_r_len, "%s_", tmp_str); if(i > 0) ja4_r_len += i;
#endif

  if(ja->client.num_ciphers > 0) {
    ndpi_sha256(tmp_str, tmp_str_len, sha_hash);
  } else {
    memset(sha_hash, '\0', 6);
  }

  rc = ndpi_snprintf(&ja_str[ja_str_len], ja_max_len - ja_str_len,
		     "%02x%02x%02x%02x%02x%02x_",
		     sha_hash[0], sha_hash[1], sha_hash[2],
		     sha_hash[3], sha_hash[4], sha_hash[5]);
  if((rc > 0) && (ja_str_len + rc < JA_STR_LEN)) ja_str_len += rc;

#ifdef DEBUG_JA
  printf("[CIPHER] %s [len: %u]\n", tmp_str, tmp_str_len);
#endif

#ifdef JA4R_DECIMAL
  rc = snprintf(&ja4_r[ja4_r_len], sizeof(ja4_r)-ja4_r_len, "_");
  if(rc > 0) ja4_r_len += rc;
#endif

  tmp_str_len = 0;
  for(i=0, num_extn = num_ndpi_extn = 0; i<ja->client.num_tls_extensions; i++) {
    if((ja->client.tls_extension[i] > 0) && (ja->client.tls_extension[i] != 0x10 /* ALPN extension */)) {
#ifdef JA4R_DECIMAL
      rc = snprintf(&ja4_r[ja4_r_len], sizeof(ja4_r)-ja4_r_len, "%s%u", (num_extn > 0) ? "," : "", ja->client.tls_extension[i]);
      if((rc > 0) && (ja4_r_len + rc < JA_STR_LEN)) ja4_r_len += rc; else break;
#endif

      rc = ndpi_snprintf((char *)&tmp_str[tmp_str_len], JA_STR_LEN-tmp_str_len, "%s%04x",
			 (num_extn > 0) ? "," : "", ja->client.tls_extension[i]);
      if((rc > 0) && (tmp_str_len + rc < JA_STR_LEN)) tmp_str_len += rc; else break;
      num_extn++;

      if(!skipTLSextension(ndpi_struct, ja->client.tls_extension[i])) {
	rc = ndpi_snprintf((char *)&tmp_ndpi_str[tmp_ndpi_str_len], sizeof(tmp_ndpi_str)-tmp_ndpi_str_len, "%s%04x",
			   (num_ndpi_extn > 0) ? "," : "", ja->client.tls_extension[i]);
	if((rc > 0) && (tmp_ndpi_str_len + rc < sizeof(tmp_ndpi_str))) tmp_ndpi_str_len += rc; else break;
	num_ndpi_extn++;
      }
    }
  }

  for(i=0; i<ja->client.num_signature_algorithms; i++) {
    rc = ndpi_snprintf((char *)&tmp_str[tmp_str_len], JA_STR_LEN-tmp_str_len, "%s%04x",
		       (i > 0) ? "," : "_", ja->client.signature_algorithm[i]);
    if((rc > 0) && (tmp_str_len + rc < JA_STR_LEN)) tmp_str_len += rc; else break;

    rc = ndpi_snprintf((char *)&tmp_ndpi_str[tmp_ndpi_str_len], sizeof(tmp_ndpi_str)-tmp_ndpi_str_len, "%s%04x",
		       (i > 0) ? "," : "_", ja->client.signature_algorithm[i]);
    if((rc > 0) && (tmp_ndpi_str_len + rc < sizeof(tmp_ndpi_str))) tmp_ndpi_str_len += rc; else break;
  }

#ifdef DEBUG_JA
  printf("[EXTN] %s [len: %u]\n", tmp_str, tmp_str_len);
#endif

#ifdef DEBUG_NDPIFP
  printf("[EXTN] %s [len: %u]\n", tmp_ndpi_str, tmp_ndpi_str_len);
#endif

  tmp_str[tmp_str_len] = 0;

#ifndef JA4R_DECIMAL
  i = snprintf(&ja4_r[ja4_r_len], sizeof(ja4_r)-ja4_r_len, "%s", tmp_str);
  if(i > 0) ja4_r_len += i;
#endif

  if(ndpi_struct->cfg.tls_ja4r_fingerprint_enabled) {
    if(flow->protos.tls_quic.ja4_client_raw == NULL)
      flow->protos.tls_quic.ja4_client_raw = ndpi_strdup(ja4_r);
#ifdef DEBUG_JA
    printf("[JA4_r] %s [len: %u]\n", ja4_r, ja4_r_len);
#endif
  }

  if(ja->client.num_tls_extensions > 0)
    ndpi_sha256(tmp_str, tmp_str_len, sha_hash);
  else
    memset(sha_hash, '\0', 6);

  ja_offset = ja_str_len;
  rc = ndpi_snprintf(&ja_str[ja_str_len], ja_max_len - ja_str_len,
		     "%02x%02x%02x%02x%02x%02x",
		     sha_hash[0], sha_hash[1], sha_hash[2],
		     sha_hash[3], sha_hash[4], sha_hash[5]);
  if((rc > 0) && (ja_str_len + rc < JA_STR_LEN)) ja_str_len += rc;
  ja_str[36] = 0;

  /* nDPI */
  if(ja->client.num_tls_extensions > 0)
    ndpi_sha256(tmp_ndpi_str, tmp_ndpi_str_len, sha_hash);
  else
    memset(sha_hash, '\0', 6);

  ja_str_len = ja_offset;
  strncpy(ja_ndpi_str, ja_str, ja_str_len);

  /* Overwrite the extensions number */
  ndpi_snprintf(&ja_ndpi_str[6], 2, "%02u", num_ndpi_extn);

  rc = ndpi_snprintf(&ja_ndpi_str[ja_str_len], ja_max_len - ja_str_len,
		     "%02x%02x%02x%02x%02x%02x",
		     sha_hash[0], sha_hash[1], sha_hash[2],
		     sha_hash[3], sha_hash[4], sha_hash[5]);
  if((rc > 0) && (ja_str_len + rc < JA_STR_LEN)) ja_str_len += rc;
  ja_ndpi_str[36] = 0;

#ifdef DEBUG_JA
  printf("[JA4] %s [len: %lu]\n", ja_str, strlen(ja_str));
#endif

#ifdef DEBUG_NDPIFP
  printf("[EXTN] %s\n", ja_ndpi_str);
#endif
}

/* **************************************** */

static void ndpi_compute_tls_server_fingerprint(struct ndpi_flow_struct *flow,
                                                bool is_dtls,
                                                u_int32_t quic_version,
                                                ndpi_tls_server_info *s) {
  char tls_s[128], fp_buf[13];
  u_int tls_s_len, i;
  u_int8_t sha_hash[NDPI_SHA256_BLOCK_SIZE];

  tls_s[0] = is_dtls ? 'd' : ((quic_version != 0) ? 'q' : 't');
  ndpi_fill_version_str(tls_s, s->tls_handshake_version);
  tls_s_len = 3;

  if(sizeof(tls_s) > tls_s_len) {
    int b_diff = sizeof(tls_s)-tls_s_len-1;

    if(b_diff > 0) {
      int rc = ndpi_snprintf(&tls_s[tls_s_len], b_diff, "%02u_%s_%04x",
			     s->num_tls_extensions,
			     (s->alpn[0] == '\0') ? "00" : s->alpn,
			     (s->num_ciphers > 0) ? s->cipher[0] : 0);

      if(rc > 0)
	tls_s_len += rc;
    }
  }

  if(sizeof(tls_s) > tls_s_len)
    tls_s[tls_s_len++] = '_';

  for(i=0; i<s->num_tls_extensions; i++) {
    int b_diff = sizeof(tls_s)-tls_s_len-1;

    if(b_diff > 0) {
      int rc = ndpi_snprintf(&tls_s[tls_s_len], b_diff, "%04x",
			     s->tls_extension[i]);

      if(rc <= 0)
	break;
      else
	tls_s_len += rc;
    } else
      break;
  }

  if(sizeof(tls_s) > tls_s_len)
    tls_s[tls_s_len++] = '_';

  if(s->num_elliptic_curve_point_format > 0) {
    for(i=0; i<s->num_elliptic_curve_point_format; i++) {
      int b_diff = sizeof(tls_s)-tls_s_len-1;

      if(b_diff > 0) {
	int rc = ndpi_snprintf(&tls_s[tls_s_len], b_diff, "%04x",
			       s->elliptic_curve_point_format[i]);

	if(rc <= 0)
	  break;
	else
	  tls_s_len += rc;
      } else
	break;
    }
  } else {
    int b_diff = sizeof(tls_s)-tls_s_len-1;

    if(b_diff > 0) {
      int rc = ndpi_snprintf(&tls_s[tls_s_len], b_diff, "%04x", 0);

      if(rc > 0)
	tls_s_len += rc;
    }
  }

  ndpi_sha256((const u_char *)tls_s, tls_s_len, sha_hash);

  ndpi_snprintf(fp_buf, sizeof(fp_buf),
		"%02x%02x%02x%02x%02x%02x",
		sha_hash[0], sha_hash[1], sha_hash[2],
		sha_hash[3], sha_hash[4], sha_hash[5]);

  flow->ndpi.server_fingerprint = ndpi_strdup((char*)fp_buf);
}

/* **************************************** */

int processClientServerHello(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow, u_int32_t quic_version) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  union ndpi_ja_info ja;
  ndpi_tls_server_info *s = &ja.server;
  u_int8_t invalid_ja = 0;
  u_int16_t tls_version;
  u_int32_t i, j;
  u_int16_t total_len;
  u_int8_t handshake_type;
  bool is_quic = (quic_version != 0);
  bool is_dtls = (packet->udp && !is_quic) || flow->stun.maybe_dtls;

#ifdef DEBUG_TLS
  printf("TLS %s() called\n", __FUNCTION__);
#endif

  handshake_type = packet->payload[0];
  total_len = (packet->payload[1] << 16) +  (packet->payload[2] << 8) + packet->payload[3];

  if((total_len > packet->payload_packet_len) || (packet->payload[1] != 0x0))
    return(0); /* Not found */

  total_len = packet->payload_packet_len;

  /* At least "magic" 3 bytes, null for string end, otherwise no need to waste cpu cycles */
  if(total_len > 4) {
    u_int16_t base_offset    = (!is_dtls) ? 38 : 46;
    u_int16_t version_offset = (!is_dtls) ? 4 : 12;
    u_int16_t offset = (!is_dtls) ? 38 : 46;
    u_int32_t tot_extension_len;
    u_int8_t  session_id_len =  0;

    if((base_offset >= total_len) ||
       (version_offset + 1) >= total_len)
      return 0; /* Not found */

    session_id_len = packet->payload[base_offset];

#ifdef DEBUG_TLS
    printf("TLS [len: %u][handshake_type: %02X]\n", packet->payload_packet_len, handshake_type);
#endif

    tls_version = ntohs(*((u_int16_t*)&packet->payload[version_offset]));

    if(handshake_type == 0x02 /* Server Hello */) {
      int rc;

      memset(&ja.server, 0, sizeof(ja.server));

      ja.server.tls_handshake_version = tls_version;

#ifdef DEBUG_TLS
      printf("TLS Server Hello [version: 0x%04X]\n", tls_version);
#endif

      /*
	The server hello decides about the TLS version of this flow
	https://networkengineering.stackexchange.com/questions/55752/why-does-wireshark-show-version-tls-1-2-here-instead-of-tls-1-3
      */
      if(packet->udp)
	offset += session_id_len + 1;
      else {
	if(tls_version < 0x7F15 /* TLS 1.3 lacks of session id */)
	  offset += session_id_len+1;
      }

      if((offset+3) > packet->payload_packet_len)
	return(0); /* Not found */

      ja.server.num_ciphers = 1, ja.server.cipher[0] = ntohs(*((u_int16_t*)&packet->payload[offset]));

      if(ndpi_struct->cfg.tls_cipher_enabled) {
        if((flow->protos.tls_quic.server_unsafe_cipher = ndpi_is_safe_ssl_cipher(ja.server.cipher[0])) != NDPI_CIPHER_SAFE) {
          if(is_flowrisk_info_enabled(ndpi_struct, NDPI_TLS_WEAK_CIPHER)) {
            char str[64];
            char unknown_cipher[8];

            snprintf(str, sizeof(str), "Cipher %s", ndpi_cipher2str(ja.server.cipher[0], unknown_cipher));
            ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_WEAK_CIPHER, str);
          } else {
            ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_WEAK_CIPHER, NULL);
          }
        }

        flow->protos.tls_quic.server_cipher = ja.server.cipher[0];
      }

#ifdef DEBUG_TLS
      printf("TLS [server][session_id_len: %u][cipher: %04X]\n", session_id_len, ja.server.cipher[0]);
#endif

      offset += 2 + 1;

      if((offset + 1) < packet->payload_packet_len) /* +1 because we are goint to read 2 bytes */
	tot_extension_len = ntohs(*((u_int16_t*)&packet->payload[offset]));
      else
	tot_extension_len = 0;

#ifdef DEBUG_TLS
      printf("TLS [server][tot_extension_len: %u]\n", tot_extension_len);
#endif
      offset += 2;

      for(i=0; i<tot_extension_len; ) {
        u_int16_t extension_id;
        u_int32_t extension_len;

	if((offset+4) > packet->payload_packet_len) break;

	extension_id  = ntohs(*((u_int16_t*)&packet->payload[offset]));
	extension_len = ntohs(*((u_int16_t*)&packet->payload[offset+2]));
	if(offset+4+extension_len > packet->payload_packet_len) {
	  break;
	}

	if(ja.server.num_tls_extensions < MAX_NUM_JA)
	  ja.server.tls_extension[ja.server.num_tls_extensions++] = extension_id;

#ifdef DEBUG_TLS
	printf("TLS [server][extension_id: %u/0x%04X][len: %u]\n",
	       extension_id, extension_id, extension_len);
#endif
	checkExtensions(ndpi_struct, flow, is_dtls, extension_id, extension_len, offset + 4);

	if(extension_id == 43 /* supported versions */) {
	  if(extension_len >= 2) {
	    u_int16_t tls_version = ntohs(*((u_int16_t*)&packet->payload[offset+4]));

#ifdef DEBUG_TLS
	    printf("TLS [server] [TLS version: 0x%04X]\n", tls_version);
#endif

	    flow->protos.tls_quic.ssl_version = ja.server.tls_supported_version = tls_version;
	  }
	} else if(extension_id == 16 /* application_layer_protocol_negotiation (ALPN) */ &&
	          offset + 6 < packet->payload_packet_len) {
	  u_int16_t s_offset = offset+4;
	  u_int16_t tot_alpn_len = ntohs(*((u_int16_t*)&packet->payload[s_offset]));
	  char alpn_str[256];
	  u_int16_t alpn_str_len = 0, i;

#ifdef DEBUG_TLS
	  printf("Server TLS [ALPN: block_len=%u/len=%u]\n", extension_len, tot_alpn_len);
#endif
	  s_offset += 2;
	  tot_alpn_len += s_offset;

	  if(tot_alpn_len > packet->payload_packet_len)
	    return 0;

	  while(s_offset < tot_alpn_len && s_offset < total_len) {
	    u_int8_t alpn_i, alpn_len = packet->payload[s_offset++];

	    if((s_offset + alpn_len) <= tot_alpn_len) {
#ifdef DEBUG_TLS
	      printf("Server TLS [ALPN: %u]\n", alpn_len);
#endif

	      if(((uint32_t)alpn_str_len+alpn_len+1) < (sizeof(alpn_str)-1)) {
	        if(alpn_str_len > 0) {
	          alpn_str[alpn_str_len] = ',';
	          alpn_str_len++;
	        }

	        for(alpn_i=0; alpn_i<alpn_len; alpn_i++) {
		    alpn_str[alpn_str_len+alpn_i] = packet->payload[s_offset+alpn_i];
		  }

	        s_offset += alpn_len, alpn_str_len += alpn_len;;
	      } else {
	        alpn_str[alpn_str_len] = '\0';
	        ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_UNCOMMON_ALPN, alpn_str);
	        break;
	      }
	    } else {
	      alpn_str[alpn_str_len] = '\0';
	      ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_UNCOMMON_ALPN, alpn_str);
	      break;
	    }
	  } /* while */

	  alpn_str[alpn_str_len] = '\0';

#ifdef DEBUG_TLS
	  printf("Server TLS [ALPN: %s][len: %u]\n", alpn_str, alpn_str_len);
#endif
	  if(ndpi_normalize_printable_string(alpn_str, alpn_str_len) == 0)
	    ndpi_set_risk(ndpi_struct, flow, NDPI_INVALID_CHARACTERS, alpn_str);

	  if(flow->protos.tls_quic.negotiated_alpn == NULL &&
	     ndpi_struct->cfg.tls_alpn_negotiated_enabled)
	    flow->protos.tls_quic.negotiated_alpn = ndpi_strdup(alpn_str);

	  /* Check ALPN only if not already checked (client-side) */
	  if(flow->protos.tls_quic.negotiated_alpn != NULL &&
	     flow->protos.tls_quic.advertised_alpns == NULL)
	    tlsCheckUncommonALPN(ndpi_struct, flow, flow->protos.tls_quic.negotiated_alpn);

	  alpn_str_len = ndpi_min(sizeof(ja.server.alpn), (size_t)alpn_str_len);
	  memcpy(ja.server.alpn, alpn_str, alpn_str_len);
	  if(alpn_str_len > 0)
	    ja.server.alpn[alpn_str_len] = '\0';

	  /* Replace , with - as in JA3 */
	  for(i=0; ja.server.alpn[i] != '\0'; i++)
	    if(ja.server.alpn[i] == ',') ja.server.alpn[i] = '-';
	} else if(extension_id == 11 /* ec_point_formats groups */) {
	  u_int16_t s_offset = offset+4 + 1;

#ifdef DEBUG_TLS
	  printf("Server TLS [EllipticCurveFormat: len=%u]\n", extension_len);
#endif
	  if((s_offset+extension_len-1) <= total_len) {
	    for(i=0; i<extension_len-1 && s_offset+i<packet->payload_packet_len; i++) {
	      u_int8_t s_group = packet->payload[s_offset+i];

#ifdef DEBUG_TLS
	      printf("Server TLS [EllipticCurveFormat: %u]\n", s_group);
#endif

	      if(ja.server.num_elliptic_curve_point_format < MAX_NUM_JA)
		ja.server.elliptic_curve_point_format[ja.server.num_elliptic_curve_point_format++] = s_group;
	      else {
		invalid_ja = 1;
#ifdef DEBUG_TLS
		printf("Server TLS Invalid num elliptic %u\n", ja.server.num_elliptic_curve_point_format);
#endif
	      }
	    }
	  } else {
	    invalid_ja = 1;
#ifdef DEBUG_TLS
	    printf("Server TLS Invalid len %u vs %u\n", s_offset+extension_len, total_len);
#endif
	  }
	}

	i += 4 + extension_len, offset += 4 + extension_len;
      } /* for */

      /* If the CH is not available and if "supported_versions" extension is not present in the SH
         (i.e. (D)TLS <= 1.2), use the version field present in the record layer */
      if(flow->protos.tls_quic.ssl_version == 0)
        flow->protos.tls_quic.ssl_version = tls_version;

      if(ndpi_struct->cfg.ndpi_server_fingerprint_enabled
	 && (flow->ndpi.server_fingerprint == NULL))
	ndpi_compute_tls_server_fingerprint(flow, is_dtls, quic_version, s);

      if(ndpi_struct->cfg.tls_ja3s_fingerprint_enabled) {
         u_int16_t ja_str_len;
         char ja_str[JA_STR_LEN];
         ndpi_MD5_CTX ctx;
         u_char md5_hash[16];

        ja_str_len = ndpi_snprintf(ja_str, JA_STR_LEN, "%u,", ja.server.tls_handshake_version);

        for(i=0; (i<ja.server.num_ciphers) && (JA_STR_LEN > ja_str_len); i++) {
	  rc = ndpi_snprintf(&ja_str[ja_str_len], JA_STR_LEN-ja_str_len, "%s%u", (i > 0) ? "-" : "", ja.server.cipher[i]);

	  if(rc <= 0) break; else ja_str_len += rc;
        }

        if(JA_STR_LEN > ja_str_len) {
	  rc = ndpi_snprintf(&ja_str[ja_str_len], JA_STR_LEN-ja_str_len, ",");
	  if(rc > 0 && ja_str_len + rc < JA_STR_LEN) ja_str_len += rc;
        }

        /* ********** */

        for(i=0; (i<ja.server.num_tls_extensions) && (JA_STR_LEN > ja_str_len); i++) {
	  int rc = ndpi_snprintf(&ja_str[ja_str_len], JA_STR_LEN-ja_str_len, "%s%u", (i > 0) ? "-" : "", ja.server.tls_extension[i]);

	  if(rc <= 0) break; else ja_str_len += rc;
        }

#ifdef DEBUG_TLS
        printf("[JA3] Server: %s \n", ja_str);
#endif

        ndpi_MD5Init(&ctx);
        ndpi_MD5Update(&ctx, (const unsigned char *)ja_str, strlen(ja_str));
        ndpi_MD5Final(md5_hash, &ctx);

        for(i=0, j=0; i<16; i++) {
	  int rc = ndpi_snprintf(&flow->protos.tls_quic.ja3_server[j],
			         sizeof(flow->protos.tls_quic.ja3_server)-j, "%02x", md5_hash[i]);
	  if(rc <= 0) break; else j += rc;
        }

#ifdef DEBUG_TLS
        printf("[JA3] Server: %s \n", flow->protos.tls_quic.ja3_server);
#endif

	if(ndpi_struct->cfg.tls_ja_data_enabled) {
	  if(flow->protos.tls_quic.ja_server == NULL) {
	    flow->protos.tls_quic.ja_server = ndpi_malloc(sizeof(ndpi_tls_server_info));

	    if(flow->protos.tls_quic.ja_server != NULL)
	      memcpy(flow->protos.tls_quic.ja_server, &ja.server, sizeof(ndpi_tls_server_info));
	  }
	}
      }
    } else if(handshake_type == 0x01 /* Client Hello */) {
      u_int16_t cipher_len, cipher_offset;
      u_int8_t cookie_len = 0;

      memset(&ja.client, 0, sizeof(ja.client));
      ja.client.alpn_original_last = '0'; /* Initialize to '0' if no ALPN */

      flow->protos.tls_quic.ssl_version = ja.client.tls_handshake_version = tls_version;
      if(flow->protos.tls_quic.ssl_version < 0x0303) /* < TLSv1.2 */ {
        if(is_flowrisk_info_enabled(ndpi_struct, NDPI_TLS_OBSOLETE_VERSION)) {
          char str[32], buf[32];
	  u_int8_t unknown_tls_version;

	  snprintf(str, sizeof(str), "%s", ndpi_ssl_version2str(buf, sizeof(buf),
							        flow->protos.tls_quic.ssl_version,
							       &unknown_tls_version));
	  ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_OBSOLETE_VERSION, str);
        } else {
          ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_OBSOLETE_VERSION, NULL);
        }
      }

      if((session_id_len+base_offset+3) > packet->payload_packet_len)
	return(0); /* Not found */

      if(!is_dtls) {
	cipher_len = packet->payload[session_id_len+base_offset+2] + (packet->payload[session_id_len+base_offset+1] << 8);
	cipher_offset = base_offset + session_id_len + 3;
      } else {
	cookie_len = packet->payload[base_offset+session_id_len+1];
#ifdef DEBUG_TLS
	printf("[JA3] Client: DTLS cookie len %d\n", cookie_len);
#endif
	if((session_id_len+base_offset+cookie_len+4) > packet->payload_packet_len)
	  return(0); /* Not found */
	cipher_len = ntohs(*((u_int16_t*)&packet->payload[base_offset+session_id_len+cookie_len+2]));
	cipher_offset = base_offset + session_id_len + cookie_len + 4;
      }

#ifdef DEBUG_TLS
      printf("Client TLS [client cipher_len: %u][tls_version: 0x%04X]\n", cipher_len, tls_version);
#endif

      if((cipher_offset+cipher_len) <= total_len - 1) { /* -1 because variable "id" is a u_int16_t */
	u_int8_t safari_ciphers = 0, chrome_ciphers = 0, this_is_not_safari = 0, looks_like_safari_on_big_sur = 0;

	for(i=0; i<cipher_len;) {
	  u_int16_t *id = (u_int16_t*)&packet->payload[cipher_offset+i];
	  u_int16_t cipher_id = ntohs(*id);

	  if(cipher_offset+i+1 < packet->payload_packet_len &&
	     ((packet->payload[cipher_offset+i] != packet->payload[cipher_offset+i+1]) ||
	      ((packet->payload[cipher_offset+i] & 0xF) != 0xA)) /* Skip GREASE */) {
	    /*
	      Skip GREASE [https://datatracker.ietf.org/doc/html/rfc8701]
	      https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967
	    */

#if defined(DEBUG_TLS) || defined(DEBUG_HEURISTIC)
	    printf("Client TLS [non-GREASE cipher suite: %u/0x%04X] [%d/%u]\n", cipher_id, cipher_id, i, cipher_len);
#endif

	    if(ja.client.num_ciphers < MAX_NUM_JA)
	      ja.client.cipher[ja.client.num_ciphers++] = cipher_id;
	    else {
	      invalid_ja = 1;
#ifdef DEBUG_TLS
	      printf("Client TLS Invalid cipher %u\n", ja.client.num_ciphers);
#endif
	    }

#if defined(DEBUG_TLS) || defined(DEBUG_HEURISTIC)
	    printf("Client TLS [cipher suite: %u/0x%04X] [%d/%u]\n", cipher_id, cipher_id, i, cipher_len);
#endif

	    switch(cipher_id) {
	    case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
	    case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
	      safari_ciphers++;
	      break;

	    case TLS_AES_128_GCM_SHA256:
	    case TLS_AES_256_GCM_SHA384:
	    case TLS_CHACHA20_POLY1305_SHA256:
	      chrome_ciphers++;
	      break;

	    case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
	    case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
	    case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
	    case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
	    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
	    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
	    case TLS_RSA_WITH_AES_128_CBC_SHA:
	    case TLS_RSA_WITH_AES_256_CBC_SHA:
	    case TLS_RSA_WITH_AES_128_GCM_SHA256:
	    case TLS_RSA_WITH_AES_256_GCM_SHA384:
	      safari_ciphers++, chrome_ciphers++;
	      break;

	    case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
	      looks_like_safari_on_big_sur = 1;
	      break;
	    }
	  } else {
#if defined(DEBUG_TLS) || defined(DEBUG_HEURISTIC)
	    printf("Client TLS [GREASE cipher suite: %u/0x%04X] [%d/%u]\n", cipher_id, cipher_id, i, cipher_len);
#endif

	    this_is_not_safari = 1; /* NOTE: BugSur and up have grease support */
	  }

	  i += 2;
	} /* for */

	if(ndpi_struct->cfg.tls_browser_enabled) {
          /* NOTE:
             we do not check for duplicates as with signatures because
             this is time consuming and we want to avoid overhead whem possible
          */
          if(this_is_not_safari)
            flow->protos.tls_quic.browser_heuristics.is_safari_tls = 0;
          else if((safari_ciphers == 12) || (this_is_not_safari && looks_like_safari_on_big_sur))
            flow->protos.tls_quic.browser_heuristics.is_safari_tls = 1;

          if(chrome_ciphers == 13)
            flow->protos.tls_quic.browser_heuristics.is_chrome_tls = 1;

          /* Note that both Safari and Chrome can overlap */
#ifdef DEBUG_HEURISTIC
          printf("[CIPHERS] [is_chrome_tls: %u (%u)][is_safari_tls: %u (%u)][this_is_not_safari: %u]\n",
                 flow->protos.tls_quic.browser_heuristics.is_chrome_tls,
                 chrome_ciphers,
                 flow->protos.tls_quic.browser_heuristics.is_safari_tls,
                 safari_ciphers,
                 this_is_not_safari);
#endif
	}
      } else {
	invalid_ja = 1;
#ifdef DEBUG_TLS
	printf("Client TLS Invalid len %u vs %u\n", (cipher_offset+cipher_len), total_len);
#endif
      }

      offset = base_offset + session_id_len + cookie_len + cipher_len + 2;
      offset += (!is_dtls) ? 1 : 2;

      if(offset < total_len) {
	u_int16_t compression_len;
	u_int16_t extensions_len;

	compression_len = packet->payload[offset];
	offset++;

#ifdef DEBUG_TLS
	printf("Client TLS [compression_len: %u]\n", compression_len);
#endif

	// offset += compression_len + 3;
	offset += compression_len;

	if(offset+1 < total_len) {
	  extensions_len = ntohs(*((u_int16_t*)&packet->payload[offset]));
	  offset += 2;

#ifdef DEBUG_TLS
	  printf("Client TLS [extensions_len: %u]\n", extensions_len);
#endif

	  if((extensions_len+offset) <= total_len) {
	    /* Move to the first extension
	       Type is u_int to avoid possible overflow on extension_len addition */
	    u_int extension_offset = 0;

	    while(extension_offset < extensions_len &&
		  offset+extension_offset+4 <= total_len) {
	      u_int16_t extension_id, extension_len, extn_off = offset+extension_offset;

	      extension_id = ntohs(*((u_int16_t*)&packet->payload[offset+extension_offset]));
	      extension_offset += 2;

	      extension_len = ntohs(*((u_int16_t*)&packet->payload[offset+extension_offset]));
	      extension_offset += 2;

#ifdef DEBUG_TLS
	      printf("Client TLS [extension_id: %u][extension_len: %u]\n", extension_id, extension_len);
#endif
	      checkExtensions(ndpi_struct, flow, is_dtls,
			      extension_id, extension_len, offset + extension_offset);

	      if(offset + 4 + extension_len > total_len) {
#ifdef DEBUG_TLS
	        printf("[TLS] extension length %u too long (%u, offset %u)\n",
	               extension_len, total_len, offset);
#endif
	        break;
	      }

	      if((extension_id == 0) || (packet->payload[extn_off] != packet->payload[extn_off+1]) ||
		 ((packet->payload[extn_off] & 0xF) != 0xA)) {
		/* Skip GREASE */

		if(ja.client.num_tls_extensions < MAX_NUM_JA) {
		  if(((extension_id == 0xFE0D /* ECHO */) || skipTLSextension(ndpi_struct, extension_id))
		     && (flow->l4_proto == IPPROTO_TCP)
		     && (ndpi_struct->cfg.tls_max_num_blocks_to_analyze > 0)
		     && (flow->l4.tcp.tls.tls_blocks != NULL)
		     && (flow->l4.tcp.tls.num_tls_blocks > 0) /* It should always be like that */) {
		    /*
		      Taking EncryptedClientHello (ECHO) lenght out of the block lenght
		      allows us to have a consistent measurement regardless of the SNI being used
		      and other information put in ECHO across requests
		    */
		    if(extension_id == 0x0 /* SNI */)
		      ; /* Nothing to do as already handled by (***) */
		    else
		      flow->l4.tcp.tls.tls_blocks[flow->l4.tcp.tls.num_tls_blocks-1].len -= extension_len + 4 /* id + len */;
		  }

		  ja.client.tls_extension[ja.client.num_tls_extensions++] = extension_id;
		} else {
		  invalid_ja = 1;
#ifdef DEBUG_TLS
		  printf("Client TLS Invalid extensions %u\n", ja.client.num_tls_extensions);
#endif
		}
	      }

	      if(extension_id == 0 /* server name */) {
		u_int16_t len;
		bool sni_numeric = false;

#ifdef DEBUG_TLS
		printf("[TLS] Extensions: found server name\n");
#endif
		if((offset+extension_offset+4) < packet->payload_packet_len) {
		  len = (packet->payload[offset+extension_offset+3] << 8) + packet->payload[offset+extension_offset+4];

		  if((offset+extension_offset+5+len) <= packet->payload_packet_len) {
		    char *sni = ndpi_hostname_sni_set(flow, &packet->payload[offset+extension_offset+5], len, NDPI_HOSTNAME_NORM_ALL);
		    int sni_len = strlen(sni);
#ifdef DEBUG_TLS
		    printf("[TLS] SNI: [%s]\n", sni);
#endif
		    if(sni /* It should always be like that */
		       && (flow->l4_proto == IPPROTO_TCP)
		       && (ndpi_struct->cfg.tls_max_num_blocks_to_analyze > 0)
		       && (flow->l4.tcp.tls.tls_blocks != NULL)
		       && (flow->l4.tcp.tls.num_tls_blocks > 0) /* It should always be like that */
		       ) {
		      /*
			Taking SNI lenght out of the block lenght allows us to have a consistent
			measurement regardless of the SNI being used
		      */
		      if(ndpi_struct->cfg.tls_ndpifp_ignore_sni_extension)
			flow->l4.tcp.tls.tls_blocks[flow->l4.tcp.tls.num_tls_blocks-1].len -= extension_len + 4 /* id + len */;
		      else
			flow->l4.tcp.tls.tls_blocks[flow->l4.tcp.tls.num_tls_blocks-1].len -= sni_len; /* (***) */
		    }

		    if(ndpi_is_valid_hostname((char *)&packet->payload[offset+extension_offset+5], len) == 0) {
		      ndpi_set_risk(ndpi_struct, flow, NDPI_INVALID_CHARACTERS, sni);

		      /* This looks like an attack */
		      ndpi_set_risk(ndpi_struct, flow, NDPI_POSSIBLE_EXPLOIT, "Invalid chars found in SNI: exploit or misconfiguration?");
		    }

		    if(!is_quic) {
		      if(ndpi_struct->cfg.tls_subclassification_enabled &&
		         flow->protos.tls_quic.subprotocol_detected == 0 &&
		         !flow->tls_quic.from_rdp && /* No (other) sub-classification; we will have TLS.RDP anyway */
		         ndpi_match_hostname_protocol(ndpi_struct, flow, ndpi_get_master_proto(ndpi_struct, flow), sni, sni_len))
		        flow->protos.tls_quic.subprotocol_detected = 1;
		    } else {
		      if(ndpi_struct->cfg.quic_subclassification_enabled &&
		         flow->protos.tls_quic.subprotocol_detected == 0 &&
		         !flow->tls_quic.from_rdp && /* No (other) sub-classification; we will have TLS.RDP anyway */
		         ndpi_match_hostname_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QUIC, sni, sni_len))
		        flow->protos.tls_quic.subprotocol_detected = 1;
		    }

		    if((flow->protos.tls_quic.subprotocol_detected == 0)
		       && (ndpi_check_is_numeric_ip(sni) == 1)) {
		      ndpi_set_risk(ndpi_struct, flow, NDPI_NUMERIC_IP_HOST, sni);
		      sni_numeric = true;
		    }

		    if(ndpi_str_endswith(sni, "signal.org")) {
		      /* printf("[SIGNAL] SNI: [%s]\n", sni); */
		      signal_add_to_cache(ndpi_struct, flow);
		    }

		    if(ndpi_check_dga_name(ndpi_struct, flow, sni, 1, 0, 0)) {
#ifdef DEBUG_TLS
		      printf("[TLS] SNI: (DGA) [%s]\n", sni);
#endif

		      if((sni_len >= 4)
		         /* Check if it ends in .com or .net */
		         && ((strcmp(&sni[sni_len-4], ".com") == 0) || (strcmp(&sni[sni_len-4], ".net") == 0))
		         && (strncmp(sni, "www.", 4) == 0)) /* Starting with www.... */
		        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TOR, ndpi_get_master_proto(ndpi_struct, flow), NDPI_CONFIDENCE_DPI);
		    } else {
#ifdef DEBUG_TLS
		      printf("[TLS] SNI: (NO DGA) [%s]\n", sni);
#endif
		    }

		    if(ndpi_struct->cfg.hostname_dns_check_enabled && (!sni_numeric)) {
		      ndpi_ip_addr_t ip_addr;

		      memset(&ip_addr, 0, sizeof(ip_addr));

		      if(packet->iph)
			ip_addr.ipv4 = packet->iph->daddr;
		      else
			memcpy(&ip_addr.ipv6, &packet->iphv6->ip6_dst,
			       sizeof(struct ndpi_in6_addr));

		      if(!ndpi_cache_find_hostname_ip(ndpi_struct, &ip_addr, sni)) {
#ifdef DEBUG_TLS
			printf("[TLS] Not found SNI %s\n", sni);
#endif
			ndpi_set_risk(ndpi_struct, flow, NDPI_UNRESOLVED_HOSTNAME, sni);

		      } else {
#ifdef DEBUG_TLS
			printf("[TLS] Found SNI %s\n", sni);
#endif
		      }
		    }
		  } else {
#ifdef DEBUG_TLS
		    printf("[TLS] Extensions server len too short: %u vs %u\n",
			   offset+extension_offset+5+len,
			   packet->payload_packet_len);
#endif
		  }
		}
	      } else if(extension_id == 10 /* supported groups */) {
		u_int16_t s_offset = offset+extension_offset + 2;

#ifdef DEBUG_TLS
		printf("Client TLS [EllipticCurveGroups: len=%u]\n", extension_len);
#endif

		if((s_offset+extension_len-2) <= total_len) {
		  for(i=0; i<(u_int32_t)extension_len-2 && s_offset + i + 1 < total_len; i += 2) {
		    u_int16_t s_group = ntohs(*((u_int16_t*)&packet->payload[s_offset+i]));

#ifdef DEBUG_TLS
		    printf("Client TLS [EllipticCurve: %u/0x%04X]\n", s_group, s_group);
#endif

		    if((s_group == 0) || (packet->payload[s_offset+i] != packet->payload[s_offset+i+1])
		       || ((packet->payload[s_offset+i] & 0xF) != 0xA)) {
		      /* Skip GREASE */
		      if(ja.client.num_elliptic_curve_groups < MAX_NUM_JA)
			ja.client.elliptic_curve_group[ja.client.num_elliptic_curve_groups++] = s_group;
		      else {
			invalid_ja = 1;
#ifdef DEBUG_TLS
			printf("Client TLS Invalid num elliptic group %u\n", ja.client.num_elliptic_curve_groups);
#endif
		      }
		    }
		  }
		} else {
		  invalid_ja = 1;
#ifdef DEBUG_TLS
		  printf("Client TLS Invalid len %u vs %u\n", (s_offset+extension_len-1), total_len);
#endif
		}
	      } else if(extension_id == 11 /* ec_point_formats groups */) {
		u_int16_t s_offset = offset+extension_offset + 1;

#ifdef DEBUG_TLS
		printf("Client TLS [EllipticCurveFormat: len=%u]\n", extension_len);
#endif
		if((s_offset+extension_len-1) <= total_len) {
		  for(i=0; i<(u_int32_t)extension_len-1 && s_offset+i < total_len; i++) {
		    u_int8_t s_group = packet->payload[s_offset+i];

#ifdef DEBUG_TLS
		    printf("Client TLS [EllipticCurveFormat: %u]\n", s_group);
#endif

		    if(ja.client.num_elliptic_curve_point_format < MAX_NUM_JA)
		      ja.client.elliptic_curve_point_format[ja.client.num_elliptic_curve_point_format++] = s_group;
		    else {
		      invalid_ja = 1;
#ifdef DEBUG_TLS
		      printf("Client TLS Invalid num elliptic %u\n", ja.client.num_elliptic_curve_point_format);
#endif
		    }
		  }
		} else {
		  invalid_ja = 1;
#ifdef DEBUG_TLS
		  printf("Client TLS Invalid len %u vs %u\n", s_offset+extension_len, total_len);
#endif
		}
	      } else if(extension_id == 13 /* signature algorithms */ &&
	                offset+extension_offset+1 < total_len) {
		int s_offset = offset+extension_offset, safari_signature_algorithms = 0, id;
		u_int16_t tot_signature_algorithms_len = ntohs(*((u_int16_t*)&packet->payload[s_offset]));

#ifdef DEBUG_TLS
		printf("Client TLS [SIGNATURE_ALGORITHMS: block_len=%u/len=%u]\n", extension_len, tot_signature_algorithms_len);
#endif

		s_offset += 2;
		tot_signature_algorithms_len = ndpi_min((sizeof(ja.client.signature_algorithms_str) / 2) - 1, tot_signature_algorithms_len);

		for(i=0, id=0; i<tot_signature_algorithms_len && s_offset+i+1<total_len; i += 2)
		  ja.client.signature_algorithm[id++] = ntohs(*(u_int16_t*)&packet->payload[s_offset+i]);

		ja.client.num_signature_algorithms = id;

		for(i=0, id=0; i<tot_signature_algorithms_len && s_offset+i+1<total_len; i++) {
		  int rc = ndpi_snprintf(&ja.client.signature_algorithms_str[i*2],
					 sizeof(ja.client.signature_algorithms_str)-i*2,
					 "%02X", packet->payload[s_offset+i]);
		  if(rc < 0) break;
		}

		if(ndpi_struct->cfg.tls_browser_enabled) {
	          int chrome_signature_algorithms = 0, duplicate_found = 0, last_signature = 0;

                  for(i=0; i<tot_signature_algorithms_len && s_offset + (int)i + 2 < packet->payload_packet_len; i+=2) {
                    u_int16_t signature_algo = (u_int16_t)ntohs(*((u_int16_t*)&packet->payload[s_offset+i]));

                    if(last_signature == signature_algo) {
                      /* Consecutive duplication */
                      duplicate_found = 1;
                      continue;
                    } else {
                      /* Check for other duplications */
                      u_int all_ok = 1;

                      for(j=0; j<tot_signature_algorithms_len; j+=2) {
                        if(j != i && s_offset + (int)j + 2 < packet->payload_packet_len) {
                          u_int16_t j_signature_algo = (u_int16_t)ntohs(*((u_int16_t*)&packet->payload[s_offset+j]));

                          if((signature_algo == j_signature_algo)
                             && (i < j) /* Don't skip both of them */) {
#ifdef DEBUG_HEURISTIC
                            printf("[SIGNATURE] [TLS Signature Algorithm] Skipping duplicate 0x%04X\n", signature_algo);
#endif

                            duplicate_found = 1, all_ok = 0;
                            break;
                          }
                        }
                      }

                      if(!all_ok)
                        continue;
                    }

                    last_signature = signature_algo;

#ifdef DEBUG_HEURISTIC
                    printf("[SIGNATURE] [TLS Signature Algorithm] 0x%04X\n", signature_algo);
#endif
                    switch(signature_algo) {
                    case ECDSA_SECP521R1_SHA512:
                      flow->protos.tls_quic.browser_heuristics.is_firefox_tls = 1;
                      break;

                    case ECDSA_SECP256R1_SHA256:
                    case ECDSA_SECP384R1_SHA384:
                    case RSA_PKCS1_SHA256:
                    case RSA_PKCS1_SHA384:
                    case RSA_PKCS1_SHA512:
                    case RSA_PSS_RSAE_SHA256:
                    case RSA_PSS_RSAE_SHA384:
                    case RSA_PSS_RSAE_SHA512:
                      chrome_signature_algorithms++, safari_signature_algorithms++;
#ifdef DEBUG_HEURISTIC
                      printf("[SIGNATURE] [Chrome/Safari] Found 0x%04X [chrome: %u][safari: %u]\n",
                             signature_algo, chrome_signature_algorithms, safari_signature_algorithms);
#endif

                      break;
                    }
                  }

#ifdef DEBUG_HEURISTIC
                  printf("[SIGNATURE] [safari_signature_algorithms: %u][chrome_signature_algorithms: %u]\n",
                         safari_signature_algorithms, chrome_signature_algorithms);
#endif

                  if(flow->protos.tls_quic.browser_heuristics.is_firefox_tls)
                    flow->protos.tls_quic.browser_heuristics.is_safari_tls = 0,
                      flow->protos.tls_quic.browser_heuristics.is_chrome_tls = 0;

                  if(safari_signature_algorithms != 8)
                    flow->protos.tls_quic.browser_heuristics.is_safari_tls = 0;

                  if((chrome_signature_algorithms != 8) || duplicate_found)
                    flow->protos.tls_quic.browser_heuristics.is_chrome_tls = 0;

                  /* Avoid Chrome and Safari overlaps, thing that cannot happen with Firefox */
                  if(flow->protos.tls_quic.browser_heuristics.is_safari_tls)
                    flow->protos.tls_quic.browser_heuristics.is_chrome_tls = 0;

                  if((flow->protos.tls_quic.browser_heuristics.is_chrome_tls == 0)
                     && duplicate_found)
                    flow->protos.tls_quic.browser_heuristics.is_safari_tls = 1; /* Safari */

#ifdef DEBUG_HEURISTIC
                  printf("[SIGNATURE] [is_firefox_tls: %u][is_chrome_tls: %u][is_safari_tls: %u][duplicate_found: %u]\n",
                         flow->protos.tls_quic.browser_heuristics.is_firefox_tls,
                         flow->protos.tls_quic.browser_heuristics.is_chrome_tls,
                         flow->protos.tls_quic.browser_heuristics.is_safari_tls,
                         duplicate_found);
#endif
		}

		if(i > 0 && i >= tot_signature_algorithms_len) {
		  ja.client.signature_algorithms_str[i*2 - 1] = '\0';
		} else {
		  ja.client.signature_algorithms_str[i*2] = '\0';
		}

#ifdef DEBUG_TLS
		printf("Client TLS [SIGNATURE_ALGORITHMS: %s]\n", ja.client.signature_algorithms_str);
#endif
	      } else if(extension_id == 14 /* use_srtp */) {
                /* This is likely a werbrtc flow */
                if(flow->stun.maybe_dtls || flow->detected_protocol_stack[0] == NDPI_PROTOCOL_DTLS)
	          flow->protos.tls_quic.webrtc = 1;
#ifdef DEBUG_TLS
                printf("Client TLS: use_srtp\n");
#endif
	      } else if(extension_id == 16 /* application_layer_protocol_negotiation */ &&
	                offset+extension_offset+1 < total_len) {
		u_int16_t s_offset = offset+extension_offset;
		u_int16_t tot_alpn_len = ntohs(*((u_int16_t*)&packet->payload[s_offset]));
		char alpn_str[256];
		u_int16_t alpn_str_len = 0, i;

#ifdef DEBUG_TLS
		printf("Client TLS [ALPN: block_len=%u/len=%u]\n", extension_len, tot_alpn_len);
#endif
		s_offset += 2;
		tot_alpn_len += s_offset;

		while(s_offset < tot_alpn_len && s_offset < total_len) {
		  u_int8_t alpn_i, alpn_len = packet->payload[s_offset++];

		  if((s_offset + alpn_len) <= tot_alpn_len &&
		     (s_offset + alpn_len) <= total_len) {
#ifdef DEBUG_TLS
		    printf("Client TLS [ALPN: %u]\n", alpn_len);
#endif

		    if(((uint32_t)alpn_str_len+alpn_len+1) < (sizeof(alpn_str)-1)) {
		      if(alpn_str_len > 0) {
			alpn_str[alpn_str_len] = ',';
			alpn_str_len++;
		      }

		      for(alpn_i=0; alpn_i<alpn_len; alpn_i++)
			alpn_str[alpn_str_len+alpn_i] = packet->payload[s_offset+alpn_i];

		      s_offset += alpn_len, alpn_str_len += alpn_len;;
		    } else
		      break;
		  } else
		    break;
		} /* while */

		alpn_str[alpn_str_len] = '\0';

#ifdef DEBUG_TLS
		printf("Client TLS [ALPN: %s][len: %u]\n", alpn_str, alpn_str_len);
#endif
		if(flow->protos.tls_quic.advertised_alpns == NULL) {
		  flow->protos.tls_quic.advertised_alpns = ndpi_strdup(alpn_str);
		  if(flow->protos.tls_quic.advertised_alpns) {
		    tlsCheckUncommonALPN(ndpi_struct, flow, flow->protos.tls_quic.advertised_alpns);

		    /* Without SNI matching we can try to sub-classify the flow via ALPN.
		       Note that this happens only on very rare cases, not the common ones
		       ("h2", "http/1.1", ...). Usefull for asymmetric traffic */
		    if(!flow->protos.tls_quic.subprotocol_detected) {
		      if((is_quic && ndpi_struct->cfg.quic_subclassification_enabled) ||
		         (!is_quic && ndpi_struct->cfg.tls_subclassification_enabled))
	                tls_subclassify_by_alpn(ndpi_struct, flow);
		    }
		  }
		}

                alpn_str_len = ndpi_min(sizeof(ja.client.alpn), (size_t)alpn_str_len);
		memcpy(ja.client.alpn, alpn_str, alpn_str_len);

		/* Store the last character of the first ALPN protocol (before any semicolon) */
		ja.client.alpn_original_last = '0';
		if(alpn_str_len > 0) {
		  /* Find the end of the first ALPN protocol (before semicolon or comma) */
		  int first_alpn_end = 0;
		  for(first_alpn_end = 0; first_alpn_end < alpn_str_len; first_alpn_end++) {
		    if(ja.client.alpn[first_alpn_end] == ';' || ja.client.alpn[first_alpn_end] == ',') {
		      break;
		    }
		  }
		  if(first_alpn_end > 0) {
		    ja.client.alpn_original_last = ja.client.alpn[first_alpn_end - 1];
		  }
		}

		if(alpn_str_len > 0)
		  ja.client.alpn[alpn_str_len - 1] = '\0';

		/* Replace , with - as in JA3 */
		for(i=0; ja.client.alpn[i] != '\0'; i++)
		  if(ja.client.alpn[i] == ',') ja.client.alpn[i] = '-';

	      } else if(extension_id == 43 /* supported versions */ &&
	                offset+extension_offset < total_len) {
		u_int16_t s_offset = offset+extension_offset;
		u_int8_t version_len = packet->payload[s_offset];
		char version_str[256];
		char buf_ver_tmp[16];
		size_t version_str_len = 0;
		version_str[0] = 0;
#ifdef DEBUG_TLS
		printf("Client TLS [TLS version len: %u]\n", version_len);
#endif

		if(version_len == (extension_len-1)) {
		  u_int8_t j;

		  s_offset++;

		  // careful not to overflow and loop forever with u_int8_t
		  for(j=0; j+1<version_len && s_offset + j + 1 < packet->payload_packet_len; j += 2) {
		    u_int16_t tls_version = ntohs(*((u_int16_t*)&packet->payload[s_offset+j]));
		    u_int8_t unknown_tls_version;

#ifdef DEBUG_TLS
		    printf("Client TLS [TLS version: %s/0x%04X]\n",
			   ndpi_ssl_version2str(buf_ver_tmp, sizeof(buf_ver_tmp), tls_version, &unknown_tls_version), tls_version);
#endif

		    if((version_str_len+8) < sizeof(version_str)) {
		      int rc = ndpi_snprintf(&version_str[version_str_len],
					     sizeof(version_str) - version_str_len, "%s%s",
					     (version_str_len > 0) ? "," : "",
					     ndpi_ssl_version2str(buf_ver_tmp, sizeof(buf_ver_tmp), tls_version, &unknown_tls_version));
		      if(rc <= 0)
			break;
		      else
			version_str_len += rc;

		      if(ja.client.num_supported_versions < MAX_NUM_JA)
			ja.client.supported_version[ja.client.num_supported_versions++] = tls_version;
		    }
		  }

#ifdef DEBUG_TLS
		  printf("Client TLS [SUPPORTED_VERSIONS: %s]\n", version_str);
#endif

		  if(flow->protos.tls_quic.tls_supported_versions == NULL &&
		     ndpi_struct->cfg.tls_versions_supported_enabled)
		    flow->protos.tls_quic.tls_supported_versions = ndpi_strdup(version_str);
		}
	      } else if(extension_id == 65037 /* ECH: latest drafts */) {
#ifdef DEBUG_TLS
		printf("Client TLS: ECH version 0x%x\n", extension_id);
#endif
		/* Beginning with draft-08, the version is the same as the code point
		   for the "encrypted_client_hello" extension. */
		flow->protos.tls_quic.encrypted_ch.version = extension_id;
	      } else if(extension_id == 65445 || /* QUIC transport parameters (drafts version) */
		        extension_id == 57) { /* QUIC transport parameters (final version) */
		u_int16_t s_offset = offset+extension_offset;
		uint16_t final_offset;
		int using_var_int = is_version_with_var_int_transport_params(quic_version);

		if(!using_var_int) {
		  if(s_offset+1 >= total_len) {
		    final_offset = 0; /* Force skipping extension */
		  } else {
		    u_int16_t seq_len = ntohs(*((u_int16_t*)&packet->payload[s_offset]));
		    s_offset += 2;
	            final_offset = ndpi_min(total_len, s_offset + seq_len);
		  }
		} else {
	          final_offset = ndpi_min(total_len, s_offset + extension_len);
		}

		while(s_offset < final_offset) {
		  u_int64_t param_type, param_len;

                  if(!using_var_int) {
		    if(s_offset+3 >= final_offset)
		      break;
		    param_type = ntohs(*((u_int16_t*)&packet->payload[s_offset]));
		    param_len = ntohs(*((u_int16_t*)&packet->payload[s_offset + 2]));
		    s_offset += 4;
		  } else {
		    if(s_offset >= final_offset ||
		       (s_offset + quic_len_buffer_still_required(packet->payload[s_offset])) >= final_offset)
		      break;
		    s_offset += quic_len(&packet->payload[s_offset], &param_type);

		    if(s_offset >= final_offset ||
		       (s_offset + quic_len_buffer_still_required(packet->payload[s_offset])) >= final_offset)
		      break;
		    s_offset += quic_len(&packet->payload[s_offset], &param_len);
		  }

#ifdef DEBUG_TLS
		  printf("Client TLS [QUIC TP: Param 0x%x Len %d]\n", (int)param_type, (int)param_len);
#endif
		  if(s_offset+param_len > final_offset)
		    break;

		  s_offset += param_len;
		}
	      } else if(extension_id == 21) { /* Padding */
		/* Padding is usually some hundreds byte long. Longer padding
		   might be used as obfuscation technique to force unusual CH fragmentation */
		if(extension_len > 500 /* Arbitrary value */) {
#ifdef DEBUG_TLS
		  printf("Padding length: %d\n", extension_len);
#endif
		  ndpi_set_risk(ndpi_struct, flow, NDPI_OBFUSCATED_TRAFFIC, "Abnormal Client Hello/Padding length");
		}
	      } else if(extension_id == 22) { /* Encrypt-then-MAC */
		if(extension_len == 0) {
		  char *sni = flow->host_server_name;

		  if(sni != NULL) {
		    u_int sni_len = strlen(sni);

		    if((flow->protos.tls_quic.advertised_alpns == NULL) /* No ALPN */
		       && (sni_len > 8)
		       && ((strcmp(&sni[sni_len-4], ".com") == 0) || (strcmp(&sni[sni_len-4], ".net") == 0))
		       && (strncmp(sni, "www.", 4) == 0) /* Starting with www.... */
		       && str_contains_digit(&sni[4])) {
		      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TOR, ndpi_get_master_proto(ndpi_struct, flow), NDPI_CONFIDENCE_DPI);
		    }
		  }
		}
	      } else if(extension_id == 51 &&  /* key_share */
	                offset + extension_offset < total_len) {
		u_int32_t extn_offset        = extn_off + 4;
		u_int16_t extn_end           = extn_offset + extension_len;

		if(extn_offset + extension_len <= total_len) {
#ifdef DEBUG_TLS
                  u_int16_t key_share_extn_len = ntohs(*((u_int16_t*)&(packet->payload[extn_offset])));

                  printf("[key_share] [len=%u][key_share_extn_len: %u][%02X %02X]\n",
                         extension_len, key_share_extn_len,
                         (packet->payload[extn_offset] & 0xFF),
                         (packet->payload[extn_offset+1] & 0xFF));
#endif

                  extn_offset += 2;

                  while(extn_offset + 4 < extn_end) {
                    u_int16_t group_id     = ntohs(*((u_int16_t*)&(packet->payload[extn_offset])));
                    u_int16_t key_extn_len = ntohs(*((u_int16_t*)&(packet->payload[extn_offset + 2])));

  #ifdef DEBUG_TLS
                    printf("\t[%02X %02X][extn_offset: %u][group_id: %u][key_extn_len: %u]\n",
                           (packet->payload[extn_offset] & 0xFF),
                           (packet->payload[extn_offset+1] & 0xFF),
                           extn_offset,
                           group_id, key_extn_len);
  #endif
		    if(group_id != 0x2A2A /* Skip GREASE */) {
		      if(ja.client.num_key_share_groups < MAX_NUM_JA)
			ja.client.key_share_group[ja.client.num_key_share_groups++] = group_id;
		    }

                    extn_offset += key_extn_len + 4;
                  }
		}

#ifdef DEBUG_TLS
		printf("[extn_offset: %u][extn_end: %u]\n", extn_offset, extn_end);
#endif
	      }

	      extension_offset += extension_len; /* Move to the next extension */

#ifdef DEBUG_TLS
	      printf("Client TLS [extension_offset/len: %u/%u]\n", extension_offset, extension_len);
#endif
	    } /* while */

	    if(!invalid_ja) {
	      /* Compute JA4 client */

compute_ja4c:
	      if(ndpi_struct->cfg.tls_ja4c_fingerprint_enabled) {
	        ndpi_compute_ja4(ndpi_struct, flow, quic_version, &ja);
		tls_match_ja4(ndpi_struct, flow);
	      }

	      if(ndpi_struct->cfg.tls_ja_data_enabled) {
		if(flow->protos.tls_quic.ja_client == NULL) {
		  flow->protos.tls_quic.ja_client = ndpi_malloc(sizeof(ndpi_tls_client_info));

		  if(flow->protos.tls_quic.ja_client != NULL)
		    memcpy(flow->protos.tls_quic.ja_client, &ja.client, sizeof(ndpi_tls_client_info));
		}
	      }

	      /* End JA4 */
	    }

	    /* Before returning to the caller we need to make a final check */
	    if((flow->protos.tls_quic.ssl_version >= 0x0303) /* >= TLSv1.2 */
	       && !flow->protos.tls_quic.webrtc
	       && (flow->protos.tls_quic.advertised_alpns == NULL) /* No ALPN */) {
	      ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_NOT_CARRYING_HTTPS, "No ALPN");
	    }

	    /* Add check for missing SNI */
	    if(flow->host_server_name[0] == '\0'
	       && (flow->protos.tls_quic.ssl_version >= 0x0302) /* TLSv1.1 */
	       && !flow->protos.tls_quic.webrtc
	       ) {
	      /* This is a bit suspicious */
	      ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_MISSING_SNI, "SNI should always be present");

	      if(flow->protos.tls_quic.advertised_alpns != NULL) {
		char buf[256], *tmp, *item;

		snprintf(buf, sizeof(buf), "%s", flow->protos.tls_quic.advertised_alpns);

		item = strtok_r(buf, ",", &tmp);

		while(item != NULL) {
		  if(item[0] == 'h') {
		    /* Example 'h2' */
		    ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_ALPN_SNI_MISMATCH, item);
		    break;
		  } else
		    item = strtok_r(NULL, ",", &tmp);
		}
	      }
	    }

	    return(2 /* Client Certificate */);
	  } else {
#ifdef DEBUG_TLS
	    printf("[TLS] Client: too short [%u vs %u]\n",
		   (extensions_len+offset), total_len);
#endif
	  }
	} else if(offset == total_len) {
	  /* TLS does not have extensions etc */
	  goto compute_ja4c;
	}
      } else {
#ifdef DEBUG_TLS
	printf("[JA3] Client: invalid length detected\n");
#endif
      }
    }
  }

  return(0); /* Not found */
}

/* **************************************** */

static void ndpi_search_tls_wrapper(struct ndpi_detection_module_struct *ndpi_struct,
				    struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  int rc = 0;

#ifdef DEBUG_TLS
  printf("==>> %s() [len: %u][version: %u]\n",
	 __FUNCTION__,
	 packet->payload_packet_len,
	 flow->protos.tls_quic.ssl_version);
#endif

  /* It is not easy to handle "standard" TLS/DTLS detection and (plain) obfuscated
     heuristic at the SAME time. Use a trivial logic: switch to heuristic
     code only if the standard functions fail */

  /* We might be in extra-dissection data-path here (if we have been
     called from STUN or from Mails/FTP/...), but plain obfuscated heuristic
     is always checked in "standard" data-path! */

  if(flow->tls_quic.obfuscated_heur_state == NULL) {
    if(packet->udp != NULL || flow->stun.maybe_dtls)
      rc = ndpi_search_dtls(ndpi_struct, flow);
    else
      rc = ndpi_search_tls_tcp(ndpi_struct, flow);

     /* We should check for this TLS heuristic if:
      * the feature is enabled
      * this flow doesn't seem a real TLS/DTLS one
      * we are not here from STUN code or from opportunistic tls path (mails/ftp)
      * with TCP, we got the 3WHS (so that we can process the beginning of the flow)
      */
    if(rc == 0 &&
       (ndpi_struct->cfg.tls_heuristics & NDPI_HEURISTICS_TLS_OBFUSCATED_PLAIN) &&
       flow->stun.maybe_dtls == 0 &&
       flow->tls_quic.from_opportunistic_tls == 0 &&
       ((flow->l4_proto == IPPROTO_TCP && ndpi_seen_flow_beginning(flow)) ||
        flow->l4_proto == IPPROTO_UDP) &&
       !is_flow_addr_informative(flow) /* The proxy server is likely hosted on some cloud providers */ ) {
      flow->tls_quic.obfuscated_heur_state = ndpi_calloc(1, sizeof(struct tls_obfuscated_heuristic_state));
    }
  }

  if(flow->tls_quic.obfuscated_heur_state) {
    tls_obfuscated_heur_search_again(ndpi_struct, flow);
  } else if(rc == 0) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
  }
}

/* **************************************** */

void init_tls_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_register_dissector("(D)TLS", ndpi_struct,
                     ndpi_search_tls_wrapper,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     2,
                     NDPI_PROTOCOL_TLS,
                     NDPI_PROTOCOL_DTLS);
}
