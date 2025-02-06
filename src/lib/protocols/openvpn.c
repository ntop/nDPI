/*
 * openvpn.c
 *
 * Copyright (C) 2011-22 - ntop.org
 *
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_OPENVPN

#include "ndpi_api.h"
#include "ndpi_private.h"


/*
 * OpenVPN TCP / UDP Detection - 128/160 hmac
 *
 * Detection based upon these openvpn protocol properties:
 *   - opcode
 *   - packet ID
 *   - session ID
 *
 * TODO
 *  - Support PSK only mode (instead of TLS)
 *  - Support PSK + TLS mode (PSK used for early authentication)
 *  - TLS certificate extraction
 *
 */

#define P_CONTROL_HARD_RESET_CLIENT_V1  (0x01 << 3)
#define P_CONTROL_HARD_RESET_SERVER_V1  (0x02 << 3)
#define P_CONTROL_V1                    (0x04 << 3)
#define P_ACK_V1                        (0x05 << 3)
#define P_CONTROL_HARD_RESET_CLIENT_V2  (0x07 << 3)
#define P_CONTROL_HARD_RESET_SERVER_V2  (0x08 << 3)
#define P_CONTROL_HARD_RESET_CLIENT_V3  (0x0A << 3)
#define P_CONTROL_WKC_V1                (0x0B << 3)

#define P_OPCODE_MASK 0xF8
#define P_SHA1_HMAC_SIZE 20
#define P_HMAC_128 16                            // (RSA-)MD5, (RSA-)MD4, ..others
#define P_HMAC_160 20                            // (RSA-|DSA-)SHA(1), ..others, SHA1 is openvpn default
#define P_HMAC_NONE 0                            // No HMAC
#define P_HARD_RESET_PACKET_ID_OFFSET(hmac_size) (9 + hmac_size)
#define P_PACKET_ID_ARRAY_LEN_OFFSET(hmac_size)  (P_HARD_RESET_PACKET_ID_OFFSET(hmac_size) + 8 * (!!(hmac_size)))


static void ndpi_int_openvpn_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                            struct ndpi_flow_struct * const flow,
                                            ndpi_confidence_t confidence)
{
  if(ndpi_struct->cfg.openvpn_subclassification_by_ip &&
     ndpi_struct->proto_defaults[flow->guessed_protocol_id_by_ip].protoCategory == NDPI_PROTOCOL_CATEGORY_VPN) {
    ndpi_set_detected_protocol(ndpi_struct, flow, flow->guessed_protocol_id_by_ip, NDPI_PROTOCOL_OPENVPN, confidence);
  } else {
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OPENVPN, NDPI_PROTOCOL_UNKNOWN, confidence);
  }
}

static int is_opcode_valid(u_int8_t opcode)
{
  /* Ignore:
     * P_DATA_V1/2: they don't have any (useful) info in the header
     * P_CONTROL_SOFT_RESET_V1: it is used to key renegotiation -> it is not at the beginning of the session
  */
  return opcode == P_CONTROL_HARD_RESET_CLIENT_V1 ||
	 opcode == P_CONTROL_HARD_RESET_SERVER_V1 ||
	 opcode == P_CONTROL_V1 ||
	 opcode == P_ACK_V1 ||
	 opcode == P_CONTROL_HARD_RESET_CLIENT_V2 ||
	 opcode == P_CONTROL_HARD_RESET_SERVER_V2 ||
	 opcode == P_CONTROL_HARD_RESET_CLIENT_V3 ||
	 opcode == P_CONTROL_WKC_V1;
}

static u_int32_t get_packet_id(const u_int8_t * payload, u_int8_t hms) {
  return(ntohl(*(u_int32_t*)(payload + P_HARD_RESET_PACKET_ID_OFFSET(hms))));
}

/* From wireshark */
/* We check the leading 4 byte of a suspected hmac for 0x00 bytes,
   if more than 1 byte out of the 4 provided contains 0x00, the
   hmac is considered not valid, which suggests that no tls auth is used.
   unfortunatly there is no other way to detect tls auth on the fly */
static int check_for_valid_hmac(u_int32_t hmac)
{
  int c = 0;

  if((hmac & 0x000000FF) == 0x00000000)
    c++;
  if((hmac & 0x0000FF00) == 0x00000000)
    c++;
  if ((hmac & 0x00FF0000) == 0x00000000)
    c++;
  if ((hmac & 0xFF000000) == 0x00000000)
    c++;
  if (c > 1)
    return 0;
  return 1;
}

static int8_t detect_hmac_size(const u_int8_t *payload, int payload_len) {
  // try to guess
  if((payload_len >= P_HARD_RESET_PACKET_ID_OFFSET(P_HMAC_160) + 4) &&
     get_packet_id(payload, P_HMAC_160) == 1)
    return P_HMAC_160;
  
  if((payload_len >= P_HARD_RESET_PACKET_ID_OFFSET(P_HMAC_128) + 4) &&
     get_packet_id(payload, P_HMAC_128) == 1)
    return P_HMAC_128;

  /* Heuristic from Wireshark, to detect no-HMAC flows (i.e. tls-crypt) */
  if(payload_len >= 14 &&
     !(payload[9] > 0 &&
       check_for_valid_hmac(ntohl(*(u_int32_t*)(payload + 9)))))
    return P_HMAC_NONE;

  return(-1);
}

static int search_standard(struct ndpi_detection_module_struct* ndpi_struct,
                           struct ndpi_flow_struct* flow) {
  struct ndpi_packet_struct* packet = &ndpi_struct->packet;
  const u_int8_t * ovpn_payload = packet->payload;
  const u_int8_t * session_remote;
  u_int8_t opcode;
  u_int8_t alen;
  int8_t hmac_size;
  int8_t failed = 0;
  /* No u_ */int16_t ovpn_payload_len = packet->payload_packet_len;
  int dir = packet->packet_direction;

  /* Detection:
   * (1) server and client resets matching (via session id -> remote session id)
   * (2) consecutive packets (in both directions) with the same session id
   * (3) asymmetric traffic
  */

  if(ovpn_payload_len < 14 + 2 * (packet->tcp != NULL)) {
    return 1; /* Exclude */
  }

  /* Skip openvpn TCP transport packet size */
  if(packet->tcp != NULL)
    ovpn_payload += 2, ovpn_payload_len -= 2;

  opcode = ovpn_payload[0] & P_OPCODE_MASK;
  if(!is_opcode_valid(opcode)) {
    return 1; /* Exclude */
  }
  /* Maybe a strong assumption... */
  if((ovpn_payload[0] & ~P_OPCODE_MASK) != 0) {
    NDPI_LOG_DBG2(ndpi_struct, "Invalid key id\n");
    return 1; /* Exclude */
  }
  if(flow->packet_direction_counter[dir] == 1 &&
     !(opcode == P_CONTROL_HARD_RESET_CLIENT_V1 ||
       opcode == P_CONTROL_HARD_RESET_CLIENT_V2 ||
       opcode == P_CONTROL_HARD_RESET_SERVER_V1 ||
       opcode == P_CONTROL_HARD_RESET_SERVER_V2 ||
       opcode == P_CONTROL_HARD_RESET_CLIENT_V3)) {
    NDPI_LOG_DBG2(ndpi_struct, "Invalid first packet\n");
    return 1; /* Exclude */
  }
  /* Resets are small packets */
  if(packet->payload_packet_len >= 1200 &&
     (opcode == P_CONTROL_HARD_RESET_CLIENT_V1 ||
      opcode == P_CONTROL_HARD_RESET_CLIENT_V2 ||
      opcode == P_CONTROL_HARD_RESET_SERVER_V1 ||
      opcode == P_CONTROL_HARD_RESET_SERVER_V2 ||
      opcode == P_CONTROL_HARD_RESET_CLIENT_V3)) {
    NDPI_LOG_DBG2(ndpi_struct, "Invalid len first pkt (QUIC collision)\n");
    return 1; /* Exclude */
  }
  if(flow->packet_direction_counter[dir] == 1 &&
     packet->tcp &&
     ntohs(*(u_int16_t *)(packet->payload)) != ovpn_payload_len) {
    NDPI_LOG_DBG2(ndpi_struct, "Invalid tcp len on reset\n");
    return 1; /* Exclude */
  }

  NDPI_LOG_DBG2(ndpi_struct, "[packets %d/%d][opcode: %u][len: %u]\n",
                flow->packet_direction_counter[dir],
                flow->packet_direction_counter[!dir],
                opcode, ovpn_payload_len);

  if(flow->packet_direction_counter[dir] > 1) {
    if(memcmp(flow->ovpn_session_id[dir], ovpn_payload + 1, 8) != 0) {
      NDPI_LOG_DBG2(ndpi_struct, "Invalid session id on two consecutive pkts in the same dir\n");
      return 1; /* Exclude */
    }
    if(flow->packet_direction_counter[dir] >= 2 &&
       flow->packet_direction_counter[!dir] >= 2) {
      /* (2) */
      NDPI_LOG_INFO(ndpi_struct,"found openvpn (session ids match on both direction)\n");
      return 2; /* Found */
    }
    if(flow->packet_direction_counter[dir] >= 4 &&
       flow->packet_direction_counter[!dir] == 0) {
      /* (3) */
      NDPI_LOG_INFO(ndpi_struct,"found openvpn (asymmetric)\n");
      return 2; /* Found */
    }
  } else {
    memcpy(flow->ovpn_session_id[dir], ovpn_payload + 1, 8);
    NDPI_LOG_DBG2(ndpi_struct, "Session key [%d]: 0x%lx\n", dir,
                  ndpi_ntohll(*(u_int64_t *)flow->ovpn_session_id[dir]));
  }

  /* (1) */
  if(flow->packet_direction_counter[!dir] > 0 &&
     (opcode == P_CONTROL_HARD_RESET_SERVER_V1 ||
      opcode == P_CONTROL_HARD_RESET_SERVER_V2)) {

    hmac_size = detect_hmac_size(ovpn_payload, ovpn_payload_len);
    NDPI_LOG_DBG2(ndpi_struct, "hmac size %d\n", hmac_size);
    failed = 0;
    if(hmac_size >= 0 &&
       P_PACKET_ID_ARRAY_LEN_OFFSET(hmac_size) < ovpn_payload_len) {
      u_int16_t offset = P_PACKET_ID_ARRAY_LEN_OFFSET(hmac_size);

      alen = ovpn_payload[offset];

      if(alen > 0) {
        offset += 1 + alen * 4;

        if((offset + 8) <= ovpn_payload_len) {
          session_remote = &ovpn_payload[offset];

          if(memcmp(flow->ovpn_session_id[!dir], session_remote, 8) == 0) {
            NDPI_LOG_INFO(ndpi_struct,"found openvpn\n");
            return 2; /* Found */
          } else {
            NDPI_LOG_DBG2(ndpi_struct, "key mismatch 0x%lx\n", ndpi_ntohll(*(u_int64_t *)session_remote));
          }
        }
        failed = 1;
      } else {
        /* Server reset without remote session id field; no failure */
      }
    }
  }

  if(failed || flow->packet_counter > 5)
    return 1; /* Exclude */
  return 0; /* Continue */
}

/* Heuristic to detect encrypted/obfusctaed OpenVPN flows, based on
   https://www.usenix.org/conference/usenixsecurity22/presentation/xue-diwen.
   Main differences between the paper and our implementation:
    * only op-code fingerprint

   Core idea: even if the OpenVPN packets are somehow encrypted to avoid trivial
   detection, the distibution of the first byte of the messages (i.e. the
   distribution of the op-codes) might still be unique
*/

static int search_heur_opcode_common(struct ndpi_detection_module_struct* ndpi_struct,
                                     struct ndpi_flow_struct* flow,
                                     u_int8_t first_byte) {
  u_int8_t opcode, found  = 0, i;
  int dir = ndpi_struct->packet.packet_direction;

  opcode = first_byte & P_OPCODE_MASK;

  /* Handshake:
      * 2 different resets
      * up to 3 different opcodes (ack, control, wkc)
      * 1 data (v1 or v2)
     So, other than the resets:
      * at least 2 different opcodes (ack, control)
      * no more than 4 (i.e. OPENVPN_HEUR_MAX_NUM_OPCODES) different opcodes
  */

  NDPI_LOG_DBG2(ndpi_struct, "Heur-opcode: [packets %d/%d msgs %d, dir %d][first byte 0x%x][opcode: 0x%x]\n",
                flow->packet_direction_counter[0],
                flow->packet_direction_counter[1],
                flow->ovpn_heur_opcode__num_msgs,
                dir, first_byte, opcode);

  flow->ovpn_heur_opcode__num_msgs++;

  if(flow->packet_direction_counter[dir] == 1) {
    flow->ovpn_heur_opcode__resets[dir] = opcode;
    if(flow->packet_direction_counter[!dir] > 0 &&
       opcode == flow->ovpn_heur_opcode__resets[!dir]) {
      NDPI_LOG_DBG2(ndpi_struct, "Heur-opcode: same resets\n");
      return 1; /* Exclude */
    }
    return 0; /* Continue */
  }

  if(opcode == flow->ovpn_heur_opcode__resets[dir]) {
    if(flow->ovpn_heur_opcode__codes_num > 0) {
      NDPI_LOG_DBG2(ndpi_struct, "Heur-opcode: resets after other opcodes\n");
      return 1; /* Exclude */
    }
    return 0; /* Continue */
  }
  if(flow->packet_direction_counter[!dir] > 0 &&
     opcode == flow->ovpn_heur_opcode__resets[!dir]) {
    NDPI_LOG_DBG2(ndpi_struct, "Heur-opcode: same resets\n");
    return 1; /* Exclude */
  }

  if(flow->packet_direction_counter[!dir] == 0) {
    NDPI_LOG_DBG2(ndpi_struct, "Heur-opcode: opcode different than reset but not reset in the other direction\n");
    return 1; /* Exclude */
  }

  if(flow->ovpn_heur_opcode__codes_num == OPENVPN_HEUR_MAX_NUM_OPCODES &&
     opcode != flow->ovpn_heur_opcode__codes[OPENVPN_HEUR_MAX_NUM_OPCODES - 1]) {
    NDPI_LOG_DBG2(ndpi_struct, "Heur-opcode: once data we can't have other opcode\n");
    /* TODO: this check assumes that the "data" opcode is the 4th one (after the resets).
     * But we usually have only ack + control + data... */
    return 1; /* Exclude */
  }

  for(i = 0; i < flow->ovpn_heur_opcode__codes_num; i++) {
    if(flow->ovpn_heur_opcode__codes[i] == opcode)
      found = 1;
  }
  if(found == 0) {
    if(flow->ovpn_heur_opcode__codes_num == OPENVPN_HEUR_MAX_NUM_OPCODES) {
      NDPI_LOG_DBG2(ndpi_struct, "Heur-opcode: too many opcodes. Early exclude\n");
      return 1; /* Exclude */
    }
    flow->ovpn_heur_opcode__codes[flow->ovpn_heur_opcode__codes_num++] = opcode;
  }

  NDPI_LOG_DBG2(ndpi_struct, "Heur-opcode: Resets 0x%x,0x%x Num %d\n",
                flow->ovpn_heur_opcode__resets[0],
                flow->ovpn_heur_opcode__resets[1],
                flow->ovpn_heur_opcode__codes_num);

  if(flow->ovpn_heur_opcode__num_msgs < ndpi_struct->cfg.openvpn_heuristics_num_msgs)
    return 0; /* Continue */

  /* Done. Check what we have found...*/

  if(flow->packet_direction_counter[0] == 0 ||
     flow->packet_direction_counter[1] == 0) {
    NDPI_LOG_DBG2(ndpi_struct, "Heur-opcode: excluded because asymmetric traffic\n");
    return 1; /* Exclude */
  }

  if(flow->ovpn_heur_opcode__codes_num >= 2) {
    NDPI_LOG_INFO(ndpi_struct,"found openvpn (Heur-opcode)\n");
    return 2; /* Found */
  }
  NDPI_LOG_DBG2(ndpi_struct, "Heur-opcode: excluded\n");
  return 1; /* Exclude */
}

static int search_heur_opcode(struct ndpi_detection_module_struct* ndpi_struct,
                              struct ndpi_flow_struct* flow) {
  struct ndpi_packet_struct* packet = &ndpi_struct->packet;
  const u_int8_t *ovpn_payload = packet->payload;
  u_int16_t ovpn_payload_len = packet->payload_packet_len;
  int dir = packet->packet_direction;
  u_int16_t pdu_len;
  int rc, offset;
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  int iter;
#endif

  /* To reduce false positives number, trigger the heuristic only for flows to
     suspicious/unknown addresses */
  if(is_flow_addr_informative(flow)) {
    NDPI_LOG_DBG2(ndpi_struct, "Heur-opcode: flow to informative address. Exclude\n");
    return 1; /* Exclude */
  }

  if(packet->tcp != NULL) {
    /* Two bytes field with pdu length */

    NDPI_LOG_DBG2(ndpi_struct, "Heur-opcode: TCP length %d (remaining %d)\n",
                  ovpn_payload_len,
                  flow->ovpn_heur_opcode__missing_bytes[dir]);

    /* We might need to "reassemble" the OpenVPN messages.
       Luckily, we are not interested in the message itself, but only in the first byte
       (after the length field), so as state we only need to know the "missing bytes"
       of the latest pdu (from the previous TCP packets) */
    if(flow->ovpn_heur_opcode__missing_bytes[dir] > 0) {
      NDPI_LOG_DBG2(ndpi_struct, "Heur-opcode: TCP, remaining bytes to ignore %d length %d\n",
                    flow->ovpn_heur_opcode__missing_bytes[dir], ovpn_payload_len);
      if(flow->ovpn_heur_opcode__missing_bytes[dir] >= ovpn_payload_len) {
        flow->ovpn_heur_opcode__missing_bytes[dir] -= ovpn_payload_len;
        return 0; /* Continue */
      } else {
        offset = flow->ovpn_heur_opcode__missing_bytes[dir];
        flow->ovpn_heur_opcode__missing_bytes[dir] = 0;
      }
    } else {
      offset = 0;
    }

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
    iter = 0;
#endif
    rc = 1; /* Exclude */
    while(offset + 2 + 1 /* The first byte is the opcode */ <= ovpn_payload_len) {
      pdu_len = ntohs((*(u_int16_t *)(ovpn_payload + offset)));
      NDPI_LOG_DBG2(ndpi_struct, "Heur-opcode: TCP, iter %d offset %d pdu_length %d\n",
                      iter, offset, pdu_len);
      if(pdu_len < 14)
        return 1; /* Exclude */
      if(pdu_len > 4 * 1500) { /* 4 full size packets: simple threshold to avoid false positives */
        NDPI_LOG_DBG2(ndpi_struct, "Heur-opcode: pdu_len %d too big. Exclude\n", pdu_len);
        return 1; /* Exclude */
      }
      rc = search_heur_opcode_common(ndpi_struct, flow, *(ovpn_payload + offset + 2));
      NDPI_LOG_DBG2(ndpi_struct, "Heur-opcode: TCP, rc %d\n", rc);
      if(rc > 0) /* Exclude || Found --> stop */
        return rc;

      if(offset + 2 + pdu_len <= ovpn_payload_len) {
        offset += 2 + pdu_len;
      } else {
        flow->ovpn_heur_opcode__missing_bytes[dir] = pdu_len - (ovpn_payload_len - (offset + 2));
        NDPI_LOG_DBG2(ndpi_struct, "Heur-opcode: TCP, missing %d bytes\n",
                      flow->ovpn_heur_opcode__missing_bytes[dir]);
        return 0; /* Continue */
      }
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
      iter++;
#endif
    }
    return rc;
  } else {
    if(ovpn_payload_len < 14)
      return 1; /* Exclude */
    return search_heur_opcode_common(ndpi_struct, flow, ovpn_payload[0]);
  }
}


static void ndpi_search_openvpn(struct ndpi_detection_module_struct* ndpi_struct,
                                struct ndpi_flow_struct* flow) {
  struct ndpi_packet_struct* packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "Search opnvpn\n");

  if(packet->payload_packet_len > 10 &&
     ntohl(*(u_int32_t *)&packet->payload[4 + 2 * (packet->tcp != NULL)]) == 0x2112A442) {
    NDPI_LOG_DBG2(ndpi_struct, "Avoid collision with STUN\n");
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  NDPI_LOG_DBG2(ndpi_struct, "States (before): %d %d\n",
                flow->ovpn_alg_standard_state,
                flow->ovpn_alg_heur_opcode_state);

  if(flow->ovpn_alg_standard_state == 0) {
    flow->ovpn_alg_standard_state = search_standard(ndpi_struct, flow);
  }
  if(ndpi_struct->cfg.openvpn_heuristics & NDPI_HEURISTICS_OPENVPN_OPCODE) {
    if(flow->ovpn_alg_heur_opcode_state == 0) {
      flow->ovpn_alg_heur_opcode_state = search_heur_opcode(ndpi_struct, flow);
    }
  } else {
    flow->ovpn_alg_heur_opcode_state = 1;
  }

  NDPI_LOG_DBG2(ndpi_struct, "States (after): %d %d\n",
                flow->ovpn_alg_standard_state,
                flow->ovpn_alg_heur_opcode_state);

  if(flow->ovpn_alg_standard_state == 2) {
    ndpi_int_openvpn_add_connection(ndpi_struct, flow, NDPI_CONFIDENCE_DPI);
  } else if (flow->ovpn_alg_heur_opcode_state == 2) {
    ndpi_int_openvpn_add_connection(ndpi_struct, flow, NDPI_CONFIDENCE_DPI_AGGRESSIVE);
    ndpi_set_risk(ndpi_struct, flow, NDPI_OBFUSCATED_TRAFFIC, "Obfuscated OpenVPN");
  } else if(flow->ovpn_alg_standard_state == 1 &&
            flow->ovpn_alg_heur_opcode_state == 1) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }

}

void init_openvpn_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			    u_int32_t *id) {
  ndpi_set_bitmask_protocol_detection("OpenVPN", ndpi_struct, *id,
				      NDPI_PROTOCOL_OPENVPN,
				      ndpi_search_openvpn,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
