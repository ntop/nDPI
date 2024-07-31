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

static void ndpi_search_openvpn(struct ndpi_detection_module_struct* ndpi_struct,
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
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }
  
  /* Skip openvpn TCP transport packet size */
  if(packet->tcp != NULL)
    ovpn_payload += 2, ovpn_payload_len -= 2;

  opcode = ovpn_payload[0] & P_OPCODE_MASK;
  if(!is_opcode_valid(opcode)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }
  /* Maybe a strong assumption... */
  if((ovpn_payload[0] & ~P_OPCODE_MASK) != 0) {
    NDPI_LOG_DBG2(ndpi_struct, "Invalid key id\n");
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }
  if(flow->packet_direction_counter[dir] == 1 &&
     !(opcode == P_CONTROL_HARD_RESET_CLIENT_V1 ||
       opcode == P_CONTROL_HARD_RESET_CLIENT_V2 ||
       opcode == P_CONTROL_HARD_RESET_SERVER_V1 ||
       opcode == P_CONTROL_HARD_RESET_SERVER_V2 ||
       opcode == P_CONTROL_HARD_RESET_CLIENT_V3)) {
    NDPI_LOG_DBG2(ndpi_struct, "Invalid first packet\n");
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }
  if(flow->packet_direction_counter[dir] == 1 &&
     packet->tcp &&
     ntohs(*(u_int16_t *)(packet->payload)) != ovpn_payload_len) {
    NDPI_LOG_DBG2(ndpi_struct, "Invalid tcp len on reset\n");
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  NDPI_LOG_DBG2(ndpi_struct, "[packets %d/%d][opcode: %u][len: %u]\n",
                flow->packet_direction_counter[dir],
                flow->packet_direction_counter[!dir],
                opcode, ovpn_payload_len);

  if(flow->packet_direction_counter[dir] > 1) {
    if(memcmp(flow->ovpn_session_id[dir], ovpn_payload + 1, 8) != 0) {
      NDPI_LOG_DBG2(ndpi_struct, "Invalid session id on two consecutive pkts in the same dir\n");
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
    if(flow->packet_direction_counter[dir] >= 2 &&
       flow->packet_direction_counter[!dir] >= 2) {
      /* (2) */
      NDPI_LOG_INFO(ndpi_struct,"found openvpn (session ids match on both direction)\n");
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OPENVPN, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
	return;
      }
    if(flow->packet_direction_counter[dir] >= 4 &&
       flow->packet_direction_counter[!dir] == 0) {
      /* (3) */
      NDPI_LOG_INFO(ndpi_struct,"found openvpn (asymmetric)\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OPENVPN, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      return;
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
            ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OPENVPN, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
            return;
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

  if(failed)
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);

  if(flow->packet_counter > 5)
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);    
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
