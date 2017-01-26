/*
 * openvpn.c
 *
 * Copyright (C) 2011-16 - ntop.org
 *
 * OpenVPN TCP / UDP Detection - 128/160 hmac
 *
 * Detection based upon these openvpn protocol properties:
 *   - opcode
 *   - packet ID
 *   - session ID
 *
 * Two (good) packets are needed to perform detection.
 *  - First packet from client: save session ID
 *  - Second packet from server: report saved session ID
 *
 * TODO
 *  - Support PSK only mode (instead of TLS)
 *  - Support PSK + TLS mode (PSK used for early authentication)
 *  - TLS certificate extraction
 *
 */

#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_OPENVPN

#define P_CONTROL_HARD_RESET_CLIENT_V1  (0x01 << 3)
#define P_CONTROL_HARD_RESET_CLIENT_V2  (0x07 << 3)
#define P_CONTROL_HARD_RESET_SERVER_V1  (0x02 << 3)
#define P_CONTROL_HARD_RESET_SERVER_V2  (0x08 << 3)
#define P_OPCODE_MASK 0xF8
#define P_SHA1_HMAC_SIZE 20
#define P_HMAC_128 16                            // (RSA-)MD5, (RSA-)MD4, ..others
#define P_HMAC_160 20                            // (RSA-|DSA-)SHA(1), ..others, SHA1 is openvpn default
#define P_HARD_RESET_PACKET_ID_OFFSET(hmac_size) (9 + hmac_size)
#define P_PACKET_ID_ARRAY_LEN_OFFSET(hmac_size)  (P_HARD_RESET_PACKET_ID_OFFSET(hmac_size) + 8)
#define P_HARD_RESET_CLIENT_MAX_COUNT  5

static 
#ifndef WIN32
inline 
#endif
u_int32_t get_packet_id(const u_int8_t * payload, u_int8_t hms) {
  return ntohl(*(u_int32_t*)(payload + P_HARD_RESET_PACKET_ID_OFFSET(hms)));
}

static 
#ifndef WIN32
inline
#endif
int8_t check_pkid_and_detect_hmac_size(const u_int8_t * payload) {
  // try to guess
  if (get_packet_id(payload, P_HMAC_160) == 1)
    return P_HMAC_160;
  if (get_packet_id(payload, P_HMAC_128) == 1)
    return P_HMAC_128;
  return -1;
}

void ndpi_search_openvpn(struct ndpi_detection_module_struct* ndpi_struct,
                         struct ndpi_flow_struct* flow) {
  struct ndpi_packet_struct* packet = &flow->packet;
  const u_int8_t * ovpn_payload = packet->payload;
  const u_int8_t * session_remote;
  u_int8_t opcode;
  u_int8_t alen;
  int8_t hmac_size;
  int8_t failed = 0;

  if (packet->payload_packet_len >= 40) {
    // skip openvpn TCP transport packet size
    if (packet->tcp != NULL)
      ovpn_payload += 2;

    opcode = ovpn_payload[0] & P_OPCODE_MASK;

    if (flow->ovpn_counter < P_HARD_RESET_CLIENT_MAX_COUNT && (opcode == P_CONTROL_HARD_RESET_CLIENT_V1 ||
				    opcode == P_CONTROL_HARD_RESET_CLIENT_V2)) {

      if (check_pkid_and_detect_hmac_size(ovpn_payload) > 0) {
        memcpy(flow->ovpn_session_id, ovpn_payload+1, 8);

        NDPI_LOG(NDPI_PROTOCOL_OPENVPN, ndpi_struct, NDPI_LOG_DEBUG,
		 "session key: %02x%02x%02x%02x%02x%02x%02x%02x\n",
		 flow->ovpn_session_id[0], flow->ovpn_session_id[1], flow->ovpn_session_id[2], flow->ovpn_session_id[3],
		 flow->ovpn_session_id[4], flow->ovpn_session_id[5], flow->ovpn_session_id[6], flow->ovpn_session_id[7]);
      }
    } else if (flow->ovpn_counter >= 1 && flow->ovpn_counter <= P_HARD_RESET_CLIENT_MAX_COUNT &&
            (opcode == P_CONTROL_HARD_RESET_SERVER_V1 || opcode == P_CONTROL_HARD_RESET_SERVER_V2)) {

      hmac_size = check_pkid_and_detect_hmac_size(ovpn_payload);

      if (hmac_size > 0) {
        alen = ovpn_payload[P_PACKET_ID_ARRAY_LEN_OFFSET(hmac_size)];
        session_remote = ovpn_payload + P_PACKET_ID_ARRAY_LEN_OFFSET(hmac_size) + 1 + alen * 4;

        if (memcmp(flow->ovpn_session_id, session_remote, 8) == 0)
          ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OPENVPN, NDPI_PROTOCOL_UNKNOWN);
        else {
          NDPI_LOG(NDPI_PROTOCOL_OPENVPN, ndpi_struct, NDPI_LOG_DEBUG,
		   "key mismatch: %02x%02x%02x%02x%02x%02x%02x%02x\n",
		   session_remote[0], session_remote[1], session_remote[2], session_remote[3],
		   session_remote[4], session_remote[5], session_remote[6], session_remote[7]);
          failed = 1;
        }
      } else
        failed = 1;
    } else
      failed = 1;

    flow->ovpn_counter++;
    
    if (failed)
      NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_OPENVPN);
  }
}

void init_openvpn_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("OpenVPN", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_OPENVPN,
				      ndpi_search_openvpn,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
