/*
 * openvpn.c
 *
 * Copyright (C) 2011-21 - ntop.org
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

/*
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
  return(ntohl(*(u_int32_t*)(payload + P_HARD_RESET_PACKET_ID_OFFSET(hms))));
}

static 
#ifndef WIN32
inline
#endif
int8_t check_pkid_and_detect_hmac_size(const u_int8_t * payload) {
  // try to guess
  if(get_packet_id(payload, P_HMAC_160) == 1)
    return P_HMAC_160;
  
  if(get_packet_id(payload, P_HMAC_128) == 1)    
    return P_HMAC_128;
  
  return(-1);
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
  /* No u_ */int16_t ovpn_payload_len = packet->payload_packet_len;
  
  if(ovpn_payload_len >= 40) {
    // skip openvpn TCP transport packet size
    if(packet->tcp != NULL)
      ovpn_payload += 2, ovpn_payload_len -= 2;;

    opcode = ovpn_payload[0] & P_OPCODE_MASK;

    if(packet->udp) {
#ifdef DEBUG
      printf("[packet_id: %u][opcode: %u][Packet ID: %d][%u <-> %u][len: %u]\n",
	     flow->num_processed_pkts,
	     opcode, check_pkid_and_detect_hmac_size(ovpn_payload),
	     htons(packet->udp->source), htons(packet->udp->dest), ovpn_payload_len);	   
#endif
      
      if(
	 (flow->num_processed_pkts == 1)
	 && (
	     ((ovpn_payload_len == 112)
	      && ((opcode == 168) || (opcode == 192))
	      )
	     || ((ovpn_payload_len == 80)
		 && ((opcode == 184) || (opcode == 88) || (opcode == 160) || (opcode == 168) || (opcode == 200)))
	     )) {
	NDPI_LOG_INFO(ndpi_struct,"found openvpn\n");
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OPENVPN, NDPI_PROTOCOL_UNKNOWN);
	return;
      }
    }
    
    if(flow->ovpn_counter < P_HARD_RESET_CLIENT_MAX_COUNT && (opcode == P_CONTROL_HARD_RESET_CLIENT_V1 ||
							      opcode == P_CONTROL_HARD_RESET_CLIENT_V2)) {
      if(check_pkid_and_detect_hmac_size(ovpn_payload) > 0) {
        memcpy(flow->ovpn_session_id, ovpn_payload+1, 8);

        NDPI_LOG_DBG2(ndpi_struct,
		      "session key: %02x%02x%02x%02x%02x%02x%02x%02x\n",
		      flow->ovpn_session_id[0], flow->ovpn_session_id[1], flow->ovpn_session_id[2], flow->ovpn_session_id[3],
		      flow->ovpn_session_id[4], flow->ovpn_session_id[5], flow->ovpn_session_id[6], flow->ovpn_session_id[7]);
      }
    } else if(flow->ovpn_counter >= 1 && flow->ovpn_counter <= P_HARD_RESET_CLIENT_MAX_COUNT &&
	      (opcode == P_CONTROL_HARD_RESET_SERVER_V1 || opcode == P_CONTROL_HARD_RESET_SERVER_V2)) {

      hmac_size = check_pkid_and_detect_hmac_size(ovpn_payload);

      if(hmac_size > 0) {
	u_int16_t offset = P_PACKET_ID_ARRAY_LEN_OFFSET(hmac_size);
	  
        alen = ovpn_payload[offset];
	
        if (alen > 0) {
	  offset += 1 + alen * 4;

	  if((offset+8) <= ovpn_payload_len) {
	    session_remote = &ovpn_payload[offset];
	    
	    if(memcmp(flow->ovpn_session_id, session_remote, 8) == 0) {
	      NDPI_LOG_INFO(ndpi_struct,"found openvpn\n");
	      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OPENVPN, NDPI_PROTOCOL_UNKNOWN);
	      return;
	    } else {
	      NDPI_LOG_DBG2(ndpi_struct,
			    "key mismatch: %02x%02x%02x%02x%02x%02x%02x%02x\n",
			    session_remote[0], session_remote[1], session_remote[2], session_remote[3],
			    session_remote[4], session_remote[5], session_remote[6], session_remote[7]);
	      failed = 1;
	    }
	  } else
	    failed = 1;
	} else
          failed = 1;
      } else
        failed = 1;
    } else
      failed = 1;

    flow->ovpn_counter++;
    
    if(failed)
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);  
  }

  if(flow->packet_counter > 5)
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);    
}

void init_openvpn_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			    u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("OpenVPN", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_OPENVPN,
				      ndpi_search_openvpn,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
