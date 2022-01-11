/*
 * gtp.c
 *
 * Copyright (C) 2011-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_GTP

#include "ndpi_api.h"


/* This code handles: GTP-U (port 2152), GTP-C (v1 and v2; port 2123) and GTP-PRIME
   (port 3386).
   It should be fine to ignore v0, since it should not be used anymore.

   Message length checks and basic headers are not uniform across these protocols.

   For GTPv2 (GTP-C v2), see TS 29.274 Sec. 5.5.1:
   "Octets 3 to 4 represent the Message Length field. This field shall indicate
   the length of the message in octets excluding the mandatory part of the GTP-C
   header (the first 4 octets). The TEID (if present) and the Sequence Number
   shall be included in the length count."

   For GTP-PRIME TS 32.295 Sec. 6.1.1
   "The Length indicates the length of payload (number of octets after the GTP'
   header). The Sequence Number of the packet is part of the GTP' header."

   For GTPv1 (GTP-U and GTP-C v1) TS TS 29.060 Sec. 6
   "Length: This field indicates the length in octets of the payload, i.e. the
   rest of the packet following the mandatory part of the GTP header (that is
   the first 8 octets). The Sequence Number, the N-PDU Number or any Extension
   headers shall be considered to be part of the payload, i.e. included in the
   length count."

*/

#define HEADER_LEN_GTP_U	8
#define HEADER_LEN_GTP_C_V1	8
#define HEADER_LEN_GTP_C_V2	4
#define HEADER_LEN_GTP_PRIME	6


/* Common header for all GTP types */
struct gtp_header_generic {
  u_int8_t flags, message_type;
  u_int16_t message_len;
};

static void ndpi_check_gtp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  if((packet->udp != NULL) && (payload_len > sizeof(struct gtp_header_generic))) {
    u_int32_t gtp_u  = ntohs(2152);
    u_int32_t gtp_c  = ntohs(2123);
    u_int32_t gtp_prime = ntohs(3386);

    struct gtp_header_generic *gtp = (struct gtp_header_generic *)packet->payload;
    u_int8_t version = (gtp->flags & 0xE0) >> 5;
    u_int8_t pt = (gtp->flags & 0x10) >> 4;
    u_int16_t message_len = ntohs(gtp->message_len);

    if((packet->udp->source == gtp_u) || (packet->udp->dest == gtp_u)) {
      if((version == 1) && (pt == 1) &&
         (payload_len >= HEADER_LEN_GTP_U) &&
         (message_len <= (payload_len - HEADER_LEN_GTP_U))) {
        NDPI_LOG_INFO(ndpi_struct, "found gtp-u\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_GTP_U, NDPI_PROTOCOL_GTP, NDPI_CONFIDENCE_DPI);
        return;
      }
    }
    if((packet->udp->source == gtp_c) || (packet->udp->dest == gtp_c)) {
      if(((version == 1) &&
          (payload_len >= HEADER_LEN_GTP_C_V1) &&
          (message_len == (payload_len - HEADER_LEN_GTP_C_V1)) &&
          (message_len >= 4 * (!!(gtp->flags & 0x07))) &&
          (gtp->message_type > 0 && gtp->message_type <= 129)) || /* Loose check based on TS 29.060 7.1 */
         ((version == 2) &&
          /* payload_len is always valid, because HEADER_LEN_GTP_C_V2 == sizeof(struct gtp_header_generic) */
          (message_len == (payload_len - HEADER_LEN_GTP_C_V2)))) {
        NDPI_LOG_INFO(ndpi_struct, "found gtp-c\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_GTP_C, NDPI_PROTOCOL_GTP, NDPI_CONFIDENCE_DPI);
        return;
      }
    }
    if((packet->udp->source == gtp_prime) || (packet->udp->dest == gtp_prime)) {
      if((pt == 0) &&
         ((gtp->flags & 0x0E) >> 1 == 0x7) && /* Spare bits */
         (payload_len >= HEADER_LEN_GTP_PRIME) &&
         (message_len <= (payload_len - HEADER_LEN_GTP_PRIME)) &&
         ((gtp->message_type > 0 && gtp->message_type <= 7) || /* Check based on TS 32.295 6.2.1 */
          gtp->message_type == 240 || gtp->message_type == 241)) {
        NDPI_LOG_INFO(ndpi_struct, "found gtp-prime\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_GTP_PRIME, NDPI_PROTOCOL_GTP, NDPI_CONFIDENCE_DPI);
        return;
      }
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  return;
}

void ndpi_search_gtp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG_DBG(ndpi_struct, "search gtp\n");

  /* skip marked packets */
  if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_GTP)
    ndpi_check_gtp(ndpi_struct, flow);
}


void init_gtp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("GTP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_GTP,
				      ndpi_search_gtp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
