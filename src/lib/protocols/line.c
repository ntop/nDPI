/*
 * line.c
 *
 * Copyright (C) 2022 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_LINE_CALL

#include "ndpi_api.h"

extern int is_valid_rtp_payload_type(uint8_t type);

static void ndpi_int_line_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                         struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found LineCall\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_PROTOCOL_LINE_CALL, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_line(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "searching LineCall\n");

  /* Some "random" UDP packets before the standard RTP stream:
     it seems that the 4th bytes of these packets is some kind of packet
     number. Look for 4 packets per direction with consecutive numbers. */

  if(packet->payload_packet_len > 10) {
    if(flow->l4.udp.line_pkts[packet->packet_direction] == 0) {
      flow->l4.udp.line_base_cnt[packet->packet_direction] = packet->payload[3];
      flow->l4.udp.line_pkts[packet->packet_direction] += 1;
      return;
    } else {
      /* It might be a RTP/RTCP packet. Ignore it and keep looking for the
         LINE packet numbers */
      /* Basic RTP detection */
      if((packet->payload[0] >> 6) == 2 && /* Version 2 */
         (packet->payload[1] == 201 || /* RTCP, Receiver Report */
          packet->payload[1] == 200 || /* RTCP, Sender Report */
          is_valid_rtp_payload_type(packet->payload[1] & 0x7F)) /* RTP */) {
        NDPI_LOG_DBG(ndpi_struct, "Probably RTP; keep looking for LINE");
        return;
      } else {
        if((u_int8_t)(flow->l4.udp.line_base_cnt[packet->packet_direction] +
                      flow->l4.udp.line_pkts[packet->packet_direction]) == packet->payload[3]) {
          flow->l4.udp.line_pkts[packet->packet_direction] += 1;
          if(flow->l4.udp.line_pkts[0] >= 4 && flow->l4.udp.line_pkts[1] >= 4) {
            /* To avoid false positives: usually "base pkt numbers" per-direction are different */
            if(flow->l4.udp.line_base_cnt[0] != flow->l4.udp.line_base_cnt[1])
              ndpi_int_line_add_connection(ndpi_struct, flow);
            else
              NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
	  }
          return;
        }
      }
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  return;
}

void init_line_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                         u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("LineCall", ndpi_struct, *id,
				      NDPI_PROTOCOL_LINE_CALL,
				      ndpi_search_line,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
