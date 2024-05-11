/*
 * h323.c
 *
 * Copyright (C) 2015-20 ntop.org
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_H323

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_h323_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow) 
{
  NDPI_LOG_INFO(ndpi_struct, "found H323\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_H323,
                             NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_h323(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  const struct ndpi_packet_struct * const packet = &ndpi_struct->packet;
  u_int16_t dport = 0, sport = 0;

  NDPI_LOG_DBG(ndpi_struct, "search H323\n");

  /* TPKT header length + Q.931 header length without IE */
  if(tpkt_verify_hdr(packet) && (packet->payload_packet_len > 20)) {
    /* Check H.245 */
    if(packet->payload[7] == 0x06 &&
       ntohl(get_u_int32_t(packet->payload, 8)) == 0x0088175) /* protocolIdentifier OID */ {
      ndpi_int_h323_add_connection(ndpi_struct, flow);
      return;
    }
    /* Check H.225.0 : check Q.931 Protocol Discriminator and call reference value length */
    if((packet->payload[4] == 0x08) && ((packet->payload[5] & 0xF) <= 3)) {
      ndpi_int_h323_add_connection(ndpi_struct, flow);
      return;
    }
  } else if (packet->udp != NULL) {
    sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);
    if(sport == 1719 || dport == 1719) {
      /* Check H.225.0 RAS */
      if(packet->payload_packet_len > 20 &&
         packet->payload[4] == 0x06 &&
         ntohl(get_u_int32_t(packet->payload, 5)) == 0x0008914A /* protocolIdentifier OID */ ) {
        ndpi_int_h323_add_connection(ndpi_struct, flow);
        return;
      }
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_h323_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                         u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("H323", ndpi_struct, *id, 
      NDPI_PROTOCOL_H323,
      ndpi_search_h323,
      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
