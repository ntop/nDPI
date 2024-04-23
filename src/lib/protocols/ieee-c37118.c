/*
 * ieee-c37118.c
 *
 * IEEE C37.118 Synchrophasor Protocol
 * 
 * Copyright (C) 2023 - ntop.org
 * Copyright (C) 2023 - V.G <v.gavrilov@securitycode.ru>
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_IEEE_C37118

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_ieee_c37118_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                            struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found IEEE C37.118\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_IEEE_C37118, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_ieee_c37118(struct ndpi_detection_module_struct *ndpi_struct,
                                    struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search IEEE C37.118\n");

  /* A little bit of heuristics. Check the minimum length, 
   * version (0xAA) and frame type (0 to 5) */
  if ((packet->payload_packet_len >= 17) && (packet->payload[0] == 0xAA) &&
      ((packet->payload[1] >> 4) < 6))
  {
    u_int16_t frame_size = ntohs(get_u_int16_t(packet->payload, 2));
    u_int16_t crc = ntohs(get_u_int16_t(packet->payload, packet->payload_packet_len-2));

    if ((frame_size == packet->payload_packet_len) &&
        (crc == ndpi_crc16_ccit_false(packet->payload, packet->payload_packet_len-2)))
    {
      ndpi_int_ieee_c37118_add_connection(ndpi_struct, flow);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_ieee_c37118_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("IEEE-C37118", ndpi_struct, *id,
                                      NDPI_PROTOCOL_IEEE_C37118,
                                      ndpi_search_ieee_c37118,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
