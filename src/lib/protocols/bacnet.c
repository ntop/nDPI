/*
 * bacnet.c
 *
 * Building Automation and Control Network
 *
 * Copyright (C) 2023 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_BACNET

#include "ndpi_api.h"
#include "ndpi_private.h"

// BVLC (BACnet Virtual Link Control) Annex is part of BVLL (BACnet Virtual Link Layer).
// See: https://www.ashrae.org/file%20library/technical%20resources/standards%20and%20guidelines/standards%20addenda/135-1995_addendum-a.pdf
PACK_ON
struct bvlc_header {
  uint8_t type;
  uint8_t function;
  uint16_t length;
} PACK_OFF;

static void ndpi_int_bacnet_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                           struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found BACnet\n");

  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_BACNET,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

/* ***************************************************** */

static void ndpi_search_bacnet(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  struct bvlc_header const * const bvlc = (struct bvlc_header *)&packet->payload[0];

  NDPI_LOG_DBG(ndpi_struct, "search BACnet\n");

  if (packet->payload_packet_len < sizeof(*bvlc))
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (bvlc->type != 0x81)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (bvlc->function > 0x0b)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (ntohs(bvlc->length) != packet->payload_packet_len)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  ndpi_int_bacnet_add_connection(ndpi_struct, flow);
}

/* ***************************************************** */
  
void init_bacnet_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                           u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("BACnet", ndpi_struct, *id,
                                      NDPI_PROTOCOL_BACNET,
                                      ndpi_search_bacnet,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK
                                     );

  *id += 1;
}
