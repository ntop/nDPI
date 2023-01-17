/*
 * merakicloud.c
 *
 * Copyright (C) 2011-23 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MERAKI_CLOUD

#include "ndpi_api.h"

static void ndpi_int_merakicloud_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                                struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found MerakiCloud\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MERAKI_CLOUD,
                             NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_merakicloud(struct ndpi_detection_module_struct *ndpi_struct,
                                    struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search MerakiCloud\n");

  if((flow->c_port == ntohs(7351) || flow->s_port == ntohs(7351)) &&
     packet->payload_packet_len > 4 &&
     get_u_int32_t(packet->payload, 0) == ntohl(0xfef72891)) {
    ndpi_int_merakicloud_add_connection(ndpi_struct, flow);
    return;
  }
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_merakicloud_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                                 u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("MerakiCloud", ndpi_struct, *id,
				      NDPI_PROTOCOL_MERAKI_CLOUD,
				      ndpi_search_merakicloud,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
