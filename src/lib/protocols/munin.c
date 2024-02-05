/*
 * munin.c
 *
 * Copyright (C) 2022-23 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MUNIN

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_munin_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                          struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found munin\n");

  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_MUNIN,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

/* ***************************************************** */

static void ndpi_search_munin(struct ndpi_detection_module_struct *ndpi_struct,
                              struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  static char const munin_prefix[] = "# munin node at ";

  NDPI_LOG_DBG(ndpi_struct, "search munin\n");

  // "# munin node at "
  if (packet->payload_packet_len < NDPI_STATICSTRING_LEN(munin_prefix))
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (memcmp(packet->payload, munin_prefix, NDPI_STATICSTRING_LEN(munin_prefix)) != 0)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  ndpi_int_munin_add_connection(ndpi_struct, flow);

  if (packet->payload[packet->payload_packet_len - 1] != '\n')
  {
    ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, "Missing Munin Hostname");
    return;
  }

  size_t host_len = packet->payload_packet_len - NDPI_STATICSTRING_LEN(munin_prefix) - 1;
  if (host_len > 0)
  {
    ndpi_hostname_sni_set(flow, packet->payload + NDPI_STATICSTRING_LEN(munin_prefix), host_len, NDPI_HOSTNAME_NORM_ALL);
  } else {
    ndpi_set_risk(ndpi_struct, flow, NDPI_MALFORMED_PACKET, "Missing Munin Hostname");
  }
}

/* ***************************************************** */
  
void init_munin_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                          u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Munin", ndpi_struct, *id,
				      NDPI_PROTOCOL_MUNIN,
				      ndpi_search_munin,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK
				      );

  *id += 1;
}
