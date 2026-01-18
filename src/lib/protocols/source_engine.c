/*
 * source_engine.c
 *
 * Source Engine Protocol (Valve’s A2S protocol)
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SOURCE_ENGINE

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_source_engine_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                                  struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Source Engine\n");

  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_SOURCE_ENGINE,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

/* ***************************************************** */

static void ndpi_search_source_engine(struct ndpi_detection_module_struct *ndpi_struct,
                                      struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Source Engine\n");

  /* https://developer.valvesoftware.com/wiki/Server_queries */

  /* A2S request */
  if (current_pkt_from_client_to_server(ndpi_struct, flow) &&
      (packet->payload_packet_len > 8 && packet->payload_packet_len < 30) &&
      get_u_int32_t(packet->payload, 0) == 0xFFFFFFFF)
  {
    if (packet->payload[4] == 'T' || /* A2S_INFO */
        packet->payload[4] == 'U' || /* A2S_PLAYER */
        packet->payload[4] == 'V')   /* A2S_RULES */
    {
      ndpi_int_source_engine_add_connection(ndpi_struct, flow);
      return;
    }
  }

  /* A2S response */
  if (current_pkt_from_server_to_client(ndpi_struct, flow))
  {
    /* Challenge response */
    if (packet->payload_packet_len == 9 && 
        get_u_int32_t(packet->payload, 0) == 0xFFFFFFFF &&
        packet->payload[4] == 'A')
    {
      ndpi_int_source_engine_add_connection(ndpi_struct, flow);
      return;
    }

    if (packet->payload_packet_len > 30 && /* A reasonable length for euristics */
        get_u_int32_t(packet->payload, 0) == 0xFFFFFFFF)
    {
      if (packet->payload[4] == 'I' || /* A2S_INFO */
          packet->payload[4] == 'D' || /* A2S_PLAYER */
          packet->payload[4] == 'E')   /* A2S_RULES */
      {
        ndpi_int_source_engine_add_connection(ndpi_struct, flow);
        return;
      }
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

/* ***************************************************** */
  
void init_source_engine_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("Source_Engine", ndpi_struct,
                     ndpi_search_source_engine,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                     1, NDPI_PROTOCOL_SOURCE_ENGINE);
}
