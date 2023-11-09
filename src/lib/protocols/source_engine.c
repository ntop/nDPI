/*
 * source_engine.c
 *
 * Source Engine Protocol
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
  char const source_engine_query[] = "Source Engine Query";
  size_t const source_engine_query_len = strlen(source_engine_query);

  NDPI_LOG_DBG(ndpi_struct, "search Source Engine\n");

  if (packet->payload_packet_len < source_engine_query_len + 1 /* '\0' */)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (packet->payload[packet->payload_packet_len - 1] != '\0')
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (strncmp((char const *)&packet->payload[packet->payload_packet_len - source_engine_query_len - 1],
              source_engine_query, source_engine_query_len) != 0)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  ndpi_int_source_engine_add_connection(ndpi_struct, flow);
}

/* ***************************************************** */
  
void init_source_engine_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                                  u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Source_Engine", ndpi_struct, *id,
                                      NDPI_PROTOCOL_SOURCE_ENGINE,
                                      ndpi_search_source_engine,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK
                                     );

  *id += 1;
}
