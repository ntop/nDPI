/*
 * tplink_shp.c
 *
 * TP-LINK Smart Home Protocol
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TPLINK_SHP

#include "ndpi_api.h"

#define _TPLSHP_MIN_LEN     2
#define _TPLSHP_TCP_LEN_HDR 4

static void ndpi_int_tplink_shp_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                                  struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found TPLINK SHP\n");

  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_TPLINK_SHP,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

/* ***************************************************** */

static void ndpi_search_tplink_shp(struct ndpi_detection_module_struct *ndpi_struct,
                                   struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search TPLINK SHP\n");

  u_int16_t offset = 0;
  /* Skip length header (TCP payloads only) */
  if(packet->tcp != NULL) offset = _TPLSHP_TCP_LEN_HDR;

  if (packet->payload_packet_len - offset < _TPLSHP_MIN_LEN)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  u_int16_t i;
  u_int8_t k = 171, b[_TPLSHP_MIN_LEN];

  for (i = 0 ; i < _TPLSHP_MIN_LEN; i++)
  {
    b[i] = packet->payload[i + offset] ^ k;
    k = packet->payload[i + offset];
  }

  if (b[0] != '{' || (b[1] != '}' && b[1] != '"'))
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  ndpi_int_tplink_shp_add_connection(ndpi_struct, flow);
}

/* ***************************************************** */
  
void init_tplink_shp_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                                  u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("TPLINK SHP", ndpi_struct, *id,
                                      NDPI_PROTOCOL_TPLINK_SHP,
                                      ndpi_search_tplink_shp,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK
                                     );

  *id += 1;
}
