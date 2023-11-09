/*
 * oicq.c
 *
 * OICQ / Tencent QQ
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_OICQ

#include "ndpi_api.h"
#include "ndpi_private.h"

PACK_ON
struct oicq_hdr {
  uint8_t flag;
  uint16_t version;
  uint16_t command;
  uint16_t sequence;
} PACK_OFF;

static void ndpi_int_oicq_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                         struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found OICQ\n");

  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_OICQ,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

/* ***************************************************** */

static void ndpi_search_oicq(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;
  struct oicq_hdr const * const hdr = (struct oicq_hdr *)&packet->payload[0];

  NDPI_LOG_DBG(ndpi_struct, "search OICQ\n");

  if (packet->payload_packet_len < sizeof(*hdr))
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (hdr->flag != 0x02)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if (ntohs(hdr->version) != 0x3b0b)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  uint16_t command = ntohs(hdr->command);
  if (command == 0x0000 || (command > 0x00b5 && command < 0x03f7) ||
      command > 0x03f7)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  ndpi_int_oicq_add_connection(ndpi_struct, flow);
}

/* ***************************************************** */
  
void init_oicq_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                         u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("OICQ", ndpi_struct, *id,
                                      NDPI_PROTOCOL_OICQ,
                                      ndpi_search_oicq,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK
                                     );

  *id += 1;
}
