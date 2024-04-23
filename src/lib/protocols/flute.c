/*
 * flute.c
 *
 * File Delivery over Unidirectional Transport
 * 
 * Copyright (C) 2024 - ntop.org
 * Copyright (C) 2024 - V.G <v.gavrilov@securitycode.ru>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_FLUTE

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_search_flute(struct ndpi_detection_module_struct *ndpi_struct,
                              struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search FLUTE\n");

  if (packet->payload_packet_len > 250) {
    if (packet->payload[0] != 0x10) {
      goto not_flute;
    }

    u_int16_t lct_hdr_len = packet->payload[2] * 4;
    if (packet->payload_packet_len <= lct_hdr_len + 43) {
      goto not_flute;
    }

    if (memcmp(&packet->payload[lct_hdr_len+4], "<?xml", NDPI_STATICSTRING_LEN("<?xml")) == 0 &&
        memcmp(&packet->payload[lct_hdr_len+43], "<FDT", NDPI_STATICSTRING_LEN("<FDT")) == 0)
    {
      NDPI_LOG_INFO(ndpi_struct, "found FLUTE\n");
      ndpi_set_detected_protocol(ndpi_struct, flow,
                                 NDPI_PROTOCOL_FLUTE, NDPI_PROTOCOL_UNKNOWN,
                                 NDPI_CONFIDENCE_DPI);
    }
  }

not_flute:
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_flute_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                          u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("FLUTE", ndpi_struct, *id,
                                      NDPI_PROTOCOL_FLUTE,
                                      ndpi_search_flute,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
