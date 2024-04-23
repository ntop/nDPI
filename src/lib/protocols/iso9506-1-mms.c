/*
 * iso9506-1-mms.c
 *
 * ISO 9506-1:2003 Manufacturing Message Specification
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_ISO9506_1_MMS

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_iso9506_1_mms_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                                struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found ISO 9506-1 MMS\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_ISO9506_1_MMS, NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_iso9506_1_mms(struct ndpi_detection_module_struct *ndpi_struct,
                                    struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search ISO 9506-1 MMS\n");
  
  if ((packet->payload_packet_len > 60) && tpkt_verify_hdr(packet))
  {
    if (current_pkt_from_client_to_server(ndpi_struct, flow)) {
      /* Check COTP and ISO 8327-1 headers */
      if ((packet->payload[4] == 2) && (packet->payload[5] == 0xF0) &&
          (packet->payload[6] == 0x80) && (packet->payload[7] - 13 <= 1) &&
          (packet->payload[8] == (packet->payload_packet_len - 9)))
      {
        /* Search for a MMS signature in initiate request from client */
        if ((get_u_int16_t(packet->payload, packet->payload_packet_len-37) == le16toh(0x280)) ||
            (get_u_int16_t(packet->payload, packet->payload_packet_len-38) == le16toh(0x380)) ||
            (get_u_int16_t(packet->payload, packet->payload_packet_len-40) == le16toh(0x280)))
        {
          ndpi_int_iso9506_1_mms_add_connection(ndpi_struct, flow);
          return;
        }
      }
    }
  }

  if (flow->packet_direction_counter[packet->packet_direction] > 2) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
}

void init_iso9506_1_mms_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                                  u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("ISO9506-1-MMS", ndpi_struct, *id,
				      NDPI_PROTOCOL_ISO9506_1_MMS,
				      ndpi_search_iso9506_1_mms,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
