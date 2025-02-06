/*
 * nomachine.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_NOMACHINE

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_nomachine_add_connection(struct ndpi_detection_module_struct *ndpi_struct, 
                                              struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found NoMachine\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_NOMACHINE,
                             NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
  ndpi_set_risk(ndpi_struct, flow, NDPI_DESKTOP_OR_FILE_SHARING_SESSION, "Found NoMachine");
}

static void ndpi_search_nomachine(struct ndpi_detection_module_struct *ndpi_struct,
                                  struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search NoMachine\n");

  if (packet->tcp != NULL) {
    /* A NoMachine connection starts with a handshake that contains 
     * only the characters NXSH (request) & NXD (response) and a version 
     * number. After that it is followed by a TLS handshake. */
    if ((packet->payload_packet_len > 10 && packet->payload_packet_len < 15) &&
        ((memcmp(packet->payload, "NXSH-", 5) == 0) || (memcmp(packet->payload, "NXD-", 4) == 0)))
    {
      ndpi_int_nomachine_add_connection(ndpi_struct, flow);
      return;
    }
  } else if (packet->udp != NULL) {
    /* NoMachine uses UDP for multimedia data */
    if (packet->payload_packet_len > 9 && /* Shortest valid packet is 10 bytes long, probably it's keep-alive */
        le16toh(get_u_int16_t(packet->payload, 2)) == 1 &&
        le16toh(get_u_int16_t(packet->payload, 4)) == packet->payload_packet_len &&
        get_u_int16_t(packet->payload, 8) == 0)
    {
      ndpi_int_nomachine_add_connection(ndpi_struct, flow);
      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}
void init_nomachine_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("NoMachine", ndpi_struct, *id,
                                      NDPI_PROTOCOL_NOMACHINE,
                                      ndpi_search_nomachine,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
