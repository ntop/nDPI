/*
 * mysql.c
 * 
 * Copyright (C) 2009-11 - ipoque GmbH
 * Copyright (C) 2011-24 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MYSQL

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_search_mysql_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search MySQL\n");

  if(packet->payload_packet_len > 70 && packet->payload_packet_len < 120) {
    u_int32_t length = (packet->payload[2] << 16) + (packet->payload[1] << 8) + packet->payload[0];

    if ((u_int32_t)(packet->payload_packet_len-4) == length && 
        packet->payload[4] == 0x0A && ((memcmp(&packet->payload[5], "5.5.5-", 6) == 0) || 
        (packet->payload[5] > 0x33 && packet->payload[5] < 0x39)))
    {
      if ((memcmp(&packet->payload[packet->payload_packet_len-10], "_password", 9) == 0) ||
          (memcmp(&packet->payload[packet->payload_packet_len-10], "_kerberos", 9) == 0) ||
          (memcmp(&packet->payload[packet->payload_packet_len-9], "_windows", 8) == 0) ||
          (memcmp(&packet->payload[packet->payload_packet_len-8], "_simple", 7) == 0) ||
          (memcmp(&packet->payload[packet->payload_packet_len-8], "_gssapi", 7) == 0) ||
          (memcmp(&packet->payload[packet->payload_packet_len-5], "_pam", 4) == 0))
      {
        NDPI_LOG_INFO(ndpi_struct, "found MySQL\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MYSQL, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
        return;
      }
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_mysql_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("MySQL", ndpi_struct, *id,
				      NDPI_PROTOCOL_MYSQL,
				      ndpi_search_mysql_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
