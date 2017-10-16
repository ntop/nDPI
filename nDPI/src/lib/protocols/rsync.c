/*
 * rsync.c
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
 * Copyright (C) 2016 ntop.org
 *
 * This module is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License.
 * If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_RSYNC
static void ndpi_int_rsync_add_connection(struct ndpi_detection_module_struct
					  *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RSYNC, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_rsync(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_RSYNC, ndpi_struct, NDPI_LOG_DEBUG, "search for RSYNC.\n");

  if(packet->tcp) {
    NDPI_LOG(NDPI_PROTOCOL_RSYNC, ndpi_struct, NDPI_LOG_DEBUG, "calculating RSYNC over tcp.\n");
    /*
     * Should match: memcmp(packet->payload, "@RSYNCD: 28", 14) == 0)
     */
    if (packet->payload_packet_len == 12 && packet->payload[0] == 0x40 &&
	packet->payload[1] == 0x52 && packet->payload[2] == 0x53 &&
	packet->payload[3] == 0x59 && packet->payload[4] == 0x4e &&
	packet->payload[5] == 0x43 && packet->payload[6] == 0x44 &&
	packet->payload[7] == 0x3a ) {
      NDPI_LOG(NDPI_PROTOCOL_RSYNC, ndpi_struct, NDPI_LOG_DEBUG, "found rsync.\n");
      ndpi_int_rsync_add_connection(ndpi_struct, flow);
    }
  } else {
    NDPI_LOG(NDPI_PROTOCOL_RSYNC, ndpi_struct, NDPI_LOG_DEBUG, "exclude RSYNC.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RSYNC);
  }
}


void init_rsync_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("RSYNC", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_RSYNC,
				      ndpi_search_rsync,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
