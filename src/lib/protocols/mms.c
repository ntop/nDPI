/*
 * mms.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-15 - ntop.org
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


#include "ndpi_protocols.h"

#ifdef NDPI_CONTENT_MMS


static void ndpi_int_mms_add_connection(struct ndpi_detection_module_struct
					*ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_CONTENT_MMS, NDPI_PROTOCOL_UNKNOWN);
}


void ndpi_search_mms_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  //      struct ndpi_id_struct         *src=ndpi_struct->src;
  //      struct ndpi_id_struct         *dst=ndpi_struct->dst;


  /* search MSMMS packets */
  if (packet->payload_packet_len >= 20) {
    if (flow->l4.tcp.mms_stage == 0 && packet->payload[4] == 0xce
	&& packet->payload[5] == 0xfa && packet->payload[6] == 0x0b
	&& packet->payload[7] == 0xb0 && packet->payload[12] == 0x4d
	&& packet->payload[13] == 0x4d && packet->payload[14] == 0x53 && packet->payload[15] == 0x20) {
      NDPI_LOG(NDPI_CONTENT_MMS, ndpi_struct, NDPI_LOG_DEBUG, "MMS: MSMMS Request found \n");
      flow->l4.tcp.mms_stage = 1 + packet->packet_direction;
      return;
    }

    if (flow->l4.tcp.mms_stage == 2 - packet->packet_direction
	&& packet->payload[4] == 0xce && packet->payload[5] == 0xfa
	&& packet->payload[6] == 0x0b && packet->payload[7] == 0xb0
	&& packet->payload[12] == 0x4d && packet->payload[13] == 0x4d
	&& packet->payload[14] == 0x53 && packet->payload[15] == 0x20) {
      NDPI_LOG(NDPI_CONTENT_MMS, ndpi_struct, NDPI_LOG_DEBUG, "MMS: MSMMS Response found \n");
      ndpi_int_mms_add_connection(ndpi_struct, flow);
      return;
    }
  }
#ifdef NDPI_PROTOCOL_HTTP
  if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_HTTP) != 0) {
#endif							/* NDPI_PROTOCOL_HTTP */
    NDPI_LOG(NDPI_CONTENT_MMS, ndpi_struct, NDPI_LOG_DEBUG, "MMS: exclude\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_CONTENT_MMS);

#ifdef NDPI_PROTOCOL_HTTP
  } else {
    NDPI_LOG(NDPI_CONTENT_MMS, ndpi_struct, NDPI_LOG_DEBUG, "MMS avoid early exclude from http\n");
  }
#endif							/* NDPI_PROTOCOL_HTTP */

}


void init_mms_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("MMS", ndpi_struct, detection_bitmask, *id,
				      NDPI_CONTENT_MMS,
				      ndpi_search_mms_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
