/*
 * Copyright (C) 2020 - ntop.org
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
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_NATS
#include "ndpi_api.h"

static const char* commands[] =
  {
   "INFO {",
   "CONNECT {",
   "PUB ",
   "SUB",
   "UNSUB ",
   "MSG ",
   "PING",
   "PONG",
   "+OK",
   "-ERR",
   NULL
  };

void ndpi_search_nats_tcp(struct ndpi_detection_module_struct *ndpi_struct,
                            struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  /* Check connection over TCP */
  NDPI_LOG_DBG(ndpi_struct, "search NATS\n");

  if(packet->tcp && (packet->payload_packet_len > 4)) {
    int i;

    for(i=0; commands[i] != NULL; i++) {
      char *match = ndpi_strnstr((const char *)packet->payload,
				 commands[i],
				 ndpi_min(strlen(commands[i]), packet->payload_packet_len));

      if(!match) continue;

      /* These commands are used by POP3 too. To avoid false positives, look for the other ones */
      if((strcmp(commands[i], "+OK") == 0) || (strcmp(commands[i], "-ERR") == 0)) {
        return;
      }

      if(ndpi_strnstr((const char *)match, "\r\n",
		      packet->payload_packet_len - ((size_t)match - (size_t)packet->payload)) != NULL) {
	NDPI_LOG_INFO(ndpi_struct, "found NATS\n");

	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_NATS, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
	return;
      }
    }

    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
}



void init_nats_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			 u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("Nats", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_NATS,
				      ndpi_search_nats_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
