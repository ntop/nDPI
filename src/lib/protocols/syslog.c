/*
 * syslog.c
 *
 * Copyright (C) 2009-11 - ipoque GmbH
 * Copyright (C) 2011-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SYSLOG

#include "ndpi_api.h"

static void ndpi_int_syslog_add_connection(struct ndpi_detection_module_struct
					   *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SYSLOG, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

void ndpi_search_syslog(struct ndpi_detection_module_struct
			*ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int8_t i;

  NDPI_LOG_DBG(ndpi_struct, "search syslog\n");

  if (packet->payload_packet_len > 20 && packet->payload[0] == '<') {
    int j;

    NDPI_LOG_DBG2(ndpi_struct, "checked len>20 and <1024 and first symbol=<\n");

    for (i = 1; i <= 3; i++) {
      if (packet->payload[i] < '0' || packet->payload[i] > '9') {
		break;
      }
    }
    NDPI_LOG_DBG2(ndpi_struct,
             "read symbols while the symbol is a number.\n");

    if (packet->payload[i++] != '>') {
      NDPI_LOG_DBG(ndpi_struct, "excluded, there is no > following the number\n");
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    } else {
      NDPI_LOG_DBG2(ndpi_struct, "a > following the number\n");
    }

    if (packet->payload[i] == 0x20) {
      NDPI_LOG_DBG2(ndpi_struct, "a blank following the >: increment i\n");
      i++;
    } else {
      NDPI_LOG_DBG2(ndpi_struct, "no blank following the >: do nothing\n");
    }

    /* Even if there are 2 RFCs (3164, 5424), syslog format after "<NUMBER>" is
       not standard. The only common pattern seems to be that the entire
       payload is made by printable characters */
    /* TODO: check only the first N bytes to avoid touching the entire payload? */
    for (j = 0; j < packet->payload_packet_len - i; j++) {
      if (!(ndpi_isprint(packet->payload[i + j]) ||
            ndpi_isspace(packet->payload[i + j]))) {
        NDPI_LOG_DBG2(ndpi_struct, "no printable char 0x%x [i/j %d/%d]\n",
                      packet->payload[i + j], i, j);
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
      }
    }

    NDPI_LOG_INFO(ndpi_struct, "found syslog\n");
    ndpi_int_syslog_add_connection(ndpi_struct, flow);
    return;
  }
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_syslog_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Syslog", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_SYSLOG,
				      ndpi_search_syslog,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
