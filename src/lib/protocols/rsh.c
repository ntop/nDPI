/*
 * rsh.c
 *
 * Copyright (C) 2022-23 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_RSH

#include "ndpi_api.h"
#include "ndpi_private.h"

#define RSH_DEFAULT_PORT 514

static void ndpi_int_rsh_add_connection(struct ndpi_detection_module_struct * ndpi_struct,
                                        struct ndpi_flow_struct * flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_RSH,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_rsh(struct ndpi_detection_module_struct * ndpi_struct,
                            struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  /* Use a port based approach for midstream detection. */
  if (packet->tcp->dest == RSH_DEFAULT_PORT ||
      packet->tcp->source == RSH_DEFAULT_PORT)
  {
    if (packet->payload[packet->payload_packet_len - 1] == '\n')
    {
      if (flow->packet_counter > 5)
      {
        ndpi_int_rsh_add_connection(ndpi_struct, flow);
        flow->protos.rsh.client_username[0] = '\0';
        flow->protos.rsh.server_username[0] = '\0';
        flow->protos.rsh.command[0] = '\0';
      }
      return;
    }
  }

  switch (flow->packet_counter)
  {
    case 1:
      if (packet->payload_packet_len >= 2 &&
          packet->payload_packet_len <= 6)
      {
        int i;

        for (i = 0; i < packet->payload_packet_len - 1; ++i)
        {
          if (ndpi_isdigit(packet->payload[i]) == 0)
          {
            NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
            return;
          }
        }
      } else {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      }
      return;

    case 2:
      if (packet->payload_packet_len < 3 ||
          packet->payload[packet->payload_packet_len - 1] != '\0')
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
      }

      {
	char str[64];
        char const * dissected_info[] = { (char const *)packet->payload,
                                          NULL, NULL };
        size_t i;

        for (i = 1; i < NDPI_ARRAY_LENGTH(dissected_info); ++i) {
          dissected_info[i] = memchr(dissected_info[i - 1], '\0',
                                     packet->payload_packet_len -
                                     (dissected_info[i - 1] - dissected_info[0]));

          if (dissected_info[i] == NULL ||
              ndpi_is_printable_buffer((uint8_t const *)dissected_info[i - 1],
                                       (dissected_info[i] - dissected_info[i - 1])) == 0)
          {
            NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
            return;
          }

          if (dissected_info[i] - dissected_info[0] >= packet->payload_packet_len - 1)
          {
            if (dissected_info[NDPI_ARRAY_LENGTH(dissected_info) - 1] == NULL)
            {
              NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
              return;
            }
            break;
          }

          dissected_info[i]++;
        }

        ndpi_int_rsh_add_connection(ndpi_struct, flow);

        strncpy(flow->protos.rsh.client_username, dissected_info[0],
                ndpi_min(NDPI_ARRAY_LENGTH(flow->protos.rsh.client_username),
                         (unsigned long)(dissected_info[1] - dissected_info[0])));
        strncpy(flow->protos.rsh.server_username, dissected_info[1],
                ndpi_min(NDPI_ARRAY_LENGTH(flow->protos.rsh.server_username),
                         (unsigned long)(dissected_info[2] - dissected_info[1])));
        strncpy(flow->protos.rsh.command, dissected_info[2],
                ndpi_min(NDPI_ARRAY_LENGTH(flow->protos.rsh.command),
                         (unsigned long)packet->payload_packet_len -
                         (unsigned long)(dissected_info[2] - dissected_info[0])));

	
        if (snprintf(str, NDPI_ARRAY_LENGTH(str), "User '%s' executing '%s'",
                     flow->protos.rsh.server_username,
                     flow->protos.rsh.command) < 0)
          str[0] = '\0';
        
        ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, str);
      }
      return;

    default:
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
  }
}


void init_rsh_dissector(struct ndpi_detection_module_struct * ndpi_struct,
                        u_int32_t * id)
{
  ndpi_set_bitmask_protocol_detection("RSH", ndpi_struct, *id,
                                      NDPI_PROTOCOL_RSH, ndpi_search_rsh,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
