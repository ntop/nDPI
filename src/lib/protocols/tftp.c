/*
 * tftp.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TFTP

#include "ndpi_api.h"

/* see: https://datatracker.ietf.org/doc/html/rfc1350 */

static void ndpi_int_tftp_add_connection(struct ndpi_detection_module_struct
					 *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TFTP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

void ndpi_search_tftp(struct ndpi_detection_module_struct
		      *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search TFTP\n");

  if (packet->payload_packet_len < 4 /* min. header size */ ||
      get_u_int8_t(packet->payload, 0) != 0x00)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /* parse TFTP opcode */
  switch (get_u_int8_t(packet->payload, 1))
  {
    case 0x01:
        /* Read request (RRQ) */
    case 0x02:
        /* Write request (WWQ) */

        if (packet->payload[packet->payload_packet_len - 1] != 0x00 /* last pdu element is a nul terminated string */)
        {
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
          return;
        }

        {
          char const * const possible_modes[] = { "netascii", "octet", "mail" };
          uint8_t mode_found = 0;
          for (uint8_t mode_idx = 0; mode_idx < sizeof(possible_modes) / sizeof(possible_modes[0]); ++mode_idx)
          {
            size_t const mode_len = strlen(possible_modes[mode_idx]);

            if (packet->payload_packet_len < mode_len + 1 /* mode is a nul terminated string */)
            {
              continue;
            }
            if (strncasecmp((char const *)&packet->payload[packet->payload_packet_len - 1 - mode_len],
                            possible_modes[mode_idx], mode_len) == 0)
            {
              mode_found = 1;
              break;
            }
          }

          if (mode_found == 0)
          {
            NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
            return;
          }

          /* We have seen enough and do not need any more TFTP packets. */
          NDPI_LOG_INFO(ndpi_struct, "found tftp (RRQ/WWQ)\n");
          ndpi_int_tftp_add_connection(ndpi_struct, flow);
        }
        return;

    case 0x03:
        /* Data (DATA) */
        if (packet->payload_packet_len > 4 /* DATA header size */ + 512 /* max. block size */)
        {
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
          return;
        }
        break;

    case 0x04:
        /* Acknowledgment (ACK) */
        if (packet->payload_packet_len != 4 /* ACK has a fixed packet size */)
        {
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
          return;
        }
        break;

    case 0x05:
        /* Error (ERROR) */

        if (packet->payload_packet_len < 5 ||
            packet->payload[packet->payload_packet_len - 1] != 0x00 ||
            packet->payload[2] != 0x00 || packet->payload[3] > 0x07)
        {
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
          return;
        }
        break;

    default:
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
  }

  if (flow->l4.udp.tftp_stage < 3)
  {
    NDPI_LOG_DBG2(ndpi_struct, "maybe tftp. need next packet\n");
    flow->l4.udp.tftp_stage++;
    return;
  }

  NDPI_LOG_INFO(ndpi_struct, "found tftp\n");
  ndpi_int_tftp_add_connection(ndpi_struct, flow);
}


void init_tftp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("TFTP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_TFTP,
				      ndpi_search_tftp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

