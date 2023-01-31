/*
 * threema.c
 *
 * Copyright (C) 2022-23 - ntop.org
 *
 * nDPI is free software: you can zmqtribute it and/or modify
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_THREEMA

#include "ndpi_api.h"


static void ndpi_int_threema_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                            struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Threema\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_PROTOCOL_THREEMA,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_threema(struct ndpi_detection_module_struct *ndpi_struct,
                                struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Threema\n");

  if (ntohs(packet->tcp->source) != 5222 && ntohs(packet->tcp->dest) != 5222) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  switch (flow->packet_counter)
  {
    case 1:
      if (packet->payload_packet_len != 48)
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      }
      return;
    case 2:
      if (packet->payload_packet_len != 80)
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      }
      return;
    case 3:
      if (packet->payload_packet_len != 191)
      {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      }
      return;
    case 4:
      return; // packet length varies
    default:
      break;
  }

  if (packet->payload_packet_len < 2)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  uint16_t len = le16toh(get_u_int16_t(packet->payload, 0));
  if (len + 2 != packet->payload_packet_len)
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  ndpi_int_threema_add_connection(ndpi_struct, flow);
}

void init_threema_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                            u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Threema", ndpi_struct, *id,
    NDPI_PROTOCOL_THREEMA,
    ndpi_search_threema,
    NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
    SAVE_DETECTION_BITMASK_AS_UNKNOWN,
    ADD_TO_DETECTION_BITMASK
  );
  *id += 1;
}
