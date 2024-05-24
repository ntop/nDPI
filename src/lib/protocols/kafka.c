/*
 * kafka.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_APACHE_KAFKA

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_kafka_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                          struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Apache Kafka\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_APACHE_KAFKA,
                             NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_kafka(struct ndpi_detection_module_struct *ndpi_struct,
                              struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Apache Kafka\n");

  /* All Kafka stuff start with 4 bytes containing the payload length 
   * minus 4 bytes.
   * API keys: https://kafka.apache.org/protocol.html#protocol_api_keys
   * API versions: https://cwiki.apache.org/confluence/display/KAFKA/Kafka+APIs
   */
  if (packet->payload_packet_len < 8 /* min. required packet length */ ||
      ntohl(get_u_int32_t(packet->payload, 0)) != (uint32_t)(packet->payload_packet_len - 4))
  {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /* Request */
  if (ntohs(get_u_int16_t(packet->payload, 4)) < 75 && /* API key */
      ntohs(get_u_int16_t(packet->payload, 6)) < 16    /* API version */)
  {
    if (packet->payload_packet_len < 14)
    {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
    }

    const uint16_t client_id_len = ntohs(get_u_int16_t(packet->payload, 12));
    if (client_id_len + 12 + 2 > packet->payload_packet_len)
    {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
    }
    if (ndpi_is_printable_buffer(&packet->payload[14], client_id_len) == 0)
    {
        NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
        return;
    }

    ndpi_int_kafka_add_connection(ndpi_struct, flow);
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_kafka_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Kafka", ndpi_struct, *id,
				      NDPI_PROTOCOL_APACHE_KAFKA,
				      ndpi_search_kafka,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
