/*
 * ubntac2.c
 *
 * Copyright (C) 2015 Thomas Fjellstrom
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UBNTAC2

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_ubntac2_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_UBNTAC2, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}


static void ndpi_search_ubntac2(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int8_t tlv_type;
  u_int16_t tlv_length, version_len;
  int off;

  NDPI_LOG_DBG(ndpi_struct, "search ubntac2\n");

  if(packet->payload_packet_len >= 4 &&
     (packet->udp->source == htons(10001) || packet->udp->dest == htons(10001)) &&
     packet->payload[0] == 0x02 &&
     packet->payload[1] == 0x06 &&
     (4 + ntohs(*(u_int16_t *)&packet->payload[2]) == packet->payload_packet_len)) {
    NDPI_LOG_INFO(ndpi_struct, "UBNT AirControl 2 request\n");
    ndpi_int_ubntac2_add_connection(ndpi_struct, flow);

    /* Parse TLV list: 1 byte type + 2 byte length + (optional) data */
    off = 4;
    while (off + 3 < packet->payload_packet_len) {
      tlv_type = packet->payload[off];
      tlv_length = ntohs(*(u_int16_t *)&packet->payload[off + 1]);

      NDPI_LOG_DBG2(ndpi_struct, "0x%x Len %d\n", tlv_type, tlv_length);

      if(tlv_type == 0x03 && off + 3 + tlv_length < packet->payload_packet_len) {
	version_len = ndpi_min(sizeof(flow->protos.ubntac2.version) - 1, tlv_length);
	memcpy(flow->protos.ubntac2.version, (const char *)&packet->payload[off + 3], version_len);
	flow->protos.ubntac2.version[version_len] = '\0';
      }

      off += 3 + tlv_length;
    }
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_ubntac2_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("UBNTAC2", ndpi_struct, *id,
				      NDPI_PROTOCOL_UBNTAC2,
				      ndpi_search_ubntac2,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
