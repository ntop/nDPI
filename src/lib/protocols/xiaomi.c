/*
 * xiaomi.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_XIAOMI

#include "ndpi_api.h"


static void xiaomi_dissect_metadata(struct ndpi_detection_module_struct *ndpi_struct,
                                    struct ndpi_flow_struct * const flow,
                                    u_int8_t const * const payload,
                                    u_int32_t payload_len)
{
  size_t offset = 16;

  while(offset + 1 < payload_len) {
    char *ptr;
    u_int8_t op = payload[offset];
    u_int8_t len = payload[offset + 1];

    offset += 2;

    /* "Strage" types which don't respect the TLV format */
    if(op == 0x28 || op == 0x08) {
      continue;
    }

    if(offset + len >= payload_len) {
      break;
    }

    NDPI_LOG_DBG(ndpi_struct, "TLV: 0x%x len %d [%.*s]\n",
                 op, len, len, &payload[offset]);

    switch(op) {
      case 0x12:
        if (ndpi_user_agent_set(flow, &payload[offset], len) == NULL)
        {
            NDPI_LOG_DBG2(ndpi_struct, "Could not set Xiaomi user agent\n");
        }
        break;

      case 0x3a:
        /* If "domain:port", strip the port */
        ptr = ndpi_strnstr((const char *)&payload[offset], ":", len);
        if(ptr == NULL)
          ndpi_hostname_sni_set(flow, &payload[offset], len);
        else
          ndpi_hostname_sni_set(flow, &payload[offset], (const u_int8_t *)ptr - &payload[offset]);
        break;

      case 0x32: /* Radio access technology (+ APN) */
      case 0x1A: /* Build version */
      case 0x42: /* Locale */
      default:
        break;
    }
    offset += len;
  }
}

static void ndpi_search_xiaomi(struct ndpi_detection_module_struct *ndpi_struct,
			       struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Xiaomi\n");

  if(packet->payload_packet_len >= 12) {
    uint32_t len;

    len = ntohl(get_u_int32_t(packet->payload, 4));
    if(len + 12 == packet->payload_packet_len &&
       ntohl(get_u_int32_t(packet->payload, 0)) == 0xC2FE0005 &&
       ntohl(get_u_int32_t(packet->payload, 8)) == 0x00020016) {
      NDPI_LOG_INFO(ndpi_struct, "found Xiaomi\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_XIAOMI, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);

      /* Better way to detect "client" packets? */
      if(ntohs(packet->tcp->dest) == 5222) {
        /* It seems that the "TLV list" is different for client and for server messages.
           For example, the type 0x12 is used as user-agent by the client and
           as something else by the server. We are interested in the metadata sent by the client */
        xiaomi_dissect_metadata(ndpi_struct, flow, packet->payload, packet->payload_packet_len);
      }

      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_xiaomi_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			   u_int32_t *id) {
  ndpi_set_bitmask_protocol_detection("Xiaomi", ndpi_struct, *id,
				      NDPI_PROTOCOL_XIAOMI,
				      ndpi_search_xiaomi,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
