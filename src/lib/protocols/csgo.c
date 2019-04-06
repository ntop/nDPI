/*
 * csgo.c
 *
 * Copyright (C) 2016-2017 Vitaly Lavrov <vel21ripn@gmail.com>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_CSGO

#include "ndpi_api.h"

void ndpi_search_csgo(struct ndpi_detection_module_struct* ndpi_struct, struct ndpi_flow_struct* flow) {
  struct ndpi_packet_struct* packet = &flow->packet;

  if (packet->udp != NULL) {
    if (packet->payload_packet_len < sizeof(uint32_t)) {
      NDPI_LOG_DBG2(ndpi_struct, "Short csgo packet\n");
      return;
    }

    uint32_t w = htonl(get_u_int32_t(packet->payload, 0));
    NDPI_LOG_DBG2(ndpi_struct, "CSGO: word %08x\n", w);

    if (!flow->csgo_state && packet->payload_packet_len == 23 && w == 0xfffffffful) {
      if (!memcmp(packet->payload + 5, "connect0x", 9)) {
        flow->csgo_state++;
        memcpy(flow->csgo_strid, packet->payload + 5, 18);
        NDPI_LOG_DBG2(ndpi_struct, "Found csgo connect0x\n");
        return;
      }
    }
    if (flow->csgo_state == 1 && packet->payload_packet_len >= 42 && w == 0xfffffffful) {
      if (!memcmp(packet->payload + 24, flow->csgo_strid, 18)) {
        flow->csgo_state++;
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CSGO, NDPI_PROTOCOL_UNKNOWN);
        NDPI_LOG_INFO( ndpi_struct, "found csgo connect0x reply\n");
        return;
      }
    }
    if (packet->payload_packet_len == 8 && ( w == 0x3a180000 || w == 0x39180000) ) {
      NDPI_LOG_INFO( ndpi_struct, "found csgo udp 8b\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CSGO, NDPI_PROTOCOL_UNKNOWN);
      return;
    }
    if (packet->payload_packet_len >= 36 && w == 0x56533031ul) {
      NDPI_LOG_INFO( ndpi_struct, "found csgo udp\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CSGO, NDPI_PROTOCOL_UNKNOWN);
      return;
    }
    if (packet->payload_packet_len >= 36 && w == 0x01007364) {
      uint32_t w2 = htonl(get_u_int32_t(packet->payload, 4));
      if (w2 == 0x70696e67) {
        NDPI_LOG_INFO( ndpi_struct, "found csgo udp ping\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CSGO, NDPI_PROTOCOL_UNKNOWN);
        return;
      }
    }
    if (flow->csgo_s2 < 3 && (w & 0xffff0000ul) == 0x0d1d0000) {
      uint32_t w2 = get_u_int32_t(packet->payload, 2);
      if (packet->payload_packet_len == 13) {
        if (!flow->csgo_s2) {
          flow->csgo_id2 = w2;
          flow->csgo_s2 = 1;
          NDPI_LOG_DBG2( ndpi_struct, "Found csgo udp 0d1d step1\n");
          return;
        }
        if (flow->csgo_s2 == 1 && flow->csgo_id2 == w2) {
          NDPI_LOG_DBG2( ndpi_struct, "Found csgo udp 0d1d step1 DUP\n");
          return;
        }
        flow->csgo_s2 = 3;
        return;
      }
      if (packet->payload_packet_len == 15) {
        if (flow->csgo_s2 == 1 && flow->csgo_id2 == w2) {
          NDPI_LOG_INFO( ndpi_struct, "found csgo udp 0d1d\n");
          ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CSGO, NDPI_PROTOCOL_UNKNOWN);
          return;
        }
      }
      flow->csgo_s2 = 3;
    }
    if (packet->payload_packet_len >= 140 && (w == 0x02124c6c || w == 0x02125c6c) &&
        !memcmp(&packet->payload[3], "lta\000mob\000tpc\000bhj\000bxd\000tae\000urg\000gkh\000", 32)) {
          NDPI_LOG_INFO( ndpi_struct, "found csgo dictionary udp\n");
          ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CSGO, NDPI_PROTOCOL_UNKNOWN);
          return;
    }
    if (packet->payload_packet_len >= 33 && packet->iph && packet->iph->daddr == 0xffffffff &&
        !memcmp(&packet->payload[17], "LanSearch", 9)) {
          NDPI_LOG_INFO( ndpi_struct, "found csgo LanSearch udp\n");
          ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CSGO, NDPI_PROTOCOL_UNKNOWN);
          return;
    }
  }
  if (flow->packet_counter > 20)
	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_csgo_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
    ndpi_set_bitmask_protocol_detection("CSGO", ndpi_struct, detection_bitmask, *id,
              NDPI_PROTOCOL_CSGO,
              ndpi_search_csgo,
              NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
              SAVE_DETECTION_BITMASK_AS_UNKNOWN,
              ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
