/*
 * ntp.c
 *
 * Copyright (C) 2009-11 - ipoque GmbH
 * Copyright (C) 2011-26 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_NTP

#include "ndpi_api.h"
#include "ndpi_private.h"


static void ndpi_int_ntp_add_connection(struct ndpi_detection_module_struct
					*ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_NTP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_ntp_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  
  NDPI_LOG_DBG(ndpi_struct, "search NTP\n");

  if (packet->udp->dest == htons(123) || packet->udp->source == htons(123)) {
  
    NDPI_LOG_DBG2(ndpi_struct, "NTP port and length detected\n");
    uint8_t version = (packet->payload[0] & 56) >> 3;

    if (version <= 4) {
      flow->protos.ntp.version = version;
      flow->protos.ntp.mode = packet->payload[0] & 7;
      flow->protos.ntp.leap_indicator = (packet->payload[0] & 192) >> 6;

      if (packet->payload_packet_len >= 48) {
        u_int32_t tmp = 0;
        flow->protos.ntp.stratum = packet->payload[1];
        flow->protos.ntp.ppol = (int8_t)packet->payload[2];
        flow->protos.ntp.precision = (int8_t)packet->payload[3];

        // https://github.com/wireshark/wireshark/blob/c383ce5173cb15463259ca862cd5b469c2a3aab8/epan/dissectors/packet-ntp.c#L1574
        tmp = ntohl(get_u_int32_t(packet->payload, 4));
        flow->protos.ntp.root_delay = (tmp >> 16) + (tmp & 0xffff) / 65536.0;
        tmp = ntohl(get_u_int32_t(packet->payload, 8));
        flow->protos.ntp.root_dispersion = (tmp >> 16) + (tmp & 0xffff) / 65536.0;

        if (flow->protos.ntp.stratum == 0 || flow->protos.ntp.stratum == 1) {
          ndpi_snprintf(flow->protos.ntp.ref_id, sizeof(flow->protos.ntp.ref_id), "%c%c%c%c", packet->payload[12],
                                                              packet->payload[13],
                                                              packet->payload[14],
                                                              packet->payload[15]);
        } else {
          if(packet->iph) {
            tmp = get_u_int32_t(packet->payload, 12);
            inet_ntop(AF_INET, &tmp, flow->protos.ntp.ref_id, sizeof(flow->protos.ntp.ref_id));
          } else {
            ndpi_snprintf(flow->protos.ntp.ref_id, sizeof(flow->protos.ntp.ref_id), "%c%c%c%c", packet->payload[12],
                                                              packet->payload[13],
                                                              packet->payload[14],
                                                              packet->payload[15]);
          }
        }
        flow->protos.ntp.ref_time = get_u_int64_t(packet->payload, 16);
        flow->protos.ntp.org_time = get_u_int64_t(packet->payload, 24);
        flow->protos.ntp.rec_time = get_u_int64_t(packet->payload, 32);
        flow->protos.ntp.trans_time = get_u_int64_t(packet->payload, 40);
      }
    }

      NDPI_LOG_INFO(ndpi_struct, "found NTP\n");
      ndpi_int_ntp_add_connection(ndpi_struct, flow);
      return;
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}


void init_ntp_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("NTP", ndpi_struct,
                     ndpi_search_ntp_udp,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                     1, NDPI_PROTOCOL_NTP);
}

