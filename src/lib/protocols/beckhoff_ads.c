/*
 * beckhoff_ads.c
 *
 * Beckhoff Automation Device Specification
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_BECKHOFF_ADS

#include "ndpi_api.h"
#include "ndpi_private.h"

PACK_ON
struct ams_tcp_hdr {
  u_int16_t reserved;
  u_int32_t length;
} PACK_OFF;

struct ams_hdr {
#if defined(__LITTLE_ENDIAN__)
  u_int64_t target_netid : 48;
  u_int64_t target_port : 16;
  u_int64_t source_netid : 48;
  u_int64_t source_port : 16;
#elif defined(__BIG_ENDIAN__)
  u_int64_t target_port : 16;
  u_int64_t target_netid : 48;
  u_int64_t source_port : 16;
  u_int64_t source_netid : 48;
#else
#error "Missing endian macro definitions."
#endif
  u_int16_t command_id;
  u_int16_t state_flags;
  u_int32_t length;
  u_int32_t error_code;
  u_int32_t invoke_id;
};

static void ndpi_int_beckhoff_ads_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                                 struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Beckhoff ADS\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_BECKHOFF_ADS,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_beckhoff_ads(struct ndpi_detection_module_struct *ndpi_struct,
                                     struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Beckhoff ADS\n");

  if (packet->payload_packet_len >= 38) {
    struct ams_tcp_hdr const * const ams_tcp = (struct ams_tcp_hdr *)packet->payload;
    u_int16_t ams_message_length = packet->payload_packet_len - sizeof(struct ams_tcp_hdr);

    if ((ams_tcp->reserved != 0) ||
        (le32toh(ams_tcp->length) != ams_message_length))
    {
      goto not_beckhoff_ads;
    }

    struct ams_hdr const * const ams = (struct ams_hdr *)&packet->payload[6];
    u_int16_t ams_data_len = ams_message_length - sizeof(struct ams_hdr);

    if (le32toh(ams->length) == ams_data_len) {
      /* Just additional checks to avoid potential 
       * false positives */
      if ((le16toh(ams->state_flags) != 0x0004) && 
          (le16toh(ams->state_flags) != 0x0005))
      {
        goto not_beckhoff_ads;
      }
      
      if ((le16toh(ams->command_id) > 0x0009) || 
          (le32toh(ams->error_code) > 0x0000001E))
      {
        goto not_beckhoff_ads;
      }

      ndpi_int_beckhoff_ads_add_connection(ndpi_struct, flow);
      return;
    }
  }

not_beckhoff_ads:
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_beckhoff_ads_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("BeckhoffADS", ndpi_struct, *id,
              NDPI_PROTOCOL_BECKHOFF_ADS,
              ndpi_search_beckhoff_ads,
              NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
              SAVE_DETECTION_BITMASK_AS_UNKNOWN,
              ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
