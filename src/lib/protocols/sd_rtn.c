/*
 * sd_rtn.c
 *
 * Copyright (C) 2011-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SD_RTN

#include "ndpi_api.h"

static void ndpi_int_sd_rtn_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                           struct ndpi_flow_struct * const flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Software Defined Real-time Network (SD-RTN)\n");
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_SD_RTN,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static int ndpi_int_sd_rtn_dissect_sni(struct ndpi_flow_struct * const flow,
                                       u_int8_t const * const payload,
                                       u_int32_t payload_len)
{
  u_int32_t sni_len = ntohs(get_u_int16_t(payload, 16));

  if (sni_len + 19 > payload_len)
  {
    return -1;
  }

  if (payload[18] != 0x00)
  {
    return -1;
  }

  ndpi_hostname_sni_set(flow, &payload[19], sni_len);

  return 0;
}

static void ndpi_search_sd_rtn(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Software Defined Real-time Network (SD-RTN)\n");

  if (packet->udp != NULL)
  {
    if (packet->payload_packet_len >= 20
        && packet->payload[6] == 0x21
        && ntohl(get_u_int32_t(packet->payload, 12)) == 0x04534e49 /* "\x04SNI" */)
    {
      int ret = ndpi_int_sd_rtn_dissect_sni(flow, packet->payload,
                                                  packet->payload_packet_len);

      if (ret == 0)
      {
        ndpi_int_sd_rtn_add_connection(ndpi_struct, flow);
        return;
      }
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_sd_rtn_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                           u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("SD-RTN", ndpi_struct, *id,
				      NDPI_PROTOCOL_SD_RTN,
				      ndpi_search_sd_rtn,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

