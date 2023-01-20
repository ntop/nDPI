/*
 * soap.c
 *
 * Copyright (C) 2020 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SOAP

#include "ndpi_api.h"

static void ndpi_int_soap_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                         struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found Soap\n");
  ndpi_set_detected_protocol_keeping_master(ndpi_struct, flow, NDPI_PROTOCOL_SOAP,
					    NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_soap(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search soap\n");

  if (packet->parsed_lines == 0)
  {
    ndpi_parse_packet_line_info(ndpi_struct, flow);
  }

  if (packet->parsed_lines > 0)
  {
    size_t i;

    for (i = 0; i < packet->parsed_lines && packet->line[i].len > 0; ++i)
    {
      if (LINE_STARTS(packet->line[i], "SOAPAction") != 0)
      {
        ndpi_int_soap_add_connection(ndpi_struct, flow);
        return;
      }
    }
  }

  if (flow->packet_counter > 3)
  {
    if (flow->l4.tcp.soap_stage == 1)
    {
      ndpi_int_soap_add_connection(ndpi_struct, flow);
    }
    else {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    }
  }

  if (flow->l4.tcp.soap_stage == 0 &&
      packet->payload_packet_len >= 19)
  {
    if (strncmp((char*)packet->payload, "<?xml version=\"1.0\"", 19) == 0)
    {
      flow->l4.tcp.soap_stage = 1;
    }
  }
}

void init_soap_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection(
    "SOAP", ndpi_struct, *id,
    NDPI_PROTOCOL_SOAP, ndpi_search_soap, NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
    SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);
  *id += 1;
}

