/*
 * mgcp.c
 *
 * Copyright (C) 2017-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MGCP

#include "ndpi_api.h"

static void ndpi_int_mgcp_add_connection(struct ndpi_detection_module_struct
					 *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG_INFO(ndpi_struct, "found MGCP\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MGCP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}


static void ndpi_search_mgcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  char const * endpoint;
  char const * endpoint_hostname;
  char const * mgcp;

  NDPI_LOG_DBG(ndpi_struct, "search MGCP\n");

  do {
    if (packet->payload_packet_len < 8) break;

    /* packet must end with 0x0d0a or with 0x0a */
    if (packet->payload[packet->payload_packet_len - 1] != 0x0a) break;

    if (packet->payload[0] != 'A' && packet->payload[0] != 'C' && packet->payload[0] != 'D' &&
        packet->payload[0] != 'E' && packet->payload[0] != 'M' && packet->payload[0] != 'N' &&
        packet->payload[0] != 'R')
  	  break;

    if (memcmp(packet->payload, "AUEP ", 5) != 0 && memcmp(packet->payload, "AUCX ", 5) != 0 &&
        memcmp(packet->payload, "CRCX ", 5) != 0 && memcmp(packet->payload, "DLCX ", 5) != 0 &&
        memcmp(packet->payload, "EPCF ", 5) != 0 && memcmp(packet->payload, "MDCX ", 5) != 0 &&
        memcmp(packet->payload, "NTFY ", 5) != 0 && memcmp(packet->payload, "RQNT ", 5) != 0 &&
        memcmp(packet->payload, "RSIP ", 5) != 0)
  	  break;

    endpoint = ndpi_strnstr((char const *)packet->payload + 5, " ", packet->payload_packet_len - 5);
    if (endpoint == NULL)
    {
      break;
    }
    endpoint++;

    mgcp = ndpi_strnstr(endpoint, " ", packet->payload_packet_len - ((u_int8_t const *)endpoint - packet->payload));
    if (mgcp == NULL)
    {
      break;
    }
    mgcp++;

    if (strncmp(mgcp, "MGCP ", ndpi_min(5, packet->payload_packet_len - ((u_int8_t const *)mgcp - packet->payload))) == 0)
    {
      ndpi_int_mgcp_add_connection(ndpi_struct, flow);

      endpoint_hostname = ndpi_strnstr(endpoint, "@", packet->payload_packet_len - ((u_int8_t const *)endpoint - packet->payload));
      if (endpoint_hostname == NULL || endpoint_hostname >= mgcp)
      {
        ndpi_hostname_sni_set(flow, (u_int8_t const *)endpoint, (mgcp - endpoint) - 1);
      } else {
        endpoint_hostname++;
        ndpi_hostname_sni_set(flow, (u_int8_t const *)endpoint_hostname, (mgcp - endpoint_hostname) - 1);
      }
      return;
    }
  } while(0);

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_mgcp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("MGCP", ndpi_struct, *id,
				      NDPI_PROTOCOL_MGCP,
				      ndpi_search_mgcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);  

  *id += 1;
}

