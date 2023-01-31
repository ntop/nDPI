/*
 * tailscale.c
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TAILSCALE

#include "ndpi_api.h"

/* https://github.com/tailscale/tailscale/blob/main/disco/disco.go
 * https://tailscale.com/kb/1082/firewall-ports/
 */

static void ndpi_search_tailscale(struct ndpi_detection_module_struct *ndpi_struct,
				  struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  unsigned char magic[6] = { 0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac };
  unsigned short port = 41641;

  NDPI_LOG_DBG(ndpi_struct, "search Tailscale\n");

  if(packet->payload_packet_len > sizeof(magic) &&
     (ntohs(flow->c_port) == port || ntohs(flow->s_port) == port) &&
     memcmp(packet->payload, magic, sizeof(magic)) == 0) {
    NDPI_LOG_INFO(ndpi_struct, "found Tailscale\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TAILSCALE, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_tailscale_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			      u_int32_t *id) {
  ndpi_set_bitmask_protocol_detection("Tailscale", ndpi_struct, *id,
				      NDPI_PROTOCOL_TAILSCALE,
				      ndpi_search_tailscale,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
