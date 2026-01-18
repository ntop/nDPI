/*
 * mikrotik.c
 *
 * Copyright (C) 2012-26 - ntop.org
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
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MIKROTIK

#include "ndpi_api.h"
#include "ndpi_private.h"

/* ********************************* */

static void ndpi_search_mikrotik(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search MIKROTIK\n");

  if((packet->iph && (packet->iph->daddr== 0xFFFFFFFF))
     || (packet->iphv6 && (ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[0]) == 0xFF020000 /* ff02:: */))
    ) {
    if(ntohs(packet->udp->dest) == 5678) {
      const u_int8_t *payload;
      u_int16_t offset;
    
      if (packet->payload_packet_len < 8) {
	NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
	return;
      } else {
	offset = 4;
	payload = packet->payload;
      }

      while((offset+4) < packet->payload_packet_len) {
	u_int16_t m_type = ((u_int16_t)payload[offset] << 8) + payload[offset+1];
	u_int16_t m_len  = ((u_int16_t)payload[offset+2] << 8) + payload[offset+3];

	// printf("%d\n", m_type);

	if((4+m_len+offset) < packet->payload_packet_len) {
	  switch(m_type) {
	  case 1 /* MAC Address */:
	    if(m_len == 6)
	      memcpy(flow->protos.mikrotik.mac_addr, &payload[offset+4], m_len);
	    break;
	  case 5 /* Identity */:
	    snprintf(flow->protos.mikrotik.identity, sizeof(flow->protos.mikrotik.identity), 
		     "%.*s", m_len, &payload[offset+4]);
	    break;
	  case 7 /* Version */:
	    snprintf(flow->protos.mikrotik.version, sizeof(flow->protos.mikrotik.version), 
		     "%.*s", m_len, &payload[offset+4]);
	    break;
	  case 10: /* Uptime */
	    if(m_len == 4)
	      flow->protos.mikrotik.uptime = ntohl(*((u_int32_t*)&payload[offset+4]));
	    break;
	  case 11: /* Software-ID */
	    snprintf(flow->protos.mikrotik.sw_id, sizeof(flow->protos.mikrotik.sw_id), 
		     "%.*s", m_len, &payload[offset+4]);
	    break;
	  case 12: /* Board */
	    snprintf(flow->protos.mikrotik.board, sizeof(flow->protos.mikrotik.board), 
		     "%.*s", m_len, &payload[offset+4]);
	    break;
	  case 15: /* IPv6 */
	    if(m_len == 16)
	      memcpy(&flow->protos.mikrotik.ipv6_addr, &payload[offset+4], m_len);
	    break;
	  case 16: /* Interface Name */
	    snprintf(flow->protos.mikrotik.iface_name, sizeof(flow->protos.mikrotik.iface_name), 
		     "%.*s", m_len, &payload[offset+4]);
	    break;
	  case 14: /* IPv4 */
	    if(m_len == 4)
	      flow->protos.mikrotik.ipv4_addr = ntohl(*((u_int32_t*)&payload[offset+4]));
	    break;
	  }
      
	  offset += 4 + m_len;
	} else
	  break;
      } /* while */
    
      ndpi_set_detected_protocol(ndpi_struct, flow,
				 NDPI_PROTOCOL_MIKROTIK,
				 NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    }
  } else
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

/* ********************************* */

void init_mikrotik_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_register_dissector("MIKROTIK", ndpi_struct,
                     ndpi_search_mikrotik,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                      1, NDPI_PROTOCOL_MIKROTIK);
}
