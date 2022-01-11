/*
 * capwap.c
 *
 * Copyright (C) 2019 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_CAPWAP

#include "ndpi_api.h"

#define NDPI_CAPWAP_CONTROL_PORT 5246
#define NDPI_CAPWAP_DATA_PORT    5247


static void ndpi_int_capwap_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					   struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CAPWAP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static int is_capwap_multicast(const struct ndpi_packet_struct *packet)
{
  /* RFC 5115 Sec 3.3
     "The WTP MUST send the Discovery Request
      message to either the limited broadcast IP address (255.255.255.255),
      the well-known CAPWAP multicast address (224.0.1.140), or to the
      unicast IP address of the AC.  For IPv6 networks, since broadcast
      does not exist, the use of "All ACs multicast address" (FF0X:0:0:0:0:
      0:0:18C) is used instead.
  */
  if(packet->iph) {
    if((packet->iph->daddr == 0xFFFFFFFF) ||
       (ntohl(packet->iph->daddr) == 0XE000018C))
      return 1;
  } else if(packet->iphv6) {
    if(((ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[0] & 0xFFF0FFFF) == 0xFF000000)) &&
       (packet->iphv6->ip6_dst.u6_addr.u6_addr32[1] == 0) &&
       (packet->iphv6->ip6_dst.u6_addr.u6_addr32[2] == 0) &&
       (ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[3] == 0x0000018C)))
      return 1;
  }
  return 0;
}

/* ************************************************** */

static void ndpi_search_setup_capwap(struct ndpi_detection_module_struct *ndpi_struct,
				     struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t sport, dport;
   
  sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);
  
  if((dport == NDPI_CAPWAP_CONTROL_PORT)
     && (is_capwap_multicast(packet))
     && (packet->payload_packet_len >= 16)
     && (packet->payload[0] == 0x0)
     && (packet->payload[8] == 6 /* Mac len */)
     )
    goto capwap_found;
  
  if(((sport == NDPI_CAPWAP_CONTROL_PORT) || (dport == NDPI_CAPWAP_CONTROL_PORT))
     && ((packet->payload[0] == 0x0) || (packet->payload[0] == 0x1))
     ) {
    u_int16_t msg_len, offset, to_add;

    if(packet->payload[0] == 0x0)
      offset = 13, to_add = 13;
    else
      offset = 15, to_add = 17;

    if (packet->payload_packet_len >= offset + sizeof(u_int16_t)) {
      msg_len = ntohs(*(u_int16_t*)&packet->payload[offset]);

      if((msg_len+to_add) == packet->payload_packet_len)
        goto capwap_found;
    }
  }
  
  if(
     (((dport == NDPI_CAPWAP_DATA_PORT) && (!is_capwap_multicast(packet))) || (sport == NDPI_CAPWAP_DATA_PORT))
     && (packet->payload_packet_len >= 16)
     && (packet->payload[0] == 0x0)
     ) {
    u_int8_t is_80211_data = (packet->payload[9] & 0x0C) >> 2;

      
    if((sport == NDPI_CAPWAP_DATA_PORT) && (is_80211_data == 2 /* IEEE 802.11 Data */))
      goto capwap_found;
    else if(dport == NDPI_CAPWAP_DATA_PORT) {
      u_int16_t msg_len = ntohs(*(u_int16_t*)&packet->payload[13]);
      
      if((packet->payload[8] == 1 /* Mac len */)
	 || (packet->payload[8] == 6 /* Mac len */)
	 || (packet->payload[8] == 4 /* Wireless len */)
	 || ((msg_len+15) == packet->payload_packet_len))
	goto capwap_found;	 
    }
  }
  
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  return;

 capwap_found:
  ndpi_int_capwap_add_connection(ndpi_struct, flow);
}

void ndpi_search_capwap(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  if(packet->udp && (flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN))
    ndpi_search_setup_capwap(ndpi_struct, flow);
}


void init_capwap_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			   u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("CAPWAP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_CAPWAP,
				      ndpi_search_capwap,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
