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
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_CAPWAP, NDPI_PROTOCOL_UNKNOWN);
}

/* ************************************************** */

static void ndpi_search_setup_capwap(struct ndpi_detection_module_struct *ndpi_struct,
				     struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t sport, dport;
   
  if(!packet->iph) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);
  
  if((dport == NDPI_CAPWAP_CONTROL_PORT)
     && (packet->iph->daddr == 0xFFFFFFFF)
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

    msg_len = ntohs(*(u_int16_t*)&packet->payload[offset]);

    if((msg_len+to_add) == packet->payload_packet_len)
      goto capwap_found;
  }
  
  if(
     (((dport == NDPI_CAPWAP_DATA_PORT) && (packet->iph->daddr != 0xFFFFFFFF)) || (sport == NDPI_CAPWAP_DATA_PORT))
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
  struct ndpi_packet_struct *packet = &flow->packet;

  if(packet->udp && (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN))
    ndpi_search_setup_capwap(ndpi_struct, flow);
}


void init_capwap_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			   u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("CAPWAP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_CAPWAP,
				      ndpi_search_capwap,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
