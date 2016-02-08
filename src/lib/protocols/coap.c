/*
 * coap.c
 *
 * Copyright (C) 2016 Sorin Zamfir <sorin.zamfir@yahoo.com>
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


#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_COAP
static void
ndpi_int_coap_add_connection (struct ndpi_detection_module_struct *ndpi_struct,
			      struct ndpi_flow_struct *flow)
{
  // not sure if this is accurate but coap runs on top of udp and should be connectionless
  if (flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
    {
      /* This is COAP and it is not a sub protocol (e.g. lwm2m) */
      ndpi_search_tcp_or_udp (ndpi_struct, flow);
//
//	    /* If no custom protocol has been detected */
      if (flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
	{
//	      if(protocol != NDPI_PROTOCOL_HTTP) {
//		ndpi_search_tcp_or_udp(ndpi_struct, flow);
//		ndpi_set_detected_protocol(ndpi_struct, flow, protocol, NDPI_PROTOCOL_UNKNOWN);
//	      } else {
//		ndpi_int_reset_protocol(flow);
//		ndpi_set_detected_protocol(ndpi_struct, flow, protocol, NDPI_PROTOCOL_UNKNOWN);
//	      }
//	    }
//
//	    flow->http_detected = 1;
	}
    }
}

//static u_int16_t coap_request_url_offset(struct ndpi_detection_module_struct * ndpi_struct,
//					 struct ndpi_flow_struct *flow)
//{
//  struct ndpi_packet_struct* packet = &flow->packet;
//  if (packet->payload_packet_len >=4 )
//}

void ndpi_search_coap (struct ndpi_detection_module_struct *ndpi_struct,
		       struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
  {
      return;
  }
  NDPI_LOG(NDPI_PROTOCOL_COAP, ndpi_struct, NDPI_LOG_DEBUG, "CoAP detection...\n");

  if (flow->l4.udp.coap_stage == 0) {
  // we must set something here
      NDPI_LOG(NDPI_PROTOCOL_COAP, ndpi_struct, NDPI_LOG_DEBUG, "====>>>> COAP: %c%c%c%c [len: %u]\n",
      	   packet->payload[0], packet->payload[1], packet->payload[2], packet->payload[3],
      	   packet->payload_packet_len);

  } else if (flow->l4.udp.coap_stage == 1 + packet->packet_direction )
    {

    }
  //	packet->
}

void init_coap_dissector (struct ndpi_detection_module_struct *ndpi_struct,
		     u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection ("COAP", ndpi_struct, detection_bitmask, *id,
				       NDPI_PROTOCOL_COAP,
				       ndpi_search_coap,
				       NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				       SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);
  *id +=1;
}


#endif // NDPI_PROTOCOL_COAP
