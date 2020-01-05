/*
 * ppstream.c
 *
 * Copyright (C) 2016-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_PPSTREAM

#include "ndpi_api.h"

#define PPS_PORT 17788


static void ndpi_int_ppstream_add_connection(struct ndpi_detection_module_struct
					     *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_PPSTREAM, NDPI_PROTOCOL_UNKNOWN);
  NDPI_LOG_INFO(ndpi_struct, "found PPStream over UDP\n");
}


void ndpi_search_ppstream(struct ndpi_detection_module_struct
			  *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search PPStream\n");
  /**
     PPS over TCP is detected inside HTTP dissector 
  */
	
  /* check PPS over UDP */
  if(packet->udp != NULL) {
    /*** on port 17788 ***/
    if(packet->payload_packet_len > 12 && ((ntohs(packet->udp->source) == PPS_PORT) || (ntohs(packet->udp->dest) == PPS_PORT))) {
      if(((packet->payload_packet_len - 4 == get_l16(packet->payload, 0))
	  || (packet->payload_packet_len == get_l16(packet->payload, 0))
	  || (packet->payload_packet_len >= 6 && packet->payload_packet_len - 6 == get_l16(packet->payload, 0)))) {
	/* check 43 and */
	if(packet->payload[2] == 0x43) {
	  if(packet->payload[5] == 0xff &&
	     packet->payload[6] == 0x00 &&
	     packet->payload[7] == 0x01 &&
	     packet->payload[8] == 0x00 &&
	     packet->payload[9] == 0x00 &&
	     packet->payload[10] == 0x00 &&
	     packet->payload[11] == 0x00 &&
	     packet->payload[12] == 0x00 &&
	     packet->payload[13] == 0x00 &&
	     packet->payload[14] == 0x00) {

	    /* increase count pkt ppstream over udp */
	    flow->l4.udp.ppstream_stage++;
	    
	    ndpi_int_ppstream_add_connection(ndpi_struct, flow);
	    return;
	  }       
	  /* check 44 */
	  else if(packet->payload[2] == 0x44) {
	    /** b1 71 **/
	    if(packet->payload[3] == 0xb1 && packet->payload[4] == 0x71) {
	      if(packet->payload[13] == 0x00 &&
		 packet->payload[14] == 0x00 &&
		 packet->payload[15] == 0x01 &&
		 packet->payload[16] == 0x00) {
		/* 02 03 04 05 */
		if(packet->payload[17] == 0x02 ||
		   packet->payload[17] == 0x03 ||
		   packet->payload[17] == 0x04 ||
		   packet->payload[17] == 0x05) {
		  if(packet->payload[18] == 0x00 &&
		     packet->payload[19] == 0x00 &&
		     packet->payload[20] == 0x00) {

		    /* increase count pkt ppstream over udp */
		    flow->l4.udp.ppstream_stage++;

		    ndpi_int_ppstream_add_connection(ndpi_struct, flow);
		    return;
		  }
		}
		/* ff */
		else if(packet->payload[17] == 0xff) {
		  if(packet->payload[18] == 0xff &&
		     packet->payload[19] == 0xff &&
		     packet->payload[20] == 0xff) {

		    /* increase count pkt ppstream over udp */
		    flow->l4.udp.ppstream_stage++;
		  
		    ndpi_int_ppstream_add_connection(ndpi_struct, flow);
		    return;
		  }
		}
	      }
	    }
	    /** 73 17 **/
	    else if(packet->payload[3] == 0x73 && packet->payload[4] == 0x17) {
	      if(packet->payload[5] == 0x00 &&
		 packet->payload[6] == 0x00 &&
		 packet->payload[7] == 0x00 &&
		 packet->payload[8] == 0x00 &&
		 packet->payload[14] == 0x00 &&
		 packet->payload[15] == 0x00 &&
		 packet->payload[16] == 0x00 &&
		 packet->payload[17] == 0x00 &&
		 packet->payload[18] == 0x00 &&
		 packet->payload[19] == 0x00 &&
		 packet->payload[20] == 0x00) {

		/* increase count pkt ppstream over udp */
		flow->l4.udp.ppstream_stage++;

		ndpi_int_ppstream_add_connection(ndpi_struct, flow);
		return;
	      }
	    }
	    /** 74 71 **/
	    else if(packet->payload[3] == 0x74 && packet->payload[4] == 0x71 && packet->payload_packet_len == 113) {
	      /* check "PPStream" string in hex */
	      if(packet->payload[94] == 0x50 &&
		 packet->payload[95] == 0x50 &&
		 packet->payload[96] == 0x53 &&
		 packet->payload[97] == 0x74 &&
		 packet->payload[98] == 0x72 &&
		 packet->payload[99] == 0x65 &&
		 packet->payload[100] == 0x61 &&
		 packet->payload[101] == 0x6d) {

		/* increase count pkt ppstream over udp */
		flow->l4.udp.ppstream_stage++;
	      
		ndpi_int_ppstream_add_connection(ndpi_struct, flow);
		return;
	      }
	    }
	  }
	  /** check 55 (1) **/
	  else if(packet->payload[2] == 0x55 && (packet->payload[13] == 0x1b &&
						 packet->payload[14] == 0xa0 &&
						 packet->payload[15] == 0x00 &&
						 packet->payload[16] == 0x00 &&
						 packet->payload[17] == 0x00 &&
						 packet->payload[18] == 0x00 &&
						 packet->payload[19] == 0x00 &&
						 packet->payload[20] == 0x00 )) {

	    /* increase count pkt ppstream over udp */
	    flow->l4.udp.ppstream_stage++;

	    ndpi_int_ppstream_add_connection(ndpi_struct, flow);
	    return;
	  }
	  /** check 55 (2) **/
	  else if(packet->payload[2] == 0x55 && packet->payload[1] == 0x00 &&
		  (packet->payload[5] == 0x00 &&
		   packet->payload[6] == 0x00 &&
		   packet->payload[7] == 0x00 &&
		   packet->payload[8] == 0x00 &&
		   packet->payload[14] == 0x00 &&
		   packet->payload[15] == 0x00 &&
		   packet->payload[16] == 0x00 &&
		   packet->payload[17] == 0x00 &&
		   packet->payload[18] == 0x00 &&
		   packet->payload[19] == 0x00 &&
		   packet->payload[20] == 0x00 )) {

	    /* increase count pkt ppstream over udp */
	    flow->l4.udp.ppstream_stage++;
	  
	    ndpi_int_ppstream_add_connection(ndpi_struct, flow);
	    return;
	  }
	}
      }
      /* No port detection */
      if(packet->payload_packet_len > 17) {
	/* 80 */
	if(packet->payload[1] == 0x80 || packet->payload[1] == 0x84 ) {
	  if(packet->payload[3] == packet->payload[4]) {

	    /* increase count pkt ppstream over udp */
	    flow->l4.udp.ppstream_stage++;
	  
	    ndpi_int_ppstream_add_connection(ndpi_struct, flow);
	    return;
	  }
	}
	/* 53 */
	else if(packet->payload[1] == 0x53 && packet->payload[3] == 0x00 &&
		(packet->payload[0] == 0x08 || packet->payload[0] == 0x0c)) {

	  /* increase count pkt ppstream over udp */
	  flow->l4.udp.ppstream_stage++;
	
	  ndpi_int_ppstream_add_connection(ndpi_struct, flow);
	  return;
	}
      }
    }

    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
}


void init_ppstream_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("PPStream", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_PPSTREAM,
				      ndpi_search_ppstream,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  
  *id += 1;
}

