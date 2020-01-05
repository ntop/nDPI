/*
 * mysql.c
 * 
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MYSQL

#include "ndpi_api.h"

void ndpi_search_mysql_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search MySQL\n");
	
  if(packet->tcp) {
    if(packet->payload_packet_len > 38	//min length
       && get_u_int16_t(packet->payload, 0) == packet->payload_packet_len - 4	//first 3 bytes are length
       && get_u_int8_t(packet->payload, 2) == 0x00	//3rd byte of packet length
       && get_u_int8_t(packet->payload, 3) == 0x00	//packet sequence number is 0 for startup packet
       && get_u_int8_t(packet->payload, 5) > 0x30	//server version > 0
       && get_u_int8_t(packet->payload, 5) < 0x37	//server version < 7
       && get_u_int8_t(packet->payload, 6) == 0x2e	//dot
       ) {
#if 0
      /* Old code */
      u_int32_t a;
      
      for(a = 7; a + 31 < packet->payload_packet_len; a++) {
	if(packet->payload[a] == 0x00) {
	  if(get_u_int8_t(packet->payload, a + 13) == 0x00	 // filler byte
	     && get_u_int64_t(packet->payload, a + 19) == 0x0ULL // 13 more
	     && get_u_int32_t(packet->payload, a + 27) == 0x0	 // filler bytes
	     && get_u_int8_t(packet->payload, a + 31) == 0x0) {
	    NDPI_LOG_INFO(ndpi_struct, "found MySQL\n");
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MYSQL, NDPI_PROTOCOL_UNKNOWN);
	    return;
	  }
	  
	  break;
	}
      }
#else
      if(strncmp((const char*)&packet->payload[packet->payload_packet_len-22],
		 "mysql_", 6) == 0) {
	NDPI_LOG_INFO(ndpi_struct, "found MySQL\n");
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MYSQL,  NDPI_PROTOCOL_UNKNOWN);
	return;
      }
#endif
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_mysql_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("MySQL", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_MYSQL,
				      ndpi_search_mysql_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
