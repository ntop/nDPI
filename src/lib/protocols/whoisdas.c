/*
 * whoisdas.c
 *
 * Copyright (C) 2016-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_WHOIS_DAS

#include "ndpi_api.h"


void ndpi_search_whois_das(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search WHOIS/DAS\n");
  if(packet->tcp != NULL) {
    u_int16_t sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
    
    if(((sport == 43) || (dport == 43)) || ((sport == 4343) || (dport == 4343))) {

      if(packet->payload_packet_len > 0) {
	
	u_int max_len = sizeof(flow->host_server_name) - 1;
	u_int i, j;

	for(i=strlen((const char *)flow->host_server_name), j=0; (i<max_len) && (j<packet->payload_packet_len); i++, j++) {
	  if((packet->payload[j] == '\n') || (packet->payload[j] == '\r')) break;	  
	  flow->host_server_name[i] = packet->payload[j];
	}
	
	flow->host_server_name[i] = '\0';
	
	flow->server_id = ((sport == 43) || (sport == 4343)) ? flow->src : flow->dst;
	
	NDPI_LOG_INFO(ndpi_struct, "[WHOIS/DAS] %s\n", flow->host_server_name);
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WHOIS_DAS, NDPI_PROTOCOL_UNKNOWN);
	return;
      }
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_whois_das_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Whois-DAS", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_WHOIS_DAS,
				      ndpi_search_whois_das,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK); 

  *id += 1;
}
