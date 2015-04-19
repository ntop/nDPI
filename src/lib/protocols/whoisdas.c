/*
 * ssh.c
 *
 * Copyright (C) 2013 - ntop.org
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
#ifdef NDPI_PROTOCOL_WHOIS_DAS

void ndpi_search_whois_das(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);

  if ((packet->tcp != NULL)
      && (
	  ((sport == 43) || (dport == 43))
	  ||
	  ((sport == 4343) || (dport == 4343))
	  )
      ) {
    if(packet->payload_packet_len > 0) {
      u_int max_len = sizeof(flow->host_server_name)-1;
      u_int i, j;

      for(i=strlen((const char *)flow->host_server_name), j=0; (i<max_len) && (j<packet->payload_packet_len); i++, j++) {
	if((packet->payload[j] == '\n') || (packet->payload[j] == '\r')) break;

	flow->host_server_name[i] = packet->payload[j];
      }

      flow->host_server_name[i] = '\0';      
      flow->server_id = ((sport == 43) || (sport == 4343)) ? flow->src : flow->dst;

      NDPI_LOG(NDPI_PROTOCOL_WHOIS_DAS, ndpi_struct, NDPI_LOG_DEBUG, "[WHOIS/DAS] %s\n", flow->host_server_name);
    }

    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_WHOIS_DAS, NDPI_REAL_PROTOCOL);
  } else {
    NDPI_LOG(NDPI_PROTOCOL_WHOIS_DAS, ndpi_struct, NDPI_LOG_TRACE, "WHOIS Excluded.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_WHOIS_DAS);
  }
}

#endif
