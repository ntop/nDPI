/*
 * tcp_or_udp.c
 *
 * Copyright (C) 2011-22 - ntop.org
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


#include "ndpi_api.h"
#include "ndpi_private.h"


u_int ndpi_search_tcp_or_udp_raw(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow,
				 u_int32_t saddr, u_int32_t daddr) /* host endianness */
{
  u_int16_t rc;
  struct in_addr host;

  if(flow)
    return(flow->guessed_protocol_id_by_ip);
  else {
    host.s_addr = htonl(saddr);
    if((rc = ndpi_network_ptree_match(ndpi_struct, &host)) != NDPI_PROTOCOL_UNKNOWN)
      return (rc);
    
    host.s_addr = htonl(daddr);
    return (ndpi_network_ptree_match(ndpi_struct, &host));
  }
}

void ndpi_search_tcp_or_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  u_int proto;
  struct ndpi_packet_struct *packet;

  if(!ndpi_struct || !flow || flow->host_server_name[0] != '\0')
    return;

  packet = &ndpi_struct->packet;
  
  if(packet->iph /* IPv4 Only: we need to support packet->iphv6 at some point */) {
    proto = ndpi_search_tcp_or_udp_raw(ndpi_struct,
				       flow,
				       ntohl(packet->iph->saddr), 
				       ntohl(packet->iph->daddr));

    if(proto != NDPI_PROTOCOL_UNKNOWN)
      ndpi_set_detected_protocol(ndpi_struct, flow, proto, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_MATCH_BY_PORT);
  }
}
