/*
 * tcp_or_udp.c
 *
 * Copyright (C) 2011-20 - ntop.org
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

/* ndpi_main.c */
extern u_int8_t  ndpi_is_tor_flow(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);

u_int ndpi_search_tcp_or_udp_raw(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow,
				 u_int8_t protocol,
				 u_int32_t saddr, u_int32_t daddr, /* host endianess */
				 u_int16_t sport, u_int16_t dport) /* host endianess */
{
  u_int16_t rc;
  struct in_addr host;

  if(protocol == IPPROTO_UDP) {
    if((sport == dport) && (sport == 17500)) {
      return(NDPI_PROTOCOL_DROPBOX);
    }
  }

  if(flow)
    return(flow->guessed_host_protocol_id);
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
  u_int16_t sport, dport;
  u_int proto;
  struct ndpi_packet_struct *packet = &flow->packet;

  if(flow->host_server_name[0] != '\0')
    return;

  if(ndpi_is_tor_flow(ndpi_struct, flow)) {
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TOR, NDPI_PROTOCOL_UNKNOWN);
    return;
  }

  if(packet->udp) sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);
  else if(packet->tcp) sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
  else sport = dport = 0;
  
  if(packet->iph /* IPv4 Only: we need to support packet->iphv6 at some point */) {
    proto = ndpi_search_tcp_or_udp_raw(ndpi_struct,
				       flow,
				       flow->packet.iph ? flow->packet.iph->protocol :
#ifdef NDPI_DETECTION_SUPPORT_IPV6
				       flow->packet.iphv6->ip6_hdr.ip6_un1_nxt,
#else
				       0,
#endif
				       ntohl(packet->iph->saddr), 
				       ntohl(packet->iph->daddr),
				       sport, dport);

    if(proto != NDPI_PROTOCOL_UNKNOWN)
      ndpi_set_detected_protocol(ndpi_struct, flow, proto, NDPI_PROTOCOL_UNKNOWN);
  }
}
