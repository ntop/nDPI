/*
 * twitter.c
 *
 * Copyright (C) 2014 - ntop.org
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

#ifdef NDPI_SERVICE_TWITTER

static void ndpi_int_twitter_add_connection(struct ndpi_detection_module_struct
                                             *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_SERVICE_TWITTER, NDPI_REAL_PROTOCOL);
}


void ndpi_search_twitter(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{

  /*
    Twitter AS34702

    http://bgp.he.net/AS13414
  */
  if(flow->packet.iph) {
    // IPv4
    u_int32_t src = ntohl(flow->packet.iph->saddr);
    u_int32_t dst = ntohl(flow->packet.iph->daddr);
    
    if(ndpi_ips_match(src, dst, 0xC0854C00, 22)     /* 192.133.76.0/22 */
       || ndpi_ips_match(src, dst, 0xC7109C00, 22)  /* 199.16.156.0/22 */
       || ndpi_ips_match(src, dst, 0xC73B9400, 22)  /* 199.59.148.0/22 */
       || ndpi_ips_match(src, dst, 0xC7603A00, 23)  /* 199.96.58.0/23  */
       || ndpi_ips_match(src, dst, 0xC7603E00, 23)  /* 199.96.62.0/23  */
       ) {
      ndpi_int_twitter_add_connection(ndpi_struct, flow);
      return;
    }

  }

  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_SERVICE_TWITTER);
}
#endif
