/*
 * non_tcp_udp.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-15 - ntop.org
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

#if defined(NDPI_PROTOCOL_IP_IPSEC) || defined(NDPI_PROTOCOL_IP_GRE) || defined(NDPI_PROTOCOL_IP_ICMP)  || defined(NDPI_PROTOCOL_IP_IGMP) || defined(NDPI_PROTOCOL_IP_EGP) || defined(NDPI_PROTOCOL_IP_SCTP) || defined(NDPI_PROTOCOL_IP_OSPF) || defined(NDPI_PROTOCOL_IP_IP_IN_IP)

#define set_protocol_and_bmask(nprot)					\
  {									\
    if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask,nprot) != 0) \
      {									\
	ndpi_int_add_connection(ndpi_struct, flow,			\
				nprot,					\
				NDPI_REAL_PROTOCOL);			\
      }									\
  }


void ndpi_search_in_non_tcp_udp(struct ndpi_detection_module_struct
				*ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  if (packet->iph == NULL) {
#ifdef NDPI_DETECTION_SUPPORT_IPV6
    if (packet->iphv6 == NULL)
#endif
      return;
  }

  switch (packet->l4_protocol) {
#ifdef NDPI_PROTOCOL_IP_IPSEC
  case NDPI_IPSEC_PROTOCOL_ESP:
  case NDPI_IPSEC_PROTOCOL_AH:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_IPSEC);
    break;
#endif							/* NDPI_PROTOCOL_IP_IPSEC */
#ifdef NDPI_PROTOCOL_IP_GRE
  case NDPI_GRE_PROTOCOL_TYPE:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_GRE);
    break;
#endif							/* NDPI_PROTOCOL_IP_GRE */
#ifdef NDPI_PROTOCOL_IP_ICMP
  case NDPI_ICMP_PROTOCOL_TYPE:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_ICMP);
    break;
#endif							/* NDPI_PROTOCOL_IP_ICMP */
#ifdef NDPI_PROTOCOL_IP_IGMP
  case NDPI_IGMP_PROTOCOL_TYPE:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_IGMP);
    break;
#endif							/* NDPI_PROTOCOL_IP_IGMP */
#ifdef NDPI_PROTOCOL_IP_EGP
  case NDPI_EGP_PROTOCOL_TYPE:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_EGP);
    break;
#endif							/* NDPI_PROTOCOL_IP_EGP */
#ifdef NDPI_PROTOCOL_IP_SCTP
  case NDPI_SCTP_PROTOCOL_TYPE:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_SCTP);
    break;
#endif							/* NDPI_PROTOCOL_IP_SCTP */
#ifdef NDPI_PROTOCOL_IP_OSPF
  case NDPI_OSPF_PROTOCOL_TYPE:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_OSPF);
    break;
#endif							/* NDPI_PROTOCOL_IP_OSPF */
#ifdef NDPI_PROTOCOL_IP_IP_IN_IP
  case NDPI_IPIP_PROTOCOL_TYPE:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_IP_IN_IP);
    break;
#endif							/* NDPI_PROTOCOL_IP_IP_IN_IP */
#ifdef NDPI_PROTOCOL_IP_ICMPV6
  case NDPI_ICMPV6_PROTOCOL_TYPE:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_ICMPV6);
    break;
#endif							/* NDPI_PROTOCOL_IP_ICMPV6 */
#ifdef NDPI_PROTOCOL_IP_VRRP
  case 112:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_VRRP);
    break;
#endif							/* NDPI_PROTOCOL_IP_VRRP */
  }
}

#endif
