/*
 * non_tcp_udp.c
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

#include "ndpi_api.h"

#define set_protocol_and_bmask(nprot)					\
  {									\
    if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask,nprot) != 0) \
      {									\
	ndpi_set_detected_protocol(ndpi_struct, flow,			\
				   nprot, NDPI_PROTOCOL_UNKNOWN);		\
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
  case NDPI_IPSEC_PROTOCOL_ESP:
  case NDPI_IPSEC_PROTOCOL_AH:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_IPSEC);
    break;

  case NDPI_GRE_PROTOCOL_TYPE:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_GRE);
    break;

  case NDPI_ICMP_PROTOCOL_TYPE:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_ICMP);
    break;

  case NDPI_IGMP_PROTOCOL_TYPE:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_IGMP);
    break;

  case NDPI_EGP_PROTOCOL_TYPE:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_EGP);
    break;

  case NDPI_SCTP_PROTOCOL_TYPE:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_SCTP);
    break;

  case NDPI_OSPF_PROTOCOL_TYPE:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_OSPF);
    break;

  case NDPI_IPIP_PROTOCOL_TYPE:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_IP_IN_IP);
    break;

  case NDPI_ICMPV6_PROTOCOL_TYPE:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_ICMPV6);
    break;

  case 112:
    set_protocol_and_bmask(NDPI_PROTOCOL_IP_VRRP);
    break;
  }
}


void init_non_tcp_udp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  
  /* always add non tcp/udp if one protocol is compiled in */
  NDPI_SAVE_AS_BITMASK(ndpi_struct->callback_buffer[*id].detection_bitmask, NDPI_PROTOCOL_UNKNOWN);

  ndpi_set_bitmask_protocol_detection("IP_IPSEC", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_IP_IPSEC,
				      ndpi_search_in_non_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;

  ndpi_set_bitmask_protocol_detection("IP_GRE", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_IP_GRE,
				      ndpi_search_in_non_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;

  ndpi_set_bitmask_protocol_detection("IP_ICMP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_IP_ICMP,
				      ndpi_search_in_non_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;

  ndpi_set_bitmask_protocol_detection("IP_IGMP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_IP_IGMP,
				      ndpi_search_in_non_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;

  ndpi_set_bitmask_protocol_detection("IP_EGP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_IP_EGP,
				      ndpi_search_in_non_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;

  ndpi_set_bitmask_protocol_detection("IP_SCTP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_IP_SCTP,
				      ndpi_search_in_non_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;

  ndpi_set_bitmask_protocol_detection("IP_OSPF", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_IP_OSPF,
				      ndpi_search_in_non_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;

  ndpi_set_bitmask_protocol_detection("IP_IP_IN_IP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_IP_IP_IN_IP,
				      ndpi_search_in_non_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;

  ndpi_set_bitmask_protocol_detection("IP_ICMPV6", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_IP_ICMPV6,
				      ndpi_search_in_non_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
