/*
 * netflow.c
 *
 * Copyright (C) 2011-15 - ntop.org
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

#ifdef NDPI_PROTOCOL_NETFLOW

#ifndef __KERNEL__
#ifdef WIN32
extern int gettimeofday(struct timeval * tp, struct timezone * tzp);
#endif
#define do_gettimeofday(a) gettimeofday(a, NULL)
#endif

static void ndpi_check_netflow(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  // const u_int8_t *packet_payload = packet->payload;
  u_int32_t payload_len = packet->payload_packet_len;
  time_t now;
  struct timeval now_tv;

  if((packet->udp != NULL) && (payload_len >= 24)) {
    u_int16_t version = (packet->payload[0] << 8) + packet->payload[1], uptime_offset;
    u_int32_t when, *_when;
    u_int16_t n = (packet->payload[2] << 8) + packet->payload[3];

    switch(version) {
    case 1:
    case 5:
    case 7:
    case 9:
      {      
	u_int16_t num_flows = n;

	if((num_flows == 0) || (num_flows > 30))
	  return;
      }
      uptime_offset = 8;
      break;
    case 10: /* IPFIX */
      {      
	u_int16_t ipfix_len = n;

	if(ipfix_len != payload_len)
	  return;
      }    
      uptime_offset = 4;
      break;
    default:
      return;
    }

    _when = (u_int32_t*)&packet->payload[uptime_offset]; /* Sysuptime */
    when = ntohl(*_when);

    do_gettimeofday(&now_tv);
    now = now_tv.tv_sec;

    if(((version == 1) && (when == 0))
       || ((when >= 946684800 /* 1/1/2000 */) && (when <= now))) {
      NDPI_LOG(NDPI_PROTOCOL_NETFLOW, ndpi_struct, NDPI_LOG_DEBUG, "Found netflow.\n");
      ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_NETFLOW, NDPI_REAL_PROTOCOL);
      return;
    }
  }
}

void ndpi_search_netflow(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG(NDPI_PROTOCOL_NETFLOW, ndpi_struct, NDPI_LOG_DEBUG, "netflow detection...\n");
  ndpi_check_netflow(ndpi_struct, flow);
}

#endif
