/*
 * quic.c
 *
 * Copyright (C) 2012-16 - ntop.org
 *
 * Based on code of:
 * Andrea Buscarinu - <andrea.buscarinu@gmail.com>
 * Michele Campus - <campus@ntop.org>
 *
 * This module is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License.
 * If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_QUIC

static int quic_ports(u_int16_t sport, u_int16_t dport)
{
  if ((sport == 443 || dport == 443 || sport == 80 || dport == 80) &&
      (sport != 123 && dport != 123))
    return 1;

  return 0;
}

/* ***************************************************************** */

static int quic_len(u_int8_t l) {
  switch(l) {
  case 0:
    return(1);
    break;
  case 1:
    return(2);
    break;
  case 2:
    return(4);
    break;
  case 3:
    return(8);
    break;
  }

  return(0); /* NOTREACHED */
}

/* ***************************************************************** */

void ndpi_search_quic(struct ndpi_detection_module_struct *ndpi_struct,
		      struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t udp_len = packet->payload_packet_len;
  u_int version_len = ((packet->payload[0] & 0x01) == 0) ? 0 : 4;
  u_int cid_len = quic_len((packet->payload[0] & 0x0C) >> 2);
  u_int seq_len = quic_len((packet->payload[0] & 0x30) >> 4);
  u_int quic_hlen = 1 /* flags */ + version_len + seq_len + cid_len;

  if(packet->udp != NULL
     && (udp_len > (quic_hlen+4 /* QXXX */))
     && ((packet->payload[0] & 0xC2) == 0x00)
     && (quic_ports(ntohs(packet->udp->source), ntohs(packet->udp->dest)))
     ) {
    int i;

    if((version_len > 0) && (packet->payload[1+cid_len] != 'Q'))
      goto no_quic;

    NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "found QUIC.\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QUIC, NDPI_PROTOCOL_UNKNOWN);

    if(udp_len > quic_hlen + 17 + 4 &&
         !strncmp((char*)&packet->payload[quic_hlen+17], "CHLO" /* Client Hello */, 4)) {
      /* Check if SNI (Server Name Identification) is present */
      for(i=quic_hlen+12; i<udp_len-3; i++) {
	if((packet->payload[i] == 'S')
	   && (packet->payload[i+1] == 'N')
	   && (packet->payload[i+2] == 'I')
	   && (packet->payload[i+3] == 0)) {
	  u_int32_t offset = *((u_int32_t*)&packet->payload[i+4]);
	  u_int32_t prev_offset = *((u_int32_t*)&packet->payload[i-4]);
	  int len = offset-prev_offset;
	  int sni_offset = i+prev_offset+1;

	  while((sni_offset < udp_len) && (packet->payload[sni_offset] == '-'))
	    sni_offset++;

	  if((sni_offset+len) < udp_len) {
	    int max_len = sizeof(flow->host_server_name)-1, j = 0;

	    if(len > max_len) len = max_len;

	    while((len > 0) && (sni_offset < udp_len)) {
	      flow->host_server_name[j++] = packet->payload[sni_offset];
	      sni_offset++, len--;
	    }

	    ndpi_match_host_subprotocol(ndpi_struct, flow, 
					(char *)flow->host_server_name,
					strlen((const char*)flow->host_server_name),
					NDPI_PROTOCOL_QUIC);
	    
	  }

	  break;
	}
      }
    }
    return;
  }

 no_quic:
  NDPI_LOG(NDPI_PROTOCOL_QUIC, ndpi_struct, NDPI_LOG_DEBUG, "exclude QUIC.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_QUIC);
}

/* ***************************************************************** */

void init_quic_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
			 NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("QUIC", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_QUIC, ndpi_search_quic,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif /* NDPI_PROTOCOL_QUIC */
