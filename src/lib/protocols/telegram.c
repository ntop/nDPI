/*
 * telegram.c
 *
 * Copyright (C) 2012-22 - ntop.org
 * Copyright (C) 2014 by Gianluca Costa xplico.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TELEGRAM

#include "ndpi_api.h"
#include "ndpi_private.h"

static void ndpi_int_telegram_add_connection(struct ndpi_detection_module_struct
                                             *ndpi_struct, struct ndpi_flow_struct *flow,
					     ndpi_confidence_t confidence) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TELEGRAM, NDPI_PROTOCOL_UNKNOWN, confidence);
  NDPI_LOG_INFO(ndpi_struct, "found telegram\n");
}

static u_int8_t is_telegram_port_range(u_int16_t port) {
  if((port >= 500) && (port <= 600))
    return(1);


  return(0);
}

static void ndpi_search_telegram(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search telegram\n");

  if(packet->tcp != NULL) {
    /* With MTProto 2.0 telegram via app is no longer TLS-based (althought based on TCP/443) so
       we need to detect it with Telegram IPs.
       Basically, we want a fast classification by ip. Note that, real Telegram traffic over
       TLS (i.e. Telegram Web) is correctly classified as TLS/Telegram because TLS dissector
       already kicked in.
       Let's check every port for the time being */
    if(flow->guessed_protocol_id_by_ip == NDPI_PROTOCOL_TELEGRAM) {
      ndpi_int_telegram_add_connection(ndpi_struct, flow, NDPI_CONFIDENCE_MATCH_BY_IP);
      return;
    }
  } else if(packet->udp != NULL) {
    /*
      The latest telegram protocol
      - contains a sequence of 12 consecutive 0xFF packets
      - it uses low UDP ports in the 500 range
     */

    if(packet->payload_packet_len >= 40) {
      u_int16_t sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);

      if(is_telegram_port_range(sport) || is_telegram_port_range(dport)) {
	u_int i, found = 0;

	for(i=0; i<packet->payload_packet_len; i++) {
	  if(packet->payload[i] == 0xFF) {
	    found = 1;
	    break;
	  }
	}

	if(!found) return;

	for(i += 1; i<packet->payload_packet_len; i++) {
	  if(packet->payload[i] == 0xFF)
	    found++;
	  else
	    break;
	}

	if(found == 12)	{
	  ndpi_int_telegram_add_connection(ndpi_struct, flow, NDPI_CONFIDENCE_DPI);
	  /* It seems this kind of traffic is used:
             * for "normal" stuff (at least years ago... and now? TODO)
             * for calls, as a custom encapsulation of STUN/DTLS/RTP packets
             Since we are not able to tell the former from the latter, always
             switch to STUN dissection. If we find STUN/DTLS/RTP stuff we will
             update the classification to something like STUN/Telegram_voip,
             otherwise it will remain Telegram */
	  switch_extra_dissection_to_stun(ndpi_struct, flow, 0);
	  return;
	}
      }
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_telegram_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Telegram", ndpi_struct, *id,
				      NDPI_PROTOCOL_TELEGRAM,
				      ndpi_search_telegram,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
