/*
 * teamspeak.c 
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
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
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TEAMSPEAK

#include "ndpi_api.h"

static void ndpi_int_teamspeak_add_connection(struct ndpi_detection_module_struct
                                             *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TEAMSPEAK, NDPI_PROTOCOL_UNKNOWN);
}


void ndpi_search_teamspeak(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search teamspeak\n");

  
#ifdef WEAK_DETECTION_CODE_DISABLED
  if(packet->udp != NULL) {
    u_int16_t udport, usport;

    usport = ntohs(packet->udp->source), udport = ntohs(packet->udp->dest);

    /* http://www.imfirewall.com/en/protocols/teamSpeak.htm  */
    if(((usport == 9987 || udport == 9987) || (usport == 8767 || udport == 8767)) && packet->payload_packet_len >= 20) {
       NDPI_LOG_INFO(ndpi_struct, "found TEAMSPEAK udp\n");
       ndpi_int_teamspeak_add_connection(ndpi_struct, flow);
    }
  }
  else
#endif
    
    if(packet->tcp != NULL) {
#if WEAK_DETECTION_CODE_DISABLED
      u_int16_t tdport, tsport;
      tsport = ntohs(packet->tcp->source), tdport = ntohs(packet->tcp->dest);
#endif
      /* https://github.com/Youx/soliloque-server/wiki/Connection-packet */
      if(packet->payload_packet_len >= 20) {
	if(((memcmp(packet->payload, "\xf4\xbe\x03\x00", 4) == 0)) ||
	    ((memcmp(packet->payload, "\xf4\xbe\x02\x00", 4) == 0)) ||
            ((memcmp(packet->payload, "\xf4\xbe\x01\x00", 4) == 0))) {
	  NDPI_LOG_INFO(ndpi_struct, "found TEAMSPEAK tcp\n");
	  ndpi_int_teamspeak_add_connection(ndpi_struct, flow);
	}  /* http://www.imfirewall.com/en/protocols/teamSpeak.htm  */
      }
#if WEAK_DETECTION_CODE_DISABLED
      else if((tsport == 14534 || tdport == 14534) || (tsport == 51234 || tdport == 51234)) {
	NDPI_LOG_INFO(ndpi_struct, "found TEAMSPEAK\n");
	ndpi_int_teamspeak_add_connection(ndpi_struct, flow);
      }
#endif
    }
  
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  return;
}

void init_teamspeak_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("TeamSpeak", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_TEAMSPEAK,
				      ndpi_search_teamspeak,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

