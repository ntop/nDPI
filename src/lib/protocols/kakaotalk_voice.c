/*
 * kakaotalk_voice.c
 *
 * Copyright (C) 2015 - ntop.org
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


/*
  KakaoTalk (call only)

  http://www.kakao.com/services/talk/voices
*/
#include "ndpi_api.h"


#ifdef NDPI_SERVICE_KAKAOTALK_VOICE
void ndpi_search_kakaotalk_voice(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  
  if(packet->iph
     && packet->udp
     && (packet->payload_packet_len > 0)
     ) {
    if((packet->payload[0] == 0x81)
       || (packet->payload[1] == 0xC8)
       || (packet->payload[2] == 0x00)
       || (packet->payload[3] == 0x0C)) {
      /* Looks good so far */

      /*
	inetnum:        1.201.0.0 - 1.201.255.255
	netname:        KINXINC-KR
      */

      if(((ntohl(packet->iph->saddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0x01C90000 /* 1.201.0.0/16 */)
	 || ((ntohl(packet->iph->daddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0x01C90000 /* 1.201.0.0/16 */)) {
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_SERVICE_KAKAOTALK_VOICE, NDPI_PROTOCOL_UNKNOWN);
	return;
      }
    } 
  }
  
  NDPI_LOG(NDPI_SERVICE_KAKAOTALK_VOICE, ndpi_struct, NDPI_LOG_DEBUG, "Exclude kakaotalk_voice.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_SERVICE_KAKAOTALK_VOICE);
}


void init_kakaotalk_voice_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("KakaoTalk_Voice", ndpi_struct, detection_bitmask, *id,
				      NDPI_SERVICE_KAKAOTALK_VOICE,
				      ndpi_search_kakaotalk_voice,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}

#endif
