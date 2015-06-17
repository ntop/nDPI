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
  unsigned char *vers;
  int ver_offs;
  
  if(packet->udp != NULL) {
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
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_SERVICE_KAKAOTALK_VOICE, NDPI_REAL_PROTOCOL);
	return;
      }
    } 
  }
  
  NDPI_LOG(NDPI_PROTOCOL_KAKAOTALK_VOICE, ndpi_struct, NDPI_LOG_DEBUG, "Exclude kakaotalk_voice.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_SERVICE_KAKAOTALK_VOICE);
}
#endif
