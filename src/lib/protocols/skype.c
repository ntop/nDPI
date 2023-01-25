/*
 * skype.c
 *
 * Copyright (C) 2017-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SKYPE_TEAMS

#include "ndpi_api.h"

static int is_port(u_int16_t a, u_int16_t b, u_int16_t c) {
  return(((a == c) || (b == c)) ? 1 : 0);
}

static void ndpi_check_skype(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  /* No need to do ntohl() with 0xFFFFFFFF */
  if(packet->iph
     && ((packet->iph->daddr == 0xFFFFFFFF /* 255.255.255.255 */)
	 || ((ntohl(packet->iph->daddr) & 0xFFFFFF00) == 0xE0000000 /* multicast */)
	 )) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if(flow->host_server_name[0] != '\0')
    return;
  
  if(packet->udp != NULL) {    

    if(flow->packet_counter < 5) {
      u_int16_t sport = ntohs(packet->udp->source);
      u_int16_t dport = ntohs(packet->udp->dest);

      /* skype-to-skype */
      if(is_port(sport, dport, 1119) /* It can be confused with battle.net */
	 || is_port(sport, dport, 80) /* No HTTP-like protocols UDP/80 */
	 ) {
	;
      } else {
	/* Too many false positives */
	if(((payload_len == 3) && ((packet->payload[2] & 0x0F)== 0x0d))
	   ||
	   ((payload_len >= 16)
	    && (((packet->payload[0] & 0xC0) >> 6) == 0x02 /* RTPv2 */
		|| (((packet->payload[0] & 0xF0) >> 4) == 0 /* Zoom */)
		|| (((packet->payload[0] & 0xF0) >> 4) == 0x07 /* Skype */)
		)
	    && (packet->payload[0] != 0x30) /* Avoid invalid SNMP detection */
	    && (packet->payload[0] != 0x00) /* Avoid invalid CAPWAP detection */
	    && (packet->payload[2] == 0x02))) {

	  if(is_port(sport, dport, 8801)) {
	    NDPI_LOG_INFO(ndpi_struct, "found ZOOM (in SKYPE_TEAMS code)\n");
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_ZOOM, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
	  } else if (payload_len >= 16 && packet->payload[0] != 0x01) /* Avoid invalid Cisco HSRP detection / RADIUS */ {
	    NDPI_LOG_INFO(ndpi_struct, "found SKYPE_TEAMS\n");
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SKYPE_TEAMS_CALL, NDPI_PROTOCOL_SKYPE_TEAMS, NDPI_CONFIDENCE_DPI);
	  }
	}

        if (flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
          const uint8_t id_flags_iv_crc_len = 11;
          const uint8_t crc_len = sizeof(flow->l4.udp.skype_crc);
          const uint8_t crc_offset = id_flags_iv_crc_len - crc_len;

          /* Look for two pkts with the same crc */
          if((payload_len >= id_flags_iv_crc_len) &&
             (packet->payload[2] == 0x02 /* Payload flag */ )) {
            if(flow->packet_counter == 1) {
              memcpy(flow->l4.udp.skype_crc, &packet->payload[crc_offset], crc_len);
            } else {
              if(memcmp(flow->l4.udp.skype_crc, &packet->payload[crc_offset], crc_len) == 0) {
                NDPI_LOG_INFO(ndpi_struct, "found SKYPE_TEAMS\n");
                ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SKYPE_TEAMS, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
                return;
              }
            }
            /* No idea if the two pkts need to be consecutive; in doubt wait for some more pkts */
            return;
          }
        }
      }
    }
    
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }
}

static void ndpi_search_skype(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG_DBG(ndpi_struct, "search skype\n");

  /* skip marked packets */
  if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_SKYPE_TEAMS)
    ndpi_check_skype(ndpi_struct, flow);
}


void init_skype_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Skype_Teams", ndpi_struct, *id,
				      NDPI_PROTOCOL_SKYPE_TEAMS,
				      ndpi_search_skype,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
