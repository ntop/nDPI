/*
 * steam.c
 *
 * Copyright (C) 2011-20 - ntop.org
 * Copyright (C) 2014 Tomasz Bujlow <tomasz@skatnet.dk>
 * 
 * The signature is mostly based on the Libprotoident library
 * except the detection of HTTP Steam flows.
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_STEAM

#include "ndpi_api.h"

static void ndpi_int_steam_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_STEAM, NDPI_PROTOCOL_UNKNOWN);
}

static void ndpi_check_steam_http(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
	
  NDPI_PARSE_PACKET_LINE_INFO(ndpi_struct, flow, packet);
  if (packet->user_agent_line.ptr != NULL 
      && packet->user_agent_line.len >= 23 
      && memcmp(packet->user_agent_line.ptr, "Valve/Steam HTTP Client", 23) == 0) {
    NDPI_LOG_INFO(ndpi_struct, "found STEAM\n");
    ndpi_int_steam_add_connection(ndpi_struct, flow);
  }
}

static void ndpi_check_steam_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;
	
  if (flow->steam_stage == 0) {
    NDPI_LOG_DBG2(ndpi_struct, "STEAM stage 0: \n");
	    
    if ((payload_len == 1 && packet->payload[0] == 0x01) || ((payload_len == 4 || payload_len == 5) && ndpi_match_strprefix(packet->payload, payload_len, "\x01\x00\x00\x00"))) {
      NDPI_LOG_DBG2(ndpi_struct, "Possible STEAM request detected, we will look further for the response..\n");

      /* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
      flow->steam_stage = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
      return;
    }
		
    if ((payload_len == 1 && packet->payload[0] == 0x00) || ((payload_len == 4 || payload_len == 5) && ndpi_match_strprefix(packet->payload, payload_len, "\x00\x00\x00"))) {
      NDPI_LOG_DBG2(ndpi_struct, "Possible STEAM request detected, we will look further for the response..\n");

      /* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
      flow->steam_stage = packet->packet_direction + 3; // packet_direction 0: stage 3, packet_direction 1: stage 4
      return;
    }
  } else if ((flow->steam_stage == 1) || (flow->steam_stage == 2)) {
    NDPI_LOG_DBG2(ndpi_struct, "STEAM stage %u: \n", flow->steam_stage);

    /* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
    if ((flow->steam_stage - packet->packet_direction) == 1) {
      return;
    }

    /* This is a packet in another direction. Check if we find the proper response. */
    if ((payload_len == 1 && packet->payload[0] == 0x00) || ((payload_len == 4 || payload_len == 5) && ndpi_match_strprefix(packet->payload, payload_len, "\x00\x00\x00"))) {
      NDPI_LOG_INFO(ndpi_struct, "found STEAM\n");
      ndpi_int_steam_add_connection(ndpi_struct, flow);
    } else {
      NDPI_LOG_DBG2(ndpi_struct, "The reply did not seem to belong to STEAM, resetting the stage to 0..\n");
      flow->steam_stage = 0;
    }
  } else if ((flow->steam_stage == 3) || (flow->steam_stage == 4)) {
    NDPI_LOG_DBG2(ndpi_struct, "STEAM stage %u: \n", flow->steam_stage);

    /* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
    if ((flow->steam_stage - packet->packet_direction) == 3) {
      return;
    }

    /* This is a packet in another direction. Check if we find the proper response. */
    if ((payload_len == 1 && packet->payload[0] == 0x01) || ((payload_len == 4 || payload_len == 5) && ndpi_match_strprefix(packet->payload, payload_len, "\x01\x00\x00\x00"))) {
      NDPI_LOG_INFO(ndpi_struct, "found STEAM\n");
      ndpi_int_steam_add_connection(ndpi_struct, flow);
    } else {
      NDPI_LOG_DBG2(ndpi_struct, "The reply did not seem to belong to STEAM, resetting the stage to 0..\n");
      flow->steam_stage = 0;
    }
  }
}

static void ndpi_check_steam_udp1(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;
	
  if (ndpi_match_strprefix(packet->payload, payload_len, "VS01")) {
    NDPI_LOG_INFO(ndpi_struct, "found STEAM\n");
    ndpi_int_steam_add_connection(ndpi_struct, flow);
    return;
  }

  /* Check if we so far detected the protocol in the request or not. */
  if (flow->steam_stage1 == 0) {
    NDPI_LOG_DBG2(ndpi_struct, "STEAM stage 0: \n");
		
    if (ndpi_match_strprefix(packet->payload, payload_len, "\x31\xff\x30\x2e")) {
      NDPI_LOG_DBG2(ndpi_struct, "Possible STEAM request detected, we will look further for the response..\n");

      /* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
      flow->steam_stage1 = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
      return;
    }
		
    if (ndpi_match_strprefix(packet->payload, payload_len, "\xff\xff\xff\xff")) {
      NDPI_LOG_DBG2(ndpi_struct, "Possible STEAM request detected, we will look further for the response..\n");

      /* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
      flow->steam_stage1 = packet->packet_direction + 3; // packet_direction 0: stage 3, packet_direction 1: stage 4
      return;
    }

  } else if ((flow->steam_stage1 == 1) || (flow->steam_stage1 == 2)) {
    NDPI_LOG_DBG2(ndpi_struct, "STEAM stage %u: \n", flow->steam_stage1);

    /* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
    if ((flow->steam_stage1 - packet->packet_direction) == 1) {
      return;
    }

    /* This is a packet in another direction. Check if we find the proper response. */
    if (ndpi_match_strprefix(packet->payload, payload_len, "\xff\xff\xff\xff")) {
      NDPI_LOG_INFO(ndpi_struct, "found STEAM\n");
      ndpi_int_steam_add_connection(ndpi_struct, flow);
    } else {
      NDPI_LOG_DBG2(ndpi_struct, "The reply did not seem to belong to STEAM, resetting the stage to 0..\n");
      flow->steam_stage1 = 0;
    }
		
  } else if ((flow->steam_stage1 == 3) || (flow->steam_stage1 == 4)) {
    NDPI_LOG_DBG2(ndpi_struct, "STEAM stage %u: \n", flow->steam_stage1);

    /* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
    if ((flow->steam_stage1 - packet->packet_direction) == 3) {
      return;
    }

    /* This is a packet in another direction. Check if we find the proper response. */
    if (ndpi_match_strprefix(packet->payload, payload_len, "\x31\xff\x30\x2e")) {
      NDPI_LOG_INFO(ndpi_struct, "found STEAM\n");
      ndpi_int_steam_add_connection(ndpi_struct, flow);
    } else {
      NDPI_LOG_DBG(ndpi_struct, "The reply did not seem to belong to STEAM, resetting the stage to 0..\n");
      flow->steam_stage1 = 0;
    }
		
  }
}

static void ndpi_check_steam_udp2(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  /* Check if we so far detected the protocol in the request or not. */
  if (flow->steam_stage2 == 0) {
    NDPI_LOG_DBG2(ndpi_struct, "STEAM stage 0: \n");
		
    if ((payload_len == 25) && ndpi_match_strprefix(packet->payload, payload_len, "\xff\xff\xff\xff")) {
      NDPI_LOG_DBG2(ndpi_struct, "Possible STEAM request detected, we will look further for the response..\n");

      /* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
      flow->steam_stage2 = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
    }

  } else {
    NDPI_LOG_DBG2(ndpi_struct, "STEAM stage %u: \n", flow->steam_stage2);

    /* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
    if ((flow->steam_stage2 - packet->packet_direction) == 1) {
      return;
    }

    /* This is a packet in another direction. Check if we find the proper response. */
    if ((payload_len == 0) || ndpi_match_strprefix(packet->payload, payload_len, "\xff\xff\xff\xff")) {
      NDPI_LOG_INFO(ndpi_struct, "found STEAM\n");
      ndpi_int_steam_add_connection(ndpi_struct, flow);
    } else {
      NDPI_LOG_DBG2(ndpi_struct, "The reply did not seem to belong to STEAM, resetting the stage to 0..\n");
      flow->steam_stage2 = 0;
    }
		
  }
}

static void ndpi_check_steam_udp3(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  /* Check if we so far detected the protocol in the request or not. */
  if (flow->steam_stage3 == 0) {
    NDPI_LOG_DBG2(ndpi_struct, "STEAM stage 0: \n");
		
    if ((payload_len == 4) && (packet->payload[0] == 0x39) && (packet->payload[1] == 0x18) && (packet->payload[2] == 0x00) && (packet->payload[3] == 0x00)) {
      NDPI_LOG_DBG2(ndpi_struct, "Possible STEAM request detected, we will look further for the response..\n");

      /* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
      flow->steam_stage3 = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
    }

  } else {
    NDPI_LOG_DBG2(ndpi_struct, "STEAM stage %u: \n", flow->steam_stage3);

    /* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
    if ((flow->steam_stage3 - packet->packet_direction) == 1) {
      return;
    }

    /* This is a packet in another direction. Check if we find the proper response. */
    if ((payload_len == 0) || ((payload_len == 8) && (packet->payload[0] == 0x3a) && (packet->payload[1] == 0x18) && (packet->payload[2] == 0x00) && (packet->payload[3] == 0x00))) {
      NDPI_LOG_INFO(ndpi_struct, "found STEAM\n");
      ndpi_int_steam_add_connection(ndpi_struct, flow);
    } else {
      NDPI_LOG_DBG2(ndpi_struct, "The reply did not seem to belong to STEAM, resetting the stage to 0..\n");
      flow->steam_stage3 = 0;
    }
		
  }
}

void ndpi_search_steam(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
	
  if(flow->packet.udp != NULL) {
    if(flow->packet_counter > 5) {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
    
    ndpi_check_steam_udp1(ndpi_struct, flow);
	
    if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_STEAM)
      return;   
	
    ndpi_check_steam_udp2(ndpi_struct, flow);
	
    if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_STEAM)
      return;   
	
    ndpi_check_steam_udp3(ndpi_struct, flow);
  } else {
    /* Break after 10 packets. */
    if(flow->packet_counter > 10) {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }


    /* skip marked or retransmitted packets */
    if(packet->tcp_retransmission != 0) {
      return;
    }

    if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_STEAM)
      return;   

    NDPI_LOG_DBG(ndpi_struct, "search STEAM\n");
    ndpi_check_steam_http(ndpi_struct, flow);
	
    if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_STEAM)
      return;   

    ndpi_check_steam_tcp(ndpi_struct, flow);
	
    if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_STEAM)
      return;   
  }
}


void init_steam_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			  u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("Steam", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_STEAM,
				      ndpi_search_steam,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
