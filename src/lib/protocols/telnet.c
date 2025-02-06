/*
 * telnet.c
 *
 * Copyright (C) 2011-22 - ntop.org
 * Copyright (C) 2009-11 - ipoque GmbH
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TELNET

#include "ndpi_api.h"
#include "ndpi_private.h"

/* #define TELNET_DEBUG 1 */

/* ************************************************************************ */

static int search_telnet_again(struct ndpi_detection_module_struct *ndpi_struct,
			       struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  int i;

#ifdef TELNET_DEBUG
  printf("==> %s() [%.*s][direction: %u]\n", __FUNCTION__, packet->payload_packet_len,
	 packet->payload, packet->packet_direction);
#endif
  
  if((packet->payload == NULL)
     || (packet->payload_packet_len == 0)
     || (packet->payload[0] == 0xFF))
    return(1);

  if(flow->protos.telnet.username_detected) {
    if((!flow->protos.telnet.password_found)
	&& (packet->payload_packet_len > 9)) {
	
      if(strncasecmp((char*)packet->payload, "password:", 9) == 0) {
	flow->protos.telnet.password_found = 1;
      }

      return(1);
    }
      
    if(packet->payload[0] == '\r') {
      if(!flow->protos.telnet.password_found)
	return(1);
	
      flow->protos.telnet.password_detected = 1;
      ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, "Found password");
      flow->protos.telnet.password[flow->protos.telnet.character_id] = '\0';
      return(0);
    }

    if(packet->packet_direction == 0) /* client -> server */ {
      for(i=0; i<packet->payload_packet_len; i++) {
	if(flow->protos.telnet.character_id < (sizeof(flow->protos.telnet.password)-1))
	  flow->protos.telnet.password[flow->protos.telnet.character_id++] = packet->payload[i];
      }
    }

    return(1);
  }

  if((!flow->protos.telnet.username_found)
     && (packet->payload_packet_len > 6)) {

    if(strncasecmp((char*)packet->payload, "login:", 6) == 0) {
      flow->protos.telnet.username_found = 1;
    }

    return(1);
  }

  if(packet->payload[0] == '\r') {
    char buf[64];
    
    flow->protos.telnet.username_detected = 1;
    flow->protos.telnet.username[flow->protos.telnet.character_id] = '\0';
    flow->protos.telnet.character_id = 0;

    snprintf(buf, sizeof(buf), "Found Telnet username (%s)",
	     flow->protos.telnet.username);
    ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, buf);

    return(1);
  }

  for(i=0; i<packet->payload_packet_len; i++) {
    if(packet->packet_direction == 0) /* client -> server */ {
      if(flow->protos.telnet.character_id < (sizeof(flow->protos.telnet.username)-1))
      {
        if (i>=packet->payload_packet_len-2 &&
            (packet->payload[i] == '\r' || packet->payload[i] == '\n'))
        {
          continue;
        }
        else if (ndpi_isprint(packet->payload[i]) == 0)
        {
          flow->protos.telnet.username[flow->protos.telnet.character_id++] = '?';
        } else {
          flow->protos.telnet.username[flow->protos.telnet.character_id++] = packet->payload[i];
        }
      }
    }
  }

  /* Possibly more processing */
  return(1);
}

/* ************************************************************************ */

static void ndpi_int_telnet_add_connection(struct ndpi_detection_module_struct
					   *ndpi_struct, struct ndpi_flow_struct *flow) {
  flow->max_extra_packets_to_check = 64;
  flow->extra_packets_func = search_telnet_again;

  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TELNET, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

/* ************************************************************************ */

#if !defined(WIN32)
static inline
#elif defined(MINGW_GCC)
__mingw_forceinline static
#else
__forceinline static
#endif
u_int8_t search_iac(struct ndpi_detection_module_struct *ndpi_struct) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  u_int16_t a;

#ifdef TELNET_DEBUG
  printf("==> %s()\n", __FUNCTION__);
#endif

  if(packet->payload_packet_len < 3)
    return(0);

  if(!((packet->payload[0] == 0xff)
       && (packet->payload[1] > 0xf9)
       && (packet->payload[1] != 0xff)
       && (packet->payload[2] < 0x28)))
    return(0);

  a = 3;

  while (a < packet->payload_packet_len - 2) {
    // commands start with a 0xff byte followed by a command byte >= 0xf0 and < 0xff
    // command bytes 0xfb to 0xfe are followed by an option byte <= 0x28
    if(!(packet->payload[a] != 0xff ||
	  (packet->payload[a] == 0xff && (packet->payload[a + 1] >= 0xf0) && (packet->payload[a + 1] <= 0xfa)) ||
	  (packet->payload[a] == 0xff && (packet->payload[a + 1] >= 0xfb) && (packet->payload[a + 1] != 0xff)
	   && (packet->payload[a + 2] <= 0x28))))
      return(0);

    a++;
  }

  return 1;
}

/* ************************************************************************ */

/* this detection also works asymmetrically */
static void ndpi_search_telnet_tcp(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow) {
  NDPI_LOG_DBG(ndpi_struct, "search telnet\n");

  if(search_iac(ndpi_struct) == 1) {
    if(flow->l4.tcp.telnet_stage == 2) {
      NDPI_LOG_INFO(ndpi_struct, "found telnet\n");
      ndpi_int_telnet_add_connection(ndpi_struct, flow);
      return;
    }

    flow->l4.tcp.telnet_stage++;
    NDPI_LOG_DBG2(ndpi_struct, "telnet stage %u\n", flow->l4.tcp.telnet_stage);
    return;
  }

  if(((flow->packet_counter < 12) && (flow->l4.tcp.telnet_stage > 0)) || (flow->packet_counter < 6)) {
#ifdef TELNET_DEBUG
    printf("==> [%s:%d] %s()\n", __FILE__, __LINE__, __FUNCTION__);
#endif
    return;
  } else {
#ifdef TELNET_DEBUG
    printf("==> [%s:%d] %s()\n", __FILE__, __LINE__, __FUNCTION__);
#endif
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
  
  return;
}


void init_telnet_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Telnet", ndpi_struct, *id,
				      NDPI_PROTOCOL_TELNET,
				      ndpi_search_telnet_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
