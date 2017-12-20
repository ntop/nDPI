/*
 * telnet.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-15 - ntop.org
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

#ifdef NDPI_PROTOCOL_TELNET

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TELNET

#include "ndpi_api.h"


static void ndpi_int_telnet_add_connection(struct ndpi_detection_module_struct
					   *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TELNET, NDPI_PROTOCOL_UNKNOWN);
}

	
#if !defined(WIN32)
static inline
#elif defined(MINGW_GCC)
__mingw_forceinline static
#else
__forceinline static
#endif
u_int8_t search_iac(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  u_int16_t a;

  if (packet->payload_packet_len < 3) {
    return 0;
  }

  if (!(packet->payload[0] == 0xff
	&& packet->payload[1] > 0xf9 && packet->payload[1] != 0xff && packet->payload[2] < 0x28)) {
    return 0;
  }

  a = 3;

  while (a < packet->payload_packet_len - 2) {
    // commands start with a 0xff byte followed by a command byte >= 0xf0 and < 0xff
    // command bytes 0xfb to 0xfe are followed by an option byte <= 0x28
    if (!(packet->payload[a] != 0xff ||
	  (packet->payload[a] == 0xff && (packet->payload[a + 1] >= 0xf0) && (packet->payload[a + 1] <= 0xfa)) ||
	  (packet->payload[a] == 0xff && (packet->payload[a + 1] >= 0xfb) && (packet->payload[a + 1] != 0xff)
	   && (packet->payload[a + 2] <= 0x28)))) {
      return 0;
    }
    a++;
  }

  return 1;
}

/* this detection also works asymmetrically */
void ndpi_search_telnet_tcp(struct ndpi_detection_module_struct
			    *ndpi_struct, struct ndpi_flow_struct *flow)
{

  NDPI_LOG_DBG(ndpi_struct, "search telnet\n");

  if (search_iac(ndpi_struct, flow) == 1) {

    if (flow->l4.tcp.telnet_stage == 2) {
      NDPI_LOG_INFO(ndpi_struct, "found telnet\n");
      ndpi_int_telnet_add_connection(ndpi_struct, flow);
      return;
    }
    flow->l4.tcp.telnet_stage++;
    NDPI_LOG_DBG2(ndpi_struct, "telnet stage %u\n", flow->l4.tcp.telnet_stage);
    return;
  }

  if ((flow->packet_counter < 12 && flow->l4.tcp.telnet_stage > 0) || flow->packet_counter < 6) {
    return;
  } else {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
  return;
}


void init_telnet_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Telnet", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_TELNET,
				      ndpi_search_telnet_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
