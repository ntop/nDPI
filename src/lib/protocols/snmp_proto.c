/*
 * snmp.c
 *
 * Copyright (C) 2011-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SNMP

#include "ndpi_api.h"

static void ndpi_search_snmp(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow);

/* *************************************************************** */

static void ndpi_int_snmp_add_connection(struct ndpi_detection_module_struct
					 *ndpi_struct, struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SNMP,
			     NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

/* *************************************************************** */

static int ndpi_search_snmp_again(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow) {

  ndpi_search_snmp(ndpi_struct, flow);

#ifdef SNMP_DEBUG
  printf("=> %s()\n", __FUNCTION__);
#endif

  return((flow->extra_packets_func == NULL) /* We're good now */ ? 0 : 1);
}

/* *************************************************************** */

void ndpi_search_snmp(struct ndpi_detection_module_struct *ndpi_struct,
		      struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t snmp_port = htons(161), trap_port = htons(162);
  u_int8_t version;
  
  if((packet->payload_packet_len <= 32)
     ||(packet->payload[0] != 0x30)
     || (((version = packet->payload[4]) != 0 /* SNMPv1 */)
	 && ((version = packet->payload[4]) != 1 /* SNMPv2c */)
	 && ((version = packet->payload[4]) != 3 /* SNMPv3 */))
     || ((packet->udp->source != snmp_port)
	 && (packet->udp->dest != snmp_port)
	 && (packet->udp->dest != trap_port))
     /* version */
     || ((packet->payload[1] + 2) != packet->payload_packet_len)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  } else {
    if((version == 0) || (version == 1)) {
      u_int8_t community_len = packet->payload[6];
      u_int8_t snmp_primitive_offset = 7 + community_len;

      if(snmp_primitive_offset < packet->payload_packet_len) {
	u_int8_t snmp_primitive = packet->payload[snmp_primitive_offset] & 0xF;

	if(snmp_primitive == 2 /* Get Response */) {
	  u_int8_t error_status_offset = 17 + community_len;
	  
	  if(error_status_offset < packet->payload_packet_len) {
	    u_int8_t error_status = packet->payload[error_status_offset];

#ifdef SNMP_DEBUG
	    printf("-> %u [offset: %u][primitive: %u]\n",
		   error_status, error_status_offset, snmp_primitive);
#endif
	    
	    flow->extra_packets_func = NULL; /* We're good now */

	    if(error_status != 0)
	      ndpi_set_risk(ndpi_struct, flow, NDPI_ERROR_CODE_DETECTED);
	  }
	}
      }
    }

    ndpi_int_snmp_add_connection(ndpi_struct, flow);

    if(flow->extra_packets_func == NULL) {
      /* This is necessary to inform the core to call this dissector again */
      flow->check_extra_packets = 1;
      flow->max_extra_packets_to_check = 8;
      flow->extra_packets_func = ndpi_search_snmp_again;
    }
    
    return;    
  }
}

/* *************************************************************** */

void init_snmp_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			 u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("SNMP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_SNMP,
				      ndpi_search_snmp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

