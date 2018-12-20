/*
 * diameter.c
 *
 * Copyright (C) 2018 - ntop.org
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
 * Based on code of:
 * Michele Campus - <campus@ntop.org>
 */
#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_DIAMETER

#include "ndpi_api.h"


// Header Flags possibile values
#define DIAMETER_REQUEST   0X80
#define DIAMETER_PROXYABLE 0X40
#define DIAMETER_ERROR     0X20
#define DIAMETER_RETRASM   0X10

typedef enum {
    AC = 271,
    AS = 274,
    CC = 272,
    CE = 257,
    DW = 280,
    DP = 282,
    RA = 258,
    ST = 275
} com_type_t;

#define DIAM_HEADER_LEN 20

// DIAMETER header
struct diameter_header_t
{
  u_int8_t  version;
  u_int8_t  length[3];
  u_int8_t  flags;
  u_int8_t  com_code[3];
  u_int32_t app_id;
  u_int32_t hop_id;
  u_int32_t end_id;
};


// Check packet
int is_diameter(struct ndpi_packet_struct *packet, int size_payload)
{
  // check param
  if(!packet || size_payload == 0) return -1;

  // cast to diameter header
  struct diameter_header_t *diameter = (struct diameter_header_t *) packet;

  // check if the packet is diameter
  if(diameter->version == 0x01 &&
     (diameter->flags == DIAMETER_REQUEST ||
      diameter->flags == DIAMETER_PROXYABLE ||
      diameter->flags == DIAMETER_ERROR ||
      diameter->flags == DIAMETER_RETRASM)) {

    u_int16_t com_code = diameter->com_code[2] + (diameter->com_code[1] << 8) + (diameter->com_code[0] << 8);
    
     if(com_code == AC || com_code == AS ||
	com_code == CC || com_code == CE ||
	com_code == DW || com_code == DP ||
	com_code == RA || com_code == ST)
       return 0; // OK
  }
  // wrong packet
  return -2;
}


void ndpi_search_diameter(struct ndpi_detection_module_struct *ndpi_struct,
			  struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  // Diameter is on TCP
  if(packet->tcp) {

    /* Check if it's diameter */
    int ret = is_diameter(packet, packet->payload_packet_len);
    if(ret != 0) {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
    else {
      NDPI_LOG_INFO(ndpi_struct, "found Diameter\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DIAMETER, NDPI_PROTOCOL_UNKNOWN);
    }
  }
  else { // UDP
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }
}


void init_diameter_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
			 NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Diameter", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_DIAMETER, ndpi_search_diameter,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

