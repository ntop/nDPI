/*
 * z3950.c
 *
 * Copyright (C) 2012-22 - ntop.org
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

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_Z3950

#include "ndpi_api.h"

/* https://github.com/wireshark/wireshark/blob/master/epan/dissectors/asn1/z3950/z3950.asn */

static void ndpi_int_z3950_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                                          struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_Z3950, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

/* ***************************************************************** */

static int z3950_parse_sequences(struct ndpi_packet_struct const * const packet,
				 struct ndpi_flow_struct *flow,
                                 int max_sequences) {
  size_t payload_offset = 2;
  int cur_sequences = 0;
  u_int8_t pdu_type;

  if(packet->payload_packet_len < 2)
    return(-1);  

  pdu_type = packet->payload[0] & 0x1F;

  if(((pdu_type < 20) || (pdu_type > 36)) && ((pdu_type < 43) || (pdu_type > 48)))
    return(-1);  

  while(cur_sequences++ < max_sequences) {
    u_int8_t const * payload;
    u_int8_t seq_type;
    u_int8_t seq_length;
    
    if((payload_offset + 2) >= packet->payload_packet_len)
      return(-1);

    payload = &packet->payload[payload_offset];

    if((payload[0] & 0x1F) == 0x1F)
      /* We ignore decoding of complex sequences for now. */
      return(cur_sequences);
    else
      seq_type = payload[0] & 0x1F;
      
    seq_length = payload[1];

    if(seq_type > 51 && (seq_type < 100 || seq_type > 105) &&
       (seq_type < 110 || seq_type > 112) && (seq_type < 120 || seq_type > 121) &&
       (seq_type < 201 || seq_type > 221))
      return(-1);

    if(seq_length >= packet->payload_packet_len - payload_offset + 1)
      return(-1);

    payload_offset += seq_length + 2;

    if(payload_offset == packet->payload_packet_len)
      return(cur_sequences);
  }

  return(cur_sequences - 1);
}

/* ***************************************************************** */

static void ndpi_search_z3950(struct ndpi_detection_module_struct *ndpi_struct,
                              struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct * packet = &ndpi_struct->packet;
  int const minimum_expected_sequences = 6;

  NDPI_LOG_DBG(ndpi_struct, "search z39.50\n");

  if(packet->tcp != NULL && packet->payload_packet_len >= 6 &&
     flow->packet_counter >= 1 && flow->packet_counter <= 8) {
    int ret = z3950_parse_sequences(packet, flow, minimum_expected_sequences);

    if(ret < 0) {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }

    if(ret < minimum_expected_sequences) {
      /* We've seen not enough sequences, wait for the next packet. */
      return;
    }

    if(flow->z3950_stage == 3) {
      if(flow->packet_direction_counter[0] && flow->packet_direction_counter[1])
	ndpi_int_z3950_add_connection(ndpi_struct, flow);
      else
	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);  /* Skip if unidirectional traffic */
    } else
      flow->z3950_stage++;

    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* ***************************************************************** */

void init_z3950_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
                          NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("Z39.50",
                                      ndpi_struct, detection_bitmask, *id,
                                      NDPI_PROTOCOL_Z3950,
                                      ndpi_search_z3950,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
