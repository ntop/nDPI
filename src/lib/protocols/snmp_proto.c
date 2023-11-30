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
#include "ndpi_private.h"

/* #define SNMP_DEBUG */

static void ndpi_search_snmp(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow);

/* *************************************************************** */

static void ndpi_int_snmp_add_connection(struct ndpi_detection_module_struct
					 *ndpi_struct, struct ndpi_flow_struct *flow) {
  NDPI_LOG_INFO(ndpi_struct, "found SNMP\n");
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

static void ndpi_search_snmp(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t snmp_port = htons(161), trap_port = htons(162);

  if((packet->udp->source != snmp_port) &&
     (packet->udp->dest != snmp_port) &&
     (packet->udp->source != trap_port) &&
     (packet->udp->dest != trap_port)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if(packet->payload_packet_len > 16 && packet->payload[0] == 0x30) {
    u_int16_t len_length = 0, offset;
    int64_t len;

    len = asn1_ber_decode_length(&packet->payload[1], packet->payload_packet_len - 1, &len_length);

    if(len > 2 &&
       1 + len_length + len == packet->payload_packet_len &&
       (packet->payload[1 + len_length + 2] == 0 /* SNMPv1 */ ||
        packet->payload[1 + len_length + 2] == 1 /* SNMPv2c */ ||
        packet->payload[1 + len_length + 2] == 3 /* SNMPv3 */)) {

      if(flow->extra_packets_func == NULL) {
        ndpi_int_snmp_add_connection(ndpi_struct, flow);
        flow->protos.snmp.version = packet->payload[1 + len_length + 2];
      }

      offset = 1 + len_length + 2;
      if((packet->payload[offset] == 0 /* SNMPv1 */ ||
          packet->payload[offset] == 1 /* SNMPv2c */) &&
	 (offset + 2 < packet->payload_packet_len)) {

        if(flow->extra_packets_func == NULL) {
          flow->max_extra_packets_to_check = 8;
          flow->extra_packets_func = ndpi_search_snmp_again;
        }

        u_int8_t community_len = packet->payload[offset + 2];
        u_int8_t snmp_primitive_offset = offset + 2 + 1 + community_len;

        if(snmp_primitive_offset < packet->payload_packet_len) {
          u_int8_t snmp_primitive = packet->payload[snmp_primitive_offset] & 0xF;

          flow->protos.snmp.primitive = snmp_primitive;

          if(snmp_primitive == 2 /* Get Response */ &&
             snmp_primitive_offset + 1 < packet->payload_packet_len) {
            offset = snmp_primitive_offset + 1;
            asn1_ber_decode_length(&packet->payload[offset], packet->payload_packet_len - offset, &len_length);
            offset += len_length + 1;
            if(offset < packet->payload_packet_len) {
              len = asn1_ber_decode_length(&packet->payload[offset], packet->payload_packet_len - offset, &len_length);

              u_int8_t error_status_offset = offset + len_length + len + 2;

              if(error_status_offset < packet->payload_packet_len) {
                u_int8_t error_status = packet->payload[error_status_offset];

#ifdef SNMP_DEBUG
                printf("-> %u [offset: %u][primitive: %u]\n",
                       error_status, error_status_offset, snmp_primitive);
#endif

                flow->extra_packets_func = NULL; /* We're good now */

		flow->protos.snmp.error_status = error_status;

                if(error_status != 0) {
                  char str[64];

                  snprintf(str, sizeof(str), "SNMP Error %d", error_status);
                  ndpi_set_risk(ndpi_struct, flow, NDPI_ERROR_CODE_DETECTED, str);
	        }
              }
            }
          }
        }
      }

      return;
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_snmp_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			 u_int32_t *id) {
  ndpi_set_bitmask_protocol_detection("SNMP", ndpi_struct, *id,
				      NDPI_PROTOCOL_SNMP,
				      ndpi_search_snmp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

