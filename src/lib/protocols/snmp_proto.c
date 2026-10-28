/*
 * snmp.c
 *
 * Copyright (C) 2011-26 - ntop.org
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
  ndpi_set_detected_protocol(ndpi_struct, &flow->core, NDPI_PROTOCOL_SNMP,
			     NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

/* *************************************************************** */

static int ndpi_search_snmp_again(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow) {

  ndpi_search_snmp(ndpi_struct, flow);

#ifdef SNMP_DEBUG
  printf("=> %s()\n", __FUNCTION__);
#endif

  return((flow->core.extra_packets_func == NULL) /* We're good now */ ? 0 : 1);
}

/* *************************************************************** */

/* Decode the INTEGER at the beginning of the buffer. Returns the number of bytes used or -1 */
static int snmp_decode_int(const u_int8_t *buf, u_int32_t buf_len, int32_t *value) {
  struct ndpi_asn1_ber_tlv tlv;
  int used = ndpi_asn1_ber_decode_tlv(buf, buf_len, &tlv);

  if(used < 0 || ndpi_asn1_ber_decode_int(buf, used, value) != 0)
    return -1;

  return used;
}

/* *************************************************************** */

/*
  Reference: https://datatracker.ietf.org/doc/html/rfc1157#section-4
             https://datatracker.ietf.org/doc/html/rfc3416#section-3

  Message ::= SEQUENCE { version INTEGER, community OCTET STRING, data PDU }
  PDU     ::= [n] SEQUENCE { request-id INTEGER, error-status INTEGER, error-index INTEGER,
                             variable-bindings }

  For SNMPv3 we only look at the version: the rest of the message has a different layout
*/
static void ndpi_search_snmp(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t snmp_port = htons(161), trap_port = htons(162);
  struct ndpi_asn1_ber_tlv msg, community, pdu, request_id;
  const u_int8_t *buf;
  u_int32_t buf_len;
  int32_t version, error_status;
  int used;

  if((packet->udp->source != snmp_port) &&
     (packet->udp->dest != snmp_port) &&
     (packet->udp->source != trap_port) &&
     (packet->udp->dest != trap_port)) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if(packet->payload_packet_len <= 16 ||
     ndpi_asn1_ber_decode_single_tlv(packet->payload, packet->payload_packet_len, &msg) != 0 ||
     msg.tag != 0x30 /* SEQUENCE */ ||
     (used = snmp_decode_int(msg.value, msg.length, &version)) < 0 ||
     (version != 0 /* SNMPv1 */ && version != 1 /* SNMPv2c */ && version != 3 /* SNMPv3 */)) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if(flow->core.extra_packets_func == NULL) {
    ndpi_int_snmp_add_connection(ndpi_struct, flow);
    flow->metadata.protos.snmp.version = version;
  }

  if(version == 3)
    return;

  if(flow->core.extra_packets_func == NULL) {
    flow->core.max_extra_packets_to_check = 8;
    flow->core.extra_packets_func = ndpi_search_snmp_again;
  }

  buf = msg.value + used;
  buf_len = msg.length - used;

  used = ndpi_asn1_ber_decode_tlv(buf, buf_len, &community);
  if(used < 0 || community.tag != 0x04 /* OCTET STRING */)
    return;
  buf += used;
  buf_len -= used;

  if(ndpi_asn1_ber_decode_tlv(buf, buf_len, &pdu) < 0)
    return;

  flow->metadata.protos.snmp.primitive = pdu.tag & 0x1F; /* GET, SET... */

  if(flow->metadata.protos.snmp.primitive != 2 /* Get Response */)
    return;

  used = ndpi_asn1_ber_decode_tlv(pdu.value, pdu.length, &request_id);
  if(used < 0 || request_id.tag != 0x02 /* INTEGER */ ||
     snmp_decode_int(pdu.value + used, pdu.length - used, &error_status) < 0)
    return;

#ifdef SNMP_DEBUG
  printf("-> %d [primitive: %u]\n", error_status, flow->metadata.protos.snmp.primitive);
#endif

  flow->core.extra_packets_func = NULL; /* We're good now */

  flow->metadata.protos.snmp.error_status = (u_int8_t)error_status;

  if(error_status != 0) {
    char str[64];

    snprintf(str, sizeof(str), "SNMP Error %d", error_status);
    ndpi_set_risk(ndpi_struct, &flow->core, NDPI_ERROR_CODE_DETECTED, str);
  }
}

void init_snmp_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_register_dissector("SNMP", ndpi_struct,
                     ndpi_search_snmp,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
                     DISSECTOR_LICENSE_LGPL,
                     1, NDPI_PROTOCOL_SNMP);
}

