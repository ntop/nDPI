/*
 * h323.c
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
 *
 */

#include "ndpi_api.h"


#ifdef NDPI_PROTOCOL_OPENVPN

void ndpi_search_openvpn(struct ndpi_detection_module_struct* ndpi_struct,
                         struct ndpi_flow_struct* flow) {
  struct ndpi_packet_struct* packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;

  if (packet->udp != NULL) {

    sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);

    if ((packet->payload_packet_len >= 25) && (sport == 443 || dport == 443) &&
        (packet->payload[0] == 0x17 && packet->payload[1] == 0x01 &&
         packet->payload[2] == 0x00 && packet->payload[3] == 0x00)) {
      NDPI_LOG(NDPI_PROTOCOL_OPENVPN, ndpi_struct, NDPI_LOG_DEBUG,
               "found openvpn udp 443.\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OPENVPN, NDPI_PROTOCOL_UNKNOWN);
      return;
    }

    if ( ( (packet->payload_packet_len > 40)   ||
           (packet->payload_packet_len <= 14) ) &&  // hard-reset
        (sport == 1194 || dport == 1194) &&
        (packet->payload[0] == 0x30 || packet->payload[0] == 0x31 ||
         packet->payload[0] == 0x32 || packet->payload[0] == 0x33 ||
         packet->payload[0] == 0x34 || packet->payload[0] == 0x35 ||
         packet->payload[0] == 0x36 || packet->payload[0] == 0x37 ||
         packet->payload[0] == 0x38 || packet->payload[0] == 0x39)) {
      NDPI_LOG(NDPI_PROTOCOL_OPENVPN, ndpi_struct, NDPI_LOG_DEBUG,
               "found openvpn broadcast udp STD.\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OPENVPN, NDPI_PROTOCOL_UNKNOWN);
      return;
    }

  }

  if (packet->tcp != NULL) {

    sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);

    if ((packet->payload_packet_len >= 40) &&
        (sport == 1194 || dport == 1194) &&
        ((packet->payload[0] == 0x00) && (packet->payload[1] == 0x2a) &&
         (packet->payload[2] == 0x38))) {
      NDPI_LOG(NDPI_PROTOCOL_OPENVPN, ndpi_struct, NDPI_LOG_DEBUG,
               "found openvpn broadcast udp STD.\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_OPENVPN, NDPI_PROTOCOL_UNKNOWN);
      return;
    }
  }

  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_OPENVPN);
}


void init_openvpn_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("OpenVPN", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_OPENVPN,
				      ndpi_search_openvpn,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
