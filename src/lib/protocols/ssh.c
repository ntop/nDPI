/*
 * ssh.c
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


#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_SSH

static void ndpi_int_ssh_add_connection(struct ndpi_detection_module_struct
					*ndpi_struct, struct ndpi_flow_struct *flow){
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SSH, NDPI_PROTOCOL_UNKNOWN);
}

static void ndpi_ssh_zap_cr(char *str, int len) {
  len--;

  while(len > 0) {
    if((str[len] == '\n') || (str[len] == '\r')) {
      str[len] = '\0';
      len--;
    } else
      break;
  }
}

void ndpi_search_ssh_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;	
  //      struct ndpi_id_struct         *src=ndpi_struct->src;
  //      struct ndpi_id_struct         *dst=ndpi_struct->dst;

  if (flow->l4.tcp.ssh_stage == 0) {
    if (packet->payload_packet_len > 7 && packet->payload_packet_len < 100
	&& memcmp(packet->payload, "SSH-", 4) == 0) {
      int len = ndpi_min(sizeof(flow->protos.ssh.client_signature)-1, packet->payload_packet_len);
      strncpy(flow->protos.ssh.client_signature, (const char *)packet->payload, len);
      flow->protos.ssh.client_signature[len] = '\0';
      ndpi_ssh_zap_cr(flow->protos.ssh.client_signature, len);
      NDPI_LOG(NDPI_PROTOCOL_SSH, ndpi_struct, NDPI_LOG_DEBUG, "ssh stage 0 passed\n");
      flow->l4.tcp.ssh_stage = 1 + packet->packet_direction;
      return;
    }
  } else if (flow->l4.tcp.ssh_stage == (2 - packet->packet_direction)) {
    if (packet->payload_packet_len > 7 && packet->payload_packet_len < 100
	&& memcmp(packet->payload, "SSH-", 4) == 0) {
      int len = ndpi_min(sizeof(flow->protos.ssh.server_signature)-1, packet->payload_packet_len);
      strncpy(flow->protos.ssh.server_signature, (const char *)packet->payload, len);
      flow->protos.ssh.server_signature[len] = '\0';
      ndpi_ssh_zap_cr(flow->protos.ssh.server_signature, len);
      NDPI_LOG(NDPI_PROTOCOL_SSH, ndpi_struct, NDPI_LOG_DEBUG, "found ssh\n");
      
      ndpi_int_ssh_add_connection(ndpi_struct, flow);
      return;

    }
  }

  NDPI_LOG(NDPI_PROTOCOL_SSH, ndpi_struct, NDPI_LOG_DEBUG, "excluding ssh at stage %d\n", flow->l4.tcp.ssh_stage);
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SSH);
}


void init_ssh_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("SSH", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_SSH,
				      ndpi_search_ssh_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
#endif
