/*
 * hangout.c
 *
 * Copyright (C) 2012-16 - ntop.org
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
#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_HANGOUT

/* https://support.google.com/a/answer/1279090?hl=en */
#define HANGOUT_UDP_LOW_PORT  19302
#define HANGOUT_UDP_HIGH_PORT 19309
#define HANGOUT_TCP_LOW_PORT  19305
#define HANGOUT_TCP_HIGH_PORT 19309

/* ***************************************************************** */

static u_int8_t isHangoutUDPPort(u_int16_t port) {
  if((port >= HANGOUT_UDP_LOW_PORT) && (port <= HANGOUT_UDP_HIGH_PORT))
    return(1);
  else
    return(0);
}

/* ***************************************************************** */

static u_int8_t isHangoutTCPPort(u_int16_t port) {
  if((port >= HANGOUT_TCP_LOW_PORT) && (port <= HANGOUT_TCP_HIGH_PORT))
    return(1);
  else
    return(0);
}

/* ******************************************* */

static u_int8_t google_ptree_match(struct ndpi_detection_module_struct *ndpi_struct, struct in_addr *pin) {
  return((ndpi_network_ptree_match(ndpi_struct, pin) == NDPI_PROTOCOL_GOOGLE) ? 1 : 0);
}

/* ******************************************* */

static u_int8_t is_google_flow(struct ndpi_detection_module_struct *ndpi_struct,
			       struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  
  if(packet->iph) {
    if(google_ptree_match(ndpi_struct, (struct in_addr *)&packet->iph->saddr)
       || google_ptree_match(ndpi_struct, (struct in_addr *)&packet->iph->daddr)) {
      return(1);
    }
  }

  return(0);
}

/* ***************************************************************** */

void ndpi_search_hangout(struct ndpi_detection_module_struct *ndpi_struct,
			 struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct * packet = &flow->packet;

  if((packet->payload_packet_len > 24) && is_google_flow(ndpi_struct, flow)) {
    if(
       ((packet->udp != NULL) && (isHangoutUDPPort(ntohs(packet->udp->source)) || isHangoutUDPPort(ntohs(packet->udp->dest))))
       ||
       ((packet->tcp != NULL) && (isHangoutTCPPort(ntohs(packet->tcp->source)) || isHangoutTCPPort(ntohs(packet->tcp->dest))))) {
      NDPI_LOG(NDPI_PROTOCOL_HANGOUT, ndpi_struct, NDPI_LOG_DEBUG, "Found Hangout.\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_HANGOUT, NDPI_PROTOCOL_UNKNOWN);
      return;
    }
  }
  
  NDPI_LOG(NDPI_PROTOCOL_HANGOUT, ndpi_struct, NDPI_LOG_DEBUG, "No Hangout.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_HANGOUT);
}

/* ***************************************************************** */

void init_hangout_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
			    NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("GoogleHangout", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_HANGOUT,
				      ndpi_search_hangout,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif /* NDPI_PROTOCOL_HANGOUT */
