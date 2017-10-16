/*
 * drda.c
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

#ifdef NDPI_PROTOCOL_DRDA

struct ndpi_drda_hdr {
  u_int16_t length;
  u_int8_t magic;
  u_int8_t format;
  u_int16_t correlID;
  u_int16_t length2;
  u_int16_t code_pnt;
};


void ndpi_search_drda(struct ndpi_detection_module_struct *ndpi_struct,
		      struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * packet = &flow->packet;
  u_int16_t payload_len = packet->payload_packet_len;
  u_int count = 0; // prevent integer overflow
  
  if(packet->tcp != NULL) {

    /* check port */
    if(payload_len >= sizeof(struct ndpi_drda_hdr)) {

      struct ndpi_drda_hdr * drda = (struct ndpi_drda_hdr *) packet->payload;

      u_int16_t len = ntohs(drda->length);

      /* check first header */
      if(len != ntohs(drda->length2) + 6 ||
	 drda->magic != 0xd0)
	goto no_drda;

      /* check if there are more drda headers */
      if(payload_len > len) {

	count = len;

	while(count + sizeof(struct ndpi_drda_hdr) < payload_len)
	{
	  /* update info */
	  drda = (struct ndpi_drda_hdr *)(packet->payload + count);
	  len = ntohs(drda->length);

	  if(len != ntohs(drda->length2) + 6 ||
	     drda->magic != 0xd0)
	    goto no_drda;
	  
	  count += len;
	}
	if(count != payload_len) goto no_drda;
      }
      NDPI_LOG(NDPI_PROTOCOL_DRDA, ndpi_struct, NDPI_LOG_DEBUG, "found DRDA.\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DRDA, NDPI_PROTOCOL_UNKNOWN);
      return;
    }
  }

 no_drda:
  NDPI_LOG(NDPI_PROTOCOL_DRDA, ndpi_struct, NDPI_LOG_DEBUG, "exclude DRDA.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_DRDA);
}


/* ***************************************************************** */


void init_drda_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
			 NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("DRDA", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_DRDA,
				      ndpi_search_drda,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif /* NDPI_PROTOCOL_DRDA */
