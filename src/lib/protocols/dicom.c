/*
 * dicom.c
 *
 * Copyright (C) 2012-24 - ntop.org
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
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_DICOM

#include "ndpi_api.h"
#include "ndpi_private.h"

PACK_ON struct dicom_header {
  u_int8_t pdu_type, pad;
  u_int32_t pdu_len;
} PACK_OFF;

/* ********************************* */

static void ndpi_search_dicom(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search DICOM\n");

  if(packet->iph && (packet->payload_packet_len > sizeof(struct dicom_header))) {
    struct dicom_header *h = (struct dicom_header*)packet->payload;
    
    if((h->pdu_type == 0x01 /* A-ASSOCIATE */)
       && (h->pad == 0x0)
       && (packet->payload_packet_len <= (ntohl(h->pdu_len)+6))
       && (packet->payload_packet_len > 9)
       && (packet->payload[6] == 0x0) && (packet->payload[7] == 0x1) /* Protocol Version */
       && (packet->payload[8] == 0x0) && (packet->payload[9] == 0x0) /* Pad */       
       ) {
      ndpi_set_detected_protocol(ndpi_struct, flow,
				 NDPI_PROTOCOL_DICOM,
				 NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    } else
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  } else
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* ********************************* */

void init_dicom_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			     u_int32_t *id) {
  ndpi_set_bitmask_protocol_detection("DICOM", ndpi_struct,
				      *id, NDPI_PROTOCOL_DICOM, ndpi_search_dicom,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
