/*
 * s7comm.c
 * Extension for s7comm recognition
 *
 * Created by Saffet Bulut
 */

#include "ndpi_protocol_ids.h"
#include "ndpi_api.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_S7COMM

void ndpi_search_s7comm_tcp(struct ndpi_detection_module_struct *ndpi_struct,
                            struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  NDPI_LOG_DBG(ndpi_struct, "search S7COMM\n");
  u_int16_t s7comm_port = htons(102); // port used by s7comm


  /* Check connection over TCP */

  if(packet->tcp) {
     /* The start byte of 104 is 0x32 */
    if (  packet->payload[0] == 0x32 && 
    ((packet->tcp->dest == s7comm_port) || (packet->tcp->source == s7comm_port)) ){
	NDPI_LOG_INFO(ndpi_struct, "found S7COMM\n");
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_S7COMM, NDPI_PROTOCOL_UNKNOWN);
	return;
      }
    }
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);

}

void init_s7comm_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                           u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {

  ndpi_set_bitmask_protocol_detection("S7COMM", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_S7COMM,
				      ndpi_search_s7comm_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
