/*
 * dnp3.c
 * Extension for dnp3 recognition
 *
 * Created by Cesar HM
 */

#include "ndpi_protocol_ids.h"
#include "ndpi_api.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_DNP3

void ndpi_search_dnp3_tcp(struct ndpi_detection_module_struct *ndpi_struct,
                            struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  NDPI_LOG_DBG(ndpi_struct, "search DNP3\n");

  /* Check connection over TCP */
    
  if(packet->tcp) {
    /* The payload of DNP3 is 10 bytes long. 
     * Header bytes: 0x0564
    */
    if (  packet->payload_packet_len >= 10 && 
          packet->payload[0] == 0x05 && packet->payload[1] == 0x64 ){
	NDPI_LOG_INFO(ndpi_struct, "found DNP3\n");
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DNP3, NDPI_PROTOCOL_UNKNOWN);
	return;
      }
    }
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
   
}



void init_dnp3_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                           u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
	
  ndpi_set_bitmask_protocol_detection("DNP3", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_DNP3,
				      ndpi_search_dnp3_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
