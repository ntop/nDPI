/*
 * iec60870-5-104.c
 * Extension for industrial 104 protocol recognition
 *
 * Created by Cesar HM
 */

#include "ndpi_protocol_ids.h"
#include "ndpi_api.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_104

void ndpi_search_104_tcp(struct ndpi_detection_module_struct *ndpi_struct,
                            struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  NDPI_LOG_DBG(ndpi_struct, "search 104\n");
  u_int16_t iec104_port = htons(2404); // port used by 104

  /* Check connection over TCP */
    
  if(packet->tcp) {
    /* The start byte of 104 is 0x68
     * The usual port: 2404
    */
    if (  packet->payload[0] == 0x68 && 
    ((packet->tcp->dest == iec104_port) || (packet->tcp->source == iec104_port)) ){
	NDPI_LOG_INFO(ndpi_struct, "found 104\n");
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_104, NDPI_PROTOCOL_UNKNOWN);
	return;
      }
    }
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
   
}



void init_104_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                           u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
	
  ndpi_set_bitmask_protocol_detection("104", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_104,
				      ndpi_search_104_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
