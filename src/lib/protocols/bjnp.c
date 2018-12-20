#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_BJNP

#include "ndpi_api.h"

static void ndpi_int_bjnp_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					    struct ndpi_flow_struct *flow,
					 u_int8_t due_to_correlation) {
  ndpi_set_detected_protocol(ndpi_struct, flow,
			     NDPI_PROTOCOL_BJNP, NDPI_PROTOCOL_UNKNOWN);
}


static void ndpi_check_bjnp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  if(packet->udp != NULL) {
    if(payload_len > 4) {
      if((memcmp((const char *)packet->payload, "BJNP", 4) == 0)
	 || (memcmp((const char *)packet->payload, "BNJB", 4) == 0)
	 || (memcmp((const char *)packet->payload, "BJNB", 4) == 0)
	 || (memcmp((const char *)packet->payload, "MFNP", 4) == 0)
	 ) {
	    NDPI_LOG_INFO(ndpi_struct, "found bjnp\n");
	    ndpi_int_bjnp_add_connection(ndpi_struct, flow, 0);
	    return;
	  }
    }
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void ndpi_search_bjnp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search bjnp\n");

  /* skip marked packets */
  if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_BJNP) {
    if (packet->tcp_retransmission == 0) {
      ndpi_check_bjnp(ndpi_struct, flow);
    }
  }
}


void init_bjnp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("BJNP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_BJNP,
				      ndpi_search_bjnp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}
