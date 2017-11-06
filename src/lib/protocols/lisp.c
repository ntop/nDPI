#include "ndpi_api.h"
#ifdef NDPI_PROTOCOL_LISP

#define LISP_PORT 4341
#define LISP_PORT1 4342

static void ndpi_int_lisp_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					    struct ndpi_flow_struct *flow,
					    u_int8_t due_to_correlation)
{

  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_LISP, NDPI_PROTOCOL_UNKNOWN);
}

static void ndpi_check_lisp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{

  struct ndpi_packet_struct *packet = &flow->packet;  
  u_int32_t payload_len = packet->payload_packet_len;

   if(packet->udp != NULL) {

    u_int16_t lisp_port = htons(LISP_PORT);
    u_int16_t lisp_port1 = htons(LISP_PORT1);
    
    if(((packet->udp->source == lisp_port)
       && (packet->udp->dest == lisp_port)) || 
	((packet->udp->source == lisp_port1)
       && (packet->udp->dest == lisp_port1)) ) {
     
	  NDPI_LOG(NDPI_PROTOCOL_LISP, ndpi_struct, NDPI_LOG_DEBUG, "Found lisp.\n");
	  ndpi_int_lisp_add_connection(ndpi_struct, flow, 0);
	  return;

      }
    }

  NDPI_LOG(NDPI_PROTOCOL_LISP, ndpi_struct, NDPI_LOG_DEBUG, "exclude lisp.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_LISP);
}

void ndpi_search_lisp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_LISP, ndpi_struct, NDPI_LOG_DEBUG, "lisp detection...\n");

  /* skip marked packets */
  if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_LISP) {
 
      ndpi_check_lisp(ndpi_struct, flow);
   
  }
}


void init_lisp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) 
{
  ndpi_set_bitmask_protocol_detection("LISP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_LISP,
				      ndpi_search_lisp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  *id += 1;
}

#endif
