#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_RX

/* See http://web.mit.edu/kolya/afs/rx/rx-spec for procotol description. */

/* The should be no need for explicit packing, but just in case... */
struct __attribute__((__packed__)) ndpi_rx_header {
  u_int32_t conn_epoch;
  u_int32_t conn_id;
  u_int32_t call_number;
  u_int32_t sequence_number;
  u_int32_t serial_number;
  u_int8_t type;
  u_int8_t flags;
  u_int8_t status;
  u_int8_t security;
  u_int16_t checksum;
  u_int16_t service_id;
};

void ndpi_check_rx(struct ndpi_detection_module_struct *ndpi_struct,
                   struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;
  int exclude = 0;
  int found = 0;

  NDPI_LOG(NDPI_PROTOCOL_RX, ndpi_struct, NDPI_LOG_DEBUG, "RX: pck: %d, dir[0]: %d, dir[1]: %d\n",
           flow->packet_counter, flow->packet_direction_counter[0], flow->packet_direction_counter[1]);

  /* Check that packet is long enough. */
  if (payload_len < sizeof(struct ndpi_rx_header)) {
    NDPI_LOG(NDPI_PROTOCOL_RX, ndpi_struct, NDPI_LOG_DEBUG, "short packet\n");
    exclude = 1;
    goto end;
  }

  /* Check whether the packet has counters beginning from one; the
     Sequence Number can be zero if the packet is just an ACK. */
  struct ndpi_rx_header *header = (struct ndpi_rx_header*) packet->payload;
  if ((ntohl(header->sequence_number) | 1) != 1 || ntohl(header->serial_number) != 1) {
    NDPI_LOG(NDPI_PROTOCOL_RX, ndpi_struct, NDPI_LOG_DEBUG, "wrong counters\n");
    exclude = 1;
    goto end;
  }

  /* If we have already seen one packet in the other direction, then
     the two must have matching connection numbers. Otherwise store
     them. */
  if (flow->packet_direction_counter[!packet->packet_direction] != 0) {
    if (flow->l4.udp.rx_conn_epoch == header->conn_epoch &&
        flow->l4.udp.rx_conn_id == header->conn_id) {
      found = 1;
      /* In theory we could inspect the service_id field of the header
         to know exactly which service is being used; see
         https://www.central.org/frameless/numbers/rxservice.html. */
    } else {
      NDPI_LOG(NDPI_PROTOCOL_RX, ndpi_struct, NDPI_LOG_DEBUG, "IDs not matching\n");
      exclude = 1;
    }
    goto end;
  } else {
    flow->l4.udp.rx_conn_epoch = header->conn_epoch;
    flow->l4.udp.rx_conn_id = header->conn_id;
  }

 end:
  if (found) {
    NDPI_LOG(NDPI_PROTOCOL_RX, ndpi_struct, NDPI_LOG_DEBUG, "found RX\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RX, NDPI_PROTOCOL_UNKNOWN);
  }
  else if (exclude) {
    NDPI_LOG(NDPI_PROTOCOL_RX, ndpi_struct, NDPI_LOG_DEBUG, "excluding RX\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RX);
  }
}

void ndpi_search_rx(struct ndpi_detection_module_struct *ndpi_struct,
                    struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_RX, ndpi_struct, NDPI_LOG_DEBUG, "entering RX search\n");
  if (packet->detected_protocol_stack[0] != NDPI_PROTOCOL_RX) {
    ndpi_check_rx(ndpi_struct, flow);
  }
}

void init_rx_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                       u_int32_t *id,
                       NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("RX", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_RX,
				      ndpi_search_rx,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
