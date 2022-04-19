#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_WZRY

#include "ndpi_api.h"

static void
ndpi_int_wzry_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct             *flow /* , */
                             /* ndpi_protocol_type_t protocol_type */) {
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WZRY,
                               NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

void ndpi_search_wzry(struct ndpi_detection_module_struct *ndpi_struct,
                      struct ndpi_flow_struct             *flow) {
    struct ndpi_packet_struct *packet = &ndpi_struct->packet;

    NDPI_LOG_DBG(ndpi_struct, "search WZRY\n");

    fprintf(stderr,"%d,%d\n",flow->l4_proto, IPPROTO_TCP);
    fprintf(stderr,"%s -> %d",flow->saddr, flow->saddr);


    if (flow->l4_proto == IPPROTO_TCP && packet->l3_packet_len > 4 &&
        get_u_int8_t(packet->payload, 0) == 0x33 &&
        get_u_int8_t(packet->payload, 1) == 0x66 &&
        get_u_int8_t(packet->payload, 2) == 0x00 &&
        get_u_int8_t(packet->payload, 3) == 0x09) {
        NDPI_LOG_INFO(ndpi_struct, "found WZRY TCP\n");
        fprintf(stderr,"found WZRY\n");

        ndpi_int_wzry_add_connection(ndpi_struct, flow);
    } else if (flow->l4_proto == IPPROTO_UDP && packet->l3_packet_len > 4 &&
               ntohl(get_u_int8_t(packet->payload, 0)) == 0x01 &&
               ntohl(get_u_int8_t(packet->payload, 1)) == 0x02 &&
               ntohl(get_u_int8_t(packet->payload, 2)) == 0x00 &&
               ntohl(get_u_int8_t(packet->payload, 3)) == 0x00) {
        NDPI_LOG_INFO(ndpi_struct, "found WZRY TCP\n");
        fprintf(stderr,"found WZRY\n");
        ndpi_int_wzry_add_connection(ndpi_struct, flow);
    } else {
        if (flow->num_processed_pkts > 8) NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    }
}

void init_wzry_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                         u_int32_t                           *id,
                         NDPI_PROTOCOL_BITMASK *detection_bitmask) {
    ndpi_set_bitmask_protocol_detection(
        "WZRY", ndpi_struct, detection_bitmask, *id, NDPI_PROTOCOL_WZRY,
        ndpi_search_wzry,
        NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
        SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);

    *id += 1;
}
