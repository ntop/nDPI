/*
 * whoisdas.c
 *
 * Copyright (C) 2016-22 - ntop.org
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
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_WHOIS_DAS

#include "ndpi_api.h"
#include "ndpi_private.h"


static void ndpi_search_whois_das(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search WHOIS/DAS\n");
  if(packet->tcp != NULL) {
    u_int16_t sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
    
    if((((sport == 43) || (dport == 43)) || ((sport == 4343) || (dport == 4343))) &&
       packet->payload_packet_len > 2 &&
       packet->payload[packet->payload_packet_len - 2] == '\r' &&
       packet->payload[packet->payload_packet_len - 1] == '\n' &&
       /* To avoid false positives with other cleartext protocol (i.e. mails).
          This check is maybe not perfect, but WHOIS/DAS is not the most
          important/used protocols nowadays
        */
       ndpi_is_valid_hostname((char * const)&packet->payload[0], packet->payload_packet_len - 2)) {

      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_WHOIS_DAS, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);

      if((dport == 43) || (dport == 4343)) { /* Request */
        ndpi_hostname_sni_set(flow, &packet->payload[0], packet->payload_packet_len - 2, NDPI_HOSTNAME_NORM_ALL); /* Skip \r\n */
        NDPI_LOG_INFO(ndpi_struct, "[WHOIS/DAS] %s\n", flow->host_server_name);
      }
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}


void init_whois_das_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("Whois-DA", ndpi_struct,
                     ndpi_search_whois_das,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_WHOIS_DAS);
}
