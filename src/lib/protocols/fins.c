/*
 * fins.c
 *
 * Factory Interface Network Service
 *
 * Copyright (C) 2023 - ntop.org
 * Copyright (C) V.G <v.gavrilov@securitycode.ru>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_FINS

#include "ndpi_api.h"
#include "ndpi_private.h"

struct fins_hdr {
  u_int8_t icf; /* Information Control Field */
  u_int8_t rsv; /* Reserved, must be set to 0 */
  u_int8_t gct; /* Permissible number of gateways */
  u_int8_t dna; /* Destination network address */
  u_int8_t da1; /* Destination node address */
  u_int8_t da2; /* Destination unit address */
  u_int8_t sna; /* Source network address */
  u_int8_t sa1; /* Source node address */
  u_int8_t sa2; /* Source unit address */
  u_int8_t sid; /* Service ID */
};

static void ndpi_int_fins_add_connection(struct ndpi_detection_module_struct * const ndpi_struct,
                                         struct ndpi_flow_struct * const flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow,
                             NDPI_PROTOCOL_FINS,
                             NDPI_PROTOCOL_UNKNOWN,
                             NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_fins(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search Omron FINS\n");

  /* FINS/TCP header is 20 bytes long, but it's usually followed
   * by 10 byte FINS header and command data
   */
  if (packet->tcp != NULL && packet->payload_packet_len >= 20) {
    /* The FINS/TCP header always contains the
     * 4 byte ASCII magic value 'FINS'
     */
    if (memcmp(packet->payload, "FINS", 4) == 0) {
      NDPI_LOG_INFO(ndpi_struct, "found FINS over TCP\n");
      ndpi_int_fins_add_connection(ndpi_struct, flow);
      return;
    }
  } else if ((packet->udp != NULL) &&
             (packet->payload_packet_len > sizeof(struct fins_hdr)))
  {
    struct fins_hdr const * const fins = (struct fins_hdr *)packet->payload;

    /* 0x80 - command, response required
     * 0xC0 - response, response not required
     * 0xC1 - response, response required
     */
    if ((fins->icf != 0x80) && (fins->icf != 0xC0) && 
        (fins->icf != 0xC1))
    {
      goto not_fins;
    }
    
    if ((fins->dna > 0x7F)  || (fins->sna > 0x7F) ||
        (fins->gct != 0x02) || (fins->rsv != 0)) 
    {
      goto not_fins;
    }

    if ((fins->da2 == 0x00) || (fins->da2 == 0xFE) ||
        (fins->da2 == 0xE1) || ((fins->da2 >= 0x10) && 
        (fins->da2 <= 0x1F)))
    {
      if ((fins->sa2 == 0x00) || (fins->sa2 == 0xFE) ||
          (fins->sa2 == 0xE1) || ((fins->sa2 >= 0x10) && 
          (fins->sa2 <= 0x1F)))
      {
        NDPI_LOG_INFO(ndpi_struct, "found FINS over UDP\n");
        ndpi_int_fins_add_connection(ndpi_struct, flow);
        return;
      }
    }
  }

not_fins:
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

void init_fins_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                                  u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("FINS", ndpi_struct, *id,
                                      NDPI_PROTOCOL_FINS,
                                      ndpi_search_fins,
                                      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                                      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
                                      ADD_TO_DETECTION_BITMASK
                                     );

  *id += 1;
}
