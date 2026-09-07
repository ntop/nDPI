/*
 * ookla.c
 *
 * Copyright (C) 2018-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_OOKLA

#include "ndpi_api.h"
#include "ndpi_private.h"

/* #define DEBUG_OOKLA_LRU */

const u_int16_t ookla_port = 8080;

/* ************************************************************* */

static u_int64_t get_ookla_key(struct ndpi_flow_core_struct *core)
{
  if(core->is_ipv6)
    return ndpi_quick_hash64((const char *)core->c_address.v6.u6_addr.u6_addr8, 16);
  else
    return core->c_address.v4;
}

/* ************************************************************* */

int ookla_search_into_cache(struct ndpi_detection_module_struct *ndpi_struct,
                            struct ndpi_flow_struct *flow)
{
  u_int64_t key;
  u_int16_t dummy;

  if(ndpi_struct->ookla_cache) {
    key = get_ookla_key(&flow->core);

    if(ndpi_lru_find_cache(ndpi_struct->ookla_cache, key,
                           &dummy, 0 /* Don't remove it as it can be used for other connections */,
			   ndpi_get_current_time(&flow->core))) {
#ifdef DEBUG_OOKLA_LRU
      printf("[LRU OOKLA] Found %lu [%u <-> %u]\n", key, ntohs(flow->core.c_port), ntohs(flow->core.s_port));
#endif
      return 1;
    } else {
#ifdef DEBUG_OOKLA_LRU
      printf("[LRU OOKLA] Not found %lu [%u <-> %u]\n", key, ntohs(flow->core.c_port), ntohs(flow->core.s_port));
#endif
    }      
  }
  
  return 0;
}

/* ************************************************************* */

void ookla_add_to_cache(struct ndpi_detection_module_struct *ndpi_struct,
                        struct ndpi_flow_core_struct *core)
{
  u_int64_t key;

  if(ndpi_struct->ookla_cache) {
    key = get_ookla_key(core);
#ifdef DEBUG_OOKLA_LRU
    printf("[LRU OOKLA] ADDING %lu [%u <-> %u]\n", key, ntohs(core->c_port), ntohs(core->s_port));
#endif
    ndpi_lru_add_to_cache(ndpi_struct->ookla_cache, key, 1 /* dummy */,
                          ndpi_get_current_time(core));
  }
}

/* ************************************************************* */

void ndpi_search_ookla(struct ndpi_detection_module_struct* ndpi_struct, struct ndpi_flow_struct* flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "Ookla detection\n");

  if(ntohs(flow->core.s_port) != ookla_port && ntohs(flow->core.c_port) != ookla_port) {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  if(flow->core.packet_counter == 1 &&
     packet->payload_packet_len >= NDPI_STATICSTRING_LEN("HI") &&
     memcmp(packet->payload, "HI", NDPI_STATICSTRING_LEN("HI")) == 0) {
    flow->metadata.ookla_stage = 1;
    return;
  }
  
  if(flow->core.packet_counter == 2 &&
     flow->metadata.ookla_stage == 1 &&
     packet->payload_packet_len >= NDPI_STATICSTRING_LEN("HELLO") &&
     memcmp(packet->payload, "HELLO", NDPI_STATICSTRING_LEN("HELLO")) == 0) {
    NDPI_LOG_INFO(ndpi_struct, "found ookla (Hi + Hello)\n");
    ndpi_set_detected_protocol(ndpi_struct, &flow->core, NDPI_PROTOCOL_OOKLA, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    ookla_add_to_cache(ndpi_struct, &flow->core);
    return;
  }
  
  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

/* ************************************************************* */

void init_ookla_dissector(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_register_dissector("Ookla", ndpi_struct,
                     ndpi_search_ookla,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     DISSECTOR_LICENSE_LGPL,
                     1, NDPI_PROTOCOL_OOKLA);
}
