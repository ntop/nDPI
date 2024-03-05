/*
 * mining.c
 *
 * Copyright (C) 2018-22 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
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
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MINING
#include "ndpi_api.h"
#include "ndpi_private.h"


/* ************************************************************************** */

u_int64_t mining_make_lru_cache_key(struct ndpi_flow_struct *flow) {
  u_int64_t key;

  /* network byte order */
  if(flow->is_ipv6)
    key = (ndpi_quick_hash64((const char *)flow->c_address.v6, 16) << 32) | (ndpi_quick_hash64((const char *)flow->s_address.v6, 16) & 0xFFFFFFFF);
  else
    key = ((u_int64_t)flow->c_address.v4 << 32) | flow->s_address.v4;

  return key;
}

/* ************************************************************************** */

static void cacheMiningHostTwins(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow) {
  if(ndpi_struct->mining_cache)
    ndpi_lru_add_to_cache(ndpi_struct->mining_cache, mining_make_lru_cache_key(flow), NDPI_PROTOCOL_MINING, ndpi_get_current_time(flow));
}

/* ************************************************************************** */

static void ndpi_search_mining(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search MINING\n");

  /* Quick test: we are looking for only Json format */
  if(packet->payload[0] != '{') {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /* STRATUMv1 */
  if(ndpi_strnstr((const char *)packet->payload, "\"mining.subscribe\"", packet->payload_packet_len) ||
     ndpi_strnstr((const char *)packet->payload, "\"mining.configure\"", packet->payload_packet_len)) {

    /* Try matching some zcash domains like "eu1-zcash.flypool.org" */
    if(ndpi_strnstr((const char *)packet->payload, "zcash", packet->payload_packet_len))
      ndpi_snprintf(flow->protos.mining.currency, sizeof(flow->protos.mining.currency), "%s", "ZCash");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MINING, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    cacheMiningHostTwins(ndpi_struct, flow);
    return;
  }

  /* Xmr-stak-cpu is a ZCash/Monero CPU miner */
  if(ndpi_strnstr((const char *)packet->payload, "\"agent\":\"xmr-stak-cpu", packet->payload_packet_len)) {
    ndpi_snprintf(flow->protos.mining.currency, sizeof(flow->protos.mining.currency), "%s", "ZCash/Monero");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MINING, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    cacheMiningHostTwins(ndpi_struct, flow);
    return;
  }
  
  if(ndpi_strnstr((const char *)packet->payload, "\"method\": \"eth_submitLogin", packet->payload_packet_len)) {
    ndpi_snprintf(flow->protos.mining.currency, sizeof(flow->protos.mining.currency), "%s", "Ethereum");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MINING, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    cacheMiningHostTwins(ndpi_struct, flow);
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* ************************************************************************** */

void init_mining_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			   u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("Mining", ndpi_struct, *id,
				      NDPI_PROTOCOL_MINING,
				      ndpi_search_mining,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

