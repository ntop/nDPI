/*
 * mining.c [ZCash, Monero]
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


/* ************************************************************************** */

u_int32_t make_mining_key(struct ndpi_flow_struct *flow) {
  u_int32_t key;

  /* network byte order */
  if(flow->is_ipv6)
    key = ndpi_quick_hash(flow->c_address.v6, 16) + ndpi_quick_hash(flow->s_address.v6, 16);
  else
    key = flow->c_address.v4 + flow->s_address.v4;

  return key;
}

/* ************************************************************************** */

static void cacheMiningHostTwins(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow) {
  if(ndpi_struct->mining_cache)
    ndpi_lru_add_to_cache(ndpi_struct->mining_cache, make_mining_key(flow), NDPI_PROTOCOL_MINING, ndpi_get_current_time(flow));
}

/* ************************************************************************** */

static void ndpi_search_mining(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG_DBG(ndpi_struct, "search MINING\n");

  if(packet->payload_packet_len > 10) {
    if(ndpi_strnstr((const char *)packet->payload, "{", packet->payload_packet_len)
	      && (ndpi_strnstr((const char *)packet->payload, "\"method\":", packet->payload_packet_len)
		  || ndpi_strnstr((const char *)packet->payload, "\"blob\":", packet->payload_packet_len)
		  /* || ndpi_strnstr((const char *)packet->payload, "\"id\":", packet->payload_packet_len) - Removed as too generic */
		)
      ) {
      /*
	ZCash

	{"method":"login","params":{"login":"4BCeEPhodgPMbPWFN1dPwhWXdRX8q4mhhdZdA1dtSMLTLCEYvAj9QXjXAfF7CugEbmfBhgkqHbdgK9b2wKA6nqRZQCgvCDm.cb2b73415c4faf214035a73b9d947c202342f3bf3bdf632132bd6d7af98cb257.ryzen","pass":"x","agent":"xmr-stak-cpu/1.3.0-1.5.0"},"id":1}
	{"id":1,"jsonrpc":"2.0","error":null,"result":{"id":"479059546883218","job":{"blob":"0606e89883d205a65d8ee78991838a1cf3ec2ebbc5fb1fa43dec5fa1cd2bee4069212a549cd731000000005a88235653097aa3e97ef2ceef4aee610751a828f9be1a0758a78365fb0a4c8c05","job_id":"722134174127131","target":"dc460300"},"status":"OK"}}
	{"method":"submit","params":{"id":"479059546883218","job_id":"722134174127131","nonce":"98024001","result":"c9be9381a68d533c059d614d961e0534d7d8785dd5c339c2f9596eb95f320100"},"id":1}

	Monero
	
	{"method":"login","params":{"login":"4BCeEPhodgPMbPWFN1dPwhWXdRX8q4mhhdZdA1dtSMLTLCEYvAj9QXjXAfF7CugEbmfBhgkqHbdgK9b2wKA6nqRZQCgvCDm.cb2b73415c4faf214035a73b9d947c202342f3bf3bdf632132bd6d7af98cb257.ryzen","pass":"x","agent":"xmr-stak-cpu/1.3.0-1.5.0"},"id":1}
	{"id":1,"jsonrpc":"2.0","error":null,"result":{"id":"479059546883218","job":{"blob":"0606e89883d205a65d8ee78991838a1cf3ec2ebbc5fb1fa43dec5fa1cd2bee4069212a549cd731000000005a88235653097aa3e97ef2ceef4aee610751a828f9be1a0758a78365fb0a4c8c05","job_id":"722134174127131","target":"dc460300"},"status":"OK"}}
	{"method":"submit","params":{"id":"479059546883218","job_id":"722134174127131","nonce":"98024001","result":"c9be9381a68d533c059d614d961e0534d7d8785dd5c339c2f9596eb95f320100"},"id":1}
      */
      ndpi_snprintf(flow->protos.mining.currency, sizeof(flow->protos.mining.currency), "%s", "ZCash/Monero");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MINING, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      cacheMiningHostTwins(ndpi_struct, flow);
      return;
    }
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

