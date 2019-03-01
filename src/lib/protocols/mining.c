/*
 * mining.c [Bitcoin, Ethereum, ZCash, Monero]
 *
 * Copyright (C) 2018 - ntop.org
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

#include "ndpi_api.h"

void ndpi_search_mining_tcp(struct ndpi_detection_module_struct *ndpi_struct,
			    struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search MINING\n");

  /* Check connection over TCP */
  if(packet->tcp && (packet->payload_packet_len > 10)) {

    if(packet->tcp->source == htons(8333)) {
      /*
	Bitcoin
	
	bitcoin.magic == 0xf9beb4d9 || bitcoin.magic == 0xfabfb5da
      */
      u_int32_t magic = htonl(0xf9beb4d9), magic1 = htonl(0xfabfb5da), *to_match = (u_int32_t*)packet->payload;
      
      if((*to_match == magic) || (*to_match == magic1)) {
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MINING, NDPI_PROTOCOL_UNKNOWN);
      }
    } if(ndpi_strnstr((const char *)packet->payload, "{", packet->payload_packet_len)
	 && (
	   ndpi_strnstr((const char *)packet->payload, "\"eth1.0\"", packet->payload_packet_len)
	   || ndpi_strnstr((const char *)packet->payload, "\"worker\":", packet->payload_packet_len)
	   /* || ndpi_strnstr((const char *)packet->payload, "\"id\":", packet->payload_packet_len) - Removed as too generic */
	   )) {
      /*
	Ethereum
	
	{"worker": "eth1.0", "jsonrpc": "2.0", "params": ["0x0fccfff9e61a230ff380530c6827caf4759337c6.rig2", "x"], "id": 2, "method": "eth_submitLogin"}
	{ "id": 2, "jsonrpc":"2.0","result":true}
	{"worker": "", "jsonrpc": "2.0", "params": [], "id": 3, "method": "eth_getWork"}
      */
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MINING, NDPI_PROTOCOL_UNKNOWN);
    } else if(ndpi_strnstr((const char *)packet->payload, "{", packet->payload_packet_len)
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
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MINING, NDPI_PROTOCOL_UNKNOWN);
    }
  }

  ndpi_exclude_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MINING, __FILE__, __FUNCTION__, __LINE__);
}


void init_mining_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			   u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Mining", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_MINING,
				      ndpi_search_mining_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

