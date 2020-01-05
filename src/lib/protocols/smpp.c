/*
 * smpp.c
 * 
 * Copyright (C) 2016 - Damir Franusic <df@release14.org>
 * Copyright (C) 2016-20 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SMPP

#include "ndpi_api.h"


static void ndpi_int_smpp_add_connection(struct ndpi_detection_module_struct* ndpi_struct, 
                                         struct ndpi_flow_struct* flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SMPP, NDPI_PROTOCOL_UNKNOWN);
}

static  u_int8_t ndpi_check_overflow(u_int32_t current_length, u_int32_t total_lenth)
{
    return (current_length > 0 && current_length > INT_MAX - total_lenth);
}

void ndpi_search_smpp_tcp(struct ndpi_detection_module_struct* ndpi_struct, 
                          struct ndpi_flow_struct* flow)
{
  NDPI_LOG_DBG(ndpi_struct, "search SMPP\n");
  if (flow->packet.detected_protocol_stack[0] != NDPI_PROTOCOL_SMPP){
    struct ndpi_packet_struct* packet = &flow->packet;
    // min SMPP packet length = 16 bytes
    if (packet->payload_packet_len < 16) {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
    // get PDU length
    u_int32_t pdu_l = ntohl(get_u_int32_t(packet->payload, 0));

    NDPI_LOG_DBG2(ndpi_struct, 
	     "calculated PDU Length: %d, received PDU Length: %d\n", 
	     pdu_l, packet->payload_packet_len);

    // if PDU size was invalid, try the following TCP segments, 3 attempts max
    if(flow->packet_counter > 3) {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
    // verify PDU length
    if(pdu_l != packet->payload_packet_len) {
      // check if multiple PDUs included
      u_int32_t total_pdu_l = pdu_l;
      u_int32_t tmp_pdu_l = 0;
      u_int16_t pdu_c = 1;
      // loop PDUs (check if lengths are valid)
      while(total_pdu_l < (packet->payload_packet_len-4)) {
	// get next PDU length
	tmp_pdu_l = ntohl(get_u_int32_t(packet->payload, total_pdu_l));
	// if zero or overflowing , return, will try the next TCP segment
	if(tmp_pdu_l == 0 ||  ndpi_check_overflow(tmp_pdu_l, total_pdu_l) ) return;
	// inc total PDU length
	total_pdu_l += ntohl(get_u_int32_t(packet->payload, total_pdu_l));
	// inc total PDU count
	++pdu_c;
      }
        
      NDPI_LOG_DBG2(ndpi_struct, 
	       "multiple PDUs included, calculated total PDU Length: %d, PDU count: %d, TCP payload length: %d\n", 
	       total_pdu_l, pdu_c, packet->payload_packet_len);

      // verify multi PDU total length
      if(total_pdu_l != packet->payload_packet_len){
	// return, will try the next TCP segment
	return;
      }
    }

    // *** check PDU type ***
    u_int32_t pdu_type = ntohl(get_u_int32_t(packet->payload, 4));
    // first byte of PDU type is either 0x00 of 0x80
    if(!(packet->payload[4] == 0x00 || packet->payload[4] == 0x80)) {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      return;
    }
    // remove 0x80, get request type pdu
    u_int32_t pdu_req = pdu_type & 0x00FFFFFF;
    // list of known PDU types
    if((pdu_req >  0x00000000 && pdu_req <= 0x00000009) ||
       (pdu_req == 0x0000000B || pdu_req == 0x00000015  ||
        pdu_req == 0x00000021 || pdu_req == 0x00000102  ||
        pdu_req == 0x00000103)){

      NDPI_LOG_DBG2(ndpi_struct, 
	       "PDU type: %x, Request PDU type = %x\n", 
	       pdu_type, pdu_req);

      // fresult flag
      char extra_passed = 1;
      // check PDU type specifics
      switch(pdu_type){
	// GENERIC_NACK
      case 0x80000000:
	// body length must be zero
	if(pdu_l > 16) extra_passed = 0;
	break;

	// BIND_RECEIVER
	// BIND_TRANSMITTER
	// BIND_TRANSCEIVER
      case 0x00000001:
      case 0x00000002:
      case 0x00000009:
	// status field must be NULL
	if(get_u_int32_t(packet->payload, 8) != 0) extra_passed = 0;
	// min body length = 10 bytes (+16 in header)
	if(pdu_l < 26) extra_passed = 0; 
	break;

	// BIND_RECEIVER_RESP
	// BIND_TRANSMITTER_RESP
	// BIND_TRANSCEIVER_RESP
      case 0x80000001:
      case 0x80000002:
      case 0x80000009:
	// min body length = 2 bytes (+16 in header)
	if(pdu_l < 18) extra_passed = 0;
	break;

	// OUTBIND
      case 0x0000000B:
	// status field must be NULL
	if(get_u_int32_t(packet->payload, 8) != 0) extra_passed = 0;
	// min body length = 4 bytes (+16 in header)
	if(pdu_l < 20) extra_passed = 0;
	break;

	// UNBIND
      case 0x00000006:
	// status field must be NULL
	if(get_u_int32_t(packet->payload, 8) != 0) extra_passed = 0;
	// body length must be zero
	if(pdu_l > 16) extra_passed = 0;
	break;

	// UNBIND_RESP
      case 0x80000006:
	// body length must be zero
	if(pdu_l > 16) extra_passed = 0;
	break;


	// SUBMIT_SM
      case 0x00000004:
	// status field must be NULL
	if(get_u_int32_t(packet->payload, 8) != 0) extra_passed = 0;
	// min body length = 17 bytes (+16 in header)
	if(pdu_l < 33) extra_passed = 0;
	break;
       
	// SUBMIT_SM_RESP
      case 0x80000004:
	// - if status != 0, body length is 2 bytes min
	// - if status > 0, body lenth must be zero
	if(get_u_int32_t(packet->payload, 8) != 0){
	  if(pdu_l > 16) extra_passed = 0; 

	}else if(pdu_l < 18) extra_passed = 0;
	break;

	// SUBMIT_MULTI
      case 0x00000021:
	// status field must be NULL
	if(get_u_int32_t(packet->payload, 8) != 0) extra_passed = 0;
	// min body length = 17 bytes (+16 in header)
	if(pdu_l < 33) extra_passed = 0;
	break;

	// SUBMIT_MULTI_RESP
      case 0x80000021:
	// min body length = 10 bytes (+16 in header)
	if(pdu_l < 26) extra_passed = 0;
	break;

	// DELIVER_SM
      case 0x00000005:
	// status field must be NULL
	if(get_u_int32_t(packet->payload, 8) != 0) extra_passed = 0;
	// min body length = 17 bytes (+16 in header)
	if(pdu_l < 33) extra_passed = 0;
	break;

	// DELIVER_SM_RESP
      case 0x80000005:
	// min body length = 1 byte (+16 in header)
	if(pdu_l < 17) extra_passed = 0;
	break;
            
	// DATA_SM
      case 0x00000103:
	// status field must be NULL
	if(get_u_int32_t(packet->payload, 8) != 0) extra_passed = 0;
	// min body length = 10 bytes (+16 in header)
	if(pdu_l < 26) extra_passed = 0;
	break;

	// DATA_SM_RESP
      case 0x80000103:
	// min body length = 2 bytes (+16 in header)
	if(pdu_l < 18) extra_passed = 0;
	break;

	// QUERY_SM
      case 0x00000003:
	// status field must be NULL
	if(get_u_int32_t(packet->payload, 8) != 0) extra_passed = 0;
	// min body length = 4 bytes (+16 in header)
	if(pdu_l < 20) extra_passed = 0;
	break;

	// QUERY_SM_RESP
      case 0x80000003:
	// min body length = 5 bytes (+16 in header)
	if(pdu_l < 21) extra_passed = 0;
	break;

	// CANCEL_SM
      case 0x00000008:
	// status field must be NULL
	if(get_u_int32_t(packet->payload, 8) != 0) extra_passed = 0;
	// min body length = 8 bytes (+16 in header)
	if(pdu_l < 24) extra_passed = 0;
	break;

	// CANCEL_SM_RESP
      case 0x80000008:
	// body lenth must be zero
	if(pdu_l > 16) extra_passed = 0;
	break;

	// REPLACE_SM
      case 0x00000007:
	// status field must be NULL
	if(get_u_int32_t(packet->payload, 8) != 0) extra_passed = 0;
	// min body length = 9 bytes (+16 in header)
	if(pdu_l < 25) extra_passed = 0;
	break;

	// REPLACE_SM_RESP
      case 0x80000007:
	// body lenth must be zero
	if(pdu_l > 16) extra_passed = 0;
	break;

	// ENQUIRE_LINK
      case 0x00000015:
	// status field must be NULL
	if(get_u_int32_t(packet->payload, 8) != 0) extra_passed = 0;
	// body length must be zero
	if(pdu_l > 16) extra_passed = 0;
	break;

	// ENQUIRE_LINK_RESP
      case 0x80000015:
	// body length must be zero
	if(pdu_l > 16) extra_passed = 0;
	break;

	// ALERT_NOTIFICATION
      case 0x00000102:
	// status field must be NULL
	if(get_u_int32_t(packet->payload, 8) != 0) extra_passed = 0;
	// min body length = 6 bytes (+16 in header)
	if(pdu_l < 22) extra_passed = 0;
	break;

      default: break;
      }

      // if extra checks passed, set as identified
      if(extra_passed) {
	NDPI_LOG_INFO(ndpi_struct, "found SMPP\n");
	ndpi_int_smpp_add_connection(ndpi_struct, flow);
	return;
      }
    }

    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
}


void init_smpp_dissector(struct ndpi_detection_module_struct* ndpi_struct, 
                         u_int32_t* id, 
                         NDPI_PROTOCOL_BITMASK* detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("SMPP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_SMPP,
				      ndpi_search_smpp_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
