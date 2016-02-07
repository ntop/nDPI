/*
 * coap.c
 *
 * Copyright (C) 2016 Sorin Zamfir <sorin.zamfir@yahoo.com>
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

#define NDPI_PROTOCOL_COAP

#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_COAP
static void ndpi_int_coap_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	// not sure if this is accurate but coap runs on top of udp and should be connectionless
	  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
	    /* This is COAP and it is not a sub protocol (e.g. lwm2m) */
	    ndpi_search_tcp_or_udp(ndpi_struct, flow);
//
//	    /* If no custom protocol has been detected */
	    if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
//	      if(protocol != NDPI_PROTOCOL_HTTP) {
//		ndpi_search_tcp_or_udp(ndpi_struct, flow);
//		ndpi_set_detected_protocol(ndpi_struct, flow, protocol, NDPI_PROTOCOL_UNKNOWN);
//	      } else {
//		ndpi_int_reset_protocol(flow);
//		ndpi_set_detected_protocol(ndpi_struct, flow, protocol, NDPI_PROTOCOL_UNKNOWN);
//	      }
//	    }
//
//	    flow->http_detected = 1;
//	  }
}

void ndpi_search_coap(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	//TODO
	if (packet->detected_protocol_stack[0]!= NDPI_PROTOCOL_UNKNOWN){
		return;
	}
	NDPI_LOG(NDPI_PROTOCOL_HTTP, ndpi_struct, NDPI_LOG_DEBUG, "CoAP detected...\n");
//	if packet->
}

void init_http_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
			 NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
//TODO

	//  ndpi_set_bitmask_protocol_detection("HTTP",ndpi_struct, detection_bitmask, *id,
//				      NDPI_PROTOCOL_HTTP,
//				      ndpi_search_http_tcp,
//				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
//				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
//				      ADD_TO_DETECTION_BITMASK);
//  *id += 1;
//
//#if 0
//  ndpi_set_bitmask_protocol_detection("HTTP_Proxy", ndpi_struct, detection_bitmask, *id,
//				      NDPI_PROTOCOL_HTTP_PROXY,
//				      ndpi_search_http_tcp,
//				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
//				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
//				      ADD_TO_DETECTION_BITMASK);
//  *id += 1;
//
//#ifdef NDPI_CONTENT_MPEG
//  ndpi_set_bitmask_protocol_detection("MPEG", ndpi_struct, detection_bitmask, *id,
//				      NDPI_CONTENT_MPEG,
//				      ndpi_search_http_tcp,
//				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
//				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
//				      ADD_TO_DETECTION_BITMASK);
//
//  *id += 1;
//#endif
//#ifdef NDPI_CONTENT_FLASH
//  ndpi_set_bitmask_protocol_detection("Flash", ndpi_struct, detection_bitmask, *id,
//				      NDPI_CONTENT_FLASH,
//				      ndpi_search_http_tcp,
//				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
//				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
//				      ADD_TO_DETECTION_BITMASK);
//  *id += 1;
//#endif
//#ifdef NDPI_CONTENT_QUICKTIME
//  ndpi_set_bitmask_protocol_detection("QuickTime", ndpi_struct, detection_bitmask, *id,
//				      NDPI_CONTENT_QUICKTIME,
//				      ndpi_search_http_tcp,
//				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
//				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
//				      ADD_TO_DETECTION_BITMASK);
//  *id += 1;
//#endif
//#ifdef NDPI_CONTENT_REALMEDIA
//  ndpi_set_bitmask_protocol_detection("RealMedia", ndpi_struct, detection_bitmask, *id,
//				      NDPI_CONTENT_REALMEDIA,
//				      ndpi_search_http_tcp,
//				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
//				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
//				      ADD_TO_DETECTION_BITMASK);
//  *id += 1;
//#endif
//#ifdef NDPI_CONTENT_WINDOWSMEDIA
//  ndpi_set_bitmask_protocol_detection("WindowsMedia", ndpi_struct, detection_bitmask, *id,
//				      NDPI_CONTENT_WINDOWSMEDIA,
//				      ndpi_search_http_tcp,
//				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
//				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
//				      ADD_TO_DETECTION_BITMASK);
//  *id += 1;
//#endif
//#ifdef NDPI_CONTENT_MMS
//  ndpi_set_bitmask_protocol_detection("MMS", ndpi_struct, detection_bitmask, *id,
//				      NDPI_CONTENT_MMS,
//				      ndpi_search_http_tcp,
//				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
//				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
//				      ADD_TO_DETECTION_BITMASK);
//  *id += 1;
//#endif
//#ifdef NDPI_PROTOCOL_XBOX
//  ndpi_set_bitmask_protocol_detection("Xbox", ndpi_struct, detection_bitmask, *id,
//				      NDPI_PROTOCOL_XBOX,
//				      ndpi_search_http_tcp,
//				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
//				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
//				      ADD_TO_DETECTION_BITMASK);
//  *id += 1;
//#endif
//#ifdef NDPI_PROTOCOL_QQ
//  ndpi_set_bitmask_protocol_detection("QQ", ndpi_struct, detection_bitmask, *id,
//				      NDPI_PROTOCOL_QQ,
//				      ndpi_search_http_tcp,
//				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
//				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
//				      ADD_TO_DETECTION_BITMASK);
//  *id += 1;
//#endif
//#ifdef NDPI_CONTENT_AVI
//  ndpi_set_bitmask_protocol_detection("AVI", ndpi_struct, detection_bitmask, *id,
//				      NDPI_CONTENT_AVI,
//				      ndpi_search_http_tcp,
//				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
//				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
//				      ADD_TO_DETECTION_BITMASK);
//  *id += 1;
//#endif
//#ifdef NDPI_CONTENT_OGG
//  ndpi_set_bitmask_protocol_detection("OggVorbis", ndpi_struct, detection_bitmask, *id,
//				      NDPI_CONTENT_OGG,
//				      ndpi_search_http_tcp,
//				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
//				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
//				      ADD_TO_DETECTION_BITMASK);
//  *id += 1;
//#endif
//#ifdef NDPI_PROTOCOL_MOVE
//  ndpi_set_bitmask_protocol_detection("Move", ndpi_struct, detection_bitmask, *id,
//				      NDPI_PROTOCOL_MOVE,
//				      ndpi_search_http_tcp,
//				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
//				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
//				      ADD_TO_DETECTION_BITMASK);
//  *id += 1;
//#endif
//
//  /* Update excluded protocol bitmask */
//  NDPI_BITMASK_SET(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask,
//  		   ndpi_struct->callback_buffer[a].detection_bitmask);
//
//  /*Delete protocol from exluded protocol bitmask*/
//  NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask, NDPI_PROTOCOL_UNKNOWN);
//
//  NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask, NDPI_PROTOCOL_QQ);
//
//#ifdef NDPI_CONTENT_FLASH
//  NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask, NDPI_CONTENT_FLASH);
//#endif
//
//  NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask,  NDPI_CONTENT_MMS);
//  /* #ifdef NDPI_PROTOCOL_RTSP */
//  /*   NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask, */
//  /* 				 NDPI_PROTOCOL_RTSP); */
//  /* #endif */
//  NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask, NDPI_PROTOCOL_XBOX);
//
//  NDPI_BITMASK_SET(ndpi_struct->generic_http_packet_bitmask, ndpi_struct->callback_buffer[a].detection_bitmask);
//
//  NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->generic_http_packet_bitmask, NDPI_PROTOCOL_UNKNOWN);
//
//  /* Update callback_buffer index */
//  a++;
//
//#endif

}

#endif // NDPI_PROTOCOL_COAP
