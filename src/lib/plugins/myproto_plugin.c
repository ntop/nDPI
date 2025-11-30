/*
 * myproto_plugin.c
 *
 * Copyright (C) 2011-25 - ntop.org
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

/* *********************************************** */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_S7COMM
#define NDPI_LIB_COMPILATION

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "ndpi_includes.h"
#include "ndpi_private.h"

/* *********************************************** */

#define NDPI_PROTOCOL_MYPROTO_ID    NDPI_NUM_DEFINED_STATIC_PROTOCOL_IDS
#define NDPI_PROTOCOL_MYPROTO_NAME  "myproto"

/* *********************************************** */

static void ndpi_search_myproto(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  if((packet->payload_packet_len > 0) && (packet->payload[0] != '\0')) {
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MYPROTO_ID,
			       NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
#ifdef DEBUG
    printf("### Protocol %s found\n", NDPI_PROTOCOL_MYPROTO_NAME);
#endif
  } else
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

/* *********************************************** */

static void myprotoInitFctn(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_port_range ports_a[MAX_DEFAULT_PORTS], ports_b[MAX_DEFAULT_PORTS];

  printf("Welcome to %s_plugin\n", NDPI_PROTOCOL_MYPROTO_NAME);

  ndpi_set_proto_defaults(ndpi_struct, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE,
			  NDPI_PROTOCOL_MYPROTO_ID, NDPI_PROTOCOL_MYPROTO_NAME,
			  NDPI_PROTOCOL_CATEGORY_IOT_SCADA, NDPI_PROTOCOL_QOE_CATEGORY_UNSPECIFIED,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */,
			  0);

  register_dissector(NDPI_PROTOCOL_MYPROTO_NAME, ndpi_struct,
                     ndpi_search_myproto,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_MYPROTO_ID);
}

/* *********************************************** */

static NDPIProtocolPluginEntryPoint myprotoPlugin = {
  NDPI_API_VERSION /* ndpi_revision */,
  NDPI_PROTOCOL_MYPROTO_NAME /* protocol_name */,
  "0.1" /* version */,
  "Dummy plugin used for demonstration purpose" /* description */,
  "ntop.org" /* author */,
  myprotoInitFctn
};

NDPIProtocolPluginEntryPoint* PluginEntryFctn(void) {
  return(&myprotoPlugin);
}
