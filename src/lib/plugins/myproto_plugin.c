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

/* TODO: this define is used only for logging. We don't have static id for
   dissectors/protocols loaded via plugin, so we use the generic
   NDPI_PROTOCOL_UNKNOWN instead
 */
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UNKNOWN

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "ndpi_includes.h"
#include "ndpi_private.h"

/* *********************************************** */

#define NDPI_PROTOCOL_MYPROTO_NAME  "myproto"

static u_int16_t myproto_id;

/* *********************************************** */

static void ndpi_search_myproto(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct const * const packet = &ndpi_struct->packet;

  if(packet->payload_packet_len == NDPI_STATICSTRING_LEN("MyProto") &&
     memcmp(packet->payload, "MyProto", NDPI_STATICSTRING_LEN("MyProto")) == 0) {
    ndpi_set_detected_protocol(ndpi_struct, flow, myproto_id,
			       NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
    NDPI_LOG_INFO(ndpi_struct, "Protocol %s found\n", NDPI_PROTOCOL_MYPROTO_NAME);
  } else {
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
  }
}

/* *********************************************** */

static void myprotoInitFctn(struct ndpi_detection_module_struct *ndpi_struct) {
  ndpi_port_range ports_a[MAX_DEFAULT_PORTS], ports_b[MAX_DEFAULT_PORTS];
  u_int16_t user_proto_id;

  NDPI_LOG_DBG(ndpi_struct, "Welcome to %s_plugin\n", NDPI_PROTOCOL_MYPROTO_NAME);

  /* Internal id: dynamically allocated by the library */
  myproto_id = ndpi_struct->num_supported_protocols; /* First free id */

  /* If you want to set an explicit, constant, id for this protocol, set it here.
     It is the same logic used for custom protocols (via protos.txt file).
     By default, external id is equal to the internal one
   */
  user_proto_id = 5000;
  ndpi_add_user_proto_id_mapping(ndpi_struct, myproto_id, user_proto_id);

  ndpi_set_proto_defaults(ndpi_struct, 1 /* cleartext */, 1 /* app proto */,
			  NDPI_PROTOCOL_ACCEPTABLE,
                          myproto_id,
                          NDPI_PROTOCOL_MYPROTO_NAME,
                          NDPI_PROTOCOL_CATEGORY_IOT_SCADA,
			  NDPI_PROTOCOL_QOE_CATEGORY_UNSPECIFIED,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */,
                          1);

  register_dissector(NDPI_PROTOCOL_MYPROTO_NAME, ndpi_struct,
                     ndpi_search_myproto,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, myproto_id);
}

/* *********************************************** */

void myprotoFreeFlowFctn(void *plugin_data) {
  __ndpi_unused_param(plugin_data);

  /* Add you logic here */
}

/* *********************************************** */

void myprotoExportFctn(struct ndpi_detection_module_struct *ndpi_str,
		       struct ndpi_flow_struct *flow,
		       ndpi_serializer *serializer) {
  __ndpi_unused_param(ndpi_str);
  __ndpi_unused_param(flow);
  __ndpi_unused_param(serializer);

  /* Add you logic here */
}

/* *********************************************** */

static NDPIProtocolPluginEntryPoint myprotoPlugin = {
  NDPI_API_VERSION /* ndpi_revision */,
  NDPI_PROTOCOL_MYPROTO_NAME /* protocol_name */,
  "0.1" /* version */,
  "Dummy plugin used for demonstration purpose" /* description */,
  "ntop.org" /* author */,
  myprotoInitFctn,
  myprotoFreeFlowFctn,
  myprotoExportFctn,
};

/* *********************************************** */

NDPIProtocolPluginEntryPoint* PluginEntryFctn(void) {
  return(&myprotoPlugin);
}
