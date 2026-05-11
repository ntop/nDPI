/*
 * iris.c
 *
 * Copyright (C) 2026 by Bryan Brauna <contato.bryankeven@gmail.com>
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_IRIS

#include "ndpi_api.h"
#include "ndpi_private.h"

enum message_type { HANDSHAKE =  21320,
                    CONNECT = 20035,
                    DISCONNECT = 17220,
                    PREPARE = 20560,
                    DIRECT_UPDATE = 21828,
                    DIRECT_QUERY = 20804,
                    DIRECT_STORED_PROCEDURE = 21316,
                    PREPARE_DIALECT = 17488,
                    DIRECT_EXECUTE_DIALECT = 17476,
                    PREPARED_UPDATE_EXECUTE = 21840,
                    PREPARED_QUERY_EXECUTE = 20816,
                    FETCH_DATA = 17478,
                    CLOSE_CURSOR = 17219,
                    PREPARE_STORED_PROCEDURE = 20563,
                    STORED_PROCEDURE_UPDATE_EXECUTE = 21843,
                    STORED_PROCEDURE_QUERY_EXECUTE = 20819,
                    STORED_PROCEDURE_FETCH_DATA = 18003,
                    EXECUTE_MULTIPLE_RESULT_SETS = 21325,
                    MULTIPLE_RESULT_SETS_FETCH_DATA = 17485,
                    GET_MORE_RESULTS = 21069,
                    GET_STREAM_SIZE = 21331,
                    READ_STREAM = 21322,
                    STORE_BINARY_STREAM = 16979,
                    STORE_CHARACTER_STREAM = 19795,
                    STREAM_GET_BYTES = 16967,
                    STREAM_SET_BYTES = 23123,
                    STREAM_TRUNCATE = 22611,
                    STREAM_GET_POSITION = 20551,
                    CLOSE_STREAM = 21315,
                    STREAM_RELEASE_READ_LOCK = 21075,
                    STREAM_SET_PREFETCH_SIZE = 20051,
                    GET_RESULT_SET_OBJECT = 21062,
                    COMMIT = 17236,
                    ROLLBACK = 21076,
                    ISOLATION_LEVEL = 19529,
                    AUTOCOMMIT_OFF = 17985,
                    AUTOCOMMIT_ON = 20033,
                    GET_AUTO_GENERATED_KEYS = 18247,
                    IN_TRANSACTION = 21577,
                    JDBC_BESTROWID = 21058,
                    JDBC_CATALOGS = 16707,
                    JDBC_COLUMNPRIV = 20547,
                    JDBC_COLUMNS = 20291,
                    JDBC_CROSSREFERENCE = 21059,
                    JDBC_EXPORTEDKEYS = 19269,
                    JDBC_IMPORTEDKEYS = 19273,
                    JDBC_INDEXINFO = 18761,
                    JDBC_PRIMARYKEYS = 19280,
                    JDBC_PROCEDURECOL = 17232,
                    JDBC_PROCEDURES = 21072,
                    JDBC_SCHEMAS = 17235,
                    JDBC_TABLEPRIV = 20564,
                    JDBC_TABLES = 16724,
                    JDBC_TABLETYPES = 21588,
                    JDBC_TYPEINFO = 18772,
                    JDBC_VERSIONCOL = 17238,
                    JDBC_UDTS = 21589,
                    JDBC_SUPER_TYPES = 22867,
                    JDBC_SUPER_TABLES = 19539,
                    JDBC_GET_ATTRIBUTES = 21569,
                    JDBC_GET_FUNCTION_COLUMNS = 17222,
                    JDBC_GET_FUNCTIONS = 20038,
                    JDBC_CLIENT_INFO_PROPERTIES = 17987,
                    SET_CLIENT_INFO_PROPERTIES = 18243,
                    JDBC_PSEUDO_COLUMNS = 18499,
                    GET_SCHEMA = 21319,
                    EXECUTE_STATIC_CURSOR = 22597,
                    DIRECT_STATIC_CURSOR = 22596,
                    FETCH_STATIC_CURSOR = 22598,
                    UPDATE_CACHE = 17237,
                    GET_SERVER_ERROR = 17743,
                    EXECUTE_STATEMENT_BATCH = 16965,
                    SET_QUERY_PREFETCH_SIZE = 16976,
                    EXTERNAL_INTERUPT = 18757,
                    GET_IRIS_INFO = 18755,
                    PING = 18256,
                    PING_TWO = 12880,
                    SEND_TWO_FACTOR_TOKEN = 17970,
                    IS_TWO_FACTOR_ENABLED = 17714,
                    GATEWAY_INIT = 18759,
                    MESSAGE_JAVA_OBJECT_CREATED = 14681,
                    CLOSE_STATEMENT = 21827,
                    COMPARE_TIMESTAMP = 22083,
                    TOGGLE_SYNCHRONOUS_COMMIT = 21332,
                    READ_UNCOMMITTED = 21842,
                    READ_COMMITTED = 17234,
                    RESET_CONNECTION = 20050,
                    OPEN_STREAM = 21327 };


static int iris_check_msg_type_or_error_code(struct ndpi_packet_struct *packet) {
    uint16_t message_type_or_error_code;

    message_type_or_error_code = le16toh(*(uint16_t *)(packet->payload + sizeof(uint32_t) * 3));

    switch (message_type_or_error_code) {
        case HANDSHAKE:
        case CONNECT:
        case DISCONNECT:
        case PREPARE:
        case DIRECT_UPDATE:
        case DIRECT_QUERY:
        case DIRECT_STORED_PROCEDURE:
        case PREPARE_DIALECT:
        case DIRECT_EXECUTE_DIALECT:
        case PREPARED_UPDATE_EXECUTE:
        case PREPARED_QUERY_EXECUTE:
        case FETCH_DATA:
        case CLOSE_CURSOR:
        case PREPARE_STORED_PROCEDURE:
        case STORED_PROCEDURE_UPDATE_EXECUTE:
        case STORED_PROCEDURE_QUERY_EXECUTE:
        case STORED_PROCEDURE_FETCH_DATA:
        case EXECUTE_MULTIPLE_RESULT_SETS:
        case MULTIPLE_RESULT_SETS_FETCH_DATA:
        case GET_MORE_RESULTS:
        case GET_STREAM_SIZE:
        case READ_STREAM:
        case STORE_BINARY_STREAM:
        case STORE_CHARACTER_STREAM:
        case STREAM_GET_BYTES:
        case STREAM_SET_BYTES:
        case STREAM_TRUNCATE:
        case STREAM_GET_POSITION:
        case CLOSE_STREAM:
        case STREAM_RELEASE_READ_LOCK:
        case STREAM_SET_PREFETCH_SIZE:
        case GET_RESULT_SET_OBJECT:
        case COMMIT:
        case ROLLBACK:
        case ISOLATION_LEVEL:
        case AUTOCOMMIT_OFF:
        case AUTOCOMMIT_ON:
        case GET_AUTO_GENERATED_KEYS:
        case IN_TRANSACTION:
        case JDBC_BESTROWID:
        case JDBC_CATALOGS:
        case JDBC_COLUMNPRIV:
        case JDBC_COLUMNS:
        case JDBC_CROSSREFERENCE:
        case JDBC_EXPORTEDKEYS:
        case JDBC_IMPORTEDKEYS:
        case JDBC_INDEXINFO:
        case JDBC_PRIMARYKEYS:
        case JDBC_PROCEDURECOL:
        case JDBC_PROCEDURES:
        case JDBC_SCHEMAS:
        case JDBC_TABLEPRIV:
        case JDBC_TABLES:
        case JDBC_TABLETYPES:
        case JDBC_TYPEINFO:
        case JDBC_VERSIONCOL:
        case JDBC_UDTS:
        case JDBC_SUPER_TYPES:
        case JDBC_SUPER_TABLES:
        case JDBC_GET_ATTRIBUTES:
        case JDBC_GET_FUNCTION_COLUMNS:
        case JDBC_GET_FUNCTIONS:
        case JDBC_CLIENT_INFO_PROPERTIES:
        case SET_CLIENT_INFO_PROPERTIES:
        case JDBC_PSEUDO_COLUMNS:
        case GET_SCHEMA:
        case EXECUTE_STATIC_CURSOR:
        case DIRECT_STATIC_CURSOR:
        case FETCH_STATIC_CURSOR:
        case UPDATE_CACHE:
        case GET_SERVER_ERROR:
        case EXECUTE_STATEMENT_BATCH:
        case SET_QUERY_PREFETCH_SIZE:
        case EXTERNAL_INTERUPT:
        case GET_IRIS_INFO:
        case PING:
        case PING_TWO:
        case SEND_TWO_FACTOR_TOKEN:
        case IS_TWO_FACTOR_ENABLED:
        case GATEWAY_INIT:
        case MESSAGE_JAVA_OBJECT_CREATED:
        case CLOSE_STATEMENT:
        case COMPARE_TIMESTAMP:
        case TOGGLE_SYNCHRONOUS_COMMIT:
        case READ_UNCOMMITTED:
        case READ_COMMITTED:
        case RESET_CONNECTION:
        case OPEN_STREAM:
	  return 1;
    }
    return 0;
}

/* this detection also works asymmetrically */
static void ndpi_search_iris(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &ndpi_struct->packet;
    uint32_t message_length;

    NDPI_LOG_DBG(ndpi_struct, "Search Iris\n");

    if((flow->s_port == ntohs(1972) || flow->c_port == ntohs(1972)) &&
       packet->payload_packet_len > 14U) {
      message_length = le32toh(*(uint32_t *)packet->payload);
      if(message_length == (packet->payload_packet_len - 14U)) {
        /* For requests, check also msg type (not present in the responses) */
        if((flow->s_port == ntohs(1972) && iris_check_msg_type_or_error_code(packet)) ||
           (flow->c_port == ntohs(1972))) {
          NDPI_LOG_INFO(ndpi_struct, "Found iris\n");
          ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_IRIS, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
	  return;
	}
      }
    }
    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
}

void init_iris_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("iris", ndpi_struct,
                          ndpi_search_iris,
                          NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                          1, NDPI_PROTOCOL_IRIS);
}
