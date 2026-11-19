/*
 * mqtt.c
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

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MQTT

#include "ndpi_api.h"
#include "ndpi_private.h"


/**
 * The type of control messages in mqtt version 3.1, 3.1.1 and 5.0
 * see http://docs.oasis-open.org/mqtt/mqtt/v3.1.1
 * and https://docs.oasis-open.org/mqtt/mqtt/v5.0
 */
enum MQTT_PACKET_TYPES {
	CONNECT = 1,
	CONNACK = 2,
	PUBLISH = 3,
	PUBACK = 4,
	PUBREC = 5,
	PUBREL = 6,
	PUBCOMP = 7,
	SUBSCRIBE = 8,
	SUBACK = 9,
	UNSUBSCRIBE = 10,
	UNSUBACK = 11,
	PINGREQ = 12,
	PINGRESP = 13,
	DISCONNECT = 14,
	AUTH = 15 /* MQTT 5 only */
};

/* Valid reason codes (MQTT 5) */
static const u_int8_t rc_connack_v5[] = { 0x00, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
					  0x89, 0x8A, 0x8C, 0x90, 0x95, 0x97, 0x99, 0x9A, 0x9B, 0x9C,
					  0x9D, 0x9F };
static const u_int8_t rc_puback_v5[] = { 0x00, 0x10, 0x80, 0x83, 0x87, 0x90, 0x91, 0x97, 0x99 }; /* PUBACK, PUBREC */
static const u_int8_t rc_pubrel_v5[] = { 0x00, 0x92 }; /* PUBREL, PUBCOMP */
static const u_int8_t rc_suback_v3[] = { 0x00, 0x01, 0x02, 0x80 };
static const u_int8_t rc_suback_v5[] = { 0x00, 0x01, 0x02, 0x80, 0x83, 0x87, 0x8F, 0x91, 0x97, 0x9E,
					 0xA1, 0xA2 };
static const u_int8_t rc_unsuback_v5[] = { 0x00, 0x11, 0x80, 0x83, 0x87, 0x8F, 0x91 };
static const u_int8_t rc_disconnect_v5[] = { 0x00, 0x04, 0x80, 0x81, 0x82, 0x83, 0x87, 0x89, 0x8B, 0x8D,
					     0x8E, 0x8F, 0x90, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
					     0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2 };
static const u_int8_t rc_auth_v5[] = { 0x00, 0x18, 0x19 };

#define IS_IN_SET(c, set)	(memchr(set, c, sizeof(set)) != NULL)

/**
 * Entry point when protocol is identified.
 */
static void ndpi_int_mqtt_add_connection (struct ndpi_detection_module_struct *ndpi_struct,
		struct ndpi_flow_struct *flow)
{
	ndpi_set_detected_protocol(ndpi_struct, &flow->core,
				   NDPI_PROTOCOL_MQTT,NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
	NDPI_LOG_INFO(ndpi_struct, "found Mqtt\n");
}

/* Variable Byte Integer: 1 to 4 bytes, minimal encoding */
static int64_t get_var_int(const unsigned char *buf, u_int32_t buf_len, u_int8_t *num_bytes)
{
	int i, multiplier = 1;
	u_int32_t value = 0;
	u_int8_t encodedByte;

	*num_bytes= 0;
	for (i = 0; i < 4; i++) {
		if ((u_int32_t)i >= buf_len)
			return -1;
		(*num_bytes)++;
		encodedByte = buf[i];
		if (i > 0 && encodedByte == 0) /* Non minimal encoding (i.e. 0x80 0x00) */
			return -1;
		value += ((encodedByte & 127) * multiplier);
		if ((encodedByte & 128) == 0)
			return value;
		multiplier *= 128;
	}
	/* Continuation bit set on the 4th byte */
	return -1;
}

/* MQTT 5 properties block (length + properties) at the beginning of buf:
   returns its size or -1 if it doesn't fit */
static int skip_properties(const u_int8_t *buf, u_int32_t buf_len)
{
	u_int8_t len_size;
	int64_t props_len = get_var_int(buf, buf_len, &len_size);

	if (props_len < 0 || len_size + props_len > buf_len)
		return -1;
	return (int)(len_size + props_len);
}

/* MQTT 5 properties block taking exactly the whole buffer */
static int properties_fill(const u_int8_t *buf, u_int32_t buf_len)
{
	return skip_properties(buf, buf_len) == (int)buf_len;
}

/* Non-empty list of reason/return codes taking exactly the whole buffer */
static int check_reason_codes(const u_int8_t *buf, u_int32_t buf_len,
			      const u_int8_t *set, size_t set_len)
{
	u_int32_t i;

	if (buf_len == 0)
		return 0;
	for (i = 0; i < buf_len; i++) {
		if (memchr(set, buf[i], set_len) == NULL)
			return 0;
	}
	return 1;
}

/* Non-empty list of topic filters (with or without subscription options)
   taking exactly the whole buffer */
static int check_topic_filters(const u_int8_t *buf, u_int32_t buf_len,
			       int with_options, int v5)
{
	u_int32_t off = 0, num = 0;
	u_int16_t filter_len;
	u_int8_t opt;

	while (off < buf_len) {
		if (off + 2 > buf_len)
			return 0;
		filter_len = ntohs(get_u_int16_t(buf, off));
		if (filter_len == 0 || off + 2 + filter_len + (with_options ? 1 : 0) > buf_len)
			return 0;
		if (memchr(&buf[off + 2], '\0', filter_len) != NULL)
			return 0;
		off += 2 + filter_len;
		if (with_options) {
			opt = buf[off++];
			if ((opt & 0x03) == 0x03) /* QoS */
				return 0;
			if (v5) {
				if ((opt & 0xC0) || ((opt >> 4) & 0x03) == 0x03) /* Reserved, Retain Handling */
					return 0;
			} else if (opt & 0xFC) { /* Reserved */
				return 0;
			}
		}
		num++;
	}
	return num > 0;
}

/* SUBSCRIBE/UNSUBSCRIBE payload after the packet identifier. We don't know the protocol
   version, so accept both the 3.1.1 layout and the 5 one (with properties) */
static int check_subscribe_payload(const u_int8_t *buf, u_int32_t buf_len, int with_options)
{
	int props;

	if (check_topic_filters(buf, buf_len, with_options, 0))
		return 1;
	props = skip_properties(buf, buf_len);
	return props >= 0 && check_topic_filters(buf + props, buf_len - props, with_options, 1);
}

/* SUBACK/UNSUBACK payload after the packet identifier: as above, accept both
   the 3.1.1 layout (if any) and the 5 one (with properties) */
static int check_ack_payload(const u_int8_t *buf, u_int32_t buf_len,
			     const u_int8_t *set_v3, size_t set_v3_len,
			     const u_int8_t *set_v5, size_t set_v5_len)
{
	int props;

	if (set_v3 && check_reason_codes(buf, buf_len, set_v3, set_v3_len))
		return 1;
	props = skip_properties(buf, buf_len);
	return props >= 0 && check_reason_codes(buf + props, buf_len - props, set_v5, set_v5_len);
}

static int check_connect(struct ndpi_detection_module_struct *ndpi_struct,
			 const u_int8_t *p, u_int32_t rl)
{
	u_int16_t name_len, client_id_len;
	u_int8_t level, connect_flags;
	u_int32_t off;
	int props;

	if (rl < 2) {
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: CONNECT too short\n");
		return 0;
	}
	name_len = ntohs(get_u_int16_t(p, 0));
	/* Protocol name, level, connect flags, keep alive */
	off = 2 + name_len + 4;
	if (off > rl) {
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: CONNECT too short\n");
		return 0;
	}
	level = p[2 + name_len];
	connect_flags = p[2 + name_len + 1];
	if (name_len == 4 && memcmp(&p[2], "MQTT", 4) == 0) {
		if (level != 4 && level != 5) {
			NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: CONNECT invalid protocol level %d\n", level);
			return 0;
		}
	} else if (name_len == 6 && memcmp(&p[2], "MQIsdp", 6) == 0) {
		if (level != 3) {
			NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: CONNECT invalid protocol level %d\n", level);
			return 0;
		}
	} else {
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: CONNECT invalid protocol name\n");
		return 0;
	}
	if ((connect_flags & 0x01) || /* Reserved */
	    ((connect_flags >> 3) & 0x03) == 0x03 || /* Will QoS */
	    (!(connect_flags & 0x04) && (connect_flags & 0x38)) || /* Will QoS/Retain without Will Flag */
	    (level < 5 && (connect_flags & 0x40) && !(connect_flags & 0x80))) { /* Password without User Name */
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: CONNECT invalid flags 0x%x\n", connect_flags);
		return 0;
	}
	if (level == 5) {
		props = skip_properties(&p[off], rl - off);
		if (props < 0) {
			NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: CONNECT invalid properties\n");
			return 0;
		}
		off += props;
	}
	/* Client identifier is always present (even if empty) */
	if (off + 2 > rl) {
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: CONNECT without client identifier\n");
		return 0;
	}
	client_id_len = ntohs(get_u_int16_t(p, off));
	if (off + 2 + client_id_len > rl) {
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: CONNECT invalid client identifier length\n");
		return 0;
	}
	return 1;
}

static int check_publish(struct ndpi_detection_module_struct *ndpi_struct,
			 u_int8_t flags, const u_int8_t *p, u_int32_t rl)
{
	u_int8_t qos = (flags & 0x06) >> 1;
	u_int8_t dup = (flags & 0x08) >> 3;
	u_int16_t topic_len;
	u_int32_t i;

	if (qos > 2) { // qos values possible are 0,1,2
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: PUBLISH invalid qos\n");
		return 0;
	}
	if (qos == 0 && dup != 0) {
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: PUBLISH invalid qos0 and dup combination\n");
		return 0;
	}
	/* At least topic (3 bytes), plus packet identifier (2 bytes) if qos > 0.
	   Payload CAN be zero bytes length (section 3.3.3 of MQTT standard) */
	if (rl < (u_int32_t)(qos ? 5 : 3)) {
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: PUBLISH too short\n");
		return 0;
	}
	/* Topic name (and packet identifier) must fit in the remaining length. This also
	   prevents plain text (i.e. SMTP/FTP replies starting with a digit) from being
	   misclassified as Mqtt */
	topic_len = ntohs(get_u_int16_t(p, 0));
	if ((u_int32_t)2 + topic_len + (qos ? 2 : 0) > rl) {
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: PUBLISH invalid topic length\n");
		return 0;
	}
	for (i = 0; i < topic_len; i++) {
		u_int8_t c = p[2 + i];

		if (c == '\0' || c == '+' || c == '#') { /* Wildcards are not allowed in PUBLISH */
			NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: PUBLISH invalid topic\n");
			return 0;
		}
	}
	if (qos && get_u_int16_t(p, 2 + topic_len) == 0) {
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: PUBLISH invalid packet identifier\n");
		return 0;
	}
	return 1;
}

/* PUBACK, PUBREC, PUBREL, PUBCOMP: packet identifier, optionally (MQTT 5)
   followed by a reason code and by the properties */
static int check_pub_ack(struct ndpi_detection_module_struct *ndpi_struct,
			 u_int8_t pt, const u_int8_t *p, u_int32_t rl)
{
	if (rl < 2 || get_u_int16_t(p, 0) == 0) {
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: PUBACK/PUBREC/PUBREL/PUBCOMP invalid packet identifier\n");
		return 0;
	}
	if (rl == 2)
		return 1;
	if ((pt == PUBACK || pt == PUBREC) ? !IS_IN_SET(p[2], rc_puback_v5) : !IS_IN_SET(p[2], rc_pubrel_v5)) {
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: PUBACK/PUBREC/PUBREL/PUBCOMP invalid reason code\n");
		return 0;
	}
	if (rl > 3 && !properties_fill(&p[3], rl - 3)) {
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: PUBACK/PUBREC/PUBREL/PUBCOMP invalid properties\n");
		return 0;
	}
	return 1;
}

/* DISCONNECT, AUTH: empty, or (MQTT 5) reason code optionally followed by the properties */
static int check_reason_and_properties(struct ndpi_detection_module_struct *ndpi_struct,
				       const u_int8_t *p, u_int32_t rl,
				       const u_int8_t *set, size_t set_len)
{
	if (rl == 0)
		return 1;
	if (memchr(set, p[0], set_len) == NULL) {
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: DISCONNECT/AUTH invalid reason code\n");
		return 0;
	}
	if (rl > 1 && !properties_fill(&p[1], rl - 1)) {
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: DISCONNECT/AUTH invalid properties\n");
		return 0;
	}
	return 1;
}

static int check_mqtt_packet(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow,
			     u_int8_t pt, u_int8_t flags, const u_int8_t *p, u_int32_t rl)
{
	/* Packet direction is reliable only if we saw the 3WH */
	if (ndpi_seen_flow_beginning(flow)) {
		int from_client = current_pkt_from_client_to_server(ndpi_struct, &flow->core);

		if ((from_client && (pt == CONNACK || pt == SUBACK || pt == UNSUBACK || pt == PINGRESP)) ||
		    (!from_client && (pt == CONNECT || pt == SUBSCRIBE || pt == UNSUBSCRIBE || pt == PINGREQ))) {
			NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: packet type %d in the wrong direction\n", pt);
			return 0;
		}
	}

	/* Fixed header flags */
	if (pt != PUBLISH) {
		u_int8_t expected = (pt == PUBREL || pt == SUBSCRIBE || pt == UNSUBSCRIBE) ? 2 : 0;

		if (flags != expected) {
			NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: packet type %d with invalid flags 0x%x\n", pt, flags);
			return 0;
		}
	}

	switch (pt) {
	case CONNECT:
		return check_connect(ndpi_struct, p, rl);

	case CONNACK:
		if (rl < 2 || (p[0] & 0xFE)) { /* Only "Session Present" flag allowed */
			NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: CONNACK invalid\n");
			return 0;
		}
		if (rl == 2) { /* 3.1.1 */
			if (p[1] > 5) {
				NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: CONNACK invalid return code\n");
				return 0;
			}
			return 1;
		}
		/* 5 */
		if (!IS_IN_SET(p[1], rc_connack_v5) || !properties_fill(&p[2], rl - 2)) {
			NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: CONNACK invalid reason code or properties\n");
			return 0;
		}
		return 1;

	case PUBLISH:
		return check_publish(ndpi_struct, flags, p, rl);

	case PUBACK:
	case PUBREC:
	case PUBREL:
	case PUBCOMP:
		return check_pub_ack(ndpi_struct, pt, p, rl);

	case SUBSCRIBE:
	case UNSUBSCRIBE:
		if (rl < 2 || get_u_int16_t(p, 0) == 0 ||
		    !check_subscribe_payload(&p[2], rl - 2, pt == SUBSCRIBE)) {
			NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: SUBSCRIBE/UNSUBSCRIBE invalid\n");
			return 0;
		}
		return 1;

	case SUBACK:
		if (rl < 2 || get_u_int16_t(p, 0) == 0 ||
		    !check_ack_payload(&p[2], rl - 2, rc_suback_v3, sizeof(rc_suback_v3),
				       rc_suback_v5, sizeof(rc_suback_v5))) {
			NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: SUBACK invalid\n");
			return 0;
		}
		return 1;

	case UNSUBACK:
		if (rl < 2 || get_u_int16_t(p, 0) == 0 ||
		    (rl > 2 && /* 5 */
		     !check_ack_payload(&p[2], rl - 2, NULL, 0, rc_unsuback_v5, sizeof(rc_unsuback_v5)))) {
			NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: UNSUBACK invalid\n");
			return 0;
		}
		return 1;

	case PINGREQ:
	case PINGRESP:
		if (rl != 0) {
			NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: PINGREQ/PINGRESP with payload\n");
			return 0;
		}
		return 1;

	case DISCONNECT:
		return check_reason_and_properties(ndpi_struct, p, rl, rc_disconnect_v5, sizeof(rc_disconnect_v5));

	case AUTH:
		return check_reason_and_properties(ndpi_struct, p, rl, rc_auth_v5, sizeof(rc_auth_v5));

	default:
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: invalid packet type %d\n", pt);
		return 0;
	}
}

/**
 * Dissector function that searches Mqtt headers
 */
static void ndpi_search_mqtt(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &ndpi_struct->packet;
	u_int8_t pt, flags, rl_len;
	int64_t rl;

	NDPI_LOG_DBG(ndpi_struct, "search Mqtt\n");
	if (flow->core.packet_counter > 10) {
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: too many packets\n");
		NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
		return;
	}

	NDPI_LOG_DBG2(ndpi_struct, "====>>>> Mqtt header: %4x%4x%4x%4x [len: %u]\n",
		      packet->payload_packet_len > 0 ? packet->payload[0] : '.',
		      packet->payload_packet_len > 1 ? packet->payload[1] : '.',
		      packet->payload_packet_len > 2 ? packet->payload[2] : '.',
		      packet->payload_packet_len > 3 ? packet->payload[3] : '.',
		      packet->payload_packet_len);
	if (packet->payload_packet_len < 2) {
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: packet too short\n");
		NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
		return;
	}
	// we extract the remaining length
	rl = get_var_int(&packet->payload[1], packet->payload_packet_len - 1, &rl_len);
	if (rl < 0) {
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: invalid remaining length\n");
		NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
		return;
	}
	NDPI_LOG_DBG(ndpi_struct, "Mqtt: msg_len %lld\n", (long long)rl);
	if (packet->payload_packet_len != rl + 1 + rl_len) {
		NDPI_LOG_DBG(ndpi_struct, "Excluding Mqtt: remaining length doesn't match packet length\n");
		NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
		return;
	}
	pt = (u_int8_t) ((packet->payload[0] & 0xF0) >> 4);
	flags = (u_int8_t) (packet->payload[0] & 0x0F);
	NDPI_LOG_DBG2(ndpi_struct, "====>>>> Mqtt packet type: [%d] flags: [%d]\n", pt, flags);

	if (!check_mqtt_packet(ndpi_struct, flow, pt, flags, &packet->payload[1 + rl_len], (u_int32_t)rl)) {
		NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
		return;
	}

	/* Very short packets (i.e. PINGREQ, PUBACK) have too few bytes to validate:
	   wait for another valid Mqtt packet */
	if (packet->payload_packet_len <= 5 && !flow->metadata.l4.tcp.mqtt_weak_match) {
		NDPI_LOG_DBG(ndpi_struct, "Mqtt: weak match (type %d), waiting for another packet\n", pt);
		flow->metadata.l4.tcp.mqtt_weak_match = 1;
		return;
	}

	NDPI_LOG_INFO(ndpi_struct, "found Mqtt (type %d)\n", pt);
	ndpi_int_mqtt_add_connection(ndpi_struct, flow);
}

/**
 * Entry point for the ndpi library
 */
void init_mqtt_dissector (struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("MQTT", ndpi_struct,
                     ndpi_search_mqtt,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                      DISSECTOR_LICENSE_LGPL,
                      1, NDPI_PROTOCOL_MQTT);
}
