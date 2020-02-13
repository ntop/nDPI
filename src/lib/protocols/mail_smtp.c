/*
 * mail_smtp.c
 *
 * Copyright (C) 2011-20 - ntop.org
 * Copyright (C) 2009-2011 by ipoque GmbH
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MAIL_SMTP

#include "ndpi_api.h"


#define SMTP_BIT_220		0x01
#define SMTP_BIT_250		0x02
#define SMTP_BIT_235		0x04
#define SMTP_BIT_334		0x08
#define SMTP_BIT_354		0x10
#define SMTP_BIT_HELO_EHLO	0x20
#define SMTP_BIT_MAIL		0x40
#define SMTP_BIT_RCPT		0x80
#define SMTP_BIT_AUTH		0x100
#define SMTP_BIT_STARTTLS	0x200
#define SMTP_BIT_DATA		0x400
#define SMTP_BIT_NOOP		0x800
#define SMTP_BIT_RSET		0x1000
#define SMTP_BIT_TlRM		0x2000

/* #define SMTP_DEBUG 1 */

static void ndpi_int_mail_smtp_add_connection(struct ndpi_detection_module_struct
					      *ndpi_struct, struct ndpi_flow_struct *flow) {
#ifdef SMTP_DEBUG
  printf("**** %s()\n", __FUNCTION__);
#endif
  
  ndpi_set_detected_protocol(ndpi_struct, flow,
			     NDPI_PROTOCOL_MAIL_SMTP, NDPI_PROTOCOL_UNKNOWN);
}

/* **************************************** */

static void smtpInitExtraPacketProcessing(struct ndpi_flow_struct *flow);

/* **************************************** */

void ndpi_search_mail_smtp_tcp(struct ndpi_detection_module_struct *ndpi_struct,
			       struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search mail_smtp\n");

  if((packet->payload_packet_len > 2)
     && (packet->parsed_lines <  NDPI_MAX_PARSE_LINES_PER_PACKET)
     && (ntohs(get_u_int16_t(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a)
     ) {
    u_int16_t a;
    u_int8_t bit_count = 0;

    NDPI_PARSE_PACKET_LINE_INFO(ndpi_struct, flow, packet);

    for(a = 0; a < packet->parsed_lines; a++) {
      // expected server responses
      if(packet->line[a].len >= 3) {
	if(memcmp(packet->line[a].ptr, "220", 3) == 0) {
	  flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_220;
	} else if(memcmp(packet->line[a].ptr, "250", 3) == 0) {
	  flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_250;
	} else if(memcmp(packet->line[a].ptr, "235", 3) == 0) {
	  flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_235;
	} else if(memcmp(packet->line[a].ptr, "334", 3) == 0) {
	  flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_334;
	} else if(memcmp(packet->line[a].ptr, "354", 3) == 0) {
	  flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_354;
	}
      }

      // expected client requests
      if(packet->line[a].len >= 5) {
	if((((packet->line[a].ptr[0] == 'H' || packet->line[a].ptr[0] == 'h')
	     && (packet->line[a].ptr[1] == 'E' || packet->line[a].ptr[1] == 'e'))
	    || ((packet->line[a].ptr[0] == 'E' || packet->line[a].ptr[0] == 'e')
		&& (packet->line[a].ptr[1] == 'H' || packet->line[a].ptr[1] == 'h')))
	   && (packet->line[a].ptr[2] == 'L' || packet->line[a].ptr[2] == 'l')
	   && (packet->line[a].ptr[3] == 'O' || packet->line[a].ptr[3] == 'o')
	   && packet->line[a].ptr[4] == ' ') {
	  flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_HELO_EHLO;
	  flow->protos.ftp_imap_pop_smtp.auth_found = 0;
	} else if((packet->line[a].ptr[0] == 'M' || packet->line[a].ptr[0] == 'm')
		  && (packet->line[a].ptr[1] == 'A' || packet->line[a].ptr[1] == 'a')
		  && (packet->line[a].ptr[2] == 'I' || packet->line[a].ptr[2] == 'i')
		  && (packet->line[a].ptr[3] == 'L' || packet->line[a].ptr[3] == 'l')
		  && packet->line[a].ptr[4] == ' ') {
	  flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_MAIL;
	  flow->protos.ftp_imap_pop_smtp.auth_found = 0;
	} else if((packet->line[a].ptr[0] == 'R' || packet->line[a].ptr[0] == 'r')
		  && (packet->line[a].ptr[1] == 'C' || packet->line[a].ptr[1] == 'c')
		  && (packet->line[a].ptr[2] == 'P' || packet->line[a].ptr[2] == 'p')
		  && (packet->line[a].ptr[3] == 'T' || packet->line[a].ptr[3] == 't')
		  && packet->line[a].ptr[4] == ' ') {
	  flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_RCPT;
	  flow->protos.ftp_imap_pop_smtp.auth_found = 0;
	} else if((packet->line[a].ptr[0] == 'A' || packet->line[a].ptr[0] == 'a')
		  && (packet->line[a].ptr[1] == 'U' || packet->line[a].ptr[1] == 'u')
		  && (packet->line[a].ptr[2] == 'T' || packet->line[a].ptr[2] == 't')
		  && (packet->line[a].ptr[3] == 'H' || packet->line[a].ptr[3] == 'h')
		  && packet->line[a].ptr[4] == ' ') {
#ifdef SMTP_DEBUG
	  printf("%s() AUTH [%s]\n", __FUNCTION__, packet->line[a].ptr);
#endif

	  flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_AUTH;
	  flow->protos.ftp_imap_pop_smtp.auth_found = 1;
	} else {
	  if(packet->line[a].ptr[3] != ' ') {
#ifdef SMTP_DEBUG
	    printf("%s() => [%s]\n", __FUNCTION__, packet->line[a].ptr);
#endif
	    
	    if(flow->protos.ftp_imap_pop_smtp.auth_found) {
	      if(flow->protos.ftp_imap_pop_smtp.username[0] == '\0') {
		/* Username */
		u_int8_t buf[48];
		u_char *out;
		size_t out_len;

		ndpi_user_pwd_payload_copy(buf, sizeof(buf), 0,
					   packet->line[a].ptr, packet->line[a].len);

#ifdef SMTP_DEBUG
		printf("%s() => [auth: %u] (username) [%s]\n", __FUNCTION__, flow->protos.ftp_imap_pop_smtp.auth_found, buf);
#endif

		out = ndpi_base64_decode((const u_char*)buf, (size_t)strlen((const char*)buf), &out_len);

		if(out) {
		  size_t len = ndpi_min(out_len, sizeof(flow->protos.ftp_imap_pop_smtp.username) - 1);

		  memcpy(flow->protos.ftp_imap_pop_smtp.username, out, len);
		  flow->protos.ftp_imap_pop_smtp.username[len] = '\0';
		  
		  ndpi_free(out);
		}
	      } else if(flow->protos.ftp_imap_pop_smtp.password[0] == '\0') {
		/* Password */
		u_int8_t buf[48];
		u_char *out;
		size_t out_len;

		ndpi_user_pwd_payload_copy(buf, sizeof(buf), 0,
					   packet->line[a].ptr, packet->line[a].len);

#ifdef SMTP_DEBUG
		printf("%s() => [auth: %u] (password) [%s]\n", __FUNCTION__, flow->protos.ftp_imap_pop_smtp.auth_found, buf);
#endif

		out = ndpi_base64_decode((const u_char*)buf, (size_t)strlen((const char*)buf), &out_len);

		if(out) {
		  size_t len = ndpi_min(out_len, sizeof(flow->protos.ftp_imap_pop_smtp.password) - 1);

		  memcpy(flow->protos.ftp_imap_pop_smtp.password, out, len);
		  flow->protos.ftp_imap_pop_smtp.password[len] = '\0';

		  ndpi_free(out);
		}
	      } else {
		NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
		return;
	      }
	    }
	  }
	}
      }

      if(packet->line[a].len >= 8) {
	if((packet->line[a].ptr[0] == 'S' || packet->line[a].ptr[0] == 's')
	   && (packet->line[a].ptr[1] == 'T' || packet->line[a].ptr[1] == 't')
	   && (packet->line[a].ptr[2] == 'A' || packet->line[a].ptr[2] == 'a')
	   && (packet->line[a].ptr[3] == 'R' || packet->line[a].ptr[3] == 'r')
	   && (packet->line[a].ptr[4] == 'T' || packet->line[a].ptr[4] == 't')
	   && (packet->line[a].ptr[5] == 'T' || packet->line[a].ptr[5] == 't')
	   && (packet->line[a].ptr[6] == 'L' || packet->line[a].ptr[6] == 'l')
	   && (packet->line[a].ptr[7] == 'S' || packet->line[a].ptr[7] == 's')) {
	  flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_STARTTLS;
	}
      }

      if(packet->line[a].len >= 4) {
	if((packet->line[a].ptr[0] == 'D' || packet->line[a].ptr[0] == 'd')
	   && (packet->line[a].ptr[1] == 'A' || packet->line[a].ptr[1] == 'a')
	   && (packet->line[a].ptr[2] == 'T' || packet->line[a].ptr[2] == 't')
	   && (packet->line[a].ptr[3] == 'A' || packet->line[a].ptr[3] == 'a')) {
	  flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_DATA;
	} else if((packet->line[a].ptr[0] == 'N' || packet->line[a].ptr[0] == 'n')
		  && (packet->line[a].ptr[1] == 'O' || packet->line[a].ptr[1] == 'o')
		  && (packet->line[a].ptr[2] == 'O' || packet->line[a].ptr[2] == 'o')
		  && (packet->line[a].ptr[3] == 'P' || packet->line[a].ptr[3] == 'p')) {
	  flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_NOOP;
	} else if((packet->line[a].ptr[0] == 'R' || packet->line[a].ptr[0] == 'r')
		  && (packet->line[a].ptr[1] == 'S' || packet->line[a].ptr[1] == 's')
		  && (packet->line[a].ptr[2] == 'E' || packet->line[a].ptr[2] == 'e')
		  && (packet->line[a].ptr[3] == 'T' || packet->line[a].ptr[3] == 't')) {
	  flow->l4.tcp.smtp_command_bitmask |= SMTP_BIT_RSET;
	}
      }
    }

    // now count the bits set in the bitmask
    if(flow->l4.tcp.smtp_command_bitmask != 0) {
      for(a = 0; a < 16; a++) {
	bit_count += (flow->l4.tcp.smtp_command_bitmask >> a) & 0x01;
      }
    }
    NDPI_LOG_DBG2(ndpi_struct, "seen smtp commands and responses: %u\n",
		  bit_count);

    if(bit_count >= 3) {
      NDPI_LOG_INFO(ndpi_struct, "mail smtp identified\n");

#ifdef SMTP_DEBUG
      printf("%s() [bit_count: %u][%s]\n", __FUNCTION__,
	     bit_count, flow->protos.ftp_imap_pop_smtp.password);
#endif

      ndpi_int_mail_smtp_add_connection(ndpi_struct, flow);
      smtpInitExtraPacketProcessing(flow);      
      return;
    }

    if(bit_count >= 1 && flow->packet_counter < 12) {
      return;
    }
  }

  /* when the first or second packets are split into two packets, those packets are ignored. */
  if(flow->packet_counter <= 4 &&
     packet->payload_packet_len >= 4 &&
     (ntohs(get_u_int16_t(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a
      || memcmp(packet->payload, "220", 3) == 0 || memcmp(packet->payload, "EHLO", 4) == 0)) {
    NDPI_LOG_DBG2(ndpi_struct, "maybe SMTP, need next packet\n");
    return;
  }

  if(!flow->check_extra_packets)
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* **************************************** */

int ndpi_extra_search_mail_smtp_tcp(struct ndpi_detection_module_struct *ndpi_struct,
				    struct ndpi_flow_struct *flow) {
  int rc;
  
  ndpi_search_mail_smtp_tcp(ndpi_struct, flow);

  rc = (flow->protos.ftp_imap_pop_smtp.password[0] == '\0') ? 1 : 0;
  
#ifdef SMTP_DEBUG
  printf("**** %s() [rc: %d]\n", __FUNCTION__, rc);
#endif  

  return(rc);
}

/* **************************************** */

static void smtpInitExtraPacketProcessing(struct ndpi_flow_struct *flow) {
#ifdef SMTP_DEBUG
  static u_int num = 0;
  
  printf("**** %s(%u)\n", __FUNCTION__, ++num);
#endif
  
  flow->check_extra_packets = 1;
  /* At most 7 packets should almost always be enough */
  flow->max_extra_packets_to_check = 12;
  flow->extra_packets_func = ndpi_extra_search_mail_smtp_tcp;
}

/* **************************************** */

void init_mail_smtp_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			      u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("MAIL_SMTP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_MAIL_SMTP,
				      ndpi_search_mail_smtp_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
