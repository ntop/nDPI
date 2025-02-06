/*
 * mail_imap.c
 *
 * Copyright (C) 2016-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_MAIL_IMAP

#include "ndpi_api.h"
#include "ndpi_private.h"

/* #define IMAP_DEBUG 1*/

static void ndpi_int_mail_imap_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow,
					      u_int16_t protocol) {
  ndpi_set_detected_protocol(ndpi_struct, flow, protocol, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

static void ndpi_search_mail_imap_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t i = 0;
  u_int16_t space_pos = 0;
  u_int16_t command_start = 0;
  u_int8_t saw_command = 0;
  /* const u_int8_t *command = 0; */

  NDPI_LOG_DBG(ndpi_struct, "search IMAP_IMAP\n");

#ifdef IMAP_DEBUG
  printf("%s() [%.*s]\n", __FUNCTION__, packet->payload_packet_len, packet->payload);
#endif

  if(packet->payload_packet_len >= 4 && ntohs(get_u_int16_t(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a) {
    // the DONE command appears without a tag
    if(packet->payload_packet_len == 6 && ((packet->payload[0] == 'D' || packet->payload[0] == 'd')
					    && (packet->payload[1] == 'O' || packet->payload[1] == 'o')
					    && (packet->payload[2] == 'N' || packet->payload[2] == 'n')
					    && (packet->payload[3] == 'E' || packet->payload[3] == 'e'))) {
      flow->l4.tcp.mail_imap_stage += 1;
      saw_command = 1;
    } else {
      if(flow->l4.tcp.mail_imap_stage < 5) {
	// search for the first space character (end of the tag)
	while (i < 20 && i < packet->payload_packet_len) {
	  if(i > 0 && packet->payload[i] == ' ') {
	    space_pos = i;
	    break;
	  }
	  if(!((packet->payload[i] >= 'a' && packet->payload[i] <= 'z') ||
		(packet->payload[i] >= 'A' && packet->payload[i] <= 'Z') ||
		(packet->payload[i] >= '0' && packet->payload[i] <= '9') || packet->payload[i] == '*' || packet->payload[i] == '.')) {
	    goto imap_excluded;
	  }
	  i++;
	}
	if(space_pos == 0 || space_pos == (packet->payload_packet_len - 1)) {
	  goto imap_excluded;
	}
	// now walk over a possible mail number to the next space
	i++;
	if(i < packet->payload_packet_len && (packet->payload[i] >= '0' && packet->payload[i] <= '9')) {
	  while (i < 20 && i < packet->payload_packet_len) {
	    if(i > 0 && packet->payload[i] == ' ') {
	      space_pos = i;
	      break;
	    }
	    if(!(packet->payload[i] >= '0' && packet->payload[i] <= '9')) {
	      goto imap_excluded;
	    }
	    i++;
	  }
	  if(space_pos == 0 || space_pos == (packet->payload_packet_len - 1)) {
	    goto imap_excluded;
	  }
	}
	command_start = space_pos + 1;
	/* command = &(packet->payload[command_start]); */
      } else {
	command_start = 0;
	/* command = &(packet->payload[command_start]); */
      }

      if((command_start + 3) < packet->payload_packet_len) {
	if((packet->payload[command_start] == 'O' || packet->payload[command_start] == 'o')
	    && (packet->payload[command_start + 1] == 'K' || packet->payload[command_start + 1] == 'k')
	    && packet->payload[command_start + 2] == ' ') {
	  flow->l4.tcp.mail_imap_stage += 1;
	  if(flow->l4.tcp.mail_imap_starttls == 1) {
	    NDPI_LOG_DBG2(ndpi_struct, "starttls detected\n");
	    ndpi_int_mail_imap_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_MAIL_IMAPS);
	    if(ndpi_struct->cfg.imap_opportunistic_tls_enabled) {
	      NDPI_LOG_DBG(ndpi_struct, "Switching to [%d/%d]\n",
			   flow->detected_protocol_stack[0], flow->detected_protocol_stack[1]);
	      /* We are done (in IMAP dissector): delegating TLS... */
	      switch_extra_dissection_to_tls(ndpi_struct, flow);
	      return;
	    }
	  }
	  saw_command = 1;
	} else if((packet->payload[command_start] == 'U' || packet->payload[command_start] == 'u')
		   && (packet->payload[command_start + 1] == 'I' || packet->payload[command_start + 1] == 'i')
		   && (packet->payload[command_start + 2] == 'D' || packet->payload[command_start + 2] == 'd')) {
	  flow->l4.tcp.mail_imap_stage += 1;
	  saw_command = 1;
	} else if((packet->payload[command_start] == 'N' || packet->payload[command_start] == 'n')
	    && (packet->payload[command_start + 1] == 'O' || packet->payload[command_start + 1] == 'o')
	    && packet->payload[command_start + 2] == ' ') {
	  flow->l4.tcp.mail_imap_stage += 1;
	  if(flow->l4.tcp.mail_imap_starttls == 1)
	    flow->l4.tcp.mail_imap_starttls = 0;
	  saw_command = 1;
	}
      }
      if((command_start + 10) < packet->payload_packet_len) {
	if((packet->payload[command_start] == 'C' || packet->payload[command_start] == 'c')
	    && (packet->payload[command_start + 1] == 'A' || packet->payload[command_start + 1] == 'a')
	    && (packet->payload[command_start + 2] == 'P' || packet->payload[command_start + 2] == 'p')
	    && (packet->payload[command_start + 3] == 'A' || packet->payload[command_start + 3] == 'a')
	    && (packet->payload[command_start + 4] == 'B' || packet->payload[command_start + 4] == 'b')
	    && (packet->payload[command_start + 5] == 'I' || packet->payload[command_start + 5] == 'i')
	    && (packet->payload[command_start + 6] == 'L' || packet->payload[command_start + 6] == 'l')
	    && (packet->payload[command_start + 7] == 'I' || packet->payload[command_start + 7] == 'i')
	    && (packet->payload[command_start + 8] == 'T' || packet->payload[command_start + 8] == 't')
	    && (packet->payload[command_start + 9] == 'Y' || packet->payload[command_start + 9] == 'y')) {
	  flow->l4.tcp.mail_imap_stage += 1;
	  saw_command = 1;
	}
      }
      if((command_start + 8) < packet->payload_packet_len) {
	if((packet->payload[command_start] == 'S' || packet->payload[command_start] == 's')
	    && (packet->payload[command_start + 1] == 'T' || packet->payload[command_start + 1] == 't')
	    && (packet->payload[command_start + 2] == 'A' || packet->payload[command_start + 2] == 'a')
	    && (packet->payload[command_start + 3] == 'R' || packet->payload[command_start + 3] == 'r')
	    && (packet->payload[command_start + 4] == 'T' || packet->payload[command_start + 4] == 't')
	    && (packet->payload[command_start + 5] == 'T' || packet->payload[command_start + 5] == 't')
	    && (packet->payload[command_start + 6] == 'L' || packet->payload[command_start + 6] == 'l')
	    && (packet->payload[command_start + 7] == 'S' || packet->payload[command_start + 7] == 's')) {
        flow->l4.tcp.mail_imap_stage += 1;
        flow->l4.tcp.mail_imap_starttls = 1;
        saw_command = 1;
	}
      }
      if((command_start + 5) < packet->payload_packet_len) {
	if((packet->payload[command_start] == 'L' || packet->payload[command_start] == 'l')
	    && (packet->payload[command_start + 1] == 'O' || packet->payload[command_start + 1] == 'o')
	    && (packet->payload[command_start + 2] == 'G' || packet->payload[command_start + 2] == 'g')
	    && (packet->payload[command_start + 3] == 'I' || packet->payload[command_start + 3] == 'i')
	    && (packet->payload[command_start + 4] == 'N' || packet->payload[command_start + 4] == 'n')) {
	  /* xxxx LOGIN "username" "password"
	     xxxx LOGIN username password */
	  char str[256], *user, *saveptr;
	  u_int len = ndpi_min(packet->payload_packet_len - (command_start + 5), (int)sizeof(str) - 1);

	  strncpy(str, (const char*)packet->payload + command_start + 5, len);
	  str[len] = '\0';

	  user = strtok_r(str, " \"\r\n", &saveptr);
	  if(user) {
	    char *pwd, buf[64];

	    ndpi_snprintf(flow->l4.tcp.ftp_imap_pop_smtp.username,
		     sizeof(flow->l4.tcp.ftp_imap_pop_smtp.username),
		     "%s", user);

	    snprintf(buf, sizeof(buf), "Found IMAP username (%s)",
		     flow->l4.tcp.ftp_imap_pop_smtp.username);
	    ndpi_set_risk(ndpi_struct, flow, NDPI_CLEAR_TEXT_CREDENTIALS, buf);

	    pwd = strtok_r(NULL, " \"\r\n", &saveptr);
	    if(pwd) {
	      ndpi_snprintf(flow->l4.tcp.ftp_imap_pop_smtp.password,
		       sizeof(flow->l4.tcp.ftp_imap_pop_smtp.password),
	               "%s", pwd);
	    }
	  }
	  
	  flow->l4.tcp.mail_imap_stage += 1;
	  saw_command = 1;
	} else if((packet->payload[command_start] == 'F' || packet->payload[command_start] == 'f')
		   && (packet->payload[command_start + 1] == 'E' || packet->payload[command_start + 1] == 'e')
		   && (packet->payload[command_start + 2] == 'T' || packet->payload[command_start + 2] == 't')
		   && (packet->payload[command_start + 3] == 'C' || packet->payload[command_start + 3] == 'c')
		   && (packet->payload[command_start + 4] == 'H' || packet->payload[command_start + 4] == 'h')) {
	  flow->l4.tcp.mail_imap_stage += 1;
	  saw_command = 1;
	} else if((packet->payload[command_start] == 'F' || packet->payload[command_start] == 'f')
		   && (packet->payload[command_start + 1] == 'L' || packet->payload[command_start + 1] == 'l')
		   && (packet->payload[command_start + 2] == 'A' || packet->payload[command_start + 2] == 'a')
		   && (packet->payload[command_start + 3] == 'G' || packet->payload[command_start + 3] == 'g')
		   && (packet->payload[command_start + 4] == 'S' || packet->payload[command_start + 4] == 's')) {
	  flow->l4.tcp.mail_imap_stage += 1;
	  saw_command = 1;
	} else if((packet->payload[command_start] == 'C' || packet->payload[command_start] == 'c')
		   && (packet->payload[command_start + 1] == 'H' || packet->payload[command_start + 1] == 'h')
		   && (packet->payload[command_start + 2] == 'E' || packet->payload[command_start + 2] == 'e')
		   && (packet->payload[command_start + 3] == 'C' || packet->payload[command_start + 3] == 'c')
		   && (packet->payload[command_start + 4] == 'K' || packet->payload[command_start + 4] == 'k')) {
	  flow->l4.tcp.mail_imap_stage += 1;
	  saw_command = 1;
	} else if((packet->payload[command_start] == 'S' || packet->payload[command_start] == 's')
		   && (packet->payload[command_start + 1] == 'T' || packet->payload[command_start + 1] == 't')
		   && (packet->payload[command_start + 2] == 'O' || packet->payload[command_start + 2] == 'o')
		   && (packet->payload[command_start + 3] == 'R' || packet->payload[command_start + 3] == 'r')
		   && (packet->payload[command_start + 4] == 'E' || packet->payload[command_start + 4] == 'e')) {
	  flow->l4.tcp.mail_imap_stage += 1;
	  saw_command = 1;
	}
      }
      if((command_start + 12) < packet->payload_packet_len) {
	if((packet->payload[command_start] == 'A' || packet->payload[command_start] == 'a')
	    && (packet->payload[command_start + 1] == 'U' || packet->payload[command_start + 1] == 'u')
	    && (packet->payload[command_start + 2] == 'T' || packet->payload[command_start + 2] == 't')
	    && (packet->payload[command_start + 3] == 'H' || packet->payload[command_start + 3] == 'h')
	    && (packet->payload[command_start + 4] == 'E' || packet->payload[command_start + 4] == 'e')
	    && (packet->payload[command_start + 5] == 'N' || packet->payload[command_start + 5] == 'n')
	    && (packet->payload[command_start + 6] == 'T' || packet->payload[command_start + 6] == 't')
	    && (packet->payload[command_start + 7] == 'I' || packet->payload[command_start + 7] == 'i')
	    && (packet->payload[command_start + 8] == 'C' || packet->payload[command_start + 8] == 'c')
	    && (packet->payload[command_start + 9] == 'A' || packet->payload[command_start + 9] == 'a')
	    && (packet->payload[command_start + 10] == 'T' || packet->payload[command_start + 10] == 't')
	    && (packet->payload[command_start + 11] == 'E' || packet->payload[command_start + 11] == 'e')) {
	  flow->l4.tcp.mail_imap_stage += 1;
	  /* Authenticate phase may have multiple messages. Ignore them since they are
	     somehow encrypted anyway. */
          ndpi_int_mail_imap_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_MAIL_IMAPS);
	  saw_command = 1;
	}
      }
      if((command_start + 9) < packet->payload_packet_len) {
	if((packet->payload[command_start] == 'N' || packet->payload[command_start] == 'n')
	    && (packet->payload[command_start + 1] == 'A' || packet->payload[command_start + 1] == 'a')
	    && (packet->payload[command_start + 2] == 'M' || packet->payload[command_start + 2] == 'm')
	    && (packet->payload[command_start + 3] == 'E' || packet->payload[command_start + 3] == 'e')
	    && (packet->payload[command_start + 4] == 'S' || packet->payload[command_start + 4] == 's')
	    && (packet->payload[command_start + 5] == 'P' || packet->payload[command_start + 5] == 'p')
	    && (packet->payload[command_start + 6] == 'A' || packet->payload[command_start + 6] == 'a')
	    && (packet->payload[command_start + 7] == 'C' || packet->payload[command_start + 7] == 'c')
	    && (packet->payload[command_start + 8] == 'E' || packet->payload[command_start + 8] == 'e')) {
	  flow->l4.tcp.mail_imap_stage += 1;
	  saw_command = 1;
	}
      }
      if((command_start + 4) < packet->payload_packet_len) {
	if((packet->payload[command_start] == 'L' || packet->payload[command_start] == 'l')
	    && (packet->payload[command_start + 1] == 'S' || packet->payload[command_start + 1] == 's')
	    && (packet->payload[command_start + 2] == 'U' || packet->payload[command_start + 2] == 'u')
	    && (packet->payload[command_start + 3] == 'B' || packet->payload[command_start + 3] == 'b')) {
	  flow->l4.tcp.mail_imap_stage += 1;
	  saw_command = 1;
	} else if((packet->payload[command_start] == 'L' || packet->payload[command_start] == 'l')
		   && (packet->payload[command_start + 1] == 'I' || packet->payload[command_start + 1] == 'i')
		   && (packet->payload[command_start + 2] == 'S' || packet->payload[command_start + 2] == 's')
		   && (packet->payload[command_start + 3] == 'T' || packet->payload[command_start + 3] == 't')) {
	  flow->l4.tcp.mail_imap_stage += 1;
	  saw_command = 1;
	} else if((packet->payload[command_start] == 'N' || packet->payload[command_start] == 'n')
		   && (packet->payload[command_start + 1] == 'O' || packet->payload[command_start + 1] == 'o')
		   && (packet->payload[command_start + 2] == 'O' || packet->payload[command_start + 2] == 'o')
		   && (packet->payload[command_start + 3] == 'P' || packet->payload[command_start + 3] == 'p')) {
	  flow->l4.tcp.mail_imap_stage += 1;
	  saw_command = 1;
	} else if((packet->payload[command_start] == 'I' || packet->payload[command_start] == 'i')
		   && (packet->payload[command_start + 1] == 'D' || packet->payload[command_start + 1] == 'd')
		   && (packet->payload[command_start + 2] == 'L' || packet->payload[command_start + 2] == 'l')
		   && (packet->payload[command_start + 3] == 'E' || packet->payload[command_start + 3] == 'e')) {
	  flow->l4.tcp.mail_imap_stage += 1;
	  saw_command = 1;
	}
      }
      if((command_start + 6) < packet->payload_packet_len) {
	if((packet->payload[command_start] == 'S' || packet->payload[command_start] == 's')
	    && (packet->payload[command_start + 1] == 'E' || packet->payload[command_start + 1] == 'e')
	    && (packet->payload[command_start + 2] == 'L' || packet->payload[command_start + 2] == 'l')
	    && (packet->payload[command_start + 3] == 'E' || packet->payload[command_start + 3] == 'e')
	    && (packet->payload[command_start + 4] == 'C' || packet->payload[command_start + 4] == 'c')
	    && (packet->payload[command_start + 5] == 'T' || packet->payload[command_start + 5] == 't')) {
	  flow->l4.tcp.mail_imap_stage += 1;
	  saw_command = 1;
	} else if((packet->payload[command_start] == 'E' || packet->payload[command_start] == 'e')
		   && (packet->payload[command_start + 1] == 'X' || packet->payload[command_start + 1] == 'x')
		   && (packet->payload[command_start + 2] == 'I' || packet->payload[command_start + 2] == 'i')
		   && (packet->payload[command_start + 3] == 'S' || packet->payload[command_start + 3] == 's')
		   && (packet->payload[command_start + 4] == 'T' || packet->payload[command_start + 4] == 't')
		   && (packet->payload[command_start + 5] == 'S' || packet->payload[command_start + 5] == 's')) {
	  flow->l4.tcp.mail_imap_stage += 1;
	  saw_command = 1;
	} else if((packet->payload[command_start] == 'A' || packet->payload[command_start] == 'a')
		   && (packet->payload[command_start + 1] == 'P' || packet->payload[command_start + 1] == 'p')
		   && (packet->payload[command_start + 2] == 'P' || packet->payload[command_start + 2] == 'p')
		   && (packet->payload[command_start + 3] == 'E' || packet->payload[command_start + 3] == 'e')
		   && (packet->payload[command_start + 4] == 'N' || packet->payload[command_start + 4] == 'n')
		   && (packet->payload[command_start + 5] == 'D' || packet->payload[command_start + 5] == 'd')) {
	  flow->l4.tcp.mail_imap_stage += 1;
	  saw_command = 1;
	}
      }

    }

    if(saw_command == 1) {
      if((flow->l4.tcp.mail_imap_stage == 3)
	 || (flow->l4.tcp.mail_imap_stage == 5)
	 || (flow->l4.tcp.mail_imap_stage == 7)
        ) {
	if((flow->l4.tcp.ftp_imap_pop_smtp.username[0] != '\0')
	   || (flow->l4.tcp.mail_imap_stage >= 7)) {
	  NDPI_LOG_INFO(ndpi_struct, "found MAIL_IMAP\n");
	  ndpi_int_mail_imap_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_MAIL_IMAP);
	}
	
	return;
      }
    }
  }

  if(packet->payload_packet_len > 1 && packet->payload[packet->payload_packet_len - 1] == ' ') {
    NDPI_LOG_DBG2(ndpi_struct,
	     "maybe a split imap command -> need next packet and imap_stage is set to 4.\n");
    flow->l4.tcp.mail_imap_stage = 4;
    return;
  }

 imap_excluded:

  // skip over possible authentication hashes etc. that cannot be identified as imap commands or responses
  // if the packet count is low enough and at least one command or response was seen before
  if((packet->payload_packet_len >= 2 && ntohs(get_u_int16_t(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a)
      && flow->packet_counter < 8 && flow->l4.tcp.mail_imap_stage >= 1) {
    NDPI_LOG_DBG2(ndpi_struct,
	     "no imap command or response but packet count < 6 and imap stage >= 1 -> skip\n");
    return;
  }

  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_mail_imap_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("MAIL_IMAP", ndpi_struct, *id,
				      NDPI_PROTOCOL_MAIL_IMAP,
				      ndpi_search_mail_imap_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
