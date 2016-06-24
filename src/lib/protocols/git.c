/*
 * git.c
 *
 * Copyright (C) 2012-16 - ntop.org
 *
 * This module is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License.
 * If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <stdlib.h>
#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_GIT

#define GIT_PORT 9418

/* read all the length even if there is a null byte inside */
u_int16_t read_all_len(char * s, u_int16_t git_len)
{
  char * p = s;
  int c = 0;
  while(*p && c < git_len-4) {
    c++;
    p++;
    if(!*p) {
      if(c < git_len-4)	{
	p++;
	c++;
      }
    }
  }
  return c;
}

void ndpi_search_git(struct ndpi_detection_module_struct *ndpi_struct,
		      struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct * packet = &flow->packet;
  const u_int8_t * pp = packet->payload;
  u_int16_t payload_len = packet->payload_packet_len;
  
  u_int8_t * git_pkt_len_buff = NULL;
  u_int8_t * git_pkt_data = NULL;
  u_int16_t git_len = 0, count = 0 , is_git = 0;

  if(packet->tcp != NULL) {

    if((ntohs(packet->tcp->source) == GIT_PORT ||
	ntohs(packet->tcp->dest) == GIT_PORT)) {

      git_pkt_len_buff = malloc(4 * sizeof(u_int8_t));

      do {
	 memcpy(git_pkt_len_buff, pp, 4);
	 git_len = (int)strtol(git_pkt_len_buff, NULL, 16);
	 
	 if(git_pkt_len_buff[0] == 48 &&
	    git_pkt_len_buff[1] == 48 &&
	    git_pkt_len_buff[2] == 48 &&
	    git_pkt_len_buff[3] == 48)
	   /* Terminator packet */
	   count += 4;
	 else {
	      git_pkt_data = malloc((git_len-4) * sizeof(u_int8_t));
	      memcpy(git_pkt_data, pp+4, git_len-4);
	      u_int16_t data_len = read_all_len(git_pkt_data, git_len);
	      free(git_pkt_data);
	      
	      if(git_len != data_len+4)
		    goto no_git;
	      else {
		    count += git_len;
		    pp += git_len;
	      }
	 }
      } while(count < payload_len);
    }
    else goto no_git;
  }
  else goto no_git;
  
  NDPI_LOG(NDPI_PROTOCOL_GIT, ndpi_struct, NDPI_LOG_DEBUG, "found Git.\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_GIT, NDPI_PROTOCOL_UNKNOWN);
  return;

 no_git:
  NDPI_LOG(NDPI_PROTOCOL_GIT, ndpi_struct, NDPI_LOG_DEBUG, "exclude Git.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_GIT);
}


/* ***************************************************************** */


void init_git_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
			 NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Git", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_GIT,
				      ndpi_search_git,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif /* NDPI_PROTOCOL_GIT */
