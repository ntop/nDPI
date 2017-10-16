/*
 * tor.c
 *
 * Copyright (C) 2016 ntop.org
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
 *
 */
#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_TOR

static void ndpi_int_tor_add_connection(struct ndpi_detection_module_struct
					*ndpi_struct, struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TOR, NDPI_PROTOCOL_UNKNOWN);
}


int ndpi_is_ssl_tor(struct ndpi_detection_module_struct *ndpi_struct,
		    struct ndpi_flow_struct *flow, char *certificate) {
  
  int prev_num = 0, numbers_found = 0, num_found = 0, i, len;
  char dummy[48], *dot, *name;

  if((certificate == NULL)
     || (strlen(certificate) < 6)
     || (strncmp(certificate, "www.", 4)))
    return(0);

  // printf("***** [SSL] %s(): %s\n", __FUNCTION__, certificate);

  snprintf(dummy, sizeof(dummy), "%s", certificate);

  if((dot = strrchr(dummy, '.')) == NULL) return(0);
  dot[0] = '\0';

  if((dot = strrchr(dummy, '.')) == NULL) return(0);
  name = &dot[1];

  len = strlen(name);
  
  if(len >= 5) {
    for(i = 0; name[i+1] != '\0'; i++) {
      // printf("***** [SSL] %s(): [%d][%c]", __FUNCTION__, i, name[i]);
      
      if((name[i] >= '0') && (name[i] <= '9')) {
	if(prev_num != 1) {
	  numbers_found++;

	  if(numbers_found == 2) {
	    ndpi_int_tor_add_connection(ndpi_struct, flow);
	    return(1);
	  }
	  prev_num = 1;
	}
      } else
	prev_num = 0;

      if(ndpi_match_bigram(ndpi_struct, &ndpi_struct->impossible_bigrams_automa, &name[i])) {
	ndpi_int_tor_add_connection(ndpi_struct, flow);
	return(1);
      }

      if(ndpi_match_bigram(ndpi_struct, &ndpi_struct->bigrams_automa, &name[i])) {
	num_found++;
      }
    }

    if(num_found == 0) {
      ndpi_int_tor_add_connection(ndpi_struct, flow);
      return(1);
    } else {
#ifdef PEDANTIC_TOR_CHECK
      if(gethostbyname(certificate) == NULL) {
	ndpi_int_tor_add_connection(ndpi_struct, flow);
	return(1);
      }
#endif
    }
  }

  return(0);
}

/* ******************************************* */

void ndpi_search_tor(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;

  NDPI_LOG(NDPI_PROTOCOL_TOR, ndpi_struct, NDPI_LOG_DEBUG, "search for TOR.\n");

  if(packet->tcp != NULL) {
    sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
    NDPI_LOG(NDPI_PROTOCOL_TOR, ndpi_struct, NDPI_LOG_DEBUG, "calculating TOR over tcp.\n");

    if ((((dport == 9001) || (sport == 9001)) || ((dport == 9030) || (sport == 9030)))
	&& ((packet->payload[0] == 0x17) || (packet->payload[0] == 0x16)) 
	&& (packet->payload[1] == 0x03) 
	&& (packet->payload[2] == 0x01) 
	&& (packet->payload[3] == 0x00)) {
      NDPI_LOG(NDPI_PROTOCOL_TOR, ndpi_struct, NDPI_LOG_DEBUG, "found tor.\n");
      ndpi_int_tor_add_connection(ndpi_struct, flow);
    }
  } else {
    NDPI_LOG(NDPI_PROTOCOL_TOR, ndpi_struct, NDPI_LOG_DEBUG, "exclude TOR.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_TOR);
  }
}


void init_tor_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Tor", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_TOR,
				      ndpi_search_tor,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
