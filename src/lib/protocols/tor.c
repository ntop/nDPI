/*
 * tor.c
 *
 * Copyright (C) 2016-18 ntop.org
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
 *
 */
#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_TOR

#include "ndpi_api.h"


static void ndpi_int_tor_add_connection(struct ndpi_detection_module_struct
					*ndpi_struct, struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TOR, NDPI_PROTOCOL_UNKNOWN);
}


int ndpi_is_tls_tor(struct ndpi_detection_module_struct *ndpi_struct,
		    struct ndpi_flow_struct *flow, char *certificate) {  
  int len;
  char dummy[48], *dot, *name;
  
  if((certificate == NULL) || (certificate[0] == '\0'))
    return(0);
  else
    len = strlen(certificate);

  /* Check if it ends in .com or .net */
  if(len>=4 && strcmp(&certificate[len-4], ".com") && strcmp(&certificate[len-4], ".net"))
    return(0);
  
  if((len < 6)
     || (!strncmp(certificate, "*.", 2))  /* Wildcard certificate */
     || (strncmp(certificate, "www.", 4)) /* Not starting with www.... */
     )
    return(0);

  // printf("***** [SSL] %s(): %s\n", __FUNCTION__, certificate);

  snprintf(dummy, sizeof(dummy), "%s", certificate);

  if((dot = strrchr(dummy, '.')) == NULL) return(0);
  dot[0] = '\0';

  if((dot = strrchr(dummy, '.')) == NULL) return(0);
  name = &dot[1];

  len = strlen(name);
  
  if(len >= 5) {
    int i, prev_num = 0, numbers_found = 0, num_found = 0, num_impossible = 0;
    
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
      
      if(ndpi_match_bigram(ndpi_struct, &ndpi_struct->bigrams_automa, &name[i])) {
	num_found++;
      } else if(ndpi_match_bigram(ndpi_struct, &ndpi_struct->impossible_bigrams_automa, &name[i])) {
	num_impossible++;
      }
    }

    if((num_found == 0) || (num_impossible > 1)) {
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

  NDPI_LOG_DBG(ndpi_struct, "search for TOR\n");

  if((packet->tcp != NULL)
     && (!packet->tls_certificate_detected)) {
    u_int16_t dport, sport;
    
    sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
    NDPI_LOG_DBG2(ndpi_struct, "calculating TOR over tcp\n");

    if ((((dport == 9001) || (sport == 9001)) || ((dport == 9030) || (sport == 9030)))
	&& ((packet->payload[0] == 0x17) || (packet->payload[0] == 0x16)) 
	&& (packet->payload[1] == 0x03) 
	&& (packet->payload[2] == 0x01) 
	&& (packet->payload[3] == 0x00)) {
      NDPI_LOG_INFO(ndpi_struct, "found tor\n");
      ndpi_int_tor_add_connection(ndpi_struct, flow);
    }
  } else {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
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

