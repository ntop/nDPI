/*
 * ndpi_fingerprint.c
 *
 * Copyright (C) 2011-26 - ntop.org and contributors
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


#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <sys/types.h>

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UNKNOWN

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "ndpi_private.h"
#include "ndpi_sha256.h"
#include "ndpi_os_fingerprint.c.inc"


/* ************************************************************** */

void ndpi_load_tcp_fingerprints(struct ndpi_detection_module_struct *ndpi_str) {

  if(ndpi_str->tcp_fingerprint_hashmap ||
     ndpi_hash_init(&ndpi_str->tcp_fingerprint_hashmap) == 0) {
    u_int i;

    for(i=0; tcp_fps[i].fingerprint != NULL; i++)
      ndpi_add_tcp_fingerprint(ndpi_str, (char*)tcp_fps[i].fingerprint, tcp_fps[i].os);
  }
}

/* ************************************************************** */

ndpi_os ndpi_get_os_from_tcp_fingerprint(struct ndpi_detection_module_struct *ndpi_str,
					 char *tcp_fingerprint) {
  if(tcp_fingerprint && (ndpi_str->tcp_fingerprint_hashmap != NULL)) {
    u_int64_t ret;

    if(ndpi_hash_find_entry(ndpi_str->tcp_fingerprint_hashmap,
			    tcp_fingerprint, strlen(tcp_fingerprint), &ret) == 0)
      return(ret);
  }

  return(ndpi_os_unknown);
}

/* ************************************************************** */

/*
  Add a new TCP fingerprint

  Return code:
  0   OK
  -1  Duplicated fingerprint
  -2  Unable to add a new entry
 */
int ndpi_add_tcp_fingerprint(struct ndpi_detection_module_struct *ndpi_str,
			     char *fingerprint, ndpi_os os) {
  u_int len;
  u_int64_t ret;

  len = strlen(fingerprint);

  if((ndpi_str->tcp_fingerprint_hashmap != NULL)
     && (ndpi_hash_find_entry(ndpi_str->tcp_fingerprint_hashmap, fingerprint, len, &ret) == 0)) {
    /* Duplicate fingerprint found */
    return(-1);
  } else {
    if(ndpi_hash_add_entry(&ndpi_str->tcp_fingerprint_hashmap, fingerprint, len,
			   (u_int64_t)os, NULL) == 0) {
      return(0);
    } else
      return(-2);
  }
}

/* ******************************************************************** */

/*
 * Format:
 *
 * <TCP fingerprint>,<numeric OS>
 * Example: 2_64_14600_8c07a80cc645,3
 *
 */
int ndpi_load_tcp_fingerprint_file(struct ndpi_detection_module_struct *ndpi_str, const char *path) {
  int rc;
  FILE *fd;

  if(!ndpi_str || !path)
    return(-1);

  fd = fopen(path, "r");
  if(fd == NULL) {
    NDPI_LOG_ERR(ndpi_str, "Unable to open file %s [%s]\n", path, strerror(errno));
    return -1;
  }

  rc = load_tcp_fingerprint_file_fd(ndpi_str, fd);

  fclose(fd);

  return rc;
}

/* ******************************************************************** */

int load_tcp_fingerprint_file_fd(struct ndpi_detection_module_struct *ndpi_str, FILE *fd) {
  char buffer[128];
  int num = 0;

  if(!ndpi_str || !fd)
    return(-1);

  if(ndpi_str->tcp_fingerprint_hashmap == NULL
     && ndpi_hash_init(&ndpi_str->tcp_fingerprint_hashmap) != 0)
    return(-1);

  while (fgets(buffer, sizeof(buffer), fd) != NULL) {
    char *fingerprint, *os, *tmp;
    ndpi_os os_num;
    size_t len = strlen(buffer);

    if(len <= 1 || buffer[0] == '#')
      continue;

    fingerprint = strtok_r(buffer, ",", &tmp);
    if(!fingerprint) continue;

    os = strtok_r(NULL, "\n", &tmp);
    if(!os) continue; else os_num = (ndpi_os)atoi(os);

    if(os_num >= ndpi_os_MAX_OS) continue;

    if(ndpi_add_tcp_fingerprint(ndpi_str, fingerprint, os_num) == 0)
      num++;
  }

  return num;
}

/* **************************************** */

static char* ndpi_compute_tls_blocks_flow_fingerprint(struct ndpi_flow_struct *flow,
						      char *fp_buf, u_int fp_buf_len) {
  u_int16_t i, idx = 0;
  int ret;
  u_int8_t sha_hash[NDPI_SHA256_BLOCK_SIZE];

  if((flow->l4_proto != IPPROTO_TCP) || (flow->l4.tcp.tls.num_tls_blocks == 0))
    return("");

  fp_buf[0] = '\0'; /* Not really necessary, but just to be sure */

  for(i=0; i< flow->l4.tcp.tls.num_tls_blocks; i++) {
    ret = snprintf(&fp_buf[idx], fp_buf_len-idx-1, "%s%u=%d",
		   (i > 0) ? "," : "",
		   flow->l4.tcp.tls.tls_blocks[i].block_type,
		   flow->l4.tcp.tls.tls_blocks[i].len);

    if(ret > 0) idx += ret; else break;
  } /* for */

#if 0
  fprintf(stderr, "#### [sport=%u] %s\n", ntohs(flow->c_port), fp_buf);
#endif

  ndpi_sha256((u_char*)fp_buf, idx, sha_hash);

  ndpi_snprintf((char*)fp_buf, fp_buf_len-1,
		"%02x%02x%02x%02x%02x%02x%02x%02x"
		"%02x%02x%02x%02x%02x%02x%02x%02x",
		sha_hash[0], sha_hash[1], sha_hash[2],    sha_hash[3],
		sha_hash[4], sha_hash[5], sha_hash[6],    sha_hash[7],
		sha_hash[8], sha_hash[9], sha_hash[10],   sha_hash[11],
		sha_hash[12], sha_hash[13], sha_hash[14], sha_hash[15]
		);

#if 0
  fprintf(stderr, " [%s]\n", fp_buf);
#endif

  return(fp_buf);
}

/* **************************************** */

u_int64_t ndpi_compare_flow_tls_blocks(struct ndpi_detection_module_struct *ndpi_str,
				       struct ndpi_flow_struct *flow,
				       ndpi_list *extra_data,
				       u_int64_t proto_id) {
  if((flow->l4_proto == IPPROTO_TCP)
     && (flow->l4.tcp.tls.num_tls_blocks == ndpi_str->cfg.tls_max_num_blocks_to_analyze)
     && (ndpi_str->cfg.tls_max_num_blocks_to_analyze <= 8 /* (&) */)
     && (flow->l4.tcp.tls.tls_blocks != NULL)) {
    float best_res = 9999999.;

    while(extra_data != NULL) {
      /* Multiple matches: let's find the best match (if any) */
      struct ndpi_tls_block *tls_blocks = (struct ndpi_tls_block*)extra_data->value;

      if(tls_blocks != NULL) {
	float res = ndpi_tls_blocks_len_compare(flow->l4.tcp.tls.tls_blocks, tls_blocks, 8 /* (&) */);


	if((res < 4) && (res < best_res)) {
	  best_res = res;
	  proto_id = tls_blocks->msec_delta; /* It stores the protocolId. See (*%*) in ndpi_main.c */

	  if(res == 0) /* identical TLS blocks */
	    break; /* No match better than this ! */
	}
      }

      extra_data = extra_data->next;
    }
  }

  return(proto_id);
}

/* **************************************** */

char* ndpi_compute_ndpi_flow_fingerprint(struct ndpi_detection_module_struct *ndpi_str,
					 struct ndpi_flow_struct *flow) {
  if(ndpi_str->cfg.ndpi_fingerprint_enabled &&
     (flow->ndpi.client_fingerprint == NULL) &&
     ndpi_stack_is_tls_like(&flow->protocol_stack) &&
     /*
       We need TCP & TLS handshake. What should we do if we don't have them?
       For the time being, keep calculating the fingerprint if we have at least
       one of them. That means:
	* we might have a fingerprint also for DTS/QUIC
	* no fingerprint for mid-flows
	TODO: is that what we really want?
     */
     (flow->tcp.fingerprint || flow->protos.tls_quic.ja4_ndpi_client[0] != '\0')) {
    char *l4_fp = "no_l4_fp";
    char *l7_pf = "no_app_fp_cli";
    char *l7_pf_tls_blocks = "";
    char *l7_pf_server = "no_app_fp_srv";
    u_int8_t sha_hash[NDPI_SHA256_BLOCK_SIZE];
    size_t s;
    u_int8_t fp_buf[128];
    char l7_pf_tls_blocks_buf[256];

    if((!ndpi_str->cfg.tls_ndpifp_ignore_tcp_fingerprint)
       && (flow->tcp.fingerprint != NULL))
      l4_fp = flow->tcp.fingerprint;

    if(flow->protos.tls_quic.ja4_ndpi_client[0] != '\0')
      l7_pf = flow->protos.tls_quic.ja4_ndpi_client;

    if(ndpi_str->cfg.tls_max_num_blocks_to_analyze > 0)
      l7_pf_tls_blocks = ndpi_compute_tls_blocks_flow_fingerprint(flow,
								  l7_pf_tls_blocks_buf, sizeof(l7_pf_tls_blocks_buf));

    if(ndpi_str->cfg.ndpi_fingerprint_format == NDPI_CLIENT_SERVER_NDPI_FINGERPRINT) {
      if(flow->protos.tls_quic.sha1_certificate_fingerprint[0] != '\0')
	l7_pf_server = (char*)flow->protos.tls_quic.sha1_certificate_fingerprint;
      else {
	if(flow->protos.tls_quic.ja3_server[0] != '\0')
	  l7_pf_server = flow->protos.tls_quic.ja3_server;
      }
    }

    s = snprintf((char*)fp_buf, sizeof(fp_buf)-1, "%s-%s%s-%s",
		 l4_fp, l7_pf, l7_pf_tls_blocks, l7_pf_server);

    if(ndpi_str->cfg.tls_ndpifp_ignore_sni_extension)
      fp_buf[strlen(l4_fp)+4] = '_';

#if 0
    fprintf(stderr, "#### [sport=%u] %s\n", ntohs(flow->c_port), fp_buf);
#endif

    if(s > 0) {
      s = ndpi_min(s, sizeof(fp_buf)-1);
      ndpi_sha256(fp_buf, s, sha_hash);

      ndpi_snprintf((char*)fp_buf, sizeof(fp_buf),
		    "%02x%02x%02x%02x%02x%02x%02x%02x"
		    "%02x%02x%02x%02x%02x%02x%02x%02x",
		    sha_hash[0], sha_hash[1], sha_hash[2],    sha_hash[3],
		    sha_hash[4], sha_hash[5], sha_hash[6],    sha_hash[7],
		    sha_hash[8], sha_hash[9], sha_hash[10],   sha_hash[11],
		    sha_hash[12], sha_hash[13], sha_hash[14], sha_hash[15]
		    );

      flow->ndpi.client_fingerprint = ndpi_strdup((char*)fp_buf);

      if((flow->ndpi.client_fingerprint != NULL)
	 && (ndpi_str->ndpifp_custom_protos != NULL)) {
	u_int64_t proto_id;
	ndpi_list *extra_data = NULL;
	
	/* This protocol has been defined in protos.txt-like files */
	if(ndpi_hash_find_entry_extra(ndpi_str->ndpifp_custom_protos,
				      flow->ndpi.client_fingerprint, strlen(flow->ndpi.client_fingerprint),
				      &proto_id, &extra_data) == 0) {

	  proto_id = ndpi_compare_flow_tls_blocks(ndpi_str, flow, extra_data, proto_id);
	  
	  if(proto_id != NDPI_PROTOCOL_UNKNOWN) {
	    ndpi_set_detected_protocol(ndpi_str, flow, proto_id,
				       ndpi_get_master_proto(ndpi_str, flow),
				       NDPI_CONFIDENCE_CUSTOM_RULE);
	    
	    flow->category = ndpi_str->proto_defaults[proto_id].protoCategory,
	      flow->breed = ndpi_str->proto_defaults[proto_id].protoBreed;
	  }
	}
      }
    }
  }

  return(flow->ndpi.client_fingerprint);
}
