/*
 * unit.c
 *
 * Copyright (C) 2019-20 - ntop.org
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

#ifdef linux
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#endif /* linux */

#ifdef WIN32
#include <winsock2.h>
#include <process.h>
#include <io.h>
#define getopt getopt____
#else
#include <unistd.h>
#include <netinet/in.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <assert.h>
#include <math.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <libgen.h>

#include "ndpi_config.h"
#include "ndpi_api.h"

#ifdef HAVE_JSON_H
#include "json.h" /* JSON-C */
#endif

static struct ndpi_detection_module_struct *ndpi_info_mod = NULL;
static int verbose = 0;

/* *********************************************** */

int serializerUnitTest() {
#ifdef HAVE_JSON_H
  ndpi_serializer serializer, deserializer;
  int i, loop_id;
  ndpi_serialization_format fmt;
  u_int32_t buffer_len;
  char *buffer;
  enum json_tokener_error jerr;
  json_object *j;

  for(loop_id=0; loop_id<3; loop_id++) {
    switch(loop_id) {
    case 0:
      if (verbose) printf("--- TLV test ---\n");
      fmt = ndpi_serialization_format_tlv;
      break;

    case 1:
      if (verbose) printf("--- JSON test ---\n");
      fmt = ndpi_serialization_format_json;
      break;

    case 2:
      if (verbose) printf("--- CSV test ---\n");
      fmt = ndpi_serialization_format_csv;
      break;
    }
    assert(ndpi_init_serializer(&serializer, fmt) != -1);

    for(i=0; i<16; i++) {
      char kbuf[32], vbuf[32];
      snprintf(kbuf, sizeof(kbuf), "Key %d", i);
      snprintf(vbuf, sizeof(vbuf), "Value %d", i);
      assert(ndpi_serialize_uint32_uint32(&serializer, i, i*i) != -1);
      assert(ndpi_serialize_uint32_string(&serializer, i, "Data") != -1);
      assert(ndpi_serialize_string_string(&serializer, kbuf, vbuf) != -1);
      assert(ndpi_serialize_string_uint32(&serializer, kbuf, i*i) != -1);
      assert(ndpi_serialize_string_float(&serializer,  kbuf, (float)(i*i), "%f") != -1);
      if ((i&0x3) == 0x3) ndpi_serialize_end_of_record(&serializer);
    }

    if (fmt == ndpi_serialization_format_json) {
      assert(ndpi_serialize_start_of_list(&serializer, "List") != -1);

      for(i=0; i<4; i++) {
	char kbuf[32], vbuf[32];
	snprintf(kbuf, sizeof(kbuf), "Ignored");
	snprintf(vbuf, sizeof(vbuf), "Item %d", i);
	assert(ndpi_serialize_uint32_uint32(&serializer, i, i*i) != -1);
	assert(ndpi_serialize_string_string(&serializer, kbuf, vbuf) != -1);
	assert(ndpi_serialize_string_float(&serializer,  kbuf, (float)(i*i), "%f") != -1);
      }
      assert(ndpi_serialize_end_of_list(&serializer) != -1);
      assert(ndpi_serialize_string_string(&serializer, "Last", "Ok") != -1);

      buffer = ndpi_serializer_get_buffer(&serializer, &buffer_len);

      if(verbose)
	printf("%s\n", buffer);

      /* Decoding JSON to validate syntax */
      jerr = json_tokener_success;
      j = json_tokener_parse_verbose(buffer, &jerr);
      if (j == NULL) {
        printf("%s: ERROR (json validation failed)\n", __FUNCTION__);
        return -1;
      } else {
        /* Validation ok */
        json_object_put(j);
      }

    } else if (fmt == ndpi_serialization_format_csv) {
      if(verbose) {
	u_int32_t buffer_len = 0;
	char *buffer;

	buffer = ndpi_serializer_get_header(&serializer, &buffer_len);
	printf("%s\n", buffer);

	buffer = ndpi_serializer_get_buffer(&serializer, &buffer_len);
	printf("%s\n", buffer);
      }

    } else {
      if(verbose)
	printf("Serialization size: %u\n", ndpi_serializer_get_buffer_len(&serializer));

      assert(ndpi_init_deserializer(&deserializer, &serializer) != -1);

      while(1) {
	ndpi_serialization_type kt, et;

	et = ndpi_deserialize_get_item_type(&deserializer, &kt);

	if(et == ndpi_serialization_unknown) {
	  break;
        } else if(et == ndpi_serialization_end_of_record) {
          if (verbose) printf("EOR\n");
	} else {
	  u_int32_t k32, v32;
	  ndpi_string ks, vs;
	  float vf;

	  switch(kt) {
          case ndpi_serialization_uint32:
            ndpi_deserialize_key_uint32(&deserializer, &k32);
	    if(verbose) printf("%u=", k32);
	    break;
          case ndpi_serialization_string:
            ndpi_deserialize_key_string(&deserializer, &ks);
            if (verbose) {
              u_int8_t bkp = ks.str[ks.str_len];
	      ks.str[ks.str_len] = '\0';
              printf("%s=", ks.str);
	      ks.str[ks.str_len] = bkp;
            }
	    break;
          default:
            printf("%s: ERROR (unsupported TLV key type %u)\n", __FUNCTION__, kt);
	    return -1;
	  }

	  switch(et) {
          case ndpi_serialization_uint32:
	    assert(ndpi_deserialize_value_uint32(&deserializer, &v32) != -1);
	    if(verbose) printf("%u\n", v32);
	    break;

          case ndpi_serialization_string:
	    assert(ndpi_deserialize_value_string(&deserializer, &vs) != -1);
	    if(verbose) {
	      u_int8_t bkp = vs.str[vs.str_len];
	      vs.str[vs.str_len] = '\0';
	      printf("%s\n", vs.str);
	      vs.str[vs.str_len] = bkp;
	    }
	    break;

          case ndpi_serialization_float:
	    assert(ndpi_deserialize_value_float(&deserializer, &vf) != -1);
	    if(verbose) printf("%f\n", vf);
	    break;

          default:
	    if (verbose) printf("\n");
            printf("%s: ERROR (unsupported type %u detected)\n", __FUNCTION__, et);
	    return -1;
	  }
	}

	ndpi_deserialize_next(&deserializer);
      }
    }

    ndpi_term_serializer(&serializer);
  }

  printf("%s                      OK\n", __FUNCTION__);
#endif
  return 0;
}

/* *********************************************** */

int main(int argc, char **argv) {
  int c;
  
  if (ndpi_get_api_version() != NDPI_API_VERSION) {
    printf("nDPI Library version mismatch: please make sure this code and the nDPI library are in sync\n");
    return -1;
  }

  ndpi_info_mod = ndpi_init_detection_module(ndpi_no_prefs);

  if (ndpi_info_mod == NULL)
    return -1;

  while((c = getopt(argc, argv, "vh")) != -1) {
    switch(c) {
    case 'v':
      verbose = 1;
      break;
      
    default:
      printf("Usage: unit [-v] [-h]\n");
      return(0);
    }
  }
    
  /* Tests */
  if (serializerUnitTest() != 0) return -1;

  return 0;
}

