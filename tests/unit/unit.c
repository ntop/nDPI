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

#ifdef __linux__
#include <sched.h>
#endif /* linux */

#ifdef WIN32
#include <winsock2.h>
#include <process.h>
#include <io.h>
#else
#include <getopt.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/mman.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <assert.h>
#include <math.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "ndpi_define.h"
#include "ndpi_categories_bin.h"
#include "ndpi_category_host_norm.h"

#include "json.h" /* JSON-C */

static struct ndpi_detection_module_struct *ndpi_info_mod = NULL;
static int verbose = 0;

/* *********************************************** */

#define FLT_MAX 3.402823466e+38F

int serializerUnitTest() {
  ndpi_serializer serializer, serializer_cloned, deserializer;
  int i, loop_id;
  ndpi_serialization_format fmt = {0};
  u_int32_t buffer_len;
  char *buffer;
  enum json_tokener_error jerr;
  json_object *j;

  memset(&serializer, 0, sizeof(serializer));
  memset(&serializer_cloned, 0, sizeof(serializer_cloned));
  memset(&deserializer, 0, sizeof(deserializer));
  
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
      int j = 0;
      ndpi_snprintf(vbuf, sizeof(vbuf), "Value %d \t with special chars:\n$!@?", i);
      assert(ndpi_serialize_uint32_uint32(&serializer, j++, i*i) != -1);
      assert(ndpi_serialize_uint32_string(&serializer, j++, "Data") != -1);
      ndpi_snprintf(kbuf, sizeof(kbuf), "Key %d", j++);
      assert(ndpi_serialize_string_string(&serializer, kbuf, vbuf) != -1);
      ndpi_snprintf(kbuf, sizeof(kbuf), "Key %d", j++);
      assert(ndpi_serialize_string_uint32(&serializer, kbuf, i*i) != -1);
      ndpi_snprintf(kbuf, sizeof(kbuf), "Key %d", j++);
      assert(ndpi_serialize_string_float(&serializer,  kbuf, (float)(i*i), "%f") != -1);
      if (fmt != ndpi_serialization_format_tlv) {
        ndpi_snprintf(kbuf, sizeof(kbuf), "Key %d", j++);
        assert(ndpi_serialize_string_double(&serializer, kbuf, ((double)(FLT_MAX))*2, "%lf") != -1);
      }
      ndpi_snprintf(kbuf, sizeof(kbuf), "Key %d", j++);
      assert(ndpi_serialize_string_int64(&serializer,  kbuf, INT64_MAX) != -1);
      assert(ndpi_serialize_string_string(&serializer, "utf-8", "küche") != -1);
      if ((i&0x3) == 0x3) ndpi_serialize_end_of_record(&serializer);
    }

    if (fmt == ndpi_serialization_format_json) {
      assert(ndpi_serialize_start_of_list(&serializer, "List") != -1);

      for(i=0; i<4; i++) {
	char kbuf[32], vbuf[32];
	ndpi_snprintf(kbuf, sizeof(kbuf), "Ignored");
	ndpi_snprintf(vbuf, sizeof(vbuf), "Item %d", i);
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
        printf("%s: ERROR (json validation failed: `%s')\n",
               __func__, json_tokener_error_desc(jerr));
        return -1;
      } else {
        /* Validation ok */
        json_object_put(j);
      }

    } else if (fmt == ndpi_serialization_format_csv) {
      if(verbose) {

	buffer_len = 0;
	buffer = ndpi_serializer_get_header(&serializer, &buffer_len);
	printf("%s\n", buffer);

	buffer_len = 0;
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
          int64_t v64;
	  ndpi_string ks, vs;
	  float vf;
	  double vd;

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
            printf("%s: ERROR Unsupported TLV key type %u (value type %u)\n", __func__, kt, et);
	    return -1;
	  }

	  switch(et) {
          case ndpi_serialization_uint32:
	    assert(ndpi_deserialize_value_uint32(&deserializer, &v32) != -1);
	    if(verbose) printf("%u\n", v32);
	    break;

          case ndpi_serialization_int64:
	    assert(ndpi_deserialize_value_int64(&deserializer, &v64) != -1);
	    if(verbose) printf("%" PRId64 "\n", v64);
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

          case ndpi_serialization_double:
	    assert(ndpi_deserialize_value_double(&deserializer, &vd) != -1);
	    if(verbose) printf("%lf\n", vd);
	    break;

          default:
	    if (verbose) printf("\n");
            printf("%s: ERROR Unsupported TLV value type %u (key type %u)\n", __func__, et, kt);
	    return -1;
	  }
	}

	ndpi_deserialize_next(&deserializer);
      }

      /* Converting from TLV to JSON */

      assert(ndpi_init_deserializer(&deserializer, &serializer) != -1);
      assert(ndpi_init_serializer(&serializer_cloned, ndpi_serialization_format_json) != -1);
      assert(ndpi_deserialize_clone_all(&deserializer, &serializer_cloned) == 0);

      buffer = ndpi_serializer_get_buffer(&serializer_cloned, &buffer_len);
      if(verbose)
        printf("TLV->JSON: %s\n", buffer);

      ndpi_term_serializer(&serializer_cloned);
    }

    ndpi_term_serializer(&serializer);
  }

  printf("%30s                      OK\n", __func__);
  return 0;
}

/* *********************************************** */

int serializeProtoUnitTest(void)
{
  ndpi_serializer serializer;
  int loop_id;
  ndpi_serialization_format fmt = {0};
  u_int32_t buffer_len;
  char * buffer;

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

    ndpi_protocol ndpi_proto;
    ndpi_risk risks = 0;

    ndpi_proto.proto.master_protocol = NDPI_PROTOCOL_TLS,
      ndpi_proto.proto.app_protocol = NDPI_PROTOCOL_FACEBOOK,
      ndpi_proto.protocol_by_ip = NDPI_PROTOCOL_FACEBOOK,
      ndpi_proto.category = NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
      ndpi_proto.breed = NDPI_PROTOCOL_FUN;
       
    NDPI_SET_BIT(risks, NDPI_MALFORMED_PACKET);
    NDPI_SET_BIT(risks, NDPI_TLS_WEAK_CIPHER);
    NDPI_SET_BIT(risks, NDPI_TLS_OBSOLETE_VERSION);
    NDPI_SET_BIT(risks, NDPI_TLS_SELFSIGNED_CERTIFICATE);
    ndpi_serialize_proto(ndpi_info_mod, &serializer, risks, NDPI_CONFIDENCE_DPI, ndpi_proto);
    assert(ndpi_serialize_string_float(&serializer,  "float", FLT_MAX, "%f") != -1);
    if (fmt != ndpi_serialization_format_tlv)
      assert(ndpi_serialize_string_double(&serializer,  "double", ((double)(FLT_MAX))*2, "%lf") != -1);

    if (fmt == ndpi_serialization_format_json)
    {
      buffer_len = 0;
      buffer = ndpi_serializer_get_buffer(&serializer, &buffer_len);
#ifndef WIN32
      char const * const expected_json_str = "{\"flow_risk\": {\"6\": {\"risk\":\"Self-signed Cert\",\"severity\":\"High\",\"risk_score\": {\"total\":300,\"client\":270,\"server\":30}},\"7\": {\"risk\":\"Obsolete TLS (v1.1 or older)\",\"severity\":\"High\",\"risk_score\": {\"total\":310,\"client\":275,\"server\":35}},\"8\": {\"risk\":\"Weak TLS Cipher\",\"severity\":\"High\",\"risk_score\": {\"total\":150,\"client\":135,\"server\":15}},\"17\": {\"risk\":\"Malformed Packet\",\"severity\":\"Low\",\"risk_score\": {\"total\":160,\"client\":80,\"server\":80}}},\"confidence\": {\"6\":\"DPI\"},\"proto\":\"TLS.Facebook\",\"proto_id\":\"91.119\",\"proto_by_ip\":\"Facebook\",\"proto_by_ip_id\":119,\"encrypted\":1,\"breed\":\"Fun\",\"category_id\":6,\"category\":\"SocialNetwork\",\"float\":340282346638528859811704183484516925440.000000,\"double\":680564693277057719623408366969033850880.000000}";

      if (strncmp(buffer, expected_json_str, buffer_len) != 0)
      {
        printf("%s: ERROR: expected JSON str: \"%s\"\n", __func__, expected_json_str);
        printf("%s: ERROR: got JSON str.....: \"%.*s\"\n", __func__, (int)buffer_len, buffer);
        return -1;
      }
#endif

      if(verbose)
        printf("%s\n", buffer);

      /* Decoding JSON to validate syntax */
      enum json_tokener_error jerr = json_tokener_success;
      json_object * const j = json_tokener_parse_verbose(buffer, &jerr);
      if (j == NULL) {
        printf("%s: ERROR (json validation failed: `%s')\n",
               __func__, json_tokener_error_desc(jerr));
        return -1;
      } else {
        /* Validation ok */
        json_object_put(j);
      }
    } else if (fmt == ndpi_serialization_format_csv)
    {
      char const * const expected_csv_hdr_str = "risk,severity,total,client,server,risk,severity,total,client,server,risk,severity,total,client,server,risk,severity,total,client,server,6,proto,proto_id,proto_by_ip,proto_by_ip_id,encrypted,breed,category_id,category,float,double";
      buffer_len = 0;
      buffer = ndpi_serializer_get_header(&serializer, &buffer_len);
      assert(buffer != NULL && buffer_len != 0);
      if (verbose)
        printf("%s\n", buffer);
      if (strncmp(buffer, expected_csv_hdr_str, buffer_len) != 0)
      {
        printf("%s: ERROR: expected CSV str: \"%s\"\n", __func__, expected_csv_hdr_str);
        printf("%s: ERROR: got CSV str.....: \"%.*s\"\n", __func__, (int)buffer_len, buffer);
      }

#ifndef WIN32
      char const * const expected_csv_buf_str = "Self-signed Cert,High,300,270,30,Obsolete TLS (v1.1 or older),High,310,275,35,Weak TLS Cipher,High,150,135,15,Malformed Packet,Low,160,80,80,DPI,TLS.Facebook,91.119,Facebook,119,1,Fun,6,SocialNetwork,340282346638528859811704183484516925440.000000,680564693277057719623408366969033850880.000000";
      buffer_len = 0;
      buffer = ndpi_serializer_get_buffer(&serializer, &buffer_len);
      assert(buffer != NULL && buffer_len != 0);
      if (verbose)
          printf("%s\n", buffer);
      if (strncmp(buffer, expected_csv_buf_str, buffer_len) != 0)
      {
        printf("%s: ERROR: expected CSV str: \"%s\"\n", __func__, expected_csv_buf_str);
        printf("%s: ERROR: got CSV str.....: \"%.*s\"\n", __func__, (int)buffer_len, buffer);
      }
#endif
    }

    ndpi_term_serializer(&serializer);
  }

  printf("%30s                      OK\n", __func__);

  return 0;
}

/* *********************************************** */

#ifndef WIN32
static uint64_t ut_fnv1a64(const char *s, size_t len) {
  uint64_t h = 1469598103934665603ULL;
  size_t i;

  for(i = 0; i < len; ++i) {
    h ^= (unsigned char)s[i];
    h *= 1099511628211ULL;
  }
  return h;
}

static int category_ndb_smoke_unit(void) {
  char path[] = "/tmp/ndpi_ut_ndbXXXXXX";
  int fd;
  FILE *fp;
  ndb_header_disk_t hdr;
  ndb_category_disk_t cat;
  ndb_bucket_disk_t bucks[2];
  ndb_entry_disk_t ent;
  const char *dom = "example.com";
  size_t dom_len = strlen(dom);
  const char pool[] = "x\0example.com\0";
  const size_t pool_len = sizeof(pool) - 1;
  ndb_ipv4_entry_disk_t v4[3];
  ndpi_protocol_category_t cat_out;
  ndpi_protocol_breed_t breed;
  uint64_t off;
  uint32_t addr_8888 = htonl(0x08080808);
  uint32_t addr_10_8 = htonl(0x0a000000);
  uint32_t addr_10_1_16 = htonl(0x0a010000);

  if(!ndpi_category_hostname_labels_valid_ascii(dom))
    return -1;
  if(ndpi_category_hostname_labels_valid_ascii("a..b"))
    return -1;

  fd = mkstemp(path);
  if(fd < 0) {
    perror("mkstemp");
    return -1;
  }
  fp = fdopen(fd, "wb");
  if(!fp) {
    close(fd);
    return -1;
  }

  memset(&hdr, 0, sizeof(hdr));
  memcpy(hdr.magic, NDB_MAGIC, 4);
  hdr.format_version = NDB_FORMAT_VERSION;
  hdr.category_count = 1;
  hdr.domain_entry_count = 1;
  hdr.domain_bucket_count = 2;
  hdr.string_pool_size = pool_len;
  hdr.ipv4_entry_count = 3;
  hdr.ipv6_entry_count = 0;

  off = sizeof(hdr);
  hdr.categories_off = off;
  off += sizeof(cat);
  hdr.domain_buckets_off = off;
  off += sizeof(bucks);
  hdr.domain_entries_off = off;
  off += sizeof(ent);
  hdr.string_pool_off = off;
  off += pool_len;
  hdr.ipv4_entries_off = off;
  off += sizeof(v4);
  hdr.ipv6_entries_off = off;
  hdr.file_size = off;

  cat.id = NDPI_PROTOCOL_CATEGORY_WEB;
  cat.name_off = 0;

  bucks[0].first = 0;
  bucks[0].count = 1;
  bucks[1].first = 0;
  bucks[1].count = 0;

  ent.hash = ut_fnv1a64(dom, dom_len);
  ent.domain_off = 2;
  ent.domain_len = (uint16_t)dom_len;
  ent.flags = 0;
  ent.category_id = NDPI_PROTOCOL_CATEGORY_WEB;

  v4[0].network_be = addr_10_8;
  v4[0].prefix_len = 8;
  v4[0].flags = 0;
  v4[0].reserved0 = 0;
  v4[0].category_id = NDPI_PROTOCOL_CATEGORY_WEB;

  v4[1].network_be = addr_10_1_16;
  v4[1].prefix_len = 16;
  v4[1].flags = 0;
  v4[1].reserved0 = 0;
  v4[1].category_id = NDPI_PROTOCOL_CATEGORY_VPN;

  v4[2].network_be = addr_8888;
  v4[2].prefix_len = 32;
  v4[2].flags = 0;
  v4[2].reserved0 = 0;
  v4[2].category_id = NDPI_PROTOCOL_CATEGORY_VPN;

  if(fwrite(&hdr, 1, sizeof(hdr), fp) != sizeof(hdr) ||
      fwrite(&cat, 1, sizeof(cat), fp) != sizeof(cat) ||
      fwrite(bucks, 1, sizeof(bucks), fp) != sizeof(bucks) ||
      fwrite(&ent, 1, sizeof(ent), fp) != sizeof(ent) ||
      fwrite(pool, 1, pool_len, fp) != pool_len ||
      fwrite(v4, 1, sizeof(v4), fp) != sizeof(v4)) {
    fclose(fp);
    unlink(path);
    return -1;
  }
  fclose(fp);

  if(ndpi_load_category_ndb_file(ndpi_info_mod, path, NDPI_CATEGORY_BACKEND_NDB_ONLY) != 0) {
    unlink(path);
    return -1;
  }

  {
    char hostbuf[] = "example.com";
    if(ndpi_match_custom_category(ndpi_info_mod, hostbuf, (u_int)strlen(hostbuf), &cat_out, &breed) != 0 ||
       cat_out != NDPI_PROTOCOL_CATEGORY_WEB) {
      ndpi_unload_category_ndb(ndpi_info_mod);
      unlink(path);
      return -1;
    }
  }

  {
    char ipbuf[] = "8.8.8.8";
    if(ndpi_get_custom_category_match(ndpi_info_mod, ipbuf, (u_int)strlen(ipbuf), &cat_out, &breed) != 0 ||
       cat_out != NDPI_PROTOCOL_CATEGORY_VPN) {
      ndpi_unload_category_ndb(ndpi_info_mod);
      unlink(path);
      return -1;
    }
  }

  /* Longest-prefix: 10.0.0.0/8 (WEB) vs 10.1.0.0/16 (VPN); more specific row must win. */
  {
    char ipbuf[] = "10.1.2.3";
    if(ndpi_get_custom_category_match(ndpi_info_mod, ipbuf, (u_int)strlen(ipbuf), &cat_out, &breed) != 0 ||
       cat_out != NDPI_PROTOCOL_CATEGORY_VPN) {
      ndpi_unload_category_ndb(ndpi_info_mod);
      unlink(path);
      return -1;
    }
  }
  {
    char ipbuf[] = "10.9.9.9";
    if(ndpi_get_custom_category_match(ndpi_info_mod, ipbuf, (u_int)strlen(ipbuf), &cat_out, &breed) != 0 ||
       cat_out != NDPI_PROTOCOL_CATEGORY_WEB) {
      ndpi_unload_category_ndb(ndpi_info_mod);
      unlink(path);
      return -1;
    }
  }

  {
    char miss[] = "nomatch.example";
    if(ndpi_match_custom_category(ndpi_info_mod, miss, (u_int)strlen(miss), &cat_out, &breed) != -1) {
      ndpi_unload_category_ndb(ndpi_info_mod);
      unlink(path);
      return -1;
    }
  }

  ndpi_unload_category_ndb(ndpi_info_mod);

  if(ndpi_load_category_ndb_file(ndpi_info_mod, path, NDPI_CATEGORY_BACKEND_HYBRID) != 0) {
    unlink(path);
    return -1;
  }
  {
    char miss6[] = "2001:db8::1";
    if(ndpi_get_custom_category_match(ndpi_info_mod, miss6, (u_int)strlen(miss6), &cat_out, &breed) != -1) {
      ndpi_unload_category_ndb(ndpi_info_mod);
      unlink(path);
      return -1;
    }
  }
  ndpi_unload_category_ndb(ndpi_info_mod);
  unlink(path);
  return 0;
}
#endif /* !WIN32 */

/* *********************************************** */

int main(int argc, char **argv) {
#ifndef WIN32
  int c;
#endif
  (void)argc;
  (void)argv;
  
  if (ndpi_get_api_version() != NDPI_API_VERSION) {
    printf("nDPI Library version mismatch: please make sure this code and the nDPI library are in sync\n");
    return -1;
  }

  ndpi_info_mod = ndpi_init_detection_module(NULL);

  if (ndpi_info_mod == NULL)
    return -1;

  if(ndpi_finalize_initialization(ndpi_info_mod) != 0)
    return -1;

/*
 * If we want argument parsing on Windows,
 * we need to re-implement it as Windows has no such function.
 */
#ifndef WIN32
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
#else
  verbose = 0;
#endif
    
  /* Tests */
  if (serializerUnitTest() != 0) return -1;
  if (serializeProtoUnitTest() != 0) return -1;
#ifndef WIN32
  if (category_ndb_smoke_unit() != 0) {
    printf("category_ndb_smoke_unit: FAILED\n");
    return -1;
  }
  if (verbose)
    printf("%30s                      OK\n", "category_ndb_smoke_unit");
#endif

  return 0;
}
