/*
 * ndpi_serializer.c
 *
 * Copyright (C) 2011-19 - ntop.org
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

#ifdef HAVE_CONFIG_H
#include "ndpi_config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>

#include "ndpi_api.h"
#include "ndpi_config.h"

#include <time.h>
#ifndef WIN32
#include <unistd.h>
#endif

#if defined __FreeBSD__ || defined __NetBSD__ || defined __OpenBSD__
#include <sys/endian.h>
#endif

/* ********************************** */

static u_int64_t ndpi_htonll(u_int64_t v) {
  union { u_int32_t lv[2]; u_int64_t llv; } u;
  u.lv[0] = htonl(v >> 32);
  u.lv[1] = htonl(v & 0xFFFFFFFFULL);
  return u.llv;
}

/* ********************************** */

static u_int64_t ndpi_ntohll(u_int64_t v) {
  union { u_int32_t lv[2]; u_int64_t llv; } u;
  u.llv = v;
  return ((u_int64_t)ntohl(u.lv[0]) << 32) | (u_int64_t)ntohl(u.lv[1]);
}

/* ********************************** */

/*
 * Escapes a string to be suitable for a JSON value, adding double quotes, and terminating the string with a null byte.
 * It is recommended to provide a destination buffer (dst) which is as large as double the source buffer (src) at least.
 * Upon successful return, these functions return the number of characters printed (excluding the null byte used to terminate the string).
 */
static int ndpi_json_string_escape(const char *src, int src_len, char *dst, int dst_max_len) {
  char c = 0;
  int i, j = 0;

  dst[j++] = '"';

  for (i = 0; i < src_len && j < dst_max_len; i++) {

    c = src[i];

    switch (c) {
      case '\\':
      case '"':
      case '/':
        dst[j++] = '\\';
        dst[j++] = c;
      break;
      case '\b':
        dst[j++] = '\\';
        dst[j++] = 'b';
      break;
      case '\t':
        dst[j++] = '\\';
        dst[j++] = 't';
      break;
      case '\n':
        dst[j++] = '\\';
        dst[j++] = 'n';
      break;
      case '\f':
        dst[j++] = '\\';
        dst[j++] = 'f';
      break;
      case '\r':
        dst[j++] = '\\';
        dst[j++] = 'r';
      break;
      default:
        if(c < ' ')
          ; /* non printable */
        else
          dst[j++] = c;
    }
  }

  dst[j++] = '"';
  dst[j+1] = '\0';

  return j;
}

/* ********************************** */

void ndpi_reset_serializer(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  
  if(serializer->fmt == ndpi_serialization_format_json) {
    u_int32_t buff_diff;

    serializer->size_used = 0;
    buff_diff = serializer->buffer_size - serializer->size_used;
    
    /* Note: please keep a space at the beginning as it is used for arrays when an end-of-record is used */
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff, " {}");
  } else if(serializer->fmt == ndpi_serialization_format_csv)
    serializer->size_used = 0;
  else /* TLV */
    serializer->size_used = 2 * sizeof(u_int8_t);
}

/* ********************************** */

int ndpi_init_serializer(ndpi_serializer *_serializer,
			 ndpi_serialization_format fmt) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  
  memset(serializer, 0, sizeof(ndpi_private_serializer));
  
  serializer->buffer_size = 8192;
  serializer->buffer      = (u_int8_t *) malloc(serializer->buffer_size * sizeof(u_int8_t));

  if(serializer->buffer == NULL)
    return(-1);

  serializer->fmt         = fmt;

  serializer->buffer[0]   = 1; /* version */
  serializer->buffer[1]   = (u_int8_t) fmt;

  serializer->csv_separator[0] = ',';
  serializer->csv_separator[1] = '\0';

  ndpi_reset_serializer(_serializer);

  return(1);
}

/* ********************************** */

char* ndpi_serializer_get_buffer(ndpi_serializer *_serializer, u_int32_t *buffer_len) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  char *buf = (char*)serializer->buffer;

  /* NULL terminate the buffer if there is space available */
  if(serializer->buffer_size > serializer->size_used)
    serializer->buffer[serializer->size_used] = '\0';
  
  *buffer_len = serializer->size_used;

  if(serializer->fmt == ndpi_serialization_format_json) {
    while(buf[0] == '\0')
      buf++, *buffer_len = *buffer_len - 1 ;
  }
  
  return(buf);
}

/* ********************************** */

u_int32_t ndpi_serializer_get_buffer_len(ndpi_serializer *_serializer) {
  return(((ndpi_private_serializer*)_serializer)->size_used);
}

  /* ********************************** */

void ndpi_serializer_set_csv_separator(ndpi_serializer *_serializer, char separator) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  
  serializer->csv_separator[0] = separator;
}

/* ********************************** */

void ndpi_term_serializer(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  
  if(serializer->buffer) {
    free(serializer->buffer);
    serializer->buffer_size = 0;
    serializer->buffer = NULL;
  }
}

/* ********************************** */

static int ndpi_extend_serializer_buffer(ndpi_serializer *_serializer, u_int32_t min_len) {
  u_int32_t new_size;
  void *r;
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  
  if(min_len < 1024)
    min_len = 1024;

  new_size = serializer->buffer_size + min_len;

  r = realloc((void *) serializer->buffer, new_size);

  if(r == NULL)
    return(-1);

  serializer->buffer = r;
  serializer->buffer_size = new_size;

  return(0);
}

/* ********************************** */

static void ndpi_serialize_single_uint32(ndpi_serializer *_serializer,
					 u_int32_t s) {
  u_int32_t v = htonl(s);
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  
  memcpy(&serializer->buffer[serializer->size_used], &v, sizeof(u_int32_t));
  serializer->size_used += sizeof(u_int32_t);
}

/* ********************************** */

static void ndpi_serialize_single_uint64(ndpi_serializer *_serializer,
					 u_int64_t s) {
  u_int64_t v = ndpi_htonll(s);
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  
  memcpy(&serializer->buffer[serializer->size_used], &v, sizeof(u_int64_t));
  serializer->size_used += sizeof(u_int64_t);
}

/* ********************************** */

/* TODO: fix portability across platforms */
static void ndpi_serialize_single_float(ndpi_serializer *_serializer, float s) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  
  memcpy(&serializer->buffer[serializer->size_used], &s, sizeof(s));
  serializer->size_used += sizeof(float);
}

/* ********************************** */

static void ndpi_serialize_single_string(ndpi_serializer *_serializer,
					 const char *s, u_int16_t slen) {
  u_int16_t l = htons(slen);
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  
  memcpy(&serializer->buffer[serializer->size_used], &l, sizeof(u_int16_t));
  serializer->size_used += sizeof(u_int16_t);

  if(slen > 0)
    memcpy(&serializer->buffer[serializer->size_used], s, slen);

  serializer->size_used += slen;
}

/* ********************************** */

static void ndpi_deserialize_single_uint32(ndpi_serializer *_deserializer,
					   u_int32_t *s) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  
  *s = ntohl(*((u_int32_t *) &deserializer->buffer[deserializer->size_used]));
  deserializer->size_used += sizeof(u_int32_t);
}

/* ********************************** */

static void ndpi_deserialize_single_int32(ndpi_serializer *_deserializer,
					  int32_t *s) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  
  *s = ntohl(*((int32_t *) &deserializer->buffer[deserializer->size_used]));
  deserializer->size_used += sizeof(int32_t);
}

/* ********************************** */

static void ndpi_deserialize_single_uint64(ndpi_serializer *_deserializer,
					   u_int64_t *s) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  
  *s = ndpi_ntohll(*(u_int64_t*)&deserializer->buffer[deserializer->size_used]);
  deserializer->size_used += sizeof(u_int64_t);
}

/* ********************************** */

static void ndpi_deserialize_single_int64(ndpi_serializer *_deserializer,
					  int64_t *s) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  
  *s = ndpi_ntohll(*(int64_t*)&deserializer->buffer[deserializer->size_used]);
  deserializer->size_used += sizeof(int64_t);
}

/* ********************************** */

/* TODO: fix portability across platforms */
static void ndpi_deserialize_single_float(ndpi_serializer *_deserializer,
					  float *s) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  
  *s = *(float*)&deserializer->buffer[deserializer->size_used];
  deserializer->size_used += sizeof(float);
}

/* ********************************** */

static void ndpi_deserialize_single_string(ndpi_serializer *_deserializer,
					   ndpi_string *v) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  
  v->str_len = ntohs(*((u_int16_t *) &deserializer->buffer[deserializer->size_used]));
  deserializer->size_used += sizeof(u_int16_t);

  v->str = (char *) &deserializer->buffer[deserializer->size_used];
  deserializer->size_used += v->str_len;
}

/* ********************************** */

int ndpi_serialize_end_of_record(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
  u_int16_t needed =
    sizeof(u_int8_t) /* type */;

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 1;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    if(!(serializer->status & NDPI_SERIALIZER_STATUS_ARRAY)) {
      // serializer->json_buffer[0] = '[';
      serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used],
					buff_diff, "]");
    }
    serializer->status |= NDPI_SERIALIZER_STATUS_ARRAY | NDPI_SERIALIZER_STATUS_EOR;
    serializer->status &= ~NDPI_SERIALIZER_STATUS_COMMA;
  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_end_of_record;
  }

  return(0);
}

/* ********************************** */

static void ndpi_serialize_json_pre(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  
  if(serializer->status & NDPI_SERIALIZER_STATUS_EOR) {
    serializer->size_used--; /* Remove ']' */
    serializer->status &= ~NDPI_SERIALIZER_STATUS_EOR;
    serializer->buffer[serializer->size_used++] = ',';
    serializer->buffer[serializer->size_used++] = '{';
  } else {
    if(serializer->status & NDPI_SERIALIZER_STATUS_ARRAY)
      serializer->size_used--; /* Remove ']'*/
    serializer->size_used--; /* Remove '}'*/
  }
  if(serializer->status & NDPI_SERIALIZER_STATUS_COMMA)
    serializer->buffer[serializer->size_used++] = ',';
}

/* ********************************** */

static void ndpi_serialize_json_post(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  
  serializer->buffer[serializer->size_used++] = '}';
  if(serializer->status & NDPI_SERIALIZER_STATUS_ARRAY)
    serializer->buffer[serializer->size_used++] = ']';

  serializer->status |= NDPI_SERIALIZER_STATUS_COMMA;
}

/* ********************************** */

int ndpi_serialize_uint32_uint32(ndpi_serializer *_serializer,
				 u_int32_t key, u_int32_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
  u_int16_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int32_t) /* key */ +
    sizeof(u_int32_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 24;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "\"%u\":%u", key, value);
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "%s%u", (serializer->size_used > 0) ? serializer->csv_separator : "", value);
  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_uint32_uint32;

    ndpi_serialize_single_uint32(_serializer, key);
    ndpi_serialize_single_uint32(_serializer, value);
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_uint32_uint64(ndpi_serializer *_serializer,
				 u_int32_t key, u_int64_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
  u_int16_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int32_t) /* key */ +
    sizeof(u_int64_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 32;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "\"%u\":%llu", key, (unsigned long long)value);
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "%s%llu",
				      (serializer->size_used > 0) ? serializer->csv_separator : "",
				      (unsigned long long)value);

  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_uint32_uint64;

    ndpi_serialize_single_uint32(_serializer, key);
    ndpi_serialize_single_uint64(_serializer, value);
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_uint32_string(ndpi_serializer *_serializer,
				 u_int32_t key, const char *_value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  const char *value = _value ? _value : "";
  u_int16_t slen = strlen(value);
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
  u_int32_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int32_t) /* key */ +
    sizeof(u_int16_t) /* len */ +
    slen;

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 24 + slen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "\"%u\":", key);
    buff_diff = serializer->buffer_size - serializer->size_used;
    serializer->size_used += ndpi_json_string_escape(value, slen,
						     (char *) &serializer->buffer[serializer->size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->size_used;
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "%s%s", (serializer->size_used > 0) ? serializer->csv_separator : "", value);
  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_uint32_string;

    ndpi_serialize_single_uint32(_serializer, key);
    ndpi_serialize_single_string(_serializer, value, slen);
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_string_int32(ndpi_serializer *_serializer,
				const char *key, int32_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int16_t klen = strlen(key);
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
  u_int32_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(u_int32_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 16 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->size_used;
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      ":%d", value);
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "%s%d", (serializer->size_used > 0) ? serializer->csv_separator : "", value);
  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_string_int32;

    ndpi_serialize_single_string(_serializer, key, klen);
    ndpi_serialize_single_uint32(_serializer, value);
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_string_int64(ndpi_serializer *_serializer,
				const char *key, int64_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int16_t klen = strlen(key);
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
  u_int32_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(u_int32_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 16 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->size_used;
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      ":%lld", (long long int)value);
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "%s%lld", (serializer->size_used > 0) ? serializer->csv_separator : "",
				      (long long int)value);
  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_string_int64;

    ndpi_serialize_single_string(_serializer, key, klen);
    ndpi_serialize_single_uint32(_serializer, value);
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_string_uint32(ndpi_serializer *_serializer,
				 const char *key, u_int32_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int16_t klen = strlen(key);
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
  u_int32_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(u_int32_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 16 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->size_used;
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      ":%u", value);
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "%s%u", (serializer->size_used > 0) ? serializer->csv_separator : "", value);
  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_string_uint32;

    ndpi_serialize_single_string(_serializer, key, klen);
    ndpi_serialize_single_uint32(_serializer, value);
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_string_uint32_format(ndpi_serializer *_serializer,
					const char *key, u_int32_t value,
					const char *format) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  
  if(serializer->fmt == ndpi_serialization_format_json) {
    /*
      JSON supports base 10 numbers only
      http://cjihrig.com/blog/json-overview/
    */

    return(ndpi_serialize_string_uint32(_serializer, key, value));
  } else
    return(ndpi_serialize_string_uint32_format(_serializer, key, value, format));
}

/* ********************************** */

int ndpi_serialize_string_uint64(ndpi_serializer *_serializer,
				 const char *key, u_int64_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int16_t klen = strlen(key);
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
  u_int32_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(u_int64_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 32 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->size_used;
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      ":%llu", (unsigned long long)value);
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "%s%llu", (serializer->size_used > 0) ? serializer->csv_separator : "",
				      (unsigned long long)value);
  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_string_uint64;

    ndpi_serialize_single_string(_serializer, key, klen);
    ndpi_serialize_single_uint64(_serializer, value);
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_string_float(ndpi_serializer *_serializer,
				const char *key, float value,
				const char *format /* e.f. "%.2f" */) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int16_t klen = strlen(key);
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
  u_int32_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(float);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 32 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->size_used;

    serializer->buffer[serializer->size_used] = ':';
    serializer->size_used++;

    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff, format, value);

    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    if(serializer->size_used > 0)
      serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff, "%s", serializer->csv_separator);

    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff, format, value);
  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_string_float;

    ndpi_serialize_single_string(_serializer, key, klen);
    ndpi_serialize_single_float(_serializer, value);
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_string_string(ndpi_serializer *_serializer,
				 const char *key, const char *_value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  const char *value = _value ? _value : "";
  u_int16_t klen = strlen(key), vlen = strlen(value);
  u_int32_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen +
    sizeof(u_int16_t) /* len */ +
    vlen;
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 16 + klen + vlen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->size_used;
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff, ":");
    buff_diff = serializer->buffer_size - serializer->size_used;
    serializer->size_used += ndpi_json_string_escape(value, vlen,
						     (char *) &serializer->buffer[serializer->size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->size_used;
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "%s%s", (serializer->size_used > 0) ? serializer->csv_separator : "",
				      value);
  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_string_string;

    ndpi_serialize_single_string(_serializer, key, klen);
    ndpi_serialize_single_string(_serializer, value, vlen);
  }

  return(0);
}

/* ********************************** */
/* ********************************** */

int ndpi_init_deserializer_buf(ndpi_deserializer *_deserializer,
			       u_int8_t *serialized_buffer,
			       u_int32_t serialized_buffer_len) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  
  if(serialized_buffer_len < (2 * sizeof(u_int8_t)))
    return(-1);

  deserializer->buffer      = serialized_buffer;

  if(deserializer->buffer[0] != 1)
    return(-2); /* Invalid version */

  deserializer->buffer_size = serialized_buffer_len;
  deserializer->fmt         = deserializer->buffer[1];
  ndpi_reset_serializer(_deserializer);

  return(0);
}

/* ********************************** */

int ndpi_init_deserializer(ndpi_deserializer *deserializer,
			   ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  
  return(ndpi_init_deserializer_buf(deserializer,
				    serializer->buffer,
				    serializer->size_used));
}

/* ********************************** */

ndpi_serialization_element_type ndpi_deserialize_get_nextitem_type(ndpi_deserializer *_deserializer) {
  ndpi_serialization_element_type et;
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  
  if(deserializer->size_used >= deserializer->buffer_size)
    return(ndpi_serialization_unknown);

  et = (ndpi_serialization_element_type) deserializer->buffer[deserializer->size_used];

  return et;
}

/* ********************************** */

int ndpi_deserialize_end_of_record(ndpi_deserializer *_deserializer) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  
  if(ndpi_deserialize_get_nextitem_type(_deserializer) == ndpi_serialization_end_of_record) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int16_t expected =
      sizeof(u_int8_t) /* type */;

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */

    return(0);
  } else
    return(-1);
}

/* ********************************** */

int ndpi_deserialize_uint32_uint32(ndpi_deserializer *_deserializer,
				   u_int32_t *key, u_int32_t *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  
  if(ndpi_deserialize_get_nextitem_type(_deserializer) == ndpi_serialization_uint32_uint32) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int16_t expected =
      sizeof(u_int8_t) /* type */ +
      sizeof(u_int32_t) /* key */ +
      sizeof(u_int32_t);

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */
    ndpi_deserialize_single_uint32(_deserializer, key);
    ndpi_deserialize_single_uint32(_deserializer, value);

    return(0);
  } else
    return(-1);
}

/* ********************************** */

int ndpi_deserialize_uint32_uint64(ndpi_deserializer *_deserializer,
				   u_int32_t *key, u_int64_t *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  
  if(ndpi_deserialize_get_nextitem_type(_deserializer) == ndpi_serialization_uint32_uint64) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int16_t expected =
      sizeof(u_int8_t) /* type */ +
      sizeof(u_int32_t) /* key */ +
      sizeof(u_int64_t);

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */
    ndpi_deserialize_single_uint32(_deserializer, key);
    ndpi_deserialize_single_uint64(_deserializer, value);

    return(0);
  } else
    return(-1);
}

/* ********************************** */

int ndpi_deserialize_uint32_string(ndpi_deserializer *_deserializer,
				   u_int32_t *key, ndpi_string *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  
  if(ndpi_deserialize_get_nextitem_type(_deserializer) == ndpi_serialization_uint32_string) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int32_t expected =
      sizeof(u_int8_t) /* type */ +
      sizeof(u_int32_t) /* key */ +
      sizeof(u_int16_t) /* len */;

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */
    ndpi_deserialize_single_uint32(_deserializer, key);
    ndpi_deserialize_single_string(_deserializer, value);

    return(0);
  } else
    return(-1);
}

/* ********************************** */

int ndpi_deserialize_string_int32(ndpi_deserializer *_deserializer,
				  ndpi_string *key, int32_t *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  
  if(ndpi_deserialize_get_nextitem_type(_deserializer) == ndpi_serialization_string_int32) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int32_t expected =
      sizeof(u_int8_t) /* type */ +
      sizeof(u_int16_t) /* key len */ +
      sizeof(int32_t);

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */
    ndpi_deserialize_single_string(_deserializer, key);
    ndpi_deserialize_single_int32(_deserializer, value);

    return(0);
  } else
    return(-1);
}

/* ********************************** */

int ndpi_deserialize_string_int64(ndpi_deserializer *_deserializer,
				  ndpi_string *key, int64_t *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  
  if(ndpi_deserialize_get_nextitem_type(_deserializer) == ndpi_serialization_string_int64) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int32_t expected =
      sizeof(u_int8_t) /* type */ +
      sizeof(u_int16_t) /* key len */ +
      sizeof(int64_t);

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */
    ndpi_deserialize_single_string(_deserializer, key);
    ndpi_deserialize_single_int64(_deserializer, value);

    return(0);
  } else
    return(-1);
}

/* ********************************** */

int ndpi_deserialize_string_uint32(ndpi_deserializer *_deserializer,
				   ndpi_string *key, u_int32_t *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  
  if(ndpi_deserialize_get_nextitem_type(_deserializer) == ndpi_serialization_string_uint32) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int32_t expected =
      sizeof(u_int8_t) /* type */ +
      sizeof(u_int16_t) /* key len */ +
      sizeof(u_int32_t);

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */
    ndpi_deserialize_single_string(_deserializer, key);
    ndpi_deserialize_single_uint32(_deserializer, value);

    return(0);
  } else
    return(-1);
}

/* ********************************** */

int ndpi_deserialize_string_uint64(ndpi_deserializer *_deserializer,
				   ndpi_string *key, u_int64_t *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  
  if(ndpi_deserialize_get_nextitem_type(_deserializer) == ndpi_serialization_string_uint64) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int32_t expected =
      sizeof(u_int8_t) /* type */ +
      sizeof(u_int16_t) /* key len */ +
      sizeof(u_int64_t);

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */
    ndpi_deserialize_single_string(_deserializer, key);
    ndpi_deserialize_single_uint64(_deserializer, value);

    return(0);
  } else
    return(-1);
}

/* ********************************** */

int ndpi_deserialize_string_float(ndpi_deserializer *_deserializer,
				  ndpi_string *key, float *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  
  if(ndpi_deserialize_get_nextitem_type(_deserializer) == ndpi_serialization_string_float) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int32_t expected =
      sizeof(u_int8_t) /* type */ +
      sizeof(u_int16_t) /* key len */ +
      sizeof(float);

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */
    ndpi_deserialize_single_string(_deserializer, key);
    ndpi_deserialize_single_float(_deserializer, value);

    return(0);
  } else
    return(-1);
}

/* ********************************** */

int ndpi_deserialize_string_string(ndpi_deserializer *_deserializer,
				   ndpi_string *key, ndpi_string *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  
  if(ndpi_deserialize_get_nextitem_type(_deserializer) == ndpi_serialization_string_string) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int32_t expected =
      sizeof(u_int8_t) /* type */ +
      sizeof(u_int16_t) /* key len */ +
      sizeof(u_int16_t) /* len */;

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */
    ndpi_deserialize_single_string(_deserializer, key);
    ndpi_deserialize_single_string(_deserializer, value);

    return(0);
  } else
    return(-1);
}

/* ********************************** */
