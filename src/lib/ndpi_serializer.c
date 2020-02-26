/*
 * ndpi_serializer.c
 *
 * Copyright (C) 2011-20 - ntop.org
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
  
  return(u.llv);
}

/* ********************************** */

static u_int64_t ndpi_ntohll(u_int64_t v) {
  union { u_int32_t lv[2]; u_int64_t llv; } u;
  
  u.llv = v;
  
  return((u_int64_t)ntohl(u.lv[0]) << 32) | (u_int64_t)ntohl(u.lv[1]);
}

/* ********************************** */

static int ndpi_is_number(const char *str, u_int32_t str_len) {
  int i;
  
  for(i = 0; i < str_len; i++)
    if(!isdigit(str[i])) return(0);
  
  return(1);
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

  for(i = 0; i < src_len && j < dst_max_len; i++) {

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

  return(j);
}

/* ********************************** */

void ndpi_reset_serializer(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;

  serializer->status.flags = 0;

  if(serializer->fmt == ndpi_serialization_format_json) {
    u_int32_t buff_diff;

    serializer->status.size_used = 0;
    buff_diff = serializer->buffer_size - serializer->status.size_used;

    /* Note: please keep a space at the beginning as it is used for arrays when an end-of-record is used */
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff, " {}");
  } else if(serializer->fmt == ndpi_serialization_format_csv)
    serializer->status.size_used = 0;
  else /* ndpi_serialization_format_tlv */
    serializer->status.size_used = 2 * sizeof(u_int8_t);
}

/* ********************************** */

int ndpi_init_serializer_ll(ndpi_serializer *_serializer,
			 ndpi_serialization_format fmt,
			 u_int32_t buffer_size) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;

  memset(serializer, 0, sizeof(ndpi_private_serializer));

  serializer->initial_buffer_size = serializer->buffer_size = buffer_size;
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

int ndpi_init_serializer(ndpi_serializer *_serializer,
			 ndpi_serialization_format fmt) {
  return(ndpi_init_serializer_ll(_serializer, fmt, NDPI_SERIALIZER_DEFAULT_BUFFER_SIZE));
}

/* ********************************** */

char* ndpi_serializer_get_buffer(ndpi_serializer *_serializer, u_int32_t *buffer_len) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  char *buf = (char*)serializer->buffer;

  /* NULL terminate the buffer if there is space available */
  if(serializer->buffer_size > serializer->status.size_used)
    serializer->buffer[serializer->status.size_used] = '\0';

  *buffer_len = serializer->status.size_used;

  if(serializer->fmt == ndpi_serialization_format_json) {
    while((buf[0] == '\0') || (buf[0] == ' '))
      buf++, *buffer_len = *buffer_len - 1;
  }

  return(buf);
}

/* ********************************** */

u_int32_t ndpi_serializer_get_buffer_len(ndpi_serializer *_serializer) {
  return(((ndpi_private_serializer*)_serializer)->status.size_used);
}

/* ********************************** */

u_int32_t ndpi_serializer_get_internal_buffer_size(ndpi_serializer *_serializer) {
  return(((ndpi_private_serializer*)_serializer)->buffer_size);
}

/* ********************************** */

int ndpi_serializer_set_buffer_len(ndpi_serializer *_serializer, u_int32_t l) {
  ndpi_private_serializer *p = (ndpi_private_serializer*)_serializer;

  if(p) {
    if(p->buffer_size <= l)
      return(-1); /* Invalid size */

    p->status.size_used = l;
    return(0);
  }

  return(-2);
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

static inline int ndpi_extend_serializer_buffer(ndpi_serializer *_serializer, u_int32_t min_len) {
  u_int32_t new_size;
  void *r;
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;

  if(min_len < NDPI_SERIALIZER_DEFAULT_BUFFER_INCR) {
    if(serializer->initial_buffer_size < NDPI_SERIALIZER_DEFAULT_BUFFER_INCR) {
      if(min_len < serializer->initial_buffer_size)
        min_len = serializer->initial_buffer_size;
    } else {
      min_len = NDPI_SERIALIZER_DEFAULT_BUFFER_INCR;
    }
  }

  new_size = serializer->buffer_size + min_len;
  new_size = ((new_size / 4) + 1) * 4; /* required by zmq encryption */

  r = realloc((void *) serializer->buffer, new_size);

  if(r == NULL)
    return(-1);

  serializer->buffer = r;
  serializer->buffer_size = new_size;

  return(0);
}

/* ********************************** */

static inline void ndpi_serialize_single_uint8(ndpi_private_serializer *serializer,
					       u_int8_t s) {
  u_int8_t v = s;

  memcpy(&serializer->buffer[serializer->status.size_used], &v, sizeof(u_int8_t));
  serializer->status.size_used += sizeof(u_int8_t);
}

/* ********************************** */

static inline void ndpi_serialize_single_uint16(ndpi_private_serializer *serializer,
						u_int16_t s) {
  u_int16_t v = htons(s);

  memcpy(&serializer->buffer[serializer->status.size_used], &v, sizeof(u_int16_t));
  serializer->status.size_used += sizeof(u_int16_t);
}

/* ********************************** */

static inline void ndpi_serialize_single_uint32(ndpi_private_serializer *serializer,
						u_int32_t s) {
  u_int32_t v = htonl(s);

  memcpy(&serializer->buffer[serializer->status.size_used], &v, sizeof(u_int32_t));
  serializer->status.size_used += sizeof(u_int32_t);
}

/* ********************************** */

static inline void ndpi_serialize_single_uint64(ndpi_private_serializer *serializer,
						u_int64_t s) {
  u_int64_t v = ndpi_htonll(s);

  memcpy(&serializer->buffer[serializer->status.size_used], &v, sizeof(u_int64_t));
  serializer->status.size_used += sizeof(u_int64_t);
}

/* ********************************** */

/* TODO: fix portability across platforms */
static inline void ndpi_serialize_single_float(ndpi_private_serializer *serializer,
					       float s) {
  memcpy(&serializer->buffer[serializer->status.size_used], &s, sizeof(s));
  serializer->status.size_used += sizeof(float);
}

/* ********************************** */

static inline void ndpi_serialize_single_string(ndpi_private_serializer *serializer,
						const char *s, u_int16_t slen) {
  u_int16_t l = htons(slen);

  memcpy(&serializer->buffer[serializer->status.size_used], &l, sizeof(u_int16_t));
  serializer->status.size_used += sizeof(u_int16_t);

  if(slen > 0)
    memcpy(&serializer->buffer[serializer->status.size_used], s, slen);

  serializer->status.size_used += slen;
}

/* ********************************** */

static inline void ndpi_deserialize_single_uint8(ndpi_private_deserializer *deserializer,
						 u_int32_t offset, u_int8_t *s) {
  *s = (*((u_int8_t *) &deserializer->buffer[offset]));
}

/* ********************************** */

static inline void ndpi_deserialize_single_uint16(ndpi_private_deserializer *deserializer,
						  u_int32_t offset, u_int16_t *s) {
  *s = ntohs(*((u_int16_t *) &deserializer->buffer[offset]));
}

/* ********************************** */

static inline void ndpi_deserialize_single_uint32(ndpi_private_deserializer *deserializer,
						  u_int32_t offset, u_int32_t *s) {
  *s = ntohl(*((u_int32_t *) &deserializer->buffer[offset]));
}

/* ********************************** */

static inline void ndpi_deserialize_single_int8(ndpi_private_deserializer *deserializer,
						u_int32_t offset, int8_t *s) {
  *s = (*((int8_t *) &deserializer->buffer[offset]));
}

/* ********************************** */

static inline void ndpi_deserialize_single_int16(ndpi_private_deserializer *deserializer,
						 u_int32_t offset, int16_t *s) {
  *s = ntohs(*((int16_t *) &deserializer->buffer[offset]));
}

/* ********************************** */

static inline void ndpi_deserialize_single_int32(ndpi_private_deserializer *deserializer,
						 u_int32_t offset, int32_t *s) {
  *s = ntohl(*((int32_t *) &deserializer->buffer[offset]));
}

/* ********************************** */

static inline void ndpi_deserialize_single_uint64(ndpi_private_deserializer *deserializer,
						  u_int32_t offset, u_int64_t *s) {
  *s = ndpi_ntohll(*(u_int64_t*)&deserializer->buffer[offset]);
}

/* ********************************** */

static inline void ndpi_deserialize_single_int64(ndpi_private_deserializer *deserializer,
						 u_int32_t offset, int64_t *s) {
  *s = ndpi_ntohll(*(int64_t*)&deserializer->buffer[offset]);
}

/* ********************************** */

/* TODO: fix portability across platforms */
static inline void ndpi_deserialize_single_float(ndpi_private_deserializer *deserializer,
						 u_int32_t offset, float *s) {
  *s = *(float*)&deserializer->buffer[offset];
}

/* ********************************** */

static inline void ndpi_deserialize_single_string(ndpi_private_deserializer *deserializer,
						  u_int32_t offset, ndpi_string *v) {
  v->str_len = ntohs(*((u_int16_t *) &deserializer->buffer[offset]));
  v->str = (char *) &deserializer->buffer[offset + sizeof(u_int16_t)];
}

/* ********************************** */

int ndpi_serialize_end_of_record(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->status.size_used;
  u_int16_t needed =
    sizeof(u_int8_t) /* type */;

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 1;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    if(!(serializer->status.flags & NDPI_SERIALIZER_STATUS_ARRAY)) {
      serializer->buffer[0] = '[';
      serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used],
					buff_diff, "]");
    }
    serializer->status.flags |= NDPI_SERIALIZER_STATUS_ARRAY | NDPI_SERIALIZER_STATUS_EOR;
    serializer->status.flags &= ~NDPI_SERIALIZER_STATUS_COMMA;
  } else {
    serializer->buffer[serializer->status.size_used++] = ndpi_serialization_end_of_record;
  }

  return(0);
}

/* ********************************** */

static inline void ndpi_serialize_json_pre(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;

  if(serializer->status.flags & NDPI_SERIALIZER_STATUS_EOR) {
    serializer->status.size_used--; /* Remove ']' */
    serializer->status.flags &= ~NDPI_SERIALIZER_STATUS_EOR;
    serializer->buffer[serializer->status.size_used++] = ',';
    serializer->buffer[serializer->status.size_used++] = '{';
  } else {
    if(serializer->status.flags & NDPI_SERIALIZER_STATUS_ARRAY)
      serializer->status.size_used--; /* Remove ']'*/
    serializer->status.size_used--; /* Remove '}'*/

    if(serializer->status.flags & NDPI_SERIALIZER_STATUS_SOB)
      serializer->status.flags &= ~NDPI_SERIALIZER_STATUS_SOB;
    else if(serializer->status.flags & NDPI_SERIALIZER_STATUS_COMMA)
      serializer->buffer[serializer->status.size_used++] = ',';
  }
}

/* ********************************** */

static inline void ndpi_serialize_json_post(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;

  serializer->buffer[serializer->status.size_used++] = '}';
  if(serializer->status.flags & NDPI_SERIALIZER_STATUS_ARRAY)
    serializer->buffer[serializer->status.size_used++] = ']';

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_COMMA;
}

/* ********************************** */

static inline ndpi_serialization_type ndpi_serialize_key_uint32(ndpi_private_serializer *serializer, u_int32_t key) {
  ndpi_serialization_type kt;

  if(key <= 0xff) {
    ndpi_serialize_single_uint8(serializer, key);
    kt = ndpi_serialization_uint8;
  } else if(key <= 0xffff) {
    ndpi_serialize_single_uint16(serializer, key);
    kt = ndpi_serialization_uint16;
  } else {
    ndpi_serialize_single_uint32(serializer, key);
    kt = ndpi_serialization_uint32;
  }

  return(kt);
}

/* ********************************** */

int ndpi_serialize_uint32_uint32(ndpi_serializer *_serializer,
				 u_int32_t key, u_int32_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->status.size_used;
  u_int16_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int32_t) /* key */ +
    sizeof(u_int32_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 24;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      "\"%u\":%u", key, value);
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      "%s%u", (serializer->status.size_used > 0) ? serializer->csv_separator : "", value);
  } else {
    ndpi_serialization_type kt;
    u_int8_t type = 0;
    u_int32_t type_offset = serializer->status.size_used++;

    kt = ndpi_serialize_key_uint32(serializer, key);
    type = (kt << 4);

    if(value <= 0xff) {
      ndpi_serialize_single_uint8(serializer, value);
      type |= ndpi_serialization_uint8;
    } else if(value <= 0xffff) {
      ndpi_serialize_single_uint16(serializer, value);
      type |= ndpi_serialization_uint16;
    } else {
      ndpi_serialize_single_uint32(serializer, value);
      type |= ndpi_serialization_uint32;
    }

    serializer->buffer[type_offset] = type;
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_uint32_uint64(ndpi_serializer *_serializer,
				 u_int32_t key, u_int64_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->status.size_used;
  u_int16_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int32_t) /* key */ +
    sizeof(u_int64_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 32;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      "\"%u\":%llu", key, (unsigned long long)value);
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      "%s%llu",
				      (serializer->status.size_used > 0) ? serializer->csv_separator : "",
				      (unsigned long long)value);
  } else {
    if(value <= 0xffffffff) {
      return(ndpi_serialize_uint32_uint32(_serializer, key, value));
    } else {
      ndpi_serialization_type kt;
      u_int8_t type = 0;
      u_int32_t type_offset = serializer->status.size_used++;

      kt = ndpi_serialize_key_uint32(serializer, key);
      type = (kt << 4);

      ndpi_serialize_single_uint64(serializer, value);
      type |= ndpi_serialization_uint64;

      serializer->buffer[type_offset] = type;
    }
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_uint32_int32(ndpi_serializer *_serializer,
				u_int32_t key, int32_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->status.size_used;
  u_int16_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int32_t) /* key */ +
    sizeof(int32_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 24;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      "\"%u\":%d", key, value);
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      "%s%d", (serializer->status.size_used > 0) ? serializer->csv_separator : "", value);
  } else {
    ndpi_serialization_type kt;
    u_int8_t type = 0;
    u_int32_t type_offset = serializer->status.size_used++;

    kt = ndpi_serialize_key_uint32(serializer, key);
    type = (kt << 4);

    if(value <= 127 && value >= -128) {
      ndpi_serialize_single_uint8(serializer, value);
      type |= ndpi_serialization_int8;
    } else if(value <= 32767 && value >= -32768) {
      ndpi_serialize_single_uint16(serializer, value);
      type |= ndpi_serialization_int16;
    } else {
      ndpi_serialize_single_uint32(serializer, value);
      type |= ndpi_serialization_int32;
    }

    serializer->buffer[type_offset] = type;
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_uint32_int64(ndpi_serializer *_serializer,
				u_int32_t key, int64_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->status.size_used;
  u_int16_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int32_t) /* key */ +
    sizeof(int64_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 32;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      "\"%u\":%lld", key, (long long int)value);
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      "%s%lld",
				      (serializer->status.size_used > 0) ? serializer->csv_separator : "",
				      (long long int)value);

  }
  else {
    if((value & 0xFFFFFFFF) == value) {
      return(ndpi_serialize_uint32_int32(_serializer, key, value));
    } else {
      ndpi_serialization_type kt;
      u_int8_t type = 0;
      u_int32_t type_offset = serializer->status.size_used++;

      kt = ndpi_serialize_key_uint32(serializer, key);
      type = (kt << 4);

      ndpi_serialize_single_uint64(serializer, value);
      type |= ndpi_serialization_int64;

      serializer->buffer[type_offset] = type;
    }
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_uint32_float(ndpi_serializer *_serializer,
				u_int32_t key, float value,
                                const char *format /* e.f. "%.2f" */) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->status.size_used;
  u_int16_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int32_t) /* key */ +
    sizeof(float);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 32;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff, "\"%u\":", key);
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff, format, value);
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff, "%s",
				      (serializer->status.size_used > 0) ? serializer->csv_separator : "");
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff, format, value);

  } else {
    ndpi_serialization_type kt;
    u_int8_t type = 0;
    u_int32_t type_offset = serializer->status.size_used++;

    kt = ndpi_serialize_key_uint32(serializer, key);
    type = (kt << 4);

    ndpi_serialize_single_float(serializer, value);
    type |= ndpi_serialization_float;

    serializer->buffer[type_offset] = type;
  }

  return(0);
}

/* ********************************** */

static int ndpi_serialize_uint32_binary(ndpi_serializer *_serializer,
					u_int32_t key, const char *value, u_int16_t slen) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->status.size_used;
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
    buff_diff = serializer->buffer_size - serializer->status.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      "\"%u\":", key);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
    serializer->status.size_used += ndpi_json_string_escape(value, slen,
						     (char *) &serializer->buffer[serializer->status.size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      "%s%s", (serializer->status.size_used > 0) ? serializer->csv_separator : "", value);
  } else {
    ndpi_serialization_type kt;
    u_int8_t type = 0;
    u_int32_t type_offset = serializer->status.size_used++;

    kt = ndpi_serialize_key_uint32(serializer, key);
    type = (kt << 4);

    ndpi_serialize_single_string(serializer, value, slen);
    type |= ndpi_serialization_string;

    serializer->buffer[type_offset] = type;
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_uint32_string(ndpi_serializer *_serializer,
				 u_int32_t key, const char *_value) {
  const char *value = _value ? _value : "";
  return(ndpi_serialize_uint32_binary(_serializer, key, value, strlen(value)));
}

/* ********************************** */

int ndpi_serialize_uint32_boolean(ndpi_serializer *_serializer,
				  u_int32_t key, u_int8_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->status.size_used;
  u_int32_t needed = 24;

  if(serializer->fmt != ndpi_serialization_format_json &&
     serializer->fmt != ndpi_serialization_format_csv)
    return -1;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      "\"%u\":%s", key, value ? "true" : "false");
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
      "%s%s", (serializer->status.size_used > 0) ? serializer->csv_separator : "",
      value ? "true" : "false");
  }

  return(0);
}

/* ********************************** */

static int ndpi_serialize_binary_int32(ndpi_serializer *_serializer,
				       const char *key, u_int16_t klen,
				       int32_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->status.size_used;
  u_int32_t needed;

  if(ndpi_is_number(key, klen))
    return(ndpi_serialize_uint32_int32(_serializer, atoi(key), value));

  needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(u_int32_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 16 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->status.size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->status.size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      ":%d", value);
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      "%s%d", (serializer->status.size_used > 0) ? serializer->csv_separator : "", value);
  } else {
    if(value <= 127 && value >= -128) {
      serializer->buffer[serializer->status.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_int8;
      ndpi_serialize_single_string(serializer, key, klen);
      ndpi_serialize_single_uint8(serializer, value);
    } else if(value <= 32767 && value >= -32768) {
      serializer->buffer[serializer->status.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_int16;
      ndpi_serialize_single_string(serializer, key, klen);
      ndpi_serialize_single_uint16(serializer, value);
    } else {
      serializer->buffer[serializer->status.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_int32;
      ndpi_serialize_single_string(serializer, key, klen);
      ndpi_serialize_single_uint32(serializer, value);
    }
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_string_int32(ndpi_serializer *_serializer,
				const char *key, int32_t value) {
  return(ndpi_serialize_binary_int32(_serializer, key, strlen(key), value));
}

/* ********************************** */

int ndpi_serialize_binary_int64(ndpi_serializer *_serializer,
				const char *key, u_int16_t klen,
				int64_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->status.size_used;
  u_int32_t needed;

  if(ndpi_is_number(key, klen))
    return(ndpi_serialize_uint32_int64(_serializer, atoi(key), value));

  needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(u_int32_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 16 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->status.size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->status.size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      ":%lld", (long long int)value);
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      "%s%lld", (serializer->status.size_used > 0) ? serializer->csv_separator : "",
				      (long long int)value);
  } else {
    if ((value & 0xFFFFFFFF) == value) {
      return(ndpi_serialize_string_int32(_serializer, key, value));
    } else {
      serializer->buffer[serializer->status.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_int64;
      ndpi_serialize_single_string(serializer, key, klen);
      ndpi_serialize_single_uint32(serializer, value);
    }
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_string_int64(ndpi_serializer *_serializer,
				const char *key, int64_t value) {
  return(ndpi_serialize_binary_int64(_serializer, key, strlen(key), value));
}

/* ********************************** */

static int ndpi_serialize_binary_uint32(ndpi_serializer *_serializer,
					const char *key, u_int16_t klen, u_int32_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->status.size_used;
  u_int32_t needed;

  if(ndpi_is_number(key, klen))
    return(ndpi_serialize_uint32_uint32(_serializer, atoi(key), value));

  needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(u_int32_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 16 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->status.size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->status.size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      ":%u", value);
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      "%s%u", (serializer->status.size_used > 0) ? serializer->csv_separator : "", value);
  } else {
    if(value <= 0xff) {
      serializer->buffer[serializer->status.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_uint8;
      ndpi_serialize_single_string(serializer, key, klen);
      ndpi_serialize_single_uint8(serializer, value);
    } else if(value <= 0xffff) {
      serializer->buffer[serializer->status.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_uint16;
      ndpi_serialize_single_string(serializer, key, klen);
      ndpi_serialize_single_uint16(serializer, value);
    } else {
      serializer->buffer[serializer->status.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_uint32;
      ndpi_serialize_single_string(serializer, key, klen);
      ndpi_serialize_single_uint32(serializer, value);
    }
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_string_uint32(ndpi_serializer *_serializer,
				 const char *key, u_int32_t value) {
  return(ndpi_serialize_binary_uint32(_serializer, key, strlen(key), value));
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

static int ndpi_serialize_binary_uint64(ndpi_serializer *_serializer,
					const char *key, u_int16_t klen,
					u_int64_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->status.size_used;
  u_int32_t needed;

  if(ndpi_is_number(key, klen))
    return(ndpi_serialize_uint32_uint64(_serializer, atoi(key), value));

  needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(u_int64_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 32 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->status.size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->status.size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      ":%llu", (unsigned long long)value);
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      "%s%llu", (serializer->status.size_used > 0) ? serializer->csv_separator : "",
				      (unsigned long long)value);
  } else {
    if(value <= 0xffffffff) {
      return(ndpi_serialize_string_uint32(_serializer, key, value));
    } else {
      serializer->buffer[serializer->status.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_uint64;
      ndpi_serialize_single_string(serializer, key, klen);
      ndpi_serialize_single_uint64(serializer, value);
    }
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_string_uint64(ndpi_serializer *_serializer,
				 const char *key, u_int64_t value) {
  return(ndpi_serialize_binary_uint64(_serializer, key, strlen(key), value));
}

/* ********************************** */

static int ndpi_serialize_binary_float(ndpi_serializer *_serializer,
				       const char *key,
				       u_int16_t klen,
				       float value,
				       const char *format /* e.f. "%.2f" */) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->status.size_used;
  u_int32_t needed;

  if(ndpi_is_number(key, klen))
    return(ndpi_serialize_uint32_float(_serializer, atoi(key), value, format));

  needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(float);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 32 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->status.size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->status.size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->status.size_used;

    serializer->buffer[serializer->status.size_used] = ':';
    serializer->status.size_used++;

    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff, format, value);

    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    if(serializer->status.size_used > 0)
      serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff, "%s", serializer->csv_separator);

    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff, format, value);
  } else {
    serializer->buffer[serializer->status.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_float;

    ndpi_serialize_single_string(serializer, key, klen);
    ndpi_serialize_single_float(serializer, value);
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_string_float(ndpi_serializer *_serializer,
				const char *key,
				float value,
				const char *format /* e.f. "%.2f" */) {
  return(ndpi_serialize_binary_float(_serializer, key, strlen(key), value, format));
}

/* ********************************** */

/* Key is a <string, len> pair, value is a raw value */
static int ndpi_serialize_binary_raw(ndpi_serializer *_serializer,
					const char *key,
					u_int16_t klen,
					const char *value,
					u_int16_t vlen,
					u_int8_t escape) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->status.size_used;
  u_int32_t needed;

  needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen +
    sizeof(u_int16_t) /* len */ +
    vlen;

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 16 + klen + vlen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->status.size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->status.size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff, ":");
    buff_diff = serializer->buffer_size - serializer->status.size_used;

    if (escape)
      serializer->status.size_used += ndpi_json_string_escape(value, vlen,
        (char *) &serializer->buffer[serializer->status.size_used], buff_diff);
    else
      serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
        value, vlen);
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
				      "%s%s", (serializer->status.size_used > 0) ? serializer->csv_separator : "",
				      value);
  } else {
    serializer->buffer[serializer->status.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_string;

    ndpi_serialize_single_string(serializer, key, klen);
    ndpi_serialize_single_string(serializer, value, vlen);
  }

  return(0);
}

/* ********************************** */

/* Key is a <string, len> pair, value is a <string, len> pair */ 
static int ndpi_serialize_binary_binary(ndpi_serializer *_serializer,
					const char *key,
					u_int16_t klen,
					const char *_value,
					u_int16_t vlen) {
  const char *value = _value ? _value : "";

  if(ndpi_is_number(key, klen))
    return(ndpi_serialize_uint32_binary(_serializer, atoi(key), value, vlen));

  return ndpi_serialize_binary_raw(_serializer, key, klen, value, vlen, 1 /* escape */);
}

/* ********************************** */

/* Key is a string, value is a <string, len> pair */
int ndpi_serialize_string_binary(ndpi_serializer *_serializer,
				 const char *key, const char *_value,
				 u_int16_t vlen) {
  return(ndpi_serialize_binary_binary(_serializer, key, strlen(key), _value, vlen));
}

/* ********************************** */

/* Key is a string, value is a string (strlen is used to compute the len) */
int ndpi_serialize_string_string(ndpi_serializer *_serializer,
				 const char *key, const char *_value) {
  const char *value = _value ? _value : "";
  return(ndpi_serialize_binary_binary(_serializer, key, strlen(key), value, strlen(value)));
}

/* ********************************** */

/* Key is a string, value is a raw json value (it can be a number, an escaped/quoted string, an array, ..) */
int ndpi_serialize_string_raw(ndpi_serializer *_serializer,
				 const char *key, const char *_value, u_int16_t vlen) {
  return(ndpi_serialize_binary_raw(_serializer, key, strlen(key), _value, vlen, 0 /* do not escape */));
}

/* ********************************** */

int ndpi_serialize_string_boolean(ndpi_serializer *_serializer,
				  const char *key, u_int8_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->status.size_used;
  u_int16_t klen = strlen(key);
  u_int32_t needed;

  if(serializer->fmt != ndpi_serialization_format_json &&
     serializer->fmt != ndpi_serialization_format_csv)
    return -1;

  if(ndpi_is_number(key, klen))
    return(ndpi_serialize_uint32_boolean(_serializer, atoi(key), value));

  needed = klen + 16;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    serializer->status.size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->status.size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff, ":%s",
      value ? "true" : "false");
    ndpi_serialize_json_post(_serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff,
      "%s%s", (serializer->status.size_used > 0) ? serializer->csv_separator : "",
      value ? "true" : "false");
  }

  return(0);
}

/* ********************************** */

/* Serialize start of nested block (JSON only)*/
int ndpi_serialize_start_of_block(ndpi_serializer *_serializer,
				  const char *key) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->status.size_used;
  u_int32_t needed, klen = strlen(key);

  if(serializer->fmt != ndpi_serialization_format_json)
    return(-1);

  needed = 16 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
  }

  ndpi_serialize_json_pre(_serializer);
  serializer->status.size_used += ndpi_json_string_escape(key, klen,
    (char *) &serializer->buffer[serializer->status.size_used], buff_diff);
  buff_diff = serializer->buffer_size - serializer->status.size_used;
  serializer->status.size_used += snprintf((char *) &serializer->buffer[serializer->status.size_used], buff_diff, ": {");
  buff_diff = serializer->buffer_size - serializer->status.size_used;
  ndpi_serialize_json_post(_serializer);

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_SOB;

  return(0);
}

/* ********************************** */

/* Serialize start of nested block (JSON only)*/
int ndpi_serialize_end_of_block(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer_size - serializer->status.size_used;
  u_int32_t needed;

  if(serializer->fmt != ndpi_serialization_format_json)
    return(-1);

  needed = 4;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(_serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->status.size_used;
  }

  // buff_diff = serializer->buffer_size - serializer->status.size_used;
  ndpi_serialize_json_post(_serializer);

  return(0);
}

/* ********************************** */

void ndpi_serializer_create_snapshot(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;

#if 0
  printf("[NDPI] Snapshot status: %s%s%s\n",
    (serializer->status.flags & NDPI_SERIALIZER_STATUS_COMMA) ? " COMMA" : "",
    (serializer->status.flags & NDPI_SERIALIZER_STATUS_ARRAY) ? " ARRAY" : "",
    (serializer->status.flags & NDPI_SERIALIZER_STATUS_EOR)   ? " EOR"   : ""
  );
#endif 
 
  memcpy(&serializer->snapshot, &serializer->status, sizeof(ndpi_private_serializer_status));
  serializer->has_snapshot = 1;
}

/* ********************************** */

void ndpi_serializer_rollback_snapshot(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  
  if(serializer->has_snapshot) {
    memcpy(&serializer->status, &serializer->snapshot, sizeof(ndpi_private_serializer_status));
    serializer->has_snapshot = 0;

    if(serializer->fmt == ndpi_serialization_format_json) {
      if(serializer->status.flags & NDPI_SERIALIZER_STATUS_ARRAY) {
        serializer->buffer[serializer->status.size_used-1] = ']';
      } else {
        serializer->buffer[0] = ' ';
        serializer->buffer[serializer->status.size_used-1] = '}';
      }
    } 
  }
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
				    serializer->status.size_used));
}

/* ********************************** */

ndpi_serialization_format ndpi_deserialize_get_format(ndpi_deserializer *_deserializer) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  return(deserializer->fmt);
}

/* ********************************** */

static inline ndpi_serialization_type ndpi_deserialize_get_key_subtype(ndpi_private_deserializer *deserializer) {
  u_int8_t type;

  if(deserializer->status.size_used >= deserializer->buffer_size)
    return(ndpi_serialization_unknown);

  type = deserializer->buffer[deserializer->status.size_used];

  return((ndpi_serialization_type) (type >> 4));
}

/* ********************************** */

static inline ndpi_serialization_type ndpi_deserialize_get_value_subtype(ndpi_private_deserializer *deserializer) {
  u_int8_t type;

  if(deserializer->status.size_used >= deserializer->buffer_size)
    return(ndpi_serialization_unknown);

  type = deserializer->buffer[deserializer->status.size_used];

  return(ndpi_serialization_type) (type & 0xf);
}

/* ********************************** */

ndpi_serialization_type ndpi_deserialize_get_item_type(ndpi_deserializer *_deserializer, ndpi_serialization_type *key_type) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  ndpi_serialization_type kt, et;

  /* Note: 32/64 bit types are automatically encoded/decoded as 8/16 bit */

  kt = ndpi_deserialize_get_key_subtype(deserializer);

  switch(kt) {
  case ndpi_serialization_uint8:
  case ndpi_serialization_uint16:
    kt = ndpi_serialization_uint32;
    break;
  default:
    break;
  }

  et = ndpi_deserialize_get_value_subtype(deserializer);

  switch(et) {
  case ndpi_serialization_uint8:
  case ndpi_serialization_uint16:
    et = ndpi_serialization_uint32;
    break;
  case ndpi_serialization_int8:
  case ndpi_serialization_int16:
    et = ndpi_serialization_int32;
    break;
  default:
    break;
  }

  *key_type = kt;
  return(et);
}

/* ********************************** */

static inline int ndpi_deserialize_get_single_string_size(ndpi_private_deserializer *deserializer, u_int32_t offset) {
  u_int32_t buff_diff = deserializer->buffer_size - offset;
  u_int16_t expected, str_len;

  expected = sizeof(u_int16_t) /* len */;
  if(buff_diff < expected) return(-2);

  str_len = ntohs(*((u_int16_t *) &deserializer->buffer[offset]));

  expected += str_len;
  if(buff_diff < expected) return(-2);

  return(expected);
}

/* ********************************** */

static inline int ndpi_deserialize_get_single_size(ndpi_private_deserializer *deserializer, ndpi_serialization_type type, u_int32_t offset) {
  u_int16_t size;

  switch(type) {
  case ndpi_serialization_uint8:
  case ndpi_serialization_int8:
    size = sizeof(u_int8_t);
    break;
  case ndpi_serialization_uint16:
  case ndpi_serialization_int16:
    size = sizeof(u_int16_t);
    break;
  case ndpi_serialization_uint32:
  case ndpi_serialization_int32:
    size = sizeof(u_int32_t);
    break;
  case ndpi_serialization_uint64:
  case ndpi_serialization_int64:
    size = sizeof(u_int64_t);
    break;
  case ndpi_serialization_float:
    size = sizeof(float);
    break;
  case ndpi_serialization_string:
    size = ndpi_deserialize_get_single_string_size(deserializer, offset);
    break;
  case ndpi_serialization_end_of_record:
  case ndpi_serialization_unknown:
    size = 0;
    break;
  default:
    return(-2);
    break;
  }

  return(size);
}

/* ********************************** */

int ndpi_deserialize_next(ndpi_deserializer *_deserializer) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer *) _deserializer;
  u_int32_t buff_diff = deserializer->buffer_size - deserializer->status.size_used;
  ndpi_serialization_type kt, et;
  u_int16_t expected;
  int size;

  expected = sizeof(u_int8_t) /* type */;

  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.size_used + expected);

  if(size < 0) return(-2);

  expected += size;

  et = ndpi_deserialize_get_value_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, et, deserializer->status.size_used + expected);

  if(size < 0) return(-2);

  expected += size;

  deserializer->status.size_used += expected;

  return(0);
}

/* ********************************** */

int ndpi_deserialize_key_uint32(ndpi_deserializer *_deserializer,
				u_int32_t *key) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  u_int32_t offset, buff_diff = deserializer->buffer_size - deserializer->status.size_used;
  ndpi_serialization_type kt;
  u_int16_t expected;
  u_int16_t v16;
  u_int8_t v8;
  int size;

  expected = sizeof(u_int8_t) /* type */;
  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);

  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.size_used + expected);
  if(size < 0) return(-2);

  offset = deserializer->status.size_used + expected;

  switch(kt) {
  case ndpi_serialization_uint32:
    ndpi_deserialize_single_uint32(deserializer, offset, key);
    break;
  case ndpi_serialization_uint16:
    ndpi_deserialize_single_uint16(deserializer, offset, &v16);
    *key = v16;
    break;
  case ndpi_serialization_uint8:
    ndpi_deserialize_single_uint8(deserializer, offset, &v8);
    *key = v8;
    break;
  default:
    return(-1);
    break;
  }

  return(0);
}

/* ********************************** */

int ndpi_deserialize_key_string(ndpi_deserializer *_deserializer,
				ndpi_string *key) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  ndpi_serialization_type kt;
  u_int32_t buff_diff = deserializer->buffer_size - deserializer->status.size_used;
  u_int16_t expected;
  int size;

  expected = sizeof(u_int8_t) /* type */;
  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);

  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.size_used + expected);
  if(size < 0) return(-2);

  ndpi_deserialize_single_string(deserializer, deserializer->status.size_used + expected, key);

  return(0);
}

/* ********************************** */

int ndpi_deserialize_value_uint32(ndpi_deserializer *_deserializer,
				  u_int32_t *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  ndpi_serialization_type kt, et;
  u_int32_t offset, buff_diff = deserializer->buffer_size - deserializer->status.size_used;
  u_int16_t v16;
  u_int8_t v8;
  u_int16_t expected;
  int size;

  expected = sizeof(u_int8_t) /* type */;
  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.size_used + expected);
  if(size < 0) return(-2);

  expected += size;

  et = ndpi_deserialize_get_value_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, et, deserializer->status.size_used + expected);
  if(size < 0) return(-2);

  offset = deserializer->status.size_used + expected;

  switch(et) {
  case ndpi_serialization_uint32:
    ndpi_deserialize_single_uint32(deserializer, offset, value);
    break;
  case ndpi_serialization_uint16:
    ndpi_deserialize_single_uint16(deserializer, offset, &v16);
    *value = v16;
    break;
  case ndpi_serialization_uint8:
    ndpi_deserialize_single_uint8(deserializer, offset, &v8);
    *value = v8;
    break;
  default:
    break;
  }

  return(0);
}

/* ********************************** */

int ndpi_deserialize_value_uint64(ndpi_deserializer *_deserializer,
				  u_int64_t *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  ndpi_serialization_type kt, et;
  u_int32_t buff_diff = deserializer->buffer_size - deserializer->status.size_used;
  u_int32_t v32;
  u_int16_t expected;
  int size;
  int rc;

  expected = sizeof(u_int8_t) /* type */;
  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.size_used + expected);
  if(size < 0) return(-2);

  expected += size;

  et = ndpi_deserialize_get_value_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, et, deserializer->status.size_used + expected);
  if(size < 0) return(-2);

  if(et != ndpi_serialization_uint64) {
    /* Try with smaller uint types */
    rc = ndpi_deserialize_value_uint32(_deserializer, &v32);
    *value = v32;
    return(rc);
  }

  ndpi_deserialize_single_uint64(deserializer, deserializer->status.size_used + expected, value);

  return(0);
}

/* ********************************** */

int ndpi_deserialize_value_int32(ndpi_deserializer *_deserializer,
				 int32_t *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  ndpi_serialization_type kt, et;
  u_int32_t offset, buff_diff = deserializer->buffer_size - deserializer->status.size_used;
  int16_t v16;
  int8_t v8;
  u_int16_t expected;
  int size;

  expected = sizeof(u_int8_t) /* type */;
  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.size_used + expected);
  if(size < 0) return(-2);

  expected += size;

  et = ndpi_deserialize_get_value_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, et, deserializer->status.size_used + expected);
  if(size < 0) return(-2);

  offset = deserializer->status.size_used + expected;

  switch(et) {
  case ndpi_serialization_int32:
    ndpi_deserialize_single_int32(deserializer, offset, value);
    break;
  case ndpi_serialization_int16:
    ndpi_deserialize_single_int16(deserializer, offset, &v16);
    *value = v16;
    break;
  case ndpi_serialization_int8:
    ndpi_deserialize_single_int8(deserializer, offset, &v8);
    *value = v8;
    break;
  default:
    break;
  }

  return(0);
}

/* ********************************** */

int ndpi_deserialize_value_int64(ndpi_deserializer *_deserializer,
				 int64_t *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  ndpi_serialization_type kt, et;
  u_int32_t buff_diff = deserializer->buffer_size - deserializer->status.size_used;
  int32_t v32;
  u_int16_t expected;
  int size;
  int rc;

  expected = sizeof(u_int8_t) /* type */;
  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.size_used + expected);
  if(size < 0) return(-2);

  expected += size;

  et = ndpi_deserialize_get_value_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, et, deserializer->status.size_used + expected);
  if(size < 0) return(-2);

  if(et != ndpi_serialization_int64) {
    /* Try with smaller int types */
    rc = ndpi_deserialize_value_int32(_deserializer, &v32);
    *value = v32;
    return(rc);
  }

  ndpi_deserialize_single_int64(deserializer, deserializer->status.size_used + expected, value);

  return(0);
}

/* ********************************** */

int ndpi_deserialize_value_float(ndpi_deserializer *_deserializer,
				 float *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  ndpi_serialization_type kt, et;
  u_int32_t buff_diff = deserializer->buffer_size - deserializer->status.size_used;
  u_int16_t expected;
  int size;

  expected = sizeof(u_int8_t) /* type */;
  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.size_used + expected);
  if(size < 0) return(-2);

  expected += size;

  et = ndpi_deserialize_get_value_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, et, deserializer->status.size_used + expected);
  if(size < 0) return(-2);

  if(et != ndpi_serialization_float)
    return(-1);

  ndpi_deserialize_single_float(deserializer, deserializer->status.size_used + expected, value);

  return(0);
}

/* ********************************** */

int ndpi_deserialize_value_string(ndpi_deserializer *_deserializer,
				  ndpi_string *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  ndpi_serialization_type kt, et;
  u_int32_t buff_diff = deserializer->buffer_size - deserializer->status.size_used;
  u_int16_t expected;
  int size;

  expected = sizeof(u_int8_t) /* type */;
  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.size_used + expected);
  if(size < 0) return(-2);

  expected += size;

  et = ndpi_deserialize_get_value_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, et, deserializer->status.size_used + expected);
  if(size < 0) return(-2);

  if(et != ndpi_serialization_string)
    return(-1);

  ndpi_deserialize_single_string(deserializer, deserializer->status.size_used + expected, value);

  return(0);
}

/* ********************************** */

/* Clone (with memcpy) the current item in deserializer to serializer (TLV only) */
int ndpi_deserialize_clone_item(ndpi_deserializer *_deserializer, ndpi_serializer *_serializer) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer *) _deserializer;
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t src_buff_diff = deserializer->buffer_size - deserializer->status.size_used;
  u_int32_t dst_buff_diff = serializer->buffer_size - serializer->status.size_used;
  ndpi_serialization_type kt, et;
  u_int16_t expected;
  int size;

  if(serializer->fmt != ndpi_serialization_format_tlv)
    return(-3);

  expected = sizeof(u_int8_t) /* type */;

  if(src_buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.size_used + expected);

  if(size < 0) return(-2);

  expected += size;

  et = ndpi_deserialize_get_value_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, et, deserializer->status.size_used + expected);

  if(size < 0) return(-2);

  expected += size;

  if(dst_buff_diff < expected) {
    if(ndpi_extend_serializer_buffer(_serializer, expected - dst_buff_diff) < 0)
      return(-1);
    dst_buff_diff = serializer->buffer_size - serializer->status.size_used;
  }

  memcpy(&serializer->buffer[serializer->status.size_used],
         &deserializer->buffer[deserializer->status.size_used],
         expected);

  serializer->status.size_used += expected;

  return(0);
}

/* ********************************** */

/* Clone all elements in deserializer to serializer (this can be used to convert a TLV record to JSON) */
int ndpi_deserialize_clone_all(ndpi_deserializer *deserializer, ndpi_serializer *serializer) {
  ndpi_serialization_type kt, et;
  u_int32_t u32, k32;
  int32_t i32;
  u_int64_t u64;
  int64_t i64;
  float f;
  ndpi_string vs, ks;
  int key_is_string;

  while((et = ndpi_deserialize_get_item_type(deserializer, &kt)) != ndpi_serialization_unknown) {

    if(et == ndpi_serialization_end_of_record) {
      ndpi_serialize_end_of_record(serializer);
      ndpi_deserialize_next(deserializer);
      continue;
    }

    key_is_string = 0;
    switch(kt) {
    case ndpi_serialization_uint32:
      ndpi_deserialize_key_uint32(deserializer, &k32);
      break;
    case ndpi_serialization_string:
      ndpi_deserialize_key_string(deserializer, &ks);
      key_is_string = 1;
      break;
    default:
      return(-1);
    }

    switch(et) {
    case ndpi_serialization_uint32:
      ndpi_deserialize_value_uint32(deserializer, &u32);
      if(key_is_string) ndpi_serialize_binary_uint32(serializer, ks.str, ks.str_len, u32);
      else ndpi_serialize_uint32_uint32(serializer, k32, u32);
      break;

    case ndpi_serialization_uint64:
      ndpi_deserialize_value_uint64(deserializer, &u64);
      if(key_is_string) ndpi_serialize_binary_uint64(serializer, ks.str, ks.str_len, u64);
      else ndpi_serialize_uint32_uint64(serializer, k32, u64);
      break;

    case ndpi_serialization_int32:
      ndpi_deserialize_value_int32(deserializer, &i32);
      if(key_is_string) ndpi_serialize_binary_int32(serializer, ks.str, ks.str_len, i32);
      else ndpi_serialize_uint32_int32(serializer, k32, i32);
      break;

    case ndpi_serialization_int64:
      ndpi_deserialize_value_int64(deserializer, &i64);
      if(key_is_string) ndpi_serialize_binary_int64(serializer, ks.str, ks.str_len, i64);
      else ndpi_serialize_uint32_int64(serializer, k32, i64);
      break;

    case ndpi_serialization_float:
      ndpi_deserialize_value_float(deserializer, &f);
      if(key_is_string) ndpi_serialize_binary_float(serializer, ks.str, ks.str_len, f, "%.3f");
      else ndpi_serialize_uint32_float(serializer, k32, f, "%.3f");
      break;

    case ndpi_serialization_string:
      ndpi_deserialize_value_string(deserializer, &vs);
      if(key_is_string) ndpi_serialize_binary_binary(serializer, ks.str, ks.str_len, vs.str, vs.str_len);
      else ndpi_serialize_uint32_binary(serializer, k32, vs.str, vs.str_len);
      break;

    default:
      return(-2);
    }

    ndpi_deserialize_next(deserializer);
  }

  return(0);
}

/* ********************************** */
