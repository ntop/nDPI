/*
 * ndpi_serializer.c
 *
 * Copyright (C) 2011-23 - ntop.org and contributors
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
#include <inttypes.h>
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

#ifdef WIN32
#define NDPI_I64_FORMAT "%I64d"
#define NDPI_U64_FORMAT "%I64u"
#else
#define NDPI_I64_FORMAT "%lld"
#define NDPI_U64_FORMAT "%llu"
#endif

#define OPTIMIZE_NUMERIC_KEYS      /* Convert numeric string keys into int keys */
#define OPTIMIZE_CSV_SERIALIZATION /* Optimize serialization speed in case of CSV */

/* ********************************** */

u_int64_t ndpi_htonll(u_int64_t v) {
  union { u_int32_t lv[2]; u_int64_t llv; } u;

  u.lv[0] = htonl(v >> 32);
  u.lv[1] = htonl(v & 0xFFFFFFFFULL);

  return(u.llv);
}

/* ********************************** */

u_int64_t ndpi_ntohll(u_int64_t v) {
  union { u_int32_t lv[2]; u_int64_t llv; } u;

  u.llv = v;

  return((u_int64_t)ntohl(u.lv[0]) << 32) | (u_int64_t)ntohl(u.lv[1]);
}

/* ********************************** */

#ifdef OPTIMIZE_NUMERIC_KEYS
static int ndpi_is_number(const char *str, u_int32_t str_len) {
  unsigned int i;

  for(i = 0; i < str_len; i++)
    if(!ndpi_isdigit(str[i])) return(0);

  return(1);
}
#endif

/* ********************************** */

/*
 * Escapes a string to be suitable for a JSON value, adding double quotes, and terminating the string with a null byte.
 * It is recommended to provide a destination buffer (dst) which is as large as double the source buffer (src) at least.
 * Upon successful return, these functions return the number of characters printed (excluding the null byte used to terminate the string).
 */
int ndpi_json_string_escape(const char *src, int src_len, char *dst, int dst_max_len) {
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

    serializer->status.buffer.size_used = 0;
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    if (serializer->multiline_json_array) {
      serializer->status.buffer.size_used += ndpi_snprintf((char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff, "{}");
    } else {
      /* Note: please keep a space at the beginning as it is used for arrays when an end-of-record is used */
      serializer->status.buffer.size_used += ndpi_snprintf((char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff, " {}");
    }
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->status.header.size_used = 0;
    serializer->status.buffer.size_used = 0;
  } else { /* ndpi_serialization_format_tlv */
    serializer->status.buffer.size_used = 2 * sizeof(u_int8_t);
  }
}

/* ********************************** */

void ndpi_serializer_skip_header(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_HDR_DONE;
}

/* ********************************** */

static int ndpi_init_serializer_buffer(ndpi_private_serializer_buffer *buffer, u_int32_t buffer_size) {
  buffer->initial_size = buffer->size = buffer_size;
  buffer->data = (u_int8_t *)ndpi_calloc(buffer->size, sizeof(u_int8_t));
  if(buffer->data == NULL)
    return(-1);

  return(0);
}

/* ********************************** */

int ndpi_init_serializer_ll(ndpi_serializer *_serializer,
			    ndpi_serialization_format fmt,
			    u_int32_t buffer_size) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;

  memset(serializer, 0, sizeof(ndpi_private_serializer));

  if (fmt == ndpi_serialization_format_multiline_json) {
    fmt = ndpi_serialization_format_json;
    serializer->multiline_json_array = 1;
  }

  serializer->fmt = fmt;

  if (buffer_size < 3 ||
      ndpi_init_serializer_buffer(&serializer->buffer, buffer_size) != 0)
    return(-1);

  if(serializer->fmt == ndpi_serialization_format_json) {
    /* nothing to do */

  } else if (fmt == ndpi_serialization_format_csv) {
    if (ndpi_init_serializer_buffer(&serializer->header, NDPI_SERIALIZER_DEFAULT_HEADER_SIZE) != 0) {
      ndpi_term_serializer(_serializer);
      return(-1);
    }

  } else /* ndpi_serialization_format_tlv */ {
    serializer->buffer.data[0]   = 1; /* version */
    serializer->buffer.data[1]   = (u_int8_t) fmt;
  }

  serializer->csv_separator[0] = ',';
  serializer->csv_separator[1] = '\0';

  ndpi_reset_serializer(_serializer);

  return(0);
}

/* ********************************** */

int ndpi_init_serializer(ndpi_serializer *_serializer,
			 ndpi_serialization_format fmt) {
  return(ndpi_init_serializer_ll(_serializer, fmt, NDPI_SERIALIZER_DEFAULT_BUFFER_SIZE));
}

/* ********************************** */

static inline int ndpi_extend_serializer_buffer(ndpi_private_serializer_buffer *buffer, u_int32_t min_len) {
  u_int32_t new_size;
  void *r;

  if(min_len < NDPI_SERIALIZER_DEFAULT_BUFFER_INCR) {
    if(buffer->initial_size < NDPI_SERIALIZER_DEFAULT_BUFFER_INCR) {
      if(min_len < buffer->initial_size)
        min_len = buffer->initial_size;
    } else {
      min_len = NDPI_SERIALIZER_DEFAULT_BUFFER_INCR;
    }
  }

  new_size = buffer->size + min_len;
  new_size = ((new_size / 4) + 1) * 4; /* required by zmq encryption */

  r = ndpi_realloc((void *) buffer->data, buffer->size, new_size);

  if(r == NULL)
    return(-1);

  buffer->data = r;
  buffer->size = new_size;

  return(0);
}

/* ********************************** */

static inline int ndpi_serializer_check_header_room(ndpi_private_serializer *serializer, u_int32_t needed) {
  u_int32_t buff_diff = serializer->header.size - serializer->status.header.size_used;

  if (buff_diff < needed)
    if (ndpi_extend_serializer_buffer(&serializer->header, needed - buff_diff) < 0)
      return(-1);

  buff_diff = serializer->header.size - serializer->status.header.size_used;

  return(buff_diff);
}

/* ********************************** */

static inline int ndpi_serializer_header_uint32(ndpi_private_serializer *serializer, u_int32_t key) {
  int room;

  if (serializer->status.flags & NDPI_SERIALIZER_STATUS_HDR_DONE)
    return(0);

  room = ndpi_serializer_check_header_room(serializer, 12);

  if (room < 0)
    return(-1);

  serializer->status.header.size_used += ndpi_snprintf((char *) &serializer->header.data[serializer->status.header.size_used],
    room, "%s%u", (serializer->status.header.size_used > 0) ? serializer->csv_separator : "", key);

  return(0);
}

/* ********************************** */

static inline int ndpi_serializer_header_string(ndpi_private_serializer *serializer, const char *key, u_int16_t klen) {
  int room;

  if (serializer->status.flags & NDPI_SERIALIZER_STATUS_HDR_DONE)
    return(0);

  room = ndpi_serializer_check_header_room(serializer, klen + 4);

  if (room < 0)
    return(-1);

  if (serializer->status.header.size_used > 0) {
    int slen = strlen(serializer->csv_separator);
    memcpy(&serializer->header.data[serializer->status.header.size_used], serializer->csv_separator, slen);
    serializer->status.header.size_used += slen;
  }

  if (klen > 0) {
    memcpy(&serializer->header.data[serializer->status.header.size_used], key, klen);
    serializer->status.header.size_used += klen;
  }

  serializer->header.data[serializer->status.header.size_used] = '\0';

  return(0);
}

/* ********************************** */

char* ndpi_serializer_get_buffer(ndpi_serializer *_serializer, u_int32_t *buffer_len) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  char *buf = (char*)serializer->buffer.data;

  /* NULL terminate the buffer */
  if(serializer->buffer.size > serializer->status.buffer.size_used) /* safety check */
    serializer->buffer.data[serializer->status.buffer.size_used] = '\0';

  *buffer_len = serializer->status.buffer.size_used;

  if(serializer->fmt == ndpi_serialization_format_json) {
    while((buf[0] == '\0') || (buf[0] == ' '))
      buf++, *buffer_len = *buffer_len - 1;
  }

  return(buf);
}

/* ********************************** */

u_int32_t ndpi_serializer_get_buffer_len(ndpi_serializer *_serializer) {
  return(((ndpi_private_serializer*)_serializer)->status.buffer.size_used);
}

/* ********************************** */

u_int32_t ndpi_serializer_get_internal_buffer_size(ndpi_serializer *_serializer) {
  return(((ndpi_private_serializer*)_serializer)->buffer.size);
}

/* ********************************** */

int ndpi_serializer_set_buffer_len(ndpi_serializer *_serializer, u_int32_t l) {
  ndpi_private_serializer *p = (ndpi_private_serializer*)_serializer;

  if(p) {
    if(p->buffer.size <= l)
      return(-1); /* Invalid size */

    p->status.buffer.size_used = l;
    return(0);
  }

  return(-2);
}

/* ********************************** */

/* Return the header automatically built from keys (CSV only) */
char* ndpi_serializer_get_header(ndpi_serializer *_serializer, u_int32_t *buffer_len) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  char *buf = (char*)serializer->header.data;

  if(buf == NULL) {
    *buffer_len = 0;
    return("");
  }

  /* NULL terminate the buffer */
  if(serializer->header.size > serializer->status.header.size_used) /* safety check */
    serializer->header.data[serializer->status.header.size_used] = '\0';

  *buffer_len = serializer->status.header.size_used;

  return(buf);
}

/* ********************************** */

ndpi_serialization_format ndpi_serializer_get_format(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;

  return(serializer->fmt);
}

/* ********************************** */

void ndpi_serializer_set_csv_separator(ndpi_serializer *_serializer, char separator) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;

  serializer->csv_separator[0] = separator;
}

/* ********************************** */

void ndpi_term_serializer(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;

  if(serializer->buffer.data) {
    ndpi_free(serializer->buffer.data);
    serializer->buffer.size = 0;
    serializer->buffer.data = NULL;
  }

  if(serializer->header.data) {
    ndpi_free(serializer->header.data);
    serializer->header.size = 0;
    serializer->header.data = NULL;
  }
}

/* ********************************** */

static inline void ndpi_serialize_single_uint8(ndpi_private_serializer *serializer,
					       u_int8_t s) {
  u_int8_t v = s;

  memcpy(&serializer->buffer.data[serializer->status.buffer.size_used], &v, sizeof(u_int8_t));
  serializer->status.buffer.size_used += sizeof(u_int8_t);
}

/* ********************************** */

static inline void ndpi_serialize_single_uint16(ndpi_private_serializer *serializer,
						u_int16_t s) {
  u_int16_t v = htons(s);

  memcpy(&serializer->buffer.data[serializer->status.buffer.size_used], &v, sizeof(u_int16_t));
  serializer->status.buffer.size_used += sizeof(u_int16_t);
}

/* ********************************** */

static inline void ndpi_serialize_single_uint32(ndpi_private_serializer *serializer,
						u_int32_t s) {
  u_int32_t v = htonl(s);

  memcpy(&serializer->buffer.data[serializer->status.buffer.size_used], &v, sizeof(u_int32_t));
  serializer->status.buffer.size_used += sizeof(u_int32_t);
}

/* ********************************** */

static inline void ndpi_serialize_single_uint64(ndpi_private_serializer *serializer,
						u_int64_t s) {
  u_int64_t v = ndpi_htonll(s);

  memcpy(&serializer->buffer.data[serializer->status.buffer.size_used], &v, sizeof(u_int64_t));
  serializer->status.buffer.size_used += sizeof(u_int64_t);
}

/* ********************************** */

/* TODO: fix portability across platforms */
static inline void ndpi_serialize_single_float(ndpi_private_serializer *serializer,
					       float s) {
  memcpy(&serializer->buffer.data[serializer->status.buffer.size_used], &s, sizeof(s));
  serializer->status.buffer.size_used += sizeof(float);
}

/* ********************************** */

/* TODO: fix portability across platforms */
#if 0
static inline void ndpi_serialize_single_double(ndpi_private_serializer *serializer,
                           double s) {
  memcpy(&serializer->buffer.data[serializer->status.buffer.size_used], &s, sizeof(s));
  serializer->status.buffer.size_used += sizeof(double);
}
#endif

/* ********************************** */

static inline void ndpi_serialize_single_string(ndpi_private_serializer *serializer,
						const char *s, u_int16_t slen) {
  u_int16_t l = htons(slen);

  memcpy(&serializer->buffer.data[serializer->status.buffer.size_used], &l, sizeof(u_int16_t));
  serializer->status.buffer.size_used += sizeof(u_int16_t);

  if(slen > 0)
    memcpy(&serializer->buffer.data[serializer->status.buffer.size_used], s, slen);

  serializer->status.buffer.size_used += slen;
}

/* ********************************** */

static inline void ndpi_deserialize_single_uint8(ndpi_private_deserializer *deserializer,
						 u_int32_t offset, u_int8_t *s) {
  *s = (*((u_int8_t *) &deserializer->buffer.data[offset]));
}

/* ********************************** */

static inline void ndpi_deserialize_single_uint16(ndpi_private_deserializer *deserializer,
						  u_int32_t offset, u_int16_t *s) {
  *s = ntohs(*((u_int16_t *) &deserializer->buffer.data[offset]));
}

/* ********************************** */

static inline void ndpi_deserialize_single_uint32(ndpi_private_deserializer *deserializer,
						  u_int32_t offset, u_int32_t *s) {
  *s = ntohl(*((u_int32_t *) &deserializer->buffer.data[offset]));
}

/* ********************************** */

static inline void ndpi_deserialize_single_int8(ndpi_private_deserializer *deserializer,
						u_int32_t offset, int8_t *s) {
  *s = (*((int8_t *) &deserializer->buffer.data[offset]));
}

/* ********************************** */

static inline void ndpi_deserialize_single_int16(ndpi_private_deserializer *deserializer,
						 u_int32_t offset, int16_t *s) {
  *s = ntohs(*((int16_t *) &deserializer->buffer.data[offset]));
}

/* ********************************** */

static inline void ndpi_deserialize_single_int32(ndpi_private_deserializer *deserializer,
						 u_int32_t offset, int32_t *s) {
  *s = ntohl(*((int32_t *) &deserializer->buffer.data[offset]));
}

/* ********************************** */

static inline void ndpi_deserialize_single_uint64(ndpi_private_deserializer *deserializer,
						  u_int32_t offset, u_int64_t *s) {
  *s = ndpi_ntohll(*(u_int64_t*)&deserializer->buffer.data[offset]);
}

/* ********************************** */

static inline void ndpi_deserialize_single_int64(ndpi_private_deserializer *deserializer,
						 u_int32_t offset, int64_t *s) {
  *s = ndpi_ntohll(*(int64_t*)&deserializer->buffer.data[offset]);
}

/* ********************************** */

/* TODO: fix portability across platforms */
static inline void ndpi_deserialize_single_float(ndpi_private_deserializer *deserializer,
						 u_int32_t offset, float *s) {
  *s = *(float*)&deserializer->buffer.data[offset];
}

/* ********************************** */

/* TODO: fix portability across platforms */
static inline void ndpi_deserialize_single_double(ndpi_private_deserializer *deserializer,
                         u_int32_t offset, double *s) {
  *s = *(double*)&deserializer->buffer.data[offset];
}

/* ********************************** */

static inline void ndpi_deserialize_single_string(ndpi_private_deserializer *deserializer,
						  u_int32_t offset, ndpi_string *v) {
  v->str_len = ntohs(*((u_int16_t *) &deserializer->buffer.data[offset]));
  v->str = (char *) &deserializer->buffer.data[offset + sizeof(u_int16_t)];
}

/* ********************************** */

/*
  This function helps extending the existing serializer by adding a new
  element in the array. This element is handled as raw without any
  further check whatsoever
*/
int ndpi_serialize_raw_record(ndpi_serializer *_serializer,
			      u_char *record, u_int32_t record_len) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int16_t needed = record_len;
  u_int8_t add_comma = 0;

  if(serializer->fmt == ndpi_serialization_format_json) {
    needed += 1;

    if (serializer->multiline_json_array) {
      if(serializer->status.buffer.size_used == 2) /* Empty buffer {} */
        serializer->status.buffer.size_used = 0; /* Remove {} */
      else
        needed += 2;

    } else {
      if(serializer->status.buffer.size_used == 3) /* Empty buffer [{} */
        serializer->status.buffer.size_used = 2; /* Remove {} */
      else
        needed += 2, add_comma = 1;
    }
  }

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);

    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    if (!serializer->multiline_json_array) {
      if (add_comma)
        serializer->buffer.data[serializer->status.buffer.size_used-1] = ',';
      else
        serializer->status.buffer.size_used--;
    }
  }

  memcpy(&serializer->buffer.data[serializer->status.buffer.size_used], record, record_len);
  serializer->status.buffer.size_used += record_len;

  if(serializer->fmt == ndpi_serialization_format_json) {
    if (!serializer->multiline_json_array) {
      serializer->buffer.data[serializer->status.buffer.size_used] = ']';
      if(add_comma) serializer->status.buffer.size_used++;
    }
  }

  ndpi_serialize_end_of_record(_serializer);

  return(0);
}

/* ********************************** */

int ndpi_serialize_end_of_record(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int16_t needed = sizeof(u_int8_t) /* type */;

  if(serializer->fmt == ndpi_serialization_format_json ||
     serializer->fmt == ndpi_serialization_format_csv)
    needed += 1;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->buffer.data[serializer->status.buffer.size_used++] = '\n';
    serializer->buffer.data[serializer->status.buffer.size_used] = '\0';
    serializer->status.flags |= NDPI_SERIALIZER_STATUS_HDR_DONE;
    serializer->status.flags |= NDPI_SERIALIZER_STATUS_EOR;

  } else if(serializer->fmt == ndpi_serialization_format_json) {

    if(serializer->multiline_json_array) {
      serializer->buffer.data[serializer->status.buffer.size_used++] = '\n';
      serializer->buffer.data[serializer->status.buffer.size_used] = '\0';

    } else {
      if(!(serializer->status.flags & NDPI_SERIALIZER_STATUS_ARRAY)) {
        serializer->buffer.data[0] = '[';
        serializer->status.buffer.size_used += ndpi_snprintf((char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff, "]");
      }
    }
    serializer->status.flags |= NDPI_SERIALIZER_STATUS_ARRAY | NDPI_SERIALIZER_STATUS_EOR;
    serializer->status.flags &= ~NDPI_SERIALIZER_STATUS_COMMA;

  } else /* ndpi_serialization_format_tlv */ {
    serializer->buffer.data[serializer->status.buffer.size_used++] = ndpi_serialization_end_of_record;
  }

  serializer->status.flags &= ~NDPI_SERIALIZER_STATUS_NOT_EMPTY;

  return(0);
}

/* ********************************** */

static inline void ndpi_serialize_csv_pre(ndpi_private_serializer *serializer) {
  if(serializer->status.flags & NDPI_SERIALIZER_STATUS_EOR) {
    serializer->status.flags &= ~NDPI_SERIALIZER_STATUS_EOR;
  } else if (serializer->status.buffer.size_used == 0) {
    /* nothing to do */
  } else {
    if(serializer->buffer.size > serializer->status.buffer.size_used) {
      serializer->buffer.data[serializer->status.buffer.size_used] = serializer->csv_separator[0];
      serializer->status.buffer.size_used++;
    }
  }
}

/* ********************************** */

static inline void ndpi_serialize_json_pre(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;

  if(serializer->status.flags & NDPI_SERIALIZER_STATUS_EOR) {
    serializer->status.flags &= ~NDPI_SERIALIZER_STATUS_EOR;
    if(serializer->multiline_json_array) {
      serializer->buffer.data[serializer->status.buffer.size_used++] = '\n';
    } else {
      serializer->status.buffer.size_used--; /* Remove ']' */
      serializer->buffer.data[serializer->status.buffer.size_used++] = ',';
    }
    serializer->buffer.data[serializer->status.buffer.size_used++] = '{';

  } else {
    if(!serializer->multiline_json_array) {
      if(serializer->status.flags & NDPI_SERIALIZER_STATUS_ARRAY)
        serializer->status.buffer.size_used--; /* Remove ']' */
    }

    serializer->status.buffer.size_used--; /* Remove '}' */

    if(serializer->status.flags & NDPI_SERIALIZER_STATUS_LIST) {
      if(!serializer->multiline_json_array)
        serializer->status.buffer.size_used--; /* Remove ']' */
      if(serializer->status.flags & NDPI_SERIALIZER_STATUS_SOL)
        serializer->status.flags &= ~NDPI_SERIALIZER_STATUS_SOL;
      else
        serializer->buffer.data[serializer->status.buffer.size_used++] = ',';
    } else {
      if(serializer->status.flags & NDPI_SERIALIZER_STATUS_SOB)
        serializer->status.flags &= ~NDPI_SERIALIZER_STATUS_SOB;
      else if(serializer->status.flags & NDPI_SERIALIZER_STATUS_COMMA)
        serializer->buffer.data[serializer->status.buffer.size_used++] = ',';
    }
  }
}

/* ********************************** */

static inline int ndpi_serialize_json_post(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;

  if (!serializer->multiline_json_array) {
    if(serializer->status.flags & NDPI_SERIALIZER_STATUS_LIST) {
      if(serializer->status.buffer.size_used >= serializer->buffer.size)
        return -1;
      serializer->buffer.data[serializer->status.buffer.size_used++] = ']';
    }
  }

  if(serializer->status.buffer.size_used >= serializer->buffer.size)
    return -1;
  serializer->buffer.data[serializer->status.buffer.size_used++] = '}';

  if (!serializer->multiline_json_array) {
    if(serializer->status.flags & NDPI_SERIALIZER_STATUS_ARRAY) {
      if(serializer->status.buffer.size_used >= serializer->buffer.size)
        return -1;
      serializer->buffer.data[serializer->status.buffer.size_used++] = ']';
    }
  }

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_COMMA;
  return 0;
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
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  int rc;
  u_int16_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int32_t) /* key */ +
    sizeof(u_int32_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 24;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    if (!(serializer->status.flags & NDPI_SERIALIZER_STATUS_LIST)) {
      rc = ndpi_snprintf((char *)
        &serializer->buffer.data[serializer->status.buffer.size_used],
        buff_diff, "\"%u\":", key);
      if(rc < 0 || (u_int)rc >= buff_diff)
        return(-1);
      serializer->status.buffer.size_used += rc;
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    }

    rc = ndpi_snprintf((char *)
      &serializer->buffer.data[serializer->status.buffer.size_used],
      buff_diff, "%u", value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;

    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    if (ndpi_serializer_header_uint32(serializer, key) < 0) return(-1);
    ndpi_serialize_csv_pre(serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    rc = ndpi_snprintf((char *)
      &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff,
      "%u", value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;
  } else {
    ndpi_serialization_type kt;
    u_int8_t type = 0;
    u_int32_t type_offset = serializer->status.buffer.size_used++;

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

    serializer->buffer.data[type_offset] = type;
  }

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_NOT_EMPTY;
  return(0);
}

/* ********************************** */

int ndpi_serialize_uint32_uint64(ndpi_serializer *_serializer,
				 u_int32_t key, u_int64_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int16_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int32_t) /* key */ +
    sizeof(u_int64_t);
  int rc;

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 32;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    if (!(serializer->status.flags & NDPI_SERIALIZER_STATUS_LIST)) {
      rc = ndpi_snprintf((char *)
        &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff,
        "\"%u\":", key);
      if(rc < 0 || (u_int)rc >= buff_diff)
        return(-1);
      serializer->status.buffer.size_used += rc;
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    }

    rc = ndpi_snprintf((char *)
      &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff,
      NDPI_U64_FORMAT, (unsigned long long)value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;

    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    if (ndpi_serializer_header_uint32(serializer, key) < 0) return(-1);
    ndpi_serialize_csv_pre(serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    rc = ndpi_snprintf((char *)
      &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff,
      NDPI_U64_FORMAT, (unsigned long long)value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;
  } else {
    if(value <= 0xffffffff) {
      return(ndpi_serialize_uint32_uint32(_serializer, key, value));
    } else {
      ndpi_serialization_type kt;
      u_int8_t type = 0;
      u_int32_t type_offset = serializer->status.buffer.size_used++;

      kt = ndpi_serialize_key_uint32(serializer, key);
      type = (kt << 4);

      ndpi_serialize_single_uint64(serializer, value);
      type |= ndpi_serialization_uint64;

      serializer->buffer.data[type_offset] = type;
    }
  }

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_NOT_EMPTY;
  return(0);
}

/* ********************************** */

int ndpi_serialize_uint32_int32(ndpi_serializer *_serializer,
				u_int32_t key, int32_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int16_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int32_t) /* key */ +
    sizeof(int32_t);
  int rc;

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 24;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    if (!(serializer->status.flags & NDPI_SERIALIZER_STATUS_LIST)) {
      rc = ndpi_snprintf((char *)
        &serializer->buffer.data[serializer->status.buffer.size_used],
        buff_diff, "\"%u\":", key);
      if(rc < 0 || (u_int)rc >= buff_diff)
        return(-1);
      serializer->status.buffer.size_used += rc;
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    }

    rc = ndpi_snprintf((char *)
      &serializer->buffer.data[serializer->status.buffer.size_used],
      buff_diff, "%d", value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;

    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    if (ndpi_serializer_header_uint32(serializer, key) < 0) return(-1);
    ndpi_serialize_csv_pre(serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    rc = ndpi_snprintf((char *)
      &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff,
      "%d", value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;
  } else {
    ndpi_serialization_type kt;
    u_int8_t type = 0;
    u_int32_t type_offset = serializer->status.buffer.size_used++;

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

    serializer->buffer.data[type_offset] = type;
  }

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_NOT_EMPTY;
  return(0);
}

/* ********************************** */

int ndpi_serialize_uint32_int64(ndpi_serializer *_serializer,
				u_int32_t key, int64_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int16_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int32_t) /* key */ +
    sizeof(int64_t);
  int rc;

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 32;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    if (!(serializer->status.flags & NDPI_SERIALIZER_STATUS_LIST)) {
      rc = ndpi_snprintf((char *)
        &serializer->buffer.data[serializer->status.buffer.size_used],
        buff_diff, "\"%u\":", key);
      if(rc < 0 || (u_int)rc >= buff_diff)
        return(-1);
      serializer->status.buffer.size_used += rc;
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    }

    rc = ndpi_snprintf((char *)
      &serializer->buffer.data[serializer->status.buffer.size_used],
      buff_diff, NDPI_I64_FORMAT, (long long int)value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;

    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    if (ndpi_serializer_header_uint32(serializer, key) < 0) return(-1);
    ndpi_serialize_csv_pre(serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    rc = ndpi_snprintf((char *)
      &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff,
      NDPI_I64_FORMAT, (long long int)value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;
  }
  else {
    if((value & 0xFFFFFFFF) == value) {
      return(ndpi_serialize_uint32_int32(_serializer, key, value));
    } else {
      ndpi_serialization_type kt;
      u_int8_t type = 0;
      u_int32_t type_offset = serializer->status.buffer.size_used++;

      kt = ndpi_serialize_key_uint32(serializer, key);
      type = (kt << 4);

      ndpi_serialize_single_uint64(serializer, value);
      type |= ndpi_serialization_int64;

      serializer->buffer.data[type_offset] = type;
    }
  }

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_NOT_EMPTY;
  return(0);
}

/* ********************************** */

int ndpi_serialize_uint32_float(ndpi_serializer *_serializer,
				u_int32_t key, float value,
                                const char *format /* e.f. "%.2f" */) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int16_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int32_t) /* key */ +
    sizeof(float) +
    32; /* Safety, because printing float might lead to LONG string */
  int rc;

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 32;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    if (!(serializer->status.flags & NDPI_SERIALIZER_STATUS_LIST)) {
      rc = ndpi_snprintf((char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff, "\"%u\":", key);
      if(rc < 0 || (u_int)rc >= buff_diff)
        return(-1);
      serializer->status.buffer.size_used += rc;
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    }

    rc = ndpi_snprintf((char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff, format, value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;

    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    if (ndpi_serializer_header_uint32(serializer, key) < 0) return(-1);
    ndpi_serialize_csv_pre(serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    rc = ndpi_snprintf((char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff, format, value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;

  } else {
    ndpi_serialization_type kt;
    u_int8_t type = 0;
    u_int32_t type_offset = serializer->status.buffer.size_used++;

    kt = ndpi_serialize_key_uint32(serializer, key);
    type = (kt << 4);

    ndpi_serialize_single_float(serializer, value);
    type |= ndpi_serialization_float;

    serializer->buffer.data[type_offset] = type;
  }

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_NOT_EMPTY;
  return(0);
}

/* ********************************** */

int ndpi_serialize_uint32_double(ndpi_serializer *_serializer,
				 u_int32_t key, double value,
                                 const char *format /* e.f. "%.2f" */) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int16_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int32_t) /* key */ +
    sizeof(double) +
    32; /* Safety, because printing double might lead to LONG string */
  int rc;

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 32;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    if (!(serializer->status.flags & NDPI_SERIALIZER_STATUS_LIST)) {
      rc = ndpi_snprintf((char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff, "\"%u\":", key);
      if(rc < 0 || (u_int)rc >= buff_diff)
        return(-1);
      serializer->status.buffer.size_used += rc;
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    }

    rc = ndpi_snprintf((char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff, format, value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;

    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    if (ndpi_serializer_header_uint32(serializer, key) < 0) return(-1);
    ndpi_serialize_csv_pre(serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    rc = ndpi_snprintf((char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff, format, value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;

  } else {
#if 1
    return(-1);
#else
    ndpi_serialization_type kt;
    u_int8_t type = 0;
    u_int32_t type_offset = serializer->status.buffer.size_used++;

    kt = ndpi_serialize_key_uint32(serializer, key);
    type = (kt << 4);

    ndpi_serialize_single_float(serializer, value);
    type |= ndpi_serialization_double;

    serializer->buffer.data[type_offset] = type;
#endif
  }

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_NOT_EMPTY;
  return(0);
}

/* ********************************** */

int ndpi_serialize_uint32_binary(ndpi_serializer *_serializer,
				 u_int32_t key, const char *value, u_int16_t slen) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int32_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int32_t) /* key */ +
    sizeof(u_int16_t) /* len */ +
    slen;
  int rc;

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 24 + slen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    if (!(serializer->status.flags & NDPI_SERIALIZER_STATUS_LIST)) {
      rc = ndpi_snprintf((char *) &serializer->buffer.data[serializer->status.buffer.size_used],
        buff_diff, "\"%u\":", key);
      if(rc < 0 || (u_int)rc >= buff_diff)
        return(-1);
      serializer->status.buffer.size_used += rc;
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    }
    serializer->status.buffer.size_used += ndpi_json_string_escape(value, slen,
						     (char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    if (ndpi_serializer_header_uint32(serializer, key) < 0) return(-1);
    ndpi_serialize_csv_pre(serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    rc = ndpi_snprintf((char *)
		       &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff,
		       "%.*s", slen, value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;
  } else {
    ndpi_serialization_type kt;
    u_int8_t type = 0;
    u_int32_t type_offset = serializer->status.buffer.size_used++;

    kt = ndpi_serialize_key_uint32(serializer, key);
    type = (kt << 4);

    ndpi_serialize_single_string(serializer, value, slen);
    type |= ndpi_serialization_string;

    serializer->buffer.data[type_offset] = type;
  }

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_NOT_EMPTY;
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
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int32_t needed = 24;
  int rc;

  if(serializer->fmt != ndpi_serialization_format_json &&
     serializer->fmt != ndpi_serialization_format_csv)
    return(-1);

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    if (!(serializer->status.flags & NDPI_SERIALIZER_STATUS_LIST)) {
      rc = ndpi_snprintf((char *)
        &serializer->buffer.data[serializer->status.buffer.size_used],
        buff_diff, "\"%u\":", key);
      if(rc < 0 || (u_int)rc >= buff_diff)
        return(-1);
      serializer->status.buffer.size_used += rc;
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    }

    rc = ndpi_snprintf((char *)
      &serializer->buffer.data[serializer->status.buffer.size_used],
      buff_diff, "%s", value ? "true" : "false");
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;

    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    if (ndpi_serializer_header_uint32(serializer, key) < 0) return(-1);
    ndpi_serialize_csv_pre(serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    rc = ndpi_snprintf((char *)
      &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff,
      "%s", value ? "true" : "false");
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;
  }

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_NOT_EMPTY;
  return(0);
}

/* ********************************** */

int ndpi_serialize_binary_int32(ndpi_serializer *_serializer,
			        const char *key, u_int16_t klen,
			        int32_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int32_t needed;
  int rc;

#ifdef OPTIMIZE_NUMERIC_KEYS
  if(ndpi_is_number(key, klen))
    return(ndpi_serialize_uint32_int32(_serializer, atoi(key), value));
#endif

  needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(u_int32_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 16 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    if (!(serializer->status.flags & NDPI_SERIALIZER_STATUS_LIST)) {
      serializer->status.buffer.size_used += ndpi_json_string_escape(key, klen,
        (char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff);
      serializer->buffer.data[serializer->status.buffer.size_used] = ':';
      serializer->status.buffer.size_used++;
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    }

    rc = ndpi_snprintf((char *)
      &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff, "%d", value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;

    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    if (ndpi_serializer_header_string(serializer, key, klen) < 0) return(-1);
    ndpi_serialize_csv_pre(serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    rc = ndpi_snprintf((char *)
      &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff,
      "%d", value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;
  } else {
    if(value <= 127 && value >= -128) {
      serializer->buffer.data[serializer->status.buffer.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_int8;
      ndpi_serialize_single_string(serializer, key, klen);
      ndpi_serialize_single_uint8(serializer, value);
    } else if(value <= 32767 && value >= -32768) {
      serializer->buffer.data[serializer->status.buffer.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_int16;
      ndpi_serialize_single_string(serializer, key, klen);
      ndpi_serialize_single_uint16(serializer, value);
    } else {
      serializer->buffer.data[serializer->status.buffer.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_int32;
      ndpi_serialize_single_string(serializer, key, klen);
      ndpi_serialize_single_uint32(serializer, value);
    }
  }

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_NOT_EMPTY;

  return(0);
}

/* ********************************** */

int ndpi_serialize_string_int32(ndpi_serializer *_serializer,
				const char *key, int32_t value) {
#ifdef OPTIMIZE_CSV_SERIALIZATION
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;

  if(serializer->fmt == ndpi_serialization_format_csv) {
    /* Key is ignored */
    u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    u_int16_t needed = 12 /* 10 (billion) + CVS separator + \0 */;
    int rc;

    if(buff_diff < needed) {
      if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
	return(-1);     	
    }

    if(!(serializer->status.flags & NDPI_SERIALIZER_STATUS_HDR_DONE)) {
      if(ndpi_serializer_header_string(serializer, key, strlen(key)) < 0)
	return(-1);
    }

    ndpi_serialize_csv_pre(serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    rc = ndpi_snprintf((char*)&serializer->buffer.data[serializer->status.buffer.size_used],
		       buff_diff, "%u", value);

    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    
    serializer->status.buffer.size_used += rc;
    
    return(0);
  } else
#endif
  return(ndpi_serialize_binary_int32(_serializer, key, strlen(key), value));
}

/* ********************************** */

int ndpi_serialize_binary_int64(ndpi_serializer *_serializer,
				const char *key, u_int16_t klen,
				int64_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int32_t needed;
  int rc;

#ifdef OPTIMIZE_NUMERIC_KEYS
  if(ndpi_is_number(key, klen))
    return(ndpi_serialize_uint32_int64(_serializer, atoi(key), value));
#endif

  needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(u_int64_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 16 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    if (!(serializer->status.flags & NDPI_SERIALIZER_STATUS_LIST)) {
      serializer->status.buffer.size_used += ndpi_json_string_escape(key, klen,
        (char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff);
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
      serializer->buffer.data[serializer->status.buffer.size_used] = ':';
      serializer->status.buffer.size_used++;
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    }

    rc = ndpi_snprintf((char *)
      &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff,
      NDPI_I64_FORMAT, (long long int)value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;

    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    if (ndpi_serializer_header_string(serializer, key, klen) < 0) return(-1);
    ndpi_serialize_csv_pre(serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    rc = ndpi_snprintf((char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff,
      NDPI_I64_FORMAT, (long long int)value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;
  } else {
    if ((value & 0xFFFFFFFF) == value) {
      return(ndpi_serialize_string_int32(_serializer, key, value));
    } else {
      serializer->buffer.data[serializer->status.buffer.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_int64;
      ndpi_serialize_single_string(serializer, key, klen);
      ndpi_serialize_single_uint64(serializer, value);
    }
  }

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_NOT_EMPTY;
  return(0);
}

/* ********************************** */

int ndpi_serialize_string_int64(ndpi_serializer *_serializer,
				const char *key, int64_t value) {
  return(ndpi_serialize_binary_int64(_serializer, key, strlen(key), value));
}

/* ********************************** */

int ndpi_serialize_binary_uint32(ndpi_serializer *_serializer,
				const char *key, u_int16_t klen, u_int32_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int32_t needed;
  int rc;

#ifdef OPTIMIZE_CSV_SERIALIZATION
  if(serializer->fmt == ndpi_serialization_format_csv) {
    /* Key is ignored */
    u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    u_int16_t needed;
    char _value[16];

    ndpi_snprintf(_value, sizeof(_value), "%u", value);
    needed = strlen(_value) + 1 /* CVS separator */;

    if(buff_diff < needed) {
      if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
	return(-1);
      else
	buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    }

    if(!(serializer->status.flags & NDPI_SERIALIZER_STATUS_HDR_DONE)) {
      if(ndpi_serializer_header_string(serializer, key, klen) < 0)
	return(-1);
    }

    ndpi_serialize_csv_pre(serializer);
    needed--;
    memcpy(&serializer->buffer.data[serializer->status.buffer.size_used], _value, needed);
    serializer->status.buffer.size_used += needed;
    return(0);
  }
#endif

#ifdef OPTIMIZE_NUMERIC_KEYS
  if(ndpi_is_number(key, klen))
    return(ndpi_serialize_uint32_uint32(_serializer, atoi(key), value));
#endif

  needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(u_int32_t) + /* value (as int) */
    20 /* value (as string, in case of CSV) */ + 
    16 /* extra overhead for JSON */;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    if (!(serializer->status.flags & NDPI_SERIALIZER_STATUS_LIST)) {
      serializer->status.buffer.size_used += ndpi_json_string_escape(key, klen,
      (char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff);
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
      serializer->buffer.data[serializer->status.buffer.size_used] = ':';
      serializer->status.buffer.size_used++;
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    }

    rc = ndpi_snprintf((char *)
		       &serializer->buffer.data[serializer->status.buffer.size_used],
		       buff_diff, "%u", value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;

    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
#ifndef OPTIMIZE_CSV_SERIALIZATION
    if (ndpi_serializer_header_string(serializer, key, klen) < 0) return(-1);
    ndpi_serialize_csv_pre(serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    rc = ndpi_snprintf((char *)
		       &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff,
		       "%u", value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;
#endif
  } else {
    if(value <= 0xff) {
      serializer->buffer.data[serializer->status.buffer.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_uint8;
      ndpi_serialize_single_string(serializer, key, klen);
      ndpi_serialize_single_uint8(serializer, value);
    } else if(value <= 0xffff) {
      serializer->buffer.data[serializer->status.buffer.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_uint16;
      ndpi_serialize_single_string(serializer, key, klen);
      ndpi_serialize_single_uint16(serializer, value);
    } else {
      serializer->buffer.data[serializer->status.buffer.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_uint32;
      ndpi_serialize_single_string(serializer, key, klen);
      ndpi_serialize_single_uint32(serializer, value);
    }
  }

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_NOT_EMPTY;
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
  } else {
    char buf[16];

    ndpi_snprintf(buf, sizeof(buf), format, value);
    return(ndpi_serialize_string_string(_serializer, key, buf));
  }
}

/* ********************************** */

int ndpi_serialize_binary_uint64(ndpi_serializer *_serializer,
				const char *key, u_int16_t klen,
				u_int64_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int32_t needed;
  int rc;

#ifdef OPTIMIZE_NUMERIC_KEYS
  if(ndpi_is_number(key, klen))
    return(ndpi_serialize_uint32_uint64(_serializer, atoi(key), value));
#endif

  needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(u_int64_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 16 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    if (!(serializer->status.flags & NDPI_SERIALIZER_STATUS_LIST)) {
      serializer->status.buffer.size_used += ndpi_json_string_escape(key, klen,
        (char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff);
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
      serializer->buffer.data[serializer->status.buffer.size_used] = ':';
      serializer->status.buffer.size_used++;
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    }

    rc = ndpi_snprintf((char *)
      &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff,
      NDPI_U64_FORMAT, (unsigned long long)value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;

    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    if (ndpi_serializer_header_string(serializer, key, klen) < 0) return(-1);
    ndpi_serialize_csv_pre(serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    rc = ndpi_snprintf((char *)
      &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff,
      NDPI_U64_FORMAT, (unsigned long long)value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;
  } else {
    if(value <= 0xffffffff) {
      return(ndpi_serialize_string_uint32(_serializer, key, value));
    } else {
      serializer->buffer.data[serializer->status.buffer.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_uint64;
      ndpi_serialize_single_string(serializer, key, klen);
      ndpi_serialize_single_uint64(serializer, value);
    }
  }

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_NOT_EMPTY;
  return(0);
}

/* ********************************** */

int ndpi_serialize_string_uint64(ndpi_serializer *_serializer,
				 const char *key, u_int64_t value) {
  return(ndpi_serialize_binary_uint64(_serializer, key, strlen(key), value));
}

/* ********************************** */

int ndpi_serialize_binary_float(ndpi_serializer *_serializer,
			        const char *key,
			        u_int16_t klen,
			        float value,
			        const char *format /* e.f. "%.2f" */) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int32_t needed;
  int rc;

#ifdef OPTIMIZE_NUMERIC_KEYS
  if(ndpi_is_number(key, klen))
    return(ndpi_serialize_uint32_float(_serializer, atoi(key), value, format));
#endif

  needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(float) +
    32; /* Safety, because printing float might lead to LONG string */

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 32 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    if (!(serializer->status.flags & NDPI_SERIALIZER_STATUS_LIST)) {
      serializer->status.buffer.size_used += ndpi_json_string_escape(key, klen,
        (char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff);
      serializer->buffer.data[serializer->status.buffer.size_used] = ':';
      serializer->status.buffer.size_used++;
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    }

    rc = ndpi_snprintf((char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff, format, value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;

    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    if (ndpi_serializer_header_string(serializer, key, klen) < 0) return(-1);
    ndpi_serialize_csv_pre(serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    rc = ndpi_snprintf((char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff, format, value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;
  } else {
    serializer->buffer.data[serializer->status.buffer.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_float;

    ndpi_serialize_single_string(serializer, key, klen);
    ndpi_serialize_single_float(serializer, value);
  }

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_NOT_EMPTY;
  return(0);
}

/* ********************************** */

/* JSON/CSV only (TLV not yet supported due to a type field limit) */
int ndpi_serialize_binary_double(ndpi_serializer *_serializer,
                    const char *key,
                    u_int16_t klen,
                    double value,
                    const char *format /* e.f. "%.2f" */) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int32_t needed;
  int rc;

  needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(double) +
    32; /* Safety, because printing double might lead to LONG string */

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 32 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    if (!(serializer->status.flags & NDPI_SERIALIZER_STATUS_LIST)) {
      serializer->status.buffer.size_used += ndpi_json_string_escape(key, klen,
        (char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff);
      serializer->buffer.data[serializer->status.buffer.size_used] = ':';
      serializer->status.buffer.size_used++;
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    }

    rc = ndpi_snprintf((char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff, format, value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;

    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    if (ndpi_serializer_header_string(serializer, key, klen) < 0) return(-1);
    ndpi_serialize_csv_pre(serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    rc = ndpi_snprintf((char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff, format, value);
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;
  } else {
#if 1
    return(-1);
#else
    serializer->buffer.data[serializer->status.buffer.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_double;

    ndpi_serialize_single_string(serializer, key, klen);
    ndpi_serialize_single_double(serializer, value);
#endif
  }

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_NOT_EMPTY;
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

int ndpi_serialize_string_double(ndpi_serializer *_serializer,
                const char *key,
                double value,
                const char *format /* e.f. "%.2f" */)
{
  return(ndpi_serialize_binary_double(_serializer, key, strlen(key), value, format));
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
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
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
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    if (!(serializer->status.flags & NDPI_SERIALIZER_STATUS_LIST)) {
      serializer->status.buffer.size_used += ndpi_json_string_escape(key, klen,
        (char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff);
      serializer->buffer.data[serializer->status.buffer.size_used] = ':';
      serializer->status.buffer.size_used++;
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    }

    if (escape)
      serializer->status.buffer.size_used += ndpi_json_string_escape(value, vlen,
        (char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff);
    else {
      memcpy(&serializer->buffer.data[serializer->status.buffer.size_used], value, vlen);
      serializer->status.buffer.size_used += vlen;
    }

    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    if (ndpi_serializer_header_string(serializer, key, klen) < 0) return(-1);
    ndpi_serialize_csv_pre(serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    memcpy(&serializer->buffer.data[serializer->status.buffer.size_used], value, vlen);
    serializer->status.buffer.size_used += vlen;

  } else {
    serializer->buffer.data[serializer->status.buffer.size_used++] = (ndpi_serialization_string << 4) | ndpi_serialization_string;

    ndpi_serialize_single_string(serializer, key, klen);
    ndpi_serialize_single_string(serializer, value, vlen);
  }

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_NOT_EMPTY;
  return(0);
}

/* ********************************** */

/* Key is a <string, len> pair, value is a <string, len> pair */
int ndpi_serialize_binary_binary(ndpi_serializer *_serializer,
				 const char *key,
				 u_int16_t klen,
				 const char *_value,
				 u_int16_t vlen) {
  const char *value = _value ? _value : "";

#ifdef OPTIMIZE_NUMERIC_KEYS
  if(ndpi_is_number(key, klen))
    return(ndpi_serialize_uint32_binary(_serializer, atoi(key), value, vlen));
#endif

  return(ndpi_serialize_binary_raw(_serializer, key, klen, value, vlen, 1 /* escape */));
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
int ndpi_serialize_string_string_len(ndpi_serializer *_serializer,
				     const char *key,
				     const char *value, u_int16_t value_len) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;

#ifdef OPTIMIZE_CSV_SERIALIZATION
  if(serializer->fmt == ndpi_serialization_format_csv) {
    /* Key is ignored */
    u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    u_int16_t needed = value_len + 1 /* CVS separator */;

    if(buff_diff < needed) {
      if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
	return(-1);
      else
	buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    }

    if(!(serializer->status.flags & NDPI_SERIALIZER_STATUS_HDR_DONE)) {
      if(ndpi_serializer_header_string(serializer, key, strlen(key)) < 0)
	return(-1);
    }

    ndpi_serialize_csv_pre(serializer);
    needed--;
    memcpy(&serializer->buffer.data[serializer->status.buffer.size_used], value, needed);
    serializer->status.buffer.size_used += needed;
    return(0);
  } else
#endif
  return(ndpi_serialize_binary_binary(_serializer, key, strlen(key),
				      value, value_len));
}

/* ********************************** */

/* Key is a string, value is a string (strlen is used to compute the len) */
int ndpi_serialize_string_string(ndpi_serializer *_serializer,
				 const char *key, const char *_value) {
  const char *value = _value ? _value : "";
  
  return(ndpi_serialize_string_string_len(_serializer, key, value, strlen(value)));
}

/* ********************************** */

/* Key is a string, value is a raw json value (it can be a number, an escaped/quoted string, an array, ..) */
int ndpi_serialize_string_raw(ndpi_serializer *_serializer,
			      const char *key, const char *_value, u_int16_t vlen) {
  return(ndpi_serialize_binary_raw(_serializer, key, strlen(key), _value, vlen, 0 /* do not escape */));
}

/* ********************************** */

int ndpi_serialize_binary_boolean(ndpi_serializer *_serializer,
				  const char *key, u_int16_t klen, u_int8_t value) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int32_t needed;
  int rc;

  if(serializer->fmt != ndpi_serialization_format_json &&
     serializer->fmt != ndpi_serialization_format_csv)
    return(-1);

#ifdef OPTIMIZE_NUMERIC_KEYS
  if(ndpi_is_number(key, klen))
    return(ndpi_serialize_uint32_boolean(_serializer, atoi(key), value));
#endif

  needed = klen + 16;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    if (!(serializer->status.flags & NDPI_SERIALIZER_STATUS_LIST)) {
      serializer->status.buffer.size_used += ndpi_json_string_escape(key, klen,
        (char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff);
      serializer->buffer.data[serializer->status.buffer.size_used] = ':';
      serializer->status.buffer.size_used++;
      buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    }

    rc = ndpi_snprintf((char *)
      &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff, "%s",
      value ? "true" : "false");
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;

    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    if (ndpi_serializer_header_string(serializer, key, strlen(key)) < 0) return(-1);
    ndpi_serialize_csv_pre(serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    rc = ndpi_snprintf((char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff,
      "%s", value ? "true" : "false");
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;
  }

  serializer->status.flags |= NDPI_SERIALIZER_STATUS_NOT_EMPTY;
  return(0);
}

/* ********************************** */

int ndpi_serialize_string_boolean(ndpi_serializer *_serializer,
				  const char *key, u_int8_t value) {
  return(ndpi_serialize_binary_boolean(_serializer, key, strlen(key), value));
}

/* ********************************** */

int ndpi_serialize_start_of_list_binary(ndpi_serializer *_serializer,
					const char *key, u_int16_t klen) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int32_t needed;
  int rc;

  if(serializer->fmt != ndpi_serialization_format_json &&
     serializer->fmt != ndpi_serialization_format_tlv)
    return(-1);

  needed = 16 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if (serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    serializer->status.buffer.size_used += ndpi_json_string_escape(key, klen,
      (char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff);

    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    rc = ndpi_snprintf((char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff, ": [");
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;

    serializer->status.flags |= NDPI_SERIALIZER_STATUS_LIST | NDPI_SERIALIZER_STATUS_SOL;

    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);
  } else {
    serializer->buffer.data[serializer->status.buffer.size_used++] = ndpi_serialization_start_of_list;
    ndpi_serialize_single_string(serializer, key, klen);
  }

  return(0);
}

/* ********************************** */

/* Serialize start of simple values list */
int ndpi_serialize_start_of_list(ndpi_serializer *_serializer,
				 const char *_key) {
  const char *key = _key ? _key : "";
  u_int16_t klen = strlen(key);

  return(ndpi_serialize_start_of_list_binary(_serializer, key, klen));
}

/* ********************************** */

/* Serialize end of simple values list */
int ndpi_serialize_end_of_list(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;

  if(serializer->fmt != ndpi_serialization_format_json &&
     serializer->fmt != ndpi_serialization_format_tlv)
    return(-1);

  if (serializer->fmt == ndpi_serialization_format_json) {
    if(serializer->status.flags & NDPI_SERIALIZER_STATUS_SOL) /* Empty list */
      serializer->status.flags &= ~NDPI_SERIALIZER_STATUS_SOL;

    serializer->status.flags &= ~NDPI_SERIALIZER_STATUS_LIST;
  } else {
    if(serializer->status.buffer.size_used == serializer->buffer.size)
      return(-1);
    serializer->buffer.data[serializer->status.buffer.size_used++] = ndpi_serialization_end_of_list;
  }

  return(0);
}

/* ********************************** */

/* Serialize start of nested block */
int ndpi_serialize_start_of_block_binary(ndpi_serializer *_serializer,
				         const char *key, u_int16_t klen) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int32_t needed;
  int rc;

  if(serializer->fmt != ndpi_serialization_format_json &&
     serializer->fmt != ndpi_serialization_format_tlv)
    return(-1);

  needed = 16 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if (serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(_serializer);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;

    serializer->status.buffer.size_used += ndpi_json_string_escape(key, klen,
      (char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    rc = ndpi_snprintf((char *) &serializer->buffer.data[serializer->status.buffer.size_used], buff_diff, ": {");
    if(rc < 0 || (u_int)rc >= buff_diff)
      return(-1);
    serializer->status.buffer.size_used += rc;
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);

    serializer->status.flags |= NDPI_SERIALIZER_STATUS_SOB;
  } else /* ndpi_serialization_format_tlv */ {
    serializer->buffer.data[serializer->status.buffer.size_used++] = ndpi_serialization_start_of_block;
    ndpi_serialize_single_string(serializer, key, klen);
  }

  return(0);
}

/* ********************************** */

/* Serialize start of nested block */
int ndpi_serialize_start_of_block(ndpi_serializer *_serializer,
				  const char *_key) {
  const char *key = _key ? _key : "";
  u_int16_t klen = strlen(key);

  return(ndpi_serialize_start_of_block_binary(_serializer, key, klen));
}

/* ********************************** */

/* Serialize start of nested block with a numeric key */
int ndpi_serialize_start_of_block_uint32(ndpi_serializer *_serializer, u_int32_t key) {
  char buf[11];
  int written = ndpi_snprintf(buf, sizeof(buf), "%u", key);

  if (written <= 0 || written == sizeof(buf))
  {
    return(-1);
  }

  return(ndpi_serialize_start_of_block_binary(_serializer, buf, written));
}

/* ********************************** */

/* Serialize end of nested block (JSON only)*/
int ndpi_serialize_end_of_block(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  u_int32_t needed;

  if(serializer->fmt != ndpi_serialization_format_json &&
     serializer->fmt != ndpi_serialization_format_tlv)
    return(-1);

  needed = 4;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  if (serializer->fmt == ndpi_serialization_format_json) {

    if(serializer->status.flags & NDPI_SERIALIZER_STATUS_SOB) /* Empty block */
      serializer->status.flags &= ~NDPI_SERIALIZER_STATUS_SOB;

    // buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
    if(ndpi_serialize_json_post(_serializer) != 0)
      return(-1);
  } else {
    serializer->buffer.data[serializer->status.buffer.size_used++] = ndpi_serialization_end_of_block;
  }

  return(0);
}

/* ********************************** */

void ndpi_serializer_create_snapshot(ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;

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
        if (!serializer->multiline_json_array)
          serializer->buffer.data[serializer->status.buffer.size_used-1] = ']';
      } else {
        if (!serializer->multiline_json_array)
          serializer->buffer.data[0] = ' ';
        serializer->buffer.data[serializer->status.buffer.size_used-1] = '}';
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

  deserializer->buffer.data      = serialized_buffer;

  if(deserializer->buffer.data[0] != 1)
    return(-2); /* Invalid version */

  deserializer->buffer.size = serialized_buffer_len;
  deserializer->fmt         = deserializer->buffer.data[1];
  ndpi_reset_serializer(_deserializer);

  return(0);
}

/* ********************************** */

int ndpi_init_deserializer(ndpi_deserializer *deserializer,
			   ndpi_serializer *_serializer) {
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;

  return(ndpi_init_deserializer_buf(deserializer,
				    serializer->buffer.data,
				    serializer->status.buffer.size_used));
}

/* ********************************** */

ndpi_serialization_format ndpi_deserialize_get_format(ndpi_deserializer *_deserializer) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  return(deserializer->fmt);
}

/* ********************************** */

static inline ndpi_serialization_type ndpi_deserialize_get_key_subtype(ndpi_private_deserializer *deserializer) {
  u_int8_t type;

  if(deserializer->status.buffer.size_used >= deserializer->buffer.size)
    return(ndpi_serialization_unknown);

  type = deserializer->buffer.data[deserializer->status.buffer.size_used];

  return((ndpi_serialization_type) (type >> 4));
}

/* ********************************** */

static inline ndpi_serialization_type ndpi_deserialize_get_value_subtype(ndpi_private_deserializer *deserializer) {
  u_int8_t type;

  if(deserializer->status.buffer.size_used >= deserializer->buffer.size)
    return(ndpi_serialization_unknown);

  type = deserializer->buffer.data[deserializer->status.buffer.size_used];

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
  u_int32_t buff_diff = deserializer->buffer.size - offset;
  u_int16_t expected, str_len;

  expected = sizeof(u_int16_t) /* len */;
  if(buff_diff < expected) return(-2);

  str_len = ntohs(*((u_int16_t *) &deserializer->buffer.data[offset]));

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
  case ndpi_serialization_double:
    size = sizeof(double);
    break;
  case ndpi_serialization_string:
  case ndpi_serialization_start_of_block:
  case ndpi_serialization_start_of_list:
    size = ndpi_deserialize_get_single_string_size(deserializer, offset);
    break;
  case ndpi_serialization_end_of_record:
  case ndpi_serialization_end_of_block:
  case ndpi_serialization_end_of_list:
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

/* Move the current offset (status.buffer.size_used) to point
 * to the next element */
int ndpi_deserialize_next(ndpi_deserializer *_deserializer) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer *) _deserializer;
  u_int32_t buff_diff = deserializer->buffer.size - deserializer->status.buffer.size_used;
  ndpi_serialization_type kt, et;
  u_int16_t expected;
  int size;

  expected = sizeof(u_int8_t) /* type */;

  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.buffer.size_used + expected);

  if(size < 0) return(-2);

  expected += size;

  et = ndpi_deserialize_get_value_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, et, deserializer->status.buffer.size_used + expected);

  if(size < 0) return(-2);

  expected += size;

  deserializer->status.buffer.size_used += expected;

  return(0);
}

/* ********************************** */

int ndpi_deserialize_key_uint32(ndpi_deserializer *_deserializer,
				u_int32_t *key) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  u_int32_t offset, buff_diff = deserializer->buffer.size - deserializer->status.buffer.size_used;
  ndpi_serialization_type kt;
  u_int16_t expected;
  u_int16_t v16;
  u_int8_t v8;
  int size;

  expected = sizeof(u_int8_t) /* type */;
  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);

  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.buffer.size_used + expected);
  if(size < 0) return(-2);

  offset = deserializer->status.buffer.size_used + expected;

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

/* Return the string key for the current element */
int ndpi_deserialize_key_string(ndpi_deserializer *_deserializer,
				ndpi_string *key) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  ndpi_serialization_type kt;
  u_int32_t buff_diff = deserializer->buffer.size - deserializer->status.buffer.size_used;
  u_int16_t expected;
  int size;

  expected = sizeof(u_int8_t) /* type */;
  key->str = NULL;
  key->str_len = 0;
  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);

  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.buffer.size_used + expected);
  if(size < 0) return(-2);

  ndpi_deserialize_single_string(deserializer, deserializer->status.buffer.size_used + expected, key);

  return(0);
}

/* ********************************** */

int ndpi_deserialize_value_uint32(ndpi_deserializer *_deserializer,
				  u_int32_t *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  ndpi_serialization_type kt, et;
  u_int32_t offset, buff_diff = deserializer->buffer.size - deserializer->status.buffer.size_used;
  u_int16_t v16;
  u_int8_t v8;
  u_int16_t expected;
  int size;

  expected = sizeof(u_int8_t) /* type */;
  *value = 0;
  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.buffer.size_used + expected);
  if(size < 0) return(-2);

  expected += size;

  et = ndpi_deserialize_get_value_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, et, deserializer->status.buffer.size_used + expected);
  if(size < 0) return(-2);

  offset = deserializer->status.buffer.size_used + expected;

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
  u_int32_t buff_diff = deserializer->buffer.size - deserializer->status.buffer.size_used;
  u_int32_t v32;
  u_int16_t expected;
  int size;
  int rc;

  expected = sizeof(u_int8_t) /* type */;
  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.buffer.size_used + expected);
  if(size < 0) return(-2);

  expected += size;

  et = ndpi_deserialize_get_value_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, et, deserializer->status.buffer.size_used + expected);
  if(size < 0) return(-2);

  if(et != ndpi_serialization_uint64) {
    /* Try with smaller uint types */
    rc = ndpi_deserialize_value_uint32(_deserializer, &v32);
    *value = v32;
    return(rc);
  }

  ndpi_deserialize_single_uint64(deserializer, deserializer->status.buffer.size_used + expected, value);

  return(0);
}

/* ********************************** */

int ndpi_deserialize_value_int32(ndpi_deserializer *_deserializer,
				 int32_t *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  ndpi_serialization_type kt, et;
  u_int32_t offset, buff_diff = deserializer->buffer.size - deserializer->status.buffer.size_used;
  int16_t v16;
  int8_t v8;
  u_int16_t expected;
  int size;

  expected = sizeof(u_int8_t) /* type */;
  *value = 0;
  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.buffer.size_used + expected);
  if(size < 0) return(-2);

  expected += size;

  et = ndpi_deserialize_get_value_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, et, deserializer->status.buffer.size_used + expected);
  if(size < 0) return(-2);

  offset = deserializer->status.buffer.size_used + expected;

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
  u_int32_t buff_diff = deserializer->buffer.size - deserializer->status.buffer.size_used;
  int32_t v32;
  u_int16_t expected;
  int size;
  int rc;

  expected = sizeof(u_int8_t) /* type */;
  *value = 0;
  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.buffer.size_used + expected);
  if(size < 0) return(-2);

  expected += size;

  et = ndpi_deserialize_get_value_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, et, deserializer->status.buffer.size_used + expected);
  if(size < 0) return(-2);

  if(et != ndpi_serialization_int64) {
    /* Try with smaller int types */
    rc = ndpi_deserialize_value_int32(_deserializer, &v32);
    *value = v32;
    return(rc);
  }

  ndpi_deserialize_single_int64(deserializer, deserializer->status.buffer.size_used + expected, value);

  return(0);
}

/* ********************************** */

int ndpi_deserialize_value_float(ndpi_deserializer *_deserializer,
				 float *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  ndpi_serialization_type kt, et;
  u_int32_t buff_diff = deserializer->buffer.size - deserializer->status.buffer.size_used;
  u_int16_t expected;
  int size;

  expected = sizeof(u_int8_t) /* type */;
  *value = 0;
  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.buffer.size_used + expected);
  if(size < 0) return(-2);

  expected += size;

  et = ndpi_deserialize_get_value_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, et, deserializer->status.buffer.size_used + expected);
  if(size < 0) return(-2);

  if(et != ndpi_serialization_float)
    return(-1);

  ndpi_deserialize_single_float(deserializer, deserializer->status.buffer.size_used + expected, value);

  return(0);
}

/* ********************************** */

int ndpi_deserialize_value_double(ndpi_deserializer *_deserializer,
                 double *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  ndpi_serialization_type kt, et;
  u_int32_t buff_diff = deserializer->buffer.size - deserializer->status.buffer.size_used;
  u_int16_t expected;
  int size;

  expected = sizeof(u_int8_t) /* type */;
  *value = 0;
  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.buffer.size_used + expected);
  if(size < 0) return(-2);

  expected += size;

  et = ndpi_deserialize_get_value_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, et, deserializer->status.buffer.size_used + expected);
  if(size < 0) return(-2);

  if(et != ndpi_serialization_double)
    return(-1);

  ndpi_deserialize_single_double(deserializer, deserializer->status.buffer.size_used + expected, value);

  return(0);
}

/* ********************************** */

/* Return the string value for the current element */
int ndpi_deserialize_value_string(ndpi_deserializer *_deserializer,
				  ndpi_string *value) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer*)_deserializer;
  ndpi_serialization_type kt, et;
  u_int32_t buff_diff = deserializer->buffer.size - deserializer->status.buffer.size_used;
  u_int16_t expected;
  int size;

  expected = sizeof(u_int8_t) /* type */;
  value->str = NULL;
  value->str_len = 0;
  if(buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);

  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.buffer.size_used + expected);
  if(size < 0) return(-2);

  expected += size;

  et = ndpi_deserialize_get_value_subtype(deserializer);

  size = ndpi_deserialize_get_single_size(deserializer, et, deserializer->status.buffer.size_used + expected);
  if(size < 0) return(-2);

  if(et != ndpi_serialization_string)
    return(-1);

  ndpi_deserialize_single_string(deserializer, deserializer->status.buffer.size_used + expected, value);

  return(0);
}

/* ********************************** */

/* Clone (with memcpy) the current item in deserializer to serializer (TLV only) */
int ndpi_deserialize_clone_item(ndpi_deserializer *_deserializer, ndpi_serializer *_serializer) {
  ndpi_private_deserializer *deserializer = (ndpi_private_deserializer *) _deserializer;
  ndpi_private_serializer *serializer = (ndpi_private_serializer*)_serializer;
  u_int32_t src_buff_diff = deserializer->buffer.size - deserializer->status.buffer.size_used;
  u_int32_t dst_buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  ndpi_serialization_type kt, et;
  u_int16_t expected;
  int size;

  if(serializer->fmt != ndpi_serialization_format_tlv)
    return(-3);

  expected = sizeof(u_int8_t) /* type */;

  if(src_buff_diff < expected) return(-2);

  kt = ndpi_deserialize_get_key_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, kt, deserializer->status.buffer.size_used + expected);

  if(size < 0) return(-2);

  expected += size;

  et = ndpi_deserialize_get_value_subtype(deserializer);
  size = ndpi_deserialize_get_single_size(deserializer, et, deserializer->status.buffer.size_used + expected);

  if(size < 0) return(-2);

  expected += size;

  if(dst_buff_diff < expected) {
    if(ndpi_extend_serializer_buffer(&serializer->buffer, expected - dst_buff_diff) < 0)
      return(-1);
    dst_buff_diff = serializer->buffer.size - serializer->status.buffer.size_used;
  }

  memcpy(&serializer->buffer.data[serializer->status.buffer.size_used],
         &deserializer->buffer.data[deserializer->status.buffer.size_used],
         expected);

  serializer->status.buffer.size_used += expected;

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
      goto next;
    } else if(et == ndpi_serialization_start_of_block) {
      ndpi_deserialize_key_string(deserializer, &ks);
      ndpi_serialize_start_of_block_binary(serializer, ks.str, ks.str_len);
      goto next;
    } else if(et == ndpi_serialization_end_of_block) {
      ndpi_serialize_end_of_block(serializer);
      goto next;
    } else if(et == ndpi_serialization_start_of_list) {
      ndpi_deserialize_key_string(deserializer, &ks);
      ndpi_serialize_start_of_list_binary(serializer, ks.str, ks.str_len);
      goto next;
    } else if(et == ndpi_serialization_end_of_list) {
      ndpi_serialize_end_of_list(serializer);
      goto next;
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

   next:
    ndpi_deserialize_next(deserializer);
  }

  return(0);
}

/* ********************************** */
