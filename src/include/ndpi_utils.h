/*
 * ndpi_main.c
 *
 * Copyright (C) 2011-22 - ntop.org
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

#ifndef __NDPI_UTILS_H__
#define __NDPI_UTILS_H__

#include "ndpi_define.h"
#ifndef NDPI_CFFI_PREPROCESSING
#include "ndpi_includes.h"
#endif

#ifndef NDPI_CFFI_PREPROCESSING
struct ndpi_detection_module_struct;
extern u_int8_t ndpi_ends_with(struct ndpi_detection_module_struct *ndpi_struct,
                               char *str, char *ends);
#endif // NDPI_CFFI_PREPROCESSING
/* **************************************** */

/* Can't call libc functions from kernel space, define some stub instead */

#define ndpi_isalpha(ch) (((ch) >= 'a' && (ch) <= 'z') || ((ch) >= 'A' && (ch) <= 'Z'))
#define ndpi_isdigit(ch) ((ch) >= '0' && (ch) <= '9')
#define ndpi_isalnum(ch) (ndpi_isalpha(ch) != 0 || ndpi_isdigit(ch) != 0)
#define ndpi_isspace(ch) (((ch) >= '\t' && (ch) <= '\r') || ((ch) == ' '))
#define ndpi_isprint(ch) ((ch) >= 0x20 && (ch) <= 0x7e)
#define ndpi_ispunct(ch) (((ch) >= '!' && (ch) <= '/') ||   \
              ((ch) >= ':' && (ch) <= '@') ||   \
              ((ch) >= '[' && (ch) <= '`') ||   \
              ((ch) >= '{' && (ch) <= '~'))

#ifndef NDPI_CFFI_PREPROCESSING
int ndpi_vsnprintf(char * str, size_t size, char const * format, va_list va_args);
int ndpi_snprintf(char * str, size_t size, char const * format, ...);
struct tm *ndpi_gmtime_r(const time_t *timep,
                         struct tm *result);
#endif

#endif
