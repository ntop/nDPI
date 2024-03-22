/*
 * ndpi_replace_printf.h
 *
 * Copyright (C) 2023 - ntop.org and contributors
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

// This file may be included in every *.c file that uses printf(...) except for ndpi_main.c !

#include "ndpi_config.h"

#ifndef NDPI_CFFI_PREPROCESSING

#undef printf
#undef fprintf

#include "ndpi_typedefs.h"

#ifdef NDPI_ENABLE_DEBUG_MESSAGES

#define printf(...) ndpi_debug_printf(0, NULL, NDPI_LOG_DEBUG_EXTRA, __FILE__, __func__, __LINE__, __VA_ARGS__)

#ifdef NDPI_REPLACE_FPRINTF
#define fprintf(stream, ...) ndpi_debug_printf(0, NULL, NDPI_LOG_ERROR, __FILE__, __func__, __LINE__, __VA_ARGS__)
#endif

#else

#define printf(...) do {} while(0);

#ifdef NDPI_REPLACE_FPRINTF
#define fprintf(stream, ...) do {} while(0);
#endif

#endif

void ndpi_debug_printf(unsigned int proto, struct ndpi_detection_module_struct *ndpi_str, ndpi_log_level_t log_level,
                       const char *file_name, const char *func_name, int line_number, const char *format, ...);

#endif
