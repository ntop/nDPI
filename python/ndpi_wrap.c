/*
 * ndpi_wrap.c
 *
 * Copyright (C) 2011-19 - ntop.org
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

#include "sys/types.h"
#include "ndpi_config.h"
#include "ndpi_main.h"

int ndpi_wrap_get_api_version(){
  return NDPI_API_VERSION;
}

int ndpi_wrap_ndpi_num_fds_bits(){
  return NDPI_NUM_FDS_BITS;
}

int ndpi_wrap_num_custom_categories(){
  return NUM_CUSTOM_CATEGORIES;
}

int ndpi_wrap_custom_category_label_len(){
  return CUSTOM_CATEGORY_LABEL_LEN;
}

int ndpi_wrap_ndpi_max_supported_protocols(){
  return NDPI_MAX_SUPPORTED_PROTOCOLS;
}

int ndpi_wrap_ndpi_max_num_custom_protocols(){
  return NDPI_MAX_NUM_CUSTOM_PROTOCOLS;
}

int ndpi_wrap_ndpi_procol_size(){
  return NDPI_PROTOCOL_SIZE;
}

void ndpi_wrap_NDPI_BITMASK_SET_ALL(NDPI_PROTOCOL_BITMASK* bitmask){
  NDPI_ONE(bitmask);
}

void dummy() {
  /* Dummy call just to cause linker to include the ndpi library */
  ndpi_tfind(NULL, NULL, NULL);
}
