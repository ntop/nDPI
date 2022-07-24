"""
------------------------------------------------------------------------------------------------------------------------
ndpi_build.py
Copyright (C) 2011-22 - ntop.org
This file is part of nDPI, an open source deep packet inspection library.
nDPI is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
version.
nDPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
You should have received a copy of the GNU Lesser General Public License along with NFStream.
If not, see <http://www.gnu.org/licenses/>.
------------------------------------------------------------------------------------------------------------------------
"""

from cffi import FFI
import subprocess
import pathlib

NDPI_INCLUDES = """
#include "ndpi_main.h"
#include "ndpi_typedefs.h"
#include "ndpi_api.h"
"""

NDPI_HELPERS = """
// nDPI cffi helper functions (function naming convention ndpi_py_*)

void ndpi_py_setup_detection_module(struct ndpi_detection_module_struct *mod) {
  if (mod == NULL) {
    return;
  } else {
    NDPI_PROTOCOL_BITMASK protos;
    NDPI_BITMASK_SET_ALL(protos); // Set bitmask for ALL protocols
    ndpi_set_protocol_detection_bitmask2(mod, &protos);
    ndpi_finalize_initialization(mod);
  }
};

struct ndpi_flow_struct * ndpi_py_initialize_flow(void) {
  struct ndpi_flow_struct * ndpi_flow = NULL;
  ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
  memset(ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
  return ndpi_flow;
};
"""


NDPI_APIS = """
u_int16_t ndpi_get_api_version(void);
char* ndpi_revision(void);
struct ndpi_detection_module_struct *ndpi_init_detection_module(ndpi_init_prefs prefs);
void ndpi_exit_detection_module(struct ndpi_detection_module_struct *ndpi_struct);
void ndpi_flow_free(void *ptr);
ndpi_protocol ndpi_detection_process_packet(struct ndpi_detection_module_struct *ndpi_struct,
                                            struct ndpi_flow_struct *flow,
                                            const unsigned char *packet,
                                            const unsigned short packetlen,
                                            const u_int64_t packet_time_ms,
                                            const struct ndpi_flow_input_info *input_info);
ndpi_protocol ndpi_detection_giveup(struct ndpi_detection_module_struct *ndpi_struct,
                                    struct ndpi_flow_struct *flow,
                                    u_int8_t enable_guess,
                                    u_int8_t *protocol_was_guessed);
void ndpi_py_setup_detection_module(struct ndpi_detection_module_struct *mod);
struct ndpi_flow_struct * ndpi_py_initialize_flow(void);
char* ndpi_protocol2name(struct ndpi_detection_module_struct *ndpi_mod, ndpi_protocol proto, char *buf, u_int buf_len);
const char* ndpi_category_get_name(struct ndpi_detection_module_struct *ndpi_mod, ndpi_protocol_category_t category);
const char* ndpi_confidence_get_name(ndpi_confidence_t confidence);
"""

ffi_builder = FFI()


INCLUDE_DIR = pathlib.Path(__file__)\
    .parent.resolve().parent.resolve().parent.resolve().\
    joinpath("src").joinpath("include")

LIBRARY_DIR = pathlib.Path(__file__)\
    .parent.resolve().parent.resolve().parent.resolve().\
    joinpath("src").joinpath("lib")


NDPI_CDEF = subprocess.run(["gcc",
                            "-DNDPI_LIB_COMPILATION",
                            "-DNDPI_CFFI_PREPROCESSING",
                            "-DNDPI_CFFI_PREPROCESSING_EXCLUDE_PACKED",
                            "-E", "-x", "c", "-P", "-C",
                            str(INCLUDE_DIR.joinpath("ndpi_typedefs.h"))],
                           capture_output=True
                           ).stdout.decode('utf-8',
                                           errors='ignore')

NDPI_MODULE_STRUCT_CDEF = NDPI_CDEF.split("//CFFI.NDPI_MODULE_STRUCT")[1]


NDPI_PACKED = subprocess.run(["gcc",
                              "-DNDPI_LIB_COMPILATION", "-DNDPI_CFFI_PREPROCESSING",
                              "-E", "-x", "c", "-P", "-C",
                              str(INCLUDE_DIR.joinpath("ndpi_typedefs.h"))],
                             capture_output=True
                             ).stdout.decode('utf-8',
                                             errors='ignore')

NDPI_PACKED_STRUCTURES = NDPI_PACKED.split("//CFFI.NDPI_PACKED_STRUCTURES")[1]

NDPI_SOURCE = NDPI_INCLUDES + NDPI_MODULE_STRUCT_CDEF + NDPI_HELPERS


ffi_builder.set_source("_ndpi",
                       NDPI_SOURCE,
                       libraries=["ndpi"],
                       library_dirs=[str(LIBRARY_DIR)],
                       include_dirs=[str(INCLUDE_DIR)])


ffi_builder.cdef("""
typedef uint64_t u_int64_t;
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;
typedef uint8_t u_char;
typedef unsigned u_int;
struct in_addr {
  unsigned long s_addr;
};
struct in6_addr {
    unsigned char s6_addr[16];
};
""")

ffi_builder.cdef(NDPI_PACKED_STRUCTURES, packed=True)
ffi_builder.cdef(NDPI_CDEF)
ffi_builder.cdef(NDPI_APIS)


if __name__ == "__main__":
    ffi_builder.compile(verbose=True)
