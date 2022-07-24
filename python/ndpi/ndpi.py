"""
------------------------------------------------------------------------------------------------------------------------
ndpi.py
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

from collections import namedtuple
from _ndpi import ffi, lib


ndpi_protocol = namedtuple('NDPIProtocol', ['C',
                                            'master_protocol',
                                            'app_protocol',
                                            'category'])

ndpi_confidence = namedtuple('NDPIConfidence', ['id',
                                                'name'])


class NDPI(object):
    __slots__ = ("_api_version",
                 "_revision",
                 "_detection_module")

    def __init__(self):
        self._detection_module = lib.ndpi_init_detection_module(0)
        if self._detection_module == ffi.NULL:
            raise MemoryError("Unable to instantiate NDPI object")
        lib.ndpi_py_setup_detection_module(self._detection_module)

    @property
    def api_version(self):
        return lib.ndpi_get_api_version()

    @property
    def revision(self):
        return ffi.string(lib.ndpi_revision()).decode('utf-8', errors='ignore')

    def process_packet(self, flow, packet, packet_time_ms, input_info):
        p = lib.ndpi_detection_process_packet(self._detection_module,
                                              flow.C,
                                              packet,
                                              len(packet),
                                              int(packet_time_ms),
                                              input_info)
        return ndpi_protocol(C=p,
                             master_protocol=p.master_protocol,
                             app_protocol=p.app_protocol,
                             category=p.category)

    def giveup(self, flow, enable_guess=True):
        p = lib.ndpi_detection_giveup(self._detection_module,
                                      flow.C,
                                      enable_guess,
                                      ffi.new("uint8_t*", 0))
        return ndpi_protocol(C=p,
                             master_protocol=p.master_protocol,
                             app_protocol=p.app_protocol,
                             category=p.category)

    def protocol_name(self, protocol):
        buf = ffi.new("char[40]")
        lib.ndpi_protocol2name(self._detection_module, protocol.C, buf, ffi.sizeof(buf))
        return ffi.string(buf).decode('utf-8', errors='ignore')

    def protocol_category_name(self, protocol):
        return ffi.string(lib.ndpi_category_get_name(self._detection_module,
                                                     protocol.C.category)).decode('utf-8',
                                                                                  errors='ignore')

    def __del__(self):
        if self._detection_module != ffi.NULL:
            lib.ndpi_exit_detection_module(self._detection_module)


class NDPIFlow(object):
    __slots__ = "C"

    @property
    def confidence(self):
        confidence = self.C.confidence
        return ndpi_confidence(id=confidence,
                               name=ffi.string(lib.ndpi_confidence_get_name(confidence)).decode('utf-8',
                                                                                                errors='ignore'))

    def __init__(self):
        self.C = lib.ndpi_py_initialize_flow()

    def __del__(self):
        if self.C != ffi.NULL:
            lib.ndpi_flow_free(self.C)
            self.C = ffi.NULL

