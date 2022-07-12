"""
------------------------------------------------------------------------------------------------------------------------
tests.py
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

from ndpi import NDPI, NDPIFlow, ffi
import time


if __name__ == '__main__':
    try:
        nDPI = NDPI()
        ndpi_flow = NDPIFlow()
        nDPI.process_packet(ndpi_flow, b'', time.time(), ffi.NULL)
        nDPI.giveup(ndpi_flow)
        print("nDPI Python bindings: OK")
    except Exception:
        raise AssertionError("nDPI Python bindings: KO")
