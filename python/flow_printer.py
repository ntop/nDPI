#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
file: flow_printer.py
This file is part of nfstream.

Copyright (C) 2019 - Zied Aouini <aouinizied@gmail.com>

nfstream is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nfstream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nfstream.
If not, see <http://www.gnu.org/licenses/>.
"""

from nfstream import NFStreamer
import sys


path = sys.argv[1]
flow_streamer = NFStreamer(source=path)
result = {}
try:
    for flow in flow_streamer:
        print(flow)
        try:
            result[flow.application_name] += flow.total_packets
        except KeyError:
            result[flow.application_name] = flow.total_packets
    print("Summary (Application Name: Packets):")
    print(result)
except KeyboardInterrupt:
    print("Summary (Application Name: Packets):")
    print(result)
    print("Terminated.")