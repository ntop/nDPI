#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
------------------------------------------------------------------------------------------------------------------------
flow_printer.py
Copyright (C) 2019-20 - NFStream Developers
This file is part of NFStream, a Flexible Network Data Analysis Framework (https://www.nfstream.org/).
NFStream is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
version.
NFStream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
You should have received a copy of the GNU Lesser General Public License along with NFStream.
If not, see <http://www.gnu.org/licenses/>.
------------------------------------------------------------------------------------------------------------------------
"""

from nfstream import NFStreamer
import sys

# Example must run with nfstream >= 6.1.1
path = sys.argv[1]
flow_streamer = NFStreamer(source=path, statistical_analysis=False, performance_report=1)
result = {}
try:
    for flow in flow_streamer:
        print(flow)
        try:
            result[flow.application_name] += flow.bidirectional_packets
        except KeyError:
            result[flow.application_name] = flow.bidirectional_packets
    print("\nSummary (Application Name: Packets):")
    print(result)
except KeyboardInterrupt:
    print("\nSummary (Application Name: Packets):")
    print(result)
    print("Terminated.")
