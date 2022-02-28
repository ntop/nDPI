#!/usr/bin/env python3

import sys
import socket, struct

# This scripts is mainly used to create "ip -> protocols" lists.
# However it is also used to create "ip -> risk" lists
proto = "NDPI_PROTOCOL_XYX"
if len (sys.argv) < 2 :
    print("Usage: ipaddr2list.py <file> <protocol>")
    sys.exit (1)

if len (sys.argv) == 3:
    proto = sys.argv[2]



print("""/*
 *
 * This file is generated automatically and part of nDPI
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

/* ****************************************************** */

""")

print("static ndpi_network "+proto.lower()+"_protocol_list[] = {")

with open(sys.argv[1]) as fp:
    for cnt, line in enumerate(fp):
        line = line.rstrip()

        if(line != ""):
            x = line.split("/")

            if(len(x) == 2):
                ipaddr = x[0]
                cidr   = x[1]
            else:
                ipaddr = line
                cidr = "32"

            if(ipaddr != ""):
                print(" { 0x"+socket.inet_aton(ipaddr).hex().upper()+" /* "+ipaddr+"/"+cidr+" */, "+cidr+", "+proto+" },")

print(" /* End */")
print(" { 0x0, 0, 0 }")
print("};")
