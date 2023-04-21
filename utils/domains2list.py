#!/usr/bin/env python3

import sys
import socket, struct

if len (sys.argv) != 6 :
    print("Usage: ipaddr2list.py <file> <protocol_name> <protocol_id> <category> <breed>")
    sys.exit (1)

proto_name = sys.argv[2]
proto = sys.argv[3]
category = sys.argv[4]
breed = sys.argv[5]



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

print("static ndpi_protocol_match "+proto_name.lower()+"_host_match[] = {")

with open(sys.argv[1]) as fp:
    for cnt, line in enumerate(fp):
        line = line.rstrip()

        if(line != ""):
            domain = line

            #Converting to the format expected by ahocorasick

            #Remove leading *.
            if(domain[0] == "*" and domain[1] == "."):
                domain = domain[2:]
            #If others *, skip the domain
            if('*' not in domain ):
                print(" { \"" + domain.lower() + "\", \"" + proto_name + "\", " + proto + ", " + category + ", " + breed + ", NDPI_PROTOCOL_DEFAULT_LEVEL },")

print(" { NULL, NULL, NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_DEFAULT_LEVEL }")
print("};")
