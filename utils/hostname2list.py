#!/usr/bin/env python3

import sys
import socket, struct

# This scripts is used to create "hostname/sni -> protocols" lists.
if len(sys.argv) < 6:
    print("Usage: {} <file> <name> <protocol> <category> <breed>".format(sys.argv[0]))
    sys.exit (1)

name = sys.argv[2]
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

print("static ndpi_protocol_match "+proto.lower()+"_hostname_list[] = {")

with open(sys.argv[1]) as fp:
    for cnt, line in enumerate(fp):
        line = line.rstrip()

        if(line != ""):
            x = line.split("/")

            if(len(x) == 2):
                host = x[0]
            else:
                host = line

            if(host != ""):
                print(' { ' + f'"{host}", "{name}", {proto}, {category}, {breed}, NDPI_PROTOCOL_DEFAULT_LEVEL' + ' },')

print(" /* End */")
print(" { NULL, NULL, NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_DEFAULT_LEVEL }")
print("};")
