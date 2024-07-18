#!/usr/bin/env python3

import sys
import socket

# This script is mainly used to create "ip -> protocols" lists.
# However, it is also used to create "ip -> risk" lists
proto = "NDPI_PROTOCOL_XYX"
append_name = ""
if len(sys.argv) < 2:
    print("Usage: ipaddr2list.py <file> <protocol> [file6] [<append_name>]")
    sys.exit(1)

if len(sys.argv) >= 3:
    proto = sys.argv[2]

if len(sys.argv) >= 5:
    append_name = sys.argv[4]

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

print("static ndpi_network " + proto.lower() + append_name + "_protocol_list[] = {")

lines = 0
with open(sys.argv[1]) as fp:
    for cnt, line in enumerate(fp):
        line = line.rstrip()

        if line != "":
            lines += 1
            x = line.split("/")

            if len(x) == 2:
                ipaddr = x[0]
                cidr = x[1]
            else:
                ipaddr = line
                cidr = "32"

            if ipaddr != "":
                print(" { 0x" + socket.inet_aton(ipaddr).hex().upper() + " /* " + ipaddr + "/" + cidr + " */, " + cidr + ", " + proto + " },")

print(" /* End */")
print(" { 0x0, 0, 0 }")
print("};")

print("")
print("static ndpi_network6 " + proto.lower() + append_name + "_protocol_list_6[] = {")

if len(sys.argv) >= 4:

    with open(sys.argv[3]) as fp:
        for cnt, line in enumerate(fp):
            line = line.rstrip()

            if line != "":
                lines += 1
                x = line.split("/")

                if len(x) == 2:
                    ipaddr = x[0]
                    cidr = x[1]
                else:
                    ipaddr = line
                    cidr = "128"

                if ipaddr != "":
                    print(" { \"" + ipaddr + "\", " + cidr + ", " + proto + " },")

print(" /* End */")
print(" { NULL, 0, 0 }")
print("};")

if lines == 0:
    sys.stderr.write(f'{sys.argv[0]}: File {sys.argv[1]} is empty.\n')
