#!/usr/bin/env python3

import sys
import socket, struct

if len (sys.argv) != 2 :
    print("Usage: toripaddr2list.py <file>")
    sys.exit (1)
            
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
                print(" { 0x"+socket.inet_aton(ipaddr).hex().upper()+" /* "+ipaddr+"/"+cidr+" */, "+cidr+", NDPI_PROTOCOL_XYX },")

