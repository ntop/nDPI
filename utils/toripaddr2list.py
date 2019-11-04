#!/usr/bin/env python3

import sys
import socket, struct

if len (sys.argv) != 2 :
    print("Usage: toripaddr2list.py <file>")
    sys.exit (1)
            
with open(sys.argv[1]) as fp:
    for cnt, line in enumerate(fp):
        x = line.rstrip().split("/")
        ipaddr = x[0]
        cidr   = x[1]
        
        if(cidr == None):
            cidr = "32"

        print(" { 0x"+socket.inet_aton(ipaddr).hex().upper()+" /* "+ipaddr+"/"+cidr+" */, "+cidr+", NDPI_PROTOCOL_XYX },")

