#!/usr/bin/env python3

import sys
import socket, struct

if len (sys.argv) != 2 :
    print("Usage: toripaddr2list.py <file>")
    sys.exit (1)
            
with open(sys.argv[1]) as fp:
    for cnt, line in enumerate(fp):
        ipaddr = line.rstrip()
        print(" { 0x"+socket.inet_aton(ipaddr).hex()+", /* "+ipaddr+" */, 32, NDPI_PROTOCOL_TOR },")

