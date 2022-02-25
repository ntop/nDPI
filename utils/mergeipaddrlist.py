#!/usr/bin/env python3

import sys
import socket
import struct
import netaddr

if len (sys.argv) == 3:
    proto = sys.argv[2]

if len(sys.argv) < 2:
    print("Usage: mergeipaddrlist.py <file>")
    sys.exit (1)

ipFile = open(sys.argv[1])
ipAddresses = list(ipFile.readlines())
ipAddresses = sorted(ipAddresses)
cidrs = netaddr.cidr_merge(ipAddresses)
for cidr in cidrs:
    print(cidr)
