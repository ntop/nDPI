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
ipAddresses = [x.replace("\n","") for x in ipAddresses]
ipAddresses = sorted(ipAddresses)
cidrs = netaddr.cidr_merge(ipAddresses)

lines = 0
for cidr in cidrs:
    lines += 1
    print(cidr)

if lines == 0:
    sys.stderr.write(f'{sys.argv[0]}: file {sys.argv[1]} is empty\n')
