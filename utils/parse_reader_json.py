#!/usr/bin/python3

#
# Usage
#
# ./example/ndpiReader -K JSON -k /tmp/a.json -L lists/public_suffix_list.dat -i packets.pcap
#
# ./parse_reader_json.py /tmp/a.json
#

import json
import sys

if(len(sys.argv) != 2):
    print("Usage: parse_reader_json.py <ndpiReader>.json")
    sys.exit()
    
fname = sys.argv[1]

fingeprints = {}

# Open and read the JSON file
with open(fname, 'r') as file:
    for line in file:
        data = json.loads(line)
    
        # Print the data
        if(('tcp_fingerprint' in data)
           and ('tls' in data['ndpi'])
           and ('hostname' in data['ndpi'])
           and ('ja4' in data['ndpi']['tls'])
           ):
            tcp_fingerprint = data['tcp_fingerprint']
            ja4 = data['ndpi']['tls']['ja4']
            domainame = data['ndpi']['domainame']
            hostname = data['ndpi']['hostname']

            key = tcp_fingerprint+"-"+ja4
            if(not(key in fingeprints)):
                fingeprints[key] = {}

            value = hostname
            fingeprints[key][value] = True


for k in fingeprints.keys():
    print(k, end =" [ ")

    for host in fingeprints[k]:
        print(host, end =" ")

    print("]")
