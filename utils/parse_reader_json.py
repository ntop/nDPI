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

#shorten_ja4 = True
shorten_ja4 = False
use_domainame = True

client_fingerprints = {}
hostname_fingerprints = {}
fingerprints        = {}

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
            src_ip = data['src_ip']
            tcp_fingerprint = data['tcp_fingerprint']
            ja4 = data['ndpi']['tls']['ja4']

            if(shorten_ja4):
                items = ja4.split("_")
                ja4   = items[1] + "_" + items[2]
            
            if(use_domainame):
                hostname = data['ndpi']['domainame']
            else:
                hostname = data['ndpi']['hostname']
                
            key = tcp_fingerprint+"-"+ja4
            if(not(src_ip in client_fingerprints)):
                client_fingerprints[src_ip] = {}

            if(not(key in client_fingerprints[src_ip])):
                client_fingerprints[src_ip][key] = {}

            value = hostname
            client_fingerprints[src_ip][key][value] = True

            #####################

            if(not(key in fingerprints)):
                fingerprints[key] = {}

            fingerprints[key][src_ip] = hostname

            #####################

            if(not(hostname in hostname_fingerprints)):
                hostname_fingerprints[hostname] = {}
                
            hostname_fingerprints[hostname][key] = True
            
####################

for host in client_fingerprints.keys():
    print(host+" [" + str(len(client_fingerprints[host].keys())) + " fingerprints]")
    for k in client_fingerprints[host].keys():
        print(k, end =" [ ")

        for client in client_fingerprints[host][k]:
            print(client, end =" ")

        print("]")

    print("")

print("------------------------")

for key in fingerprints:
    print(key, end =" [ ")
    
    for client in fingerprints[key]:
        print(client, end =" ")

    print("]")

sys.exit(0)

print("------------------------")

for hostname in hostname_fingerprints:
    print(hostname, end ="\n[ ")
    
    for f_print in hostname_fingerprints[hostname]:
        print(f_print, end =" ")

    print("]\n")

