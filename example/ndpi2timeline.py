#!/usr/bin/env python
#
# Copyright (C) 2019 - ntop.org
#
# nDPI is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# nDPI is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
#

#
# Usage
#
# 1) Generate a CSV file using the ndpiReader tool. Example:
# ./ndpiReader -C sample.json -i sample.pcap
#
# 2) Open Google Chrome and type in the URL 'chrome://tracing/'
# 
# 3) Inside Chrome click on 'Load' or drop sample.json in the
#    Chrome window to visualize the output
#

import sys
import json

protos = {}
lastId = 1

def get_timestamp(seen):
    tok = seen.split(".")
    return int(tok[0]) * 1000 + int(tok[1])

def get_record(toks, csv_fields):
    global protos
    global lastId
    
    if len(toks) < 11:
        return None

    record = dict()
    ndpiProtocol = toks[10]

    ndpi_protos = ndpiProtocol.split(".")    
    if(len(ndpi_protos) == 1):
        app_proto = ndpi_protos[0]
    else:
        app_proto = ndpi_protos[1]
    
    id = protos.get(ndpiProtocol)
    if(id == None):
        lastId = lastId + 1
        protos[ndpiProtocol] = lastId
        id = lastId
        #print(ndpiProtocol+"="+str(id))

    ip_address = toks[5]
    server_name = toks[11]
    record["cat"]  = "flow"
    record["pid"]  = ip_address
    record["tid"]  = ndpiProtocol # id
    record["ts"]   = get_timestamp(toks[2])
    record["ph"]   = "X"
    record["name"] = app_proto

    if(server_name == ""):
        args = {}
    else:
        args = { "name": server_name }
    record["args"] = args
    record["dur"]  = get_timestamp(toks[3]) - record["ts"]

    # if we do not have the legend we just return
    if csv_fields is None:
        return record

    # Otherwise we just add everything we find as a string
    if(0):
        idx = 0
        for tok in toks:
            name = csv_fields[idx]
            idx += 1
            record["args"][name] = str(tok)

    return record

def get_record_dict(filename):
    csv_fields = None
    records = []
    fin = open(filename, "r");
    for line in fin:
        line = line.replace("\n","")

        # Get the legend if present
        if line[0] == '#':
            csv_fields = []
            line = line.replace("#", "")
            toks = line.split(",")
            for tok in toks:
                csv_fields.append(tok)
            continue

        toks = line.split(",")
        flow_id = int(toks[0])
        record = get_record(toks, csv_fields)
        if record is None:
            print("Error while parsing " + line)
            continue

        records.append(record)

    json_dict = dict()
    json_dict["traceEvents"] = records

    return json_dict

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("ndpi2json <csv_file> <json_file>")
        sys.exit(0)

    record_dict = get_record_dict(sys.argv[1])
    #print(record_dict)
    #json_string = json.dumps(json_dict)
    #print(json_string)

    with open(sys.argv[2], 'w') as fp:
        json.dump(record_dict, fp)
        print("Written " + str(len(record_dict["traceEvents"])) + " records")
