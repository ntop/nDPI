# Tshark Lua Class

This directory implements a Lua class that leverages on tshark for parsing packets

## Lib

This directory contains the implementation of the tshark class that contains three simple and self-explanatory methods:

- function tshark:open(pcap_file_or_dev, filter)
- function tshark:close()
- function tshark:read()

## Examples
This this directory you can find simple code examples that show how to use the tshark class including counting packets and flow traffic accounting.
