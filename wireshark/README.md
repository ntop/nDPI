# nDPI Wireshark Plugin

## Introduction

nDPI can provide Wireshark protocol dissection to complement internal protocol decoding. In order to do this, the ndpiReader application is used to provide Wireshark nDPI protocol dissection, and a Wireshark plugin interprets nDPI information.

## Installation

- Copy the ndpiReader application (it is located under nDPI/example) to the Extcap path. See Wireshark -> About menu for identifying the extcap directory. Under OSX it is usually /Applications/Wireshark.app/Contents/MacOS/extcap
- Copy the ndpi.lua plugin under ~/.wireshark/plugins (or in the global Wireshark plugins directory)

## Usage

At Wireshark startup you will find a new extcap interface named "nDPI interface". Select that interface and specify an interface name (for live capture) or a pcap file path (for reading packets from a pcap file). You can choose a nDPI protocol list from the dropdown menu in case you want Wireshark to dissect only protocols of the specified nDPI application protocol.

During capture the ndpiReader plugin will pass Wireshark the nDPI protocol information adding an ethernet packet trailer that contains nDPI information. The lua plugin interprets this information and it displays it in the Wireshark GUI.

## nDPI Packet Filtering

As nDPI is natively integrated into Wireshark, you can filter packets using the usual filtering mechanism. Example use "ndpi.protocol.name==BitTorrent" to filter all BitTorrent traffic.
