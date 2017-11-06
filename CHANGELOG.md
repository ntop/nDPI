# CHANGELOG

#### nDPI 2.0 (May 2017)

## Main New Features

* nDPI Wireshark plugin for Layer-7 protocol dissection. The plugin, available via an extcap interface, passes Wireshark the nDPI-detected protocols by adding an ethernet packet trailer that is then interpreted and displayed inside the Wireshark GUI. Readme: https://github.com/ntop/nDPI/blob/dev/wireshark/README.md


## New Supported Protocols and Services

* STARTTLS
* IMAPS
* DNScrypt
* QUIC (Quick UDP Internet Connections)
* AMQP (Advanced Message Queueing Protocol)
* Ookla (SpeedTest)
* BJNP
* AFP (Apple Filing Protocol)
* SMPP (Short Message Peer-to-Peer)
* VNC
* OpenVPN
* OpenDNS
* RX protocol (used by AFS)
* CoAP and MQTT (IoT specific protocols)
* Cloudflare
* Office 365
* OCS
* MS Lync
* Ubiquity AirControl 2
* HEP (Extensible Encapsulation Protocol)
* WhatsApp Voice vs WhatsApp (chat, no voice)
* Viber	
* Wechat
* Github
* Hotmail
* Slack
* Instagram
* Snapchat
* MPEG TS protocol
* Twitch
* KakaoTalk Voice and Chat
* Meu
* EAQ
* iQIYI media service
* Weibo
* PPStream


## Improvements

* SSH client/server version dissection
* Improved SSL dissection
* SSL server certificate detection
* Added double tagging 802.1Q in dissection of vlan-tagged packets
* Improved netBIOS dissection
* Improved Skype detection
* Improved Netflix traffic detection
* Improved HTTP subprotocol matching
* Implemented DHCP host name extraction
* Updated Facebook detection by ip server ranges
* Updated Twitter networks	  
* Improved Microsoft detection
* Enhanced Google detection
* Improved BT-uTP protocol dissection
* Added detection of Cisco datalink layer (Cisco hDLC and Cisco SLARP)


#### Older releases

#### 2014-03-21
* improved support for eDonkey/eMule/Kademlia
* improved support for PPLive

#### 2014-03-20
* code optimizations
* consistency improvements
* added support for new applications: Pando Media Booster
* improved support for Steam
* added support for new web services: Wikipedia, MSN, Amazon, eBay, CNN

#### 2014-03-19
* added new protocols: FTP, code improvements

#### 2014-03-17
* added new protocols: SOCKSv4, SOCKSv5, RTMP
