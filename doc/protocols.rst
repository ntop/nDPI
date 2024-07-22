nDPI Protocols List
###################

This page provides the list of the protocols/applications supported by nDPI. For each protocol there is a brief description, some links to further, more detailed information and, optionally, some notes that might be useful when handling such a protocol (from the application/integrator point of view)

Work in progress!

.. _Proto 32:

`NDPI_PROTOCOL_BFCP`
=======================
BFCP (Binary Floor Control Protocol) is used for controlling and coordinating real-time data sharing and collaboration during video conferencing sessions.

References: `RFC: <https://datatracker.ietf.org/doc/html/rfc8855>`_


.. _Proto 54:

`NDPI_PROTOCOL_IQIYI`
===========================
iQIYI is a Chinese online video platform that offers a wide range of original and licensed content including movies, dramas, variety shows, and anime.

References: `Main site: <https://www.iqiyi.com/>`_


.. _Proto 59:

`NDPI_PROTOCOL_ADOBE_CONNECT`
===========================
Adobe Connect is a web conferencing platform that allows users to conduct online meetings, webinars, and virtual classrooms.

References: `Main site: <https://www.adobe.com/products/adobeconnect.html>`_


.. _Proto 65:

`NDPI_PROTOCOL_IRC`
==================
IRC (Internet Relay Chat) is a text-based chat system for instant messaging.

References: `Wikipiedia: <https://en.wikipedia.org/wiki/IRC>`_ and `Some statistics: <https://netsplit.de/networks/top10.php>`


.. _Proto 72:

`NDPI_PROTOCOL_HART_IP`
=======================
Highway Addressable Remote Transducer over IP

References: `Protocol Specs: <https://library.fieldcommgroup.org/20085/TS20085>`_


.. _Proto 96:

`NDPI_PROTOCOL_TFTP`
====================
TFTP is a very simple protocol used to transfer files. It is from this that its name comes, Trivial File Transfer Protocol or TFTP.

References: `RFC1350 <https://datatracker.ietf.org/doc/html/rfc1350>`_ and `RFC2347 <https://datatracker.ietf.org/doc/html/rfc2347>`_ and `RFC2349 <https://datatracker.ietf.org/doc/html/rfc2349>`_


.. _Proto 127:

`NDPI_PROTOCOL_MS_RPCH`
=======================
A Remote Procedure Call protocol over HTTP from Microsoft.

References: `Protocol Specs: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpch/c0f4c9c5-1a61-4d10-b8e2-005378d1d212>`_


.. _Proto 149:

`NDPI_PROTOCOL_EGD`
=========================
Ethernet Global Data (EGD) is a communication protocol developed by GE Fanuc Automation for real-time data exchange between automation devices and control systems using standard Ethernet technology. It is widely adopted in industrial environments for its simplicity and reliability in data communication.

References: `Wikipedia <https://en.wikipedia.org/wiki/Ethernet_Global_Data_Protocol>`_

Notes:

- This dissector only works for data packets, not configuration commands.
- IPv6 is not supported


.. _Proto 182:

`NDPI_PROTOCOL_RESP`
=======================
Redis Serialization Protocol

References: `Protocol Specs: <https://redis.io/docs/reference/protocol-spec/>`_


.. _Proto 186:

`NDPI_PROTOCOL_COD_MOBILE`
=======================
Call of Duty: Mobile is a free-to-play shooter game for iOS and Android devices. It has amassed over 650 million downloads worldwide, making it one of the most popular mobile games.

References: `Main site: <https://www.callofduty.com/mobile/>`_


.. _Proto 201:

`NDPI_PROTOCOL_GOOGLE_MEET`
===========================
Google Meet is a video conferencing service from Google.

References: `Main site: <https://meet.google.com/>`_


.. _Proto 235:

`NDPI_PROTOCOL_VALVE_SDR`
===========================
Steam Datagram Relay (SDR) is Valve's virtual private gaming network. Used in all modern games from Valve, but can also be used by developers via the Steamworks SDK for their games.

References: `Main site: <https://partner.steamgames.com/doc/features/multiplayer/steamdatagramrelay>`_


.. _Proto 338:

`NDPI_PROTOCOL_SRTP`
====================
The Secure Real-time Transport Protocol (SRTP) is a profile for Real-time Transport Protocol (RTP) intended to provide encryption, message authentication, integrity, and replay attack protection to the RTP data.

References: `RFC3711 <https://datatracker.ietf.org/doc/html/rfc3711>`_

Notes:

- You can think of SRTP simply as the "encrypted" version of RTP, something like HTTPS vs HTTP;
- It is not usually possible to tell RTP from SRTP. nDPI generally uses the former and it uses the latter only when it is really sure that the media stream has been encrypted.


.. _Proto 339:

`NDPI_PROTOCOL_OPERA_VPN`
=========================
Opera VPN is a free VPN included with Opera Browser.

References: `Main site <https://www.opera.com/it/features/free-vpn>`_


.. _Proto 340:

`NDPI_PROTOCOL_EPICGAMES`
=========================
Epic Games is a video game company developing the Unreal Engine and some successful games as Fortnite and Gears of War.

References: `Main site <https://store.epicgames.com/en-US/>`_ and `Fortnite <https://www.fortnite.com/>`_


.. _Proto 341:

`NDPI_PROTOCOL_GEFORCENOW`
==========================
GeForce Now is the brand used by Nvidia for its cloud gaming service.

References: `Main site <https://www.nvidia.com/en-us/geforce-now/>`_


.. _Proto 342:

`NDPI_PROTOCOL_NVIDIA`
======================
Generic web traffic from Nvidia sites.

References: `Main site <https://www.nvidia.com>`_


.. _Proto 343:

`NDPI_PROTOCOL_BITCOIN`
=======================
Bitcoin is one of the most common crypto currencies.

References: `Main site <https://en.bitcoin.it/wiki/Protocol_documentation>`_

Notes:

- Not each crypto exchange is a mining, it could be a normal transaction, sending or receving.
- Bitcoin network protocol covers the broader set of rules that govern how all nodes in the network communicate and sync with each others blocks and transactions. 
- On the other hand mining protocols are more specific and deal directly with how miners interact with the network and participate in the mining process.


.. _Proto 344:

`NDPI_PROTOCOL_PROTONVPN`
=========================
Proton VPN is a VPN service operated by the Swiss company Proton AG, the company behind the email service Proton Mail

References: `Main site <https://protonvpn.com/>`_


.. _Proto 345:

`NDPI_PROTOCOL_THRIFT`
======================
Apache Thrift is a generic data interchange framework that supports a bunch of different languages and platforms.

References: `Official site <https://thrift.apache.org>`_ and `Github <https://github.com/apache/thrift>`_


.. _Proto 346:

`NDPI_PROTOCOL_ROBLOX`
======================
Roblox is an online game platform and game creation system.

References: `Main site <https://www.roblox.com/>`_

Notes:

- Since Roblox games use a custom version of the RakNet protocol, some Roblox flows might be classified as RakNet.


.. _Proto 347:

`NDPI_PROTOCOL_SERVICE_LOCATION`
================================
The Service Location Protocol is a service discovery protocol that allows computers and other devices to find services in a local area network without prior configuration.

References: `SLPv1 <https://datatracker.ietf.org/doc/html/rfc2165>`_ and `SLPv2 <https://datatracker.ietf.org/doc/html/rfc2608>`_


.. _Proto 348:

`NDPI_PROTOCOL_MULLVAD`
=======================
Mullvad is a VPN service operated by Mullvad VPN AB, based in Sweden

References: `Main site <https://mullvad.net/>`_


.. _Proto 349:

`NDPI_PROTOCOL_HTTP2`
=====================
HTTP/2 (originally named HTTP/2.0) is a major revision of the HTTP network protocol used by the World Wide Web.

References: `RFC <https://datatracker.ietf.org/doc/html/rfc9113>`_

Notes:

- HTTP/2 is almost always encrypted, i.e. transported over TLS.


.. _Proto 350:

`NDPI_PROTOCOL_HAPROXY`
=======================
HAProxy is a free and open source software that provides a high availability load balancer and reverse proxy for TCP and HTTP-based applications that spreads requests across multiple servers.

References: `Main site: <https://www.haproxy.org>`_


.. _Proto 351:

`NDPI_PROTOCOL_RMCP`
====================
The Intelligent Platform Management Interface (IPMI) is a set of computer interface specifications for an autonomous computer subsystem that provides management and monitoring capabilities independently of the host system's CPU, firmware (BIOS or UEFI) and operating system.

References: `Protocol Specs: <https://www.dmtf.org/sites/default/files/standards/documents/DSP0114.pdf>`_


.. _Proto 352:

`NDPI_PROTOCOL_CAN`
===================
Controller Area Network (CAN) is used extensively in automotive applications, with in excess of 400 million CAN enabled microcontrollers manufactured each year.

References: `Protocol Specs: <https://www.iso.org/standard/63648.html>`_


.. _Proto 353:

`NDPI_PROTOCOL_PROTOBUF`
========================
Protocol Buffers (Protobuf) is a free and open-source cross-platform data format used to serialize structured data.

References: `Encoding: <https://protobuf.dev/programming-guides/encoding>`_


.. _Proto 354:

`NDPI_PROTOCOL_ETHEREUM`
=======================
Ethereum is a decentralized, open-source blockchain with smart contract functionality.

References: `Main site <https://ethereum.org/en/developers/docs/intro-to-ethereum/>`_

Notes:

- same as Bitcoin, not each crypto exchange is a mining, it could be a normal transaction, sending or receving or even blockchain exploration.


.. _Proto 355:

`NDPI_PROTOCOL_TELEGRAM_VOIP`
============================
Audio/video calls made using the telegram app.

References: `Wikipedia <https://en.wikipedia.org/wiki/telegram_(software)/>`_


.. _Proto 356:

`NDPI_PROTOCOL_SINA_WEIBO`
============================
Chinese microblogging (weibo) website.

References: `Wikipedia <https://en.wikipedia.org/wiki/Sina_Weibo>`_


.. _Proto 358:

`NDPI_PROTOCOL_PTPV2`
============================
IEEE 1588-2008 Precision Time Protocol (PTP) Version 2.

References: `Protocol Specs: <https://standards.ieee.org/ieee/1588/4355/>`_


.. _Proto 359:

`NDPI_PROTOCOL_RTPS`
============================
Real-Time Publish Subscribe Protocol

References: `Protocol Specs: <https://www.omg.org/spec/DDSI-RTPS/>`_


.. _Proto 360:

`NDPI_PROTOCOL_OPC_UA`
============================
IEC62541 OPC Unified Architecture

References: `Protocol Specs: <https://reference.opcfoundation.org/>`_


.. _Proto 361:

`NDPI_PROTOCOL_S7COMM_PLUS`
============================
A proprietary protocol from Siemens used for data exchange between PLCs and access PLC data via SCADA systems.
Completely different from classic S7Comm, but also uses TPKT/COTP as a transport.

References: `Unofficial description: <https://plc4x.apache.org/protocols/s7/s7comm-plus.html>`_


.. _Proto 362:

`NDPI_PROTOCOL_FINS`
============================
Factory Interface Network Service (FINS) is a network protocol used by Omron PLCs.

References: `Protocol Specs: <https://assets.omron.eu/downloads/manual/en/v4/w421_cj1w-etn21_cs1w-etn21_ethernet_units_-_construction_of_applications_operation_manual_en.pdf>`_


.. _Proto 363:

`NDPI_PROTOCOL_ETHERSIO`
============================
Ether-S-I/O is a proprietary protocol used by Saia-Burgess's PLCs.

References: `Wireshark wiki: <https://wiki.wireshark.org/EtherSIO.md>`_


.. _Proto 364:

`NDPI_PROTOCOL_UMAS`
============================
UMAS is a proprietary Schneider Electric protocol based on Modbus. It's used in Modicon M580 and Modicon M340 CPU-based PLCs.

References: `Unofficial article: <https://ics-cert.kaspersky.com/publications/reports/2022/09/29/the-secrets-of-schneider-electrics-umas-protocol/>`_


.. _Proto 365:

`NDPI_PROTOCOL_BECKHOFF_ADS`
============================
Automation Device Specification is the protocol used for interfacing with Beckhoff PLCs via TwinCAT.

References: `Protocol Specs: <https://infosys.beckhoff.com/english.php?content=../content/1033/tc3_ads_intro/115847307.html>`_


.. _Proto 366:

`NDPI_PROTOCOL_ISO9506_1_MMS`
============================
The international standard MMS (Manufacturing Message Specification) is an OSI application layer messaging protocol origionally designed for the remote control and monitoring of devices such as Remote Terminal Units (RTU), Programmable Logic Controllers (PLC), Numerical Controllers (NC), or Robot Controllers (RC).

References: `Paid Specs: <https://www.iso.org/ru/standard/37079.html>`_


.. _Proto 367:

`NDPI_PROTOCOL_IEEE_C37118`
============================
IEEE Standard for Synchrophasor Data Transfer for Power Systems

References: `Paid Specs: <https://standards.ieee.org/ieee/C37.118.1/4902/>`_


.. _Proto 368:

`NDPI_PROTOCOL_ETHERSBUS`
============================
Ether-S-Bus is a proprietary protocol used for the communication with and between PLCs manufactured by Saia-Burgess Controls Ltd.

References: `Wireshark wiki: <https://wiki.wireshark.org/EtherSBus>`_


.. _Proto 369:

`NDPI_PROTOCOL_MONERO`
======================
Monero is a private and decentralized cryptocurrency with focus on confidentiality and security.


.. _Proto 370:

`NDPI_PROTOCOL_DCERPC`
======================
DCE/RPC is a specification for a remote procedure call mechanism that defines both APIs and an over-the-network protocol.

References: `Wireshark wiki: <https://wiki.wireshark.org/DCE/RPC>`_


.. _Proto 371:

`NDPI_PROTOCOL_PROFINET_IO`
===========================
PROFINET/IO is a field bus protocol based on connectionless DCE/RPC.

References: `Protocol Specs: <https://www.profibus.com/download/profinet-specification>`_


.. _Proto 372:

`NDPI_PROTOCOL_HISLIP`
======================
High-Speed LAN Instrument Protocol (HiSLIP) is a protocol for remote instrument control of LAN-based test and measurement instruments.

References: `Protocol Specs: <https://www.ivifoundation.org/downloads/Protocol%20Specifications/IVI-6.1_HiSLIP-2.0-2020-04-23.pdf>`_


.. _Proto 373:

`NDPI_PROTOCOL_UFTP`
====================
Encrypted UDP based FTP with multicast.

References: `Protocol Specs: <https://uftp-multicast.sourceforge.net/protocol.txt>`_.


.. _Proto 374:

`NDPI_PROTOCOL_OPENFLOW`
========================
OpenFlow protocol is a network protocol closely associated with Software-Defined Networking (SDN).

References: `Protocol Specs: <https://opennetworking.org/wp-content/uploads/2014/10/openflow-switch-v1.5.1.pdf>`_


.. _Proto 375:

`NDPI_PROTOCOL_JSON_RPC`
========================
JSON-RPC is a remote procedure call protocol encoded in JSON.

References: `Protocol Specs: <https://www.jsonrpc.org/specification>`_


.. _Proto 376:

`NDPI_PROTOCOL_WEBDAV`
======================
WebDAV is a set of extensions to the HTTP protocol that allows WebDAV clients to collaboratively edit and manage files on remote Web servers.

References: `RFC4918: <https://datatracker.ietf.org/doc/html/rfc4918>`_

Notes:

- WebDAV is almost always encrypted, i.e. transported over TLS.


.. _Proto 377:

`NDPI_PROTOCOL_APACHE_KAFKA`
============================
Apache Kafka is a distributed event store and stream-processing platform.

References: `Official site <https://kafka.apache.org>`_ and `Github <https://github.com/apache/kafka>`_


.. _Proto 378:

`NDPI_PROTOCOL_NOMACHINE`
=========================
NoMachine is a popular proprietary remote desktop software.

References: `Main site <https://www.nomachine.com/>`_


.. _Proto 379:

`NDPI_PROTOCOL_IEC62056`
============================
IEC 62056-4-7 DLMS/COSEM is a transport layer for IP networks.

References: `Paid Specs: <https://webstore.iec.ch/publication/22487>`_

Notes:

- Wireshark is not able to recognize this protocol. Some old plugins/code (with some documentation) are available `here <https://github.com/bearxiong99/wireshark-dlms>` and `here <https://github.com/matousp/dlms-analysis/tree/master>`.


.. _Proto 380:

`NDPI_PROTOCOL_HL7`
=========================
HL7 is a range of global standards for the transfer of clinical and administrative health data between applications.

References: `Main site <https://www.hl7.org/>`_


.. _Proto 381:

`NDPI_PROTOCOL_CEPH`
=========================
Ceph is a scalable distributed storage system.

References: `Main site <https://ceph.io/en/>`_


.. _Proto 382:

`NDPI_PROTOCOL_GOOGLE_CHAT`
=========================
Google Chat is an instant messaging service from Google, which replaced Hangouts.

References: `Main site <https://chat.google.com/>`_


.. _Proto 383:

`NDPI_PROTOCOL_ROUGHTIME`
=========================
A protocol that aims to achieve rough time synchronization while detecting servers that provide inaccurate time and providing cryptographic proof of their malfeasance.

References: `IETF Draft <https://www.ietf.org/archive/id/draft-ietf-ntp-roughtime-08.html>`_


.. _Proto 384:

`NDPI_PROTOCOL_PIA`
=========================
Private Internet Access (PIA) is a popular VPN service from Kape Technologies.

References: `Main site <https://www.privateinternetaccess.com/>`_


.. _Proto 385:

`NDPI_PROTOCOL_KCP`
===================
KCP - A Fast and Reliable ARQ Protocol. It provides TCP-like stream support with low latency at the cost of bandwidth usage - used by lot's of Open Source / Third Party applications.

References: `Protocol Specs: <https://github.com/skywind3000/kcp/blob/master/protocol.txt>`_


.. _Proto 386:

`NDPI_PROTOCOL_DOTA2`
=========================
Dota 2 is an extremely popular multiplayer MOBA game from Valve.

References: `Main site <https://www.dota2.com/>`_


.. _Proto 387:

`NDPI_PROTOCOL_MUMBLE`
=========================
Mumble is a free, open source, low latency, high quality voice chat application.

References: `Main site <https://www.mumble.info/>`_


.. _Proto 388:

`NDPI_PROTOCOL_YOJIMBO`
=======================
Yojimbo (netcode) is a secure connection-based client/server protocol built on top of UDP.

References: `Protocol Specs: <https://github.com/mas-bandwidth/netcode/blob/main/STANDARD.md>`_


.. _Proto 389:

`NDPI_PROTOCOL_ELECTRONICARTS`
=========================
Electronic Arts is a leading publisher of games on Console, PC and Mobile.

References: `Main site <https://www.ea.com/>`_

Notes:

- Almost all of that traffic is related to their EA Origin game store.


.. _Proto 390:

`NDPI_PROTOCOL_STOMP`
========================
STOMP is a simple interoperable protocol designed for asynchronous message passing between clients via mediating servers. Supported in ActiveMQ and RabbitMQ.

References: `Protocol Specs: <https://stomp.github.io/stomp-specification-1.2.html>`_


.. _Proto 391:

`NDPI_PROTOCOL_RADMIN`
=========================
Radmin is remote access software for the Microsoft Windows platform.

References: `Main site <https://www.radmin.com/>`_


.. _Proto 392:

`NDPI_PROTOCOL_RAFT`
====================
Raft is a consensus algorithm and protocol for managing a replicated log.

References: `C implementation <https://github.com/canonical/raft>`_ and `Paper <https://raft.github.io/raft.pdf>`_


.. _Proto 394:

`NDPI_PROTOCOL_GEARMAN`
====================
Gearman is a network-based job-queuing system that was initially developed by Danga Interactive in order to process large volumes of jobs.

References: `Main site <http://gearman.org/>`_


.. _Proto 395:

`NDPI_PROTOCOL_TENCENTGAMES`
====================
A protocol used by various games from Tencent (mostly mobile games).

References: `Main site <https://www.tencentgames.com/>`_


.. _Proto 396:

`NDPI_PROTOCOL_GAIJIN`
====================
Protocols used in various games from Gaijin Entertainment.

References: `Main site <https://gaijin.net/>`_


.. _Proto 397:

`NDPI_PROTOCOL_C1222`
====================
ANSI C12.22 (IEEE Std 1703) describe a protocol for transporting ANSI C12.19 table data over networks. It's mostly used to communicate with electric meters.

References: `Paid specs <https://www.nema.org/Standards/view/American-National-Standard-for-Protocol-Specification-for-Interfacing-to-Data-Communication-Networks/>`_


.. _Proto 398:

`NDPI_PROTOCOL_HUAWEI`
======================
Generic Huawei traffic.

References: `Main site <https://www.huawei.com/>`_


.. _Proto 399:

`NDPI_PROTOCOL_HUAWEI_CLOUD`
============================
Huawei Mobile Cloud.

References: `Main site <https://cloud.huawei.com/>`_


.. _Proto 400:

`NDPI_PROTOCOL_DLEP`
=====================
The Dynamic Link ExchangeProtocol (DLEP) is a radio aware routing (RAR) protocol.

References: `RFC <https://datatracker.ietf.org/doc/html/rfc8175>`_


.. _Proto 401:

`NDPI_PROTOCOL_BFD`
=====================
Bidirectional Forwarding Detection is a network protocol that is used to detect faults between two routers or switches.

References: `RFC <https://datatracker.ietf.org/doc/html/rfc5880>`_


.. _Proto 402:

`NDPI_PROTOCOL_NETEASE_GAMES`
============================
Traffic of various NetEase games.

References: `Main site <https://www.neteasegames.com/>`_


.. _Proto 403:

`NDPI_PROTOCOL_PATHOFEXILE`
============================
Path of Exile is a free-to-play online Action RPG.

References: `Main site <https://pathofexile.com/>`_


.. _Proto 404:

`NDPI_PROTOCOL_GOOGLE_CALL`
===========================
Audio/video calls made by (any) Google applications (i.e Google Meet).

References: `Main site: <https://meet.google.com/>`_

Notes:

- nDPI usually uses different protocol ids for the generic application traffic and for its "realtime" traffic (examples: NDPI_PROTOCOL_MEET/NDPI_PROTOCOL_GOOGLE_CALL, NDPI_PROTOCOL_WHATSAPP/NDPI_PROTOCOL_WHATSAPP_CALL, ...)


.. _Proto 405:

`NDPI_PROTOCOL_PFCP`
=====================
PFCP is a protocol used for communicating between control plane (CP) and user plane (UP) functions in 4G and 5G networks.

References: `Protocol Specs: <https://www.etsi.org/deliver/etsi_ts/129200_129299/129244/16.05.00_60/ts_129244v160500p.pdf>`_


.. _Proto 406:

`NDPI_PROTOCOL_FLUTE`
=====================
File Delivery over Unidirectional Transport.

References: `RFC <https://datatracker.ietf.org/doc/html/rfc6726>`_


.. _Proto 407:

`NDPI_PROTOCOL_LOLWILDRIFT`
============================
League of Legends: Wild Rift is a mobile MOBA game.

References: `Main site <https://wildrift.leagueoflegends.com/>`_


.. _Proto 408:

`NDPI_PROTOCOL_TESO`
============================
The Elder Scrolls Online is a MMORPG set in the fantasy world of Tamriel.

References: `Main site <https://www.elderscrollsonline.com/>`_


.. _Proto 409:

`NDPI_PROTOCOL_LDP`
=====================
The Label Distribution Protocol (LDP) is a routing protocol used to establish and maintain label-switched paths in a Multiprotocol Label Switching (MPLS) network.

References: `RFC <https://datatracker.ietf.org/doc/html/rfc5036>`_


.. _Proto 410:

`NDPI_PROTOCOL_KNXNET_IP`
=====================
KNXnet/IP is a building automation protocol that enables the exchange of data and control information over IP networks, extending the KNX standard for home and building automation.

References: `Paid Specs: <https://webstore.ansi.org/standards/ds/dsiso225102019>`_


.. _Proto 411:

`NDPI_PROTOCOL_BLUESKY`
======================
Bluesky, also known as Bluesky Social, is a decentralized microblogging social platform.

References: `Main site: <https://bsky.app/>`_


.. _Proto 412:

`NDPI_PROTOCOL_MASTODON`
=======================
Mastodon is free and open-source software for running self-hosted social networking services. It has microblogging features similar to Twitter.

References: `Main site: <https://joinmastodon.org/>`_


.. _Proto 413:

`NDPI_PROTOCOL_THREADS`
======================
Threads is an online social media and social networking service operated by Meta Platforms.

References: `Main site: <https://www.threads.net>`_


.. _Proto 414:

`NDPI_PROTOCOL_VIBER_VOIP`
=========================
Audio/video calls made using the Viber app.

References: `Wikipedia <https://en.wikipedia.org/wiki/Viber>`_


.. _Proto 415:

`NDPI_PROTOCOL_ZUG`
=========================
The ZUG protocol is part of the Casper 2.0 consensus model.

References: `Main Site <https://casperlabs.io>`_ and `Blog Post <https://casperlabs.io/blog/beyond-eth-30-theres-casper-20>`_


.. _Proto 416:

`NDPI_PROTOCOL_JRMI`
=========================
The JRMI protocol is the Java Remote Method Invocation protocol.

References:  `Oracle site <https://docs.oracle.com/en/java/javase/21/docs/specs/rmi/protocol.html>`_


.. _Proto 417:

`NDPI_PROTOCOL_RIPE_ATLAS`
==========================
The RIPE Atlas probe protocol is used for the world's largest active Internet measurement network.

References: `Main Site <https://atlas.ripe.net/>`_ and `Documentation <https://ripe-atlas-tools.readthedocs.io/en/latest/index.html>`_


.. _Proto 418:

`NDPI_PROTOCOL_HLS`
=====================
HTTP Live Streaming (HLS) is an adaptive bitrate streaming communications protocol developed by Apple Inc. It allows for the delivery of media content over the internet by breaking the stream into small segments and adjusting the quality of the stream in real time based on the viewer's network conditions.

References: `RFC <https://datatracker.ietf.org/doc/html/rfc8216>`_


.. _Proto 419:

`NDPI_PROTOCOL_CLICKHOUSE`
======================
ClickHouse is an open-source columnar database management system designed for online analytical processing (OLAP) of queries.

References: `Main site: <https://clickhouse.com/>`_


.. _Proto 420:

`NDPI_PROTOCOL_NANO`
======================
Nano (XNO) is a decentralized, open-source cryptocurrency that focuses on delivering fast, fee-less, and eco-friendly transactions through its unique block-lattice structure.

References: `Main site: <https://nano.org/>`_


.. _Proto 421:

`NDPI_PROTOCOL_OPENWIRE`
======================
OpenWire is a wire protocol used by Apache ActiveMQ for communication between clients and brokers, providing an efficient and flexible messaging framework. While it's not the most popular choice compared to other protocols like AMQP or MQTT, it is still utilized in scenarios where ActiveMQ is heavily integrated.

References: `Main site: <https://activemq.apache.org/components/classic/documentation/openwire>`_
