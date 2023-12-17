nDPI Protocols List
###################

This page provides the list of the protocols/applications supported by nDPI. For each protocol there is a brief description, some links to further, more detailed information and, optionally, some notes that might be useful when handling such a protocol (from the application/integrator point of view)

Work in progress!

.. _Proto 72:

`NDPI_PROTOCOL_HART_IP`
============================
Highway Addressable Remote Transducer over IP

References: `Protocol Specs: <https://library.fieldcommgroup.org/20085/TS20085>`_.


.. _Proto 96:

`NDPI_PROTOCOL_TFTP`
====================
TFTP is a very simple protocol used to transfer files. It is from this that its name comes, Trivial File Transfer Protocol or TFTP.

References: `RFC1350 <https://datatracker.ietf.org/doc/html/rfc1350>`_ and `RFC2347 <https://datatracker.ietf.org/doc/html/rfc2347>`_ and `RFC2349 <https://datatracker.ietf.org/doc/html/rfc2349>`_


.. _Proto 338:

`NDPI_PROTOCOL_SRTP`
====================
The Secure Real-time Transport Protocol (SRTP) is a profile for Real-time Transport Protocol (RTP) intended to provide encryption, message authentication, integrity, and replay attack protection to the RTP data.

References: `RFC3711 <https://datatracker.ietf.org/doc/html/rfc3711>`_.

Notes:

- You can think of SRTP simply as the "encrypted" version of RTP, something like HTTPS vs HTTP;
- It is not usually possible to tell RTP from SRTP. nDPI generally uses the former and it uses the latter only when it is really sure that the media stream has been encrypted.


.. _Proto 339:

`NDPI_PROTOCOL_OPERA_VPN`
=========================
Opera VPN is a free VPN included with Opera Browser.

References: `Main site <https://www.opera.com/it/features/free-vpn>`_.


.. _Proto 340:

`NDPI_PROTOCOL_EPICGAMES`
=========================
Epic Games is a video game company developing the Unreal Engine and some successful games as Fortnite and Gears of War.

References: `Main site <https://store.epicgames.com/en-US/>`_ and `Fortnite <https://www.fortnite.com/>`_.


.. _Proto 341:

`NDPI_PROTOCOL_GEFORCENOW`
==========================
GeForce Now is the brand used by Nvidia for its cloud gaming service.

References: `Main site <https://www.nvidia.com/en-us/geforce-now/>`_.


.. _Proto 342:

`NDPI_PROTOCOL_NVIDIA`
======================
Generic web traffic from Nvidia sites.

References: `Main site <https://www.nvidia.com>`_.


.. _Proto 343:

`NDPI_PROTOCOL_BITCOIN`
=======================
Bitcoin is one of the most common crypto currencies.

References: `Main site <https://en.bitcoin.it/wiki/Protocol_documentation>`_.

Notes:

- Not each crypto exchange is a mining, it could be a normal transaction, sending or receving.
- Bitcoin network protocol covers the broader set of rules that govern how all nodes in the network communicate and sync with each others blocks and transactions. 
- On the other hand mining protocols are more specific and deal directly with how miners interact with the network and participate in the mining process.


.. _Proto 344:

`NDPI_PROTOCOL_PROTONVPN`
=========================
Proton VPN is a VPN service operated by the Swiss company Proton AG, the company behind the email service Proton Mail

References: `Main site <https://protonvpn.com/>`_.


.. _Proto 345:

`NDPI_PROTOCOL_THRIFT`
======================
Apache Thrift is a generic data interchange framework that supports a bunch of different languages and platforms.

References: `Official site <https://thrift.apache.org>`_ and `Github <https://github.com/apache/thrift>`_.


.. _Proto 346:

`NDPI_PROTOCOL_ROBLOX`
======================
Roblox is an online game platform and game creation system.

References: `Main site <https://www.roblox.com/>`_.

Notes:

- Since Roblox games use a custom version of the RakNet protocol, some Roblox flows might be classified as RakNet.


.. _Proto 347:

`NDPI_PROTOCOL_SERVICE_LOCATION`
================================
The Service Location Protocol is a service discovery protocol that allows computers and other devices to find services in a local area network without prior configuration.

References: `SLPv1 <https://datatracker.ietf.org/doc/html/rfc2165>`_ and `SLPv2 <https://datatracker.ietf.org/doc/html/rfc2608>`_.


.. _Proto 348:

`NDPI_PROTOCOL_MULLVAD`
=======================
Mullvad is a VPN service operated by Mullvad VPN AB, based in Sweden

References: `Main site <https://mullvad.net/>`_.


.. _Proto 349:

`NDPI_PROTOCOL_HTTP2`
=====================
HTTP/2 (originally named HTTP/2.0) is a major revision of the HTTP network protocol used by the World Wide Web.

References: `RFC <https://datatracker.ietf.org/doc/html/rfc9113>`_.

Notes:

- HTTP/2 is almost always encrypted, i.e. transported over TLS.


.. _Proto 350:

`NDPI_PROTOCOL_HAPROXY`
=======================
HAProxy is a free and open source software that provides a high availability load balancer and reverse proxy for TCP and HTTP-based applications that spreads requests across multiple servers.

References: `Main site: <https://www.haproxy.org>`_.


.. _Proto 351:

`NDPI_PROTOCOL_RMCP`
====================
The Intelligent Platform Management Interface (IPMI) is a set of computer interface specifications for an autonomous computer subsystem that provides management and monitoring capabilities independently of the host system's CPU, firmware (BIOS or UEFI) and operating system.

References: `Protocol Specs: <https://www.dmtf.org/sites/default/files/standards/documents/DSP0114.pdf>`_.


.. _Proto 352:

`NDPI_PROTOCOL_CAN`
===================
Controller Area Network (CAN) is used extensively in automotive applications, with in excess of 400 million CAN enabled microcontrollers manufactured each year.

References: `Protocol Specs: <https://www.iso.org/standard/63648.html>`_.


.. _Proto 353:

`NDPI_PROTOCOL_PROTOBUF`
========================
Protocol Buffers (Protobuf) is a free and open-source cross-platform data format used to serialize structured data.

References: `Encoding: <https://protobuf.dev/programming-guides/encoding>`_.


.. _Proto 354:

`NDPI_PROTOCOL_ETHEREUM`
=======================
Ethereum is a decentralized, open-source blockchain with smart contract functionality.

References: `Main site <https://ethereum.org/en/developers/docs/intro-to-ethereum/>`_.


Notes:

- same as Bitcoin, not each crypto exchange is a mining, it could be a normal transaction, sending or receving or even blockchain exploration.


.. _Proto 355:

`NDPI_PROTOCOL_TELEGRAM_VOIP`
============================
Audio/video calls made using the telegram app.

References: `Wikipedia <https://en.wikipedia.org/wiki/telegram_(software)/>`_.


.. _Proto 356:

`NDPI_PROTOCOL_SINA_WEIBO`
============================
Chinese microblogging (weibo) website.

References: `Wikipedia <https://en.wikipedia.org/wiki/Sina_Weibo>`_.


.. _Proto 358:

`NDPI_PROTOCOL_PTPV2`
============================
IEEE 1588-2008 Precision Time Protocol (PTP) Version 2.

References: `Protocol Specs: <https://standards.ieee.org/ieee/1588/4355/>`_.


.. _Proto 359:

`NDPI_PROTOCOL_RTPS`
============================
Real-Time Publish Subscribe Protocol

References: `Protocol Specs: <https://www.omg.org/spec/DDSI-RTPS/>`_.


.. _Proto 360:

`NDPI_PROTOCOL_OPC_UA`
============================
IEC62541 OPC Unified Architecture

References: `Protocol Specs: <https://reference.opcfoundation.org/>`_.


.. _Proto 361:

`NDPI_PROTOCOL_S7COMM_PLUS`
============================
A proprietary protocol from Siemens used for data exchange between PLCs and access PLC data via SCADA systems.
Completely different from classic S7Comm, but also uses TPKT/COTP as a transport.

References: `Unofficial description: <https://plc4x.apache.org/protocols/s7/s7comm-plus.html>`_.


.. _Proto 362:

`NDPI_PROTOCOL_FINS`
============================
Factory Interface Network Service (FINS) is a network protocol used by Omron PLCs.

References: `Protocol Specs: <https://assets.omron.eu/downloads/manual/en/v4/w421_cj1w-etn21_cs1w-etn21_ethernet_units_-_construction_of_applications_operation_manual_en.pdf>`_.


.. _Proto 363:

`NDPI_PROTOCOL_ETHERSIO`
============================
Ether-S-I/O is a proprietary protocol used by Saia-Burgess's PLCs.

References: `Wireshark wiki: <https://wiki.wireshark.org/EtherSIO.md>`_.


.. _Proto 364:

`NDPI_PROTOCOL_UMAS`
============================
UMAS is a proprietary Schneider Electric protocol based on Modbus. It's used in Modicon M580 and Modicon M340 CPU-based PLCs.

References: `Unofficial article: <https://ics-cert.kaspersky.com/publications/reports/2022/09/29/the-secrets-of-schneider-electrics-umas-protocol/>`_.


.. _Proto 365:

`NDPI_PROTOCOL_BECKHOFF_ADS`
============================
Automation Device Specification is the protocol used for interfacing with Beckhoff PLCs via TwinCAT.

References: `Protocol Specs: <https://infosys.beckhoff.com/english.php?content=../content/1033/tc3_ads_intro/115847307.html>`_.


.. _Proto 366:

`NDPI_PROTOCOL_ISO9506_1_MMS`
============================
The international standard MMS (Manufacturing Message Specification) is an OSI application layer messaging protocol origionally designed for the remote control and monitoring of devices such as Remote Terminal Units (RTU), 
Programmable Logic Controllers (PLC), Numerical Controllers (NC), or Robot Controllers (RC).

References: `Paid Specs: <https://www.iso.org/ru/standard/37079.html>`_.


.. _Proto 367:

`NDPI_PROTOCOL_IEEE_C37118`
============================
IEEE Standard for Synchrophasor Data Transfer for Power Systems

References: `Paid Specs: <https://standards.ieee.org/ieee/C37.118.1/4902/>`_.


.. _Proto 368:

`NDPI_PROTOCOL_ETHERSBUS`
============================
Ether-S-Bus is a proprietary protocol used for the communication with and between PLCs manufactured by Saia-Burgess Controls Ltd.

References: `Wireshark wiki: <https://wiki.wireshark.org/EtherSBus>`_.


.. _Proto 369:

`NDPI_PROTOCOL_MONERO`
======================
Monero is a private and decentralized cryptocurrency with focus on confidentiality and security.


.. _Proto 370:

`NDPI_PROTOCOL_DCERPC`
======================
DCE/RPC is a specification for a remote procedure call mechanism that defines both APIs and an over-the-network protocol.

References: `Wireshark wiki: <https://wiki.wireshark.org/DCE/RPC>`_.


.. _Proto 371:

`NDPI_PROTOCOL_PROFINET_IO`
======================
PROFINET/IO is a field bus protocol based on connectionless DCE/RPC.

References: `Protocol Specs: <https://www.profibus.com/download/profinet-specification>`_.


.. _Proto 372:

`NDPI_PROTOCOL_HISLIP`
======================
High-Speed LAN Instrument Protocol (HiSLIP) is a protocol for remote instrument control of LAN-based test and measurement instruments.

References: `Protocol Specs: <https://www.ivifoundation.org/downloads/Protocol%20Specifications/IVI-6.1_HiSLIP-2.0-2020-04-23.pdf>`_.
