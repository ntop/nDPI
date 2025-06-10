FAQ
===

From `blog post <https://www.ntop.org/ndpi/ndpi-internals-and-frequent-questions/>`_

**Q**: How does nDPI implement protocol detection?  
**A**: nDPI includes a list of protocol dissectors (364 as of today) that can dissect protocols such as WhatsApp or TLS. As soon as a new flow is submitted to nDPI, the library applies in sequence dissectors that can potentially match the protocols (i.e., Telnet is a TCP-based protocol, and it will not be considered for UDP flows).  
nDPI starts with the dissector most likely to match based on the port number (e.g., TCP/22 starts with SSH). Dissection completes when a match is found or if none match, in which case the flow is labeled as Unknown.

**Q**: What is the nDPI release cycle?  
**A**: A release is made approximately every 6–8 months. Fixes and improvements happen daily (see the nDPI code on GitHub).

**Q**: Is nDPI running on all popular platforms?  
**A**: Yes, it runs on Linux, macOS, Windows… and even on less common platforms like IBM mainframes. It supports ARM, Intel, RISC… architectures.

**Q**: How many packets does nDPI need to perform detection?  
**A**: It depends on the protocol. For UDP-based protocols like DNS, one packet may suffice. More complex protocols like TLS require about 10 packets.  
If no protocol is detected after 15–20 packets, the protocol is labeled as Unknown.

**Q**: Is nDPI detection only based on protocol dissectors?  
**A**: No. While payload inspection is the primary method, nDPI can also use IP addresses, ports, TLS certificates, etc., as protocol signatures.  
After detection, nDPI reports whether matching was based on payload or other means (e.g., IP address).

**Q**: Does nDPI contain a list of known IP addresses?  
**A**: Yes, it includes known IP lists, such as those provided by Microsoft or Meta, to identify known services.

**Q**: Can I extend nDPI by defining new protocols with a configuration file?  
**A**: Yes. See this `example file <https://github.com/ntop/nDPI/blob/dev/example/protos.txt>`_ for defining new protocols.

**Q**: Can nDPI detect VPNs?  
**A**: Yes, it can detect VPNs like Tailscale, WireGuard, OpenVPN, FortiClient, and in-app VPNs such as UltraSurf or OperaVPN.

**Q**: Can nDPI detect malware and viruses?  
**A**: It can detect anomalous behavior caused by malware. However, nDPI is not signature-based, so it does not include specific malware signatures.  
This is because `signature-based tools <https://en.wikipedia.org/wiki/Intrusion_detection_system>`_ are limited and resource-intensive, whereas nDPI is designed for high-speed (100 Gbit+) networks.

**Q**: Can nDPI detect security issues?  
**A**: Yes, using a technique called `flow risk <https://github.com/ntop/nDPI/blob/dev/doc/flow_risks.rst>`_. It can detect 50+ threats (e.g., a host communicating with a malware host).

**Q**: Can nDPI block traffic?  
**A**: No. nDPI is a passive traffic analysis library. You can build applications on top of it to block or shape traffic (e.g., ntopng Edge, nProbe IPS, nProbe Cento).

