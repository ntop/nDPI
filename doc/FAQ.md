
# FAQ

From [blog post](https://www.ntop.org/ndpi/ndpi-internals-and-frequent-questions/)

**Q**: How nDPI implements protocol detection?\
**A**: nDPI includes a list of protocol dissectors (364 as of today) that are able to dissect protocols such as WhatsApp or TLS. As soon as a new flow is submitted to nDPI, the library applies in sequence dissectors that can potentially match the protocols (i.e. telnet is a TCP-based protocol, and it will not be considered for UDP flows). We start from the dissector that can most probably match using the port number. This means for traffic on TCP/22 nDPI will start with the SSH dissectors and if not matching continue with the others. Dissection completes as soon as a protocol matches or when none of them matched and in this case the flow will be labelled as Unknown.

**Q**: What is the nDPI release cycle?\
**A**: We cut a release approximately every 6-8 months, fixes and improvements are on a daily basis (check the nDPI code on GitHub).

**Q**: Is nDPI running on all popular platforms?\
**A**: Yes it runs on Linux, macOS, Windows… and also on not-so-popular ones such as IBM mainframes. We support ARM, Intel, RISC… architectures.

**Q**: How many packets does nDPI need in order to implement detection?\
**A**: It depends on the protocol. For UDP-based protocols such as DNS one packet is enough, for more complex protocols such as TLS about 10 packets. For sure if after 15-20 packets nDPI has not detected the application protocol, then the protocol is labelled as Unknown.

**Q**: Is nDPI detection only based on protocol dissectors?\
**A**: No, payload inspection is the main technique, but nDPI can also use IP address, ports, TLS certificates, etc., as signatures for protocols. In this case, after detection is complete, nDPI will report if the match was performed on payload inspection or other means (e.g. IP address).

**Q**: Does nDPI contain list of known IP addresses?\
**A**: Yes it includes lists of well known IPs such as those provided by Microsoft of Meta for identifying known service.

**Q**: Can I extend nDPI by defining new protocols with a configuration file?\
**A**: Yes you can. See this [file](https://github.com/ntop/nDPI/blob/dev/example/protos.txt) as an example for defining new protocols.

**Q**: Is nDPI able to detect VPNs?\
**A**: Yes it can detect VPNS such as Tailscale, WireGuard, OpenVPN, FortiClient.. and also in-app VPNs such as UltraSurf or OperaVPN.

**Q**: Is nDPI able to detect malware and viruses?\
**A**: It can detect anomalous behaviour that can be caused by a malware, but nDPI is not a signature-based tool, so it does not include signatures for malware A or B. This is because [signature-based tools](https://en.wikipedia.org/wiki/Intrusion_detection_system) have various limitations and resource intensive, whereas nDPI has been designed to be used also in high-speed (100 Gbit+) networks.

**Q**: Is nDPI able to detect security issues?\
**A**: Yes it can by means of a technique called [flow risk](https://github.com/ntop/nDPI/blob/dev/doc/flow_risks.rst). It can identify 50+ threats (e.g. a host that is talking with a malware host).

**Q**: Is nDPI able to block traffic?\
**A**: No, nDPI is a passive traffic analysis library that does not manipulate packets. You can create applications on top of it for policing (i.e. blocking or shaping) traffic. Examples of such applications are ntopng Edge, nProbe IPS and nProbe Cento.
