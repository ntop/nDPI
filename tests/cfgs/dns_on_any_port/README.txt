dns_any_port_edge_cases.pcapng exercises the one-packet, stateless
dns.custom_port=0 heuristic. Each source address identifies one case:

192.0.2.1  Root QNAME. Expected: DNS.
192.0.2.2  Two questions; the second QNAME is compressed. Expected: DNS.
192.0.2.3  Uncompressed QNAME with the RFC 1035 maximum 255-byte wire
           representation. Expected: DNS.
192.0.2.4  Truncated QNAME and missing QTYPE/QCLASS. Expected: Unknown.
192.0.2.5  Reserved 0x40 label encoding. Expected: Unknown.
192.0.2.6  Non-DNS application data with a valid DNS-shaped prefix.
           Expected: DNS, demonstrating the unavoidable ambiguity of
           stateless arbitrary-port detection.
