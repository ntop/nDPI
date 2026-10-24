Regression guard for the case where the TLS "obfuscated plain" heuristic and the OpenVPN
opcode heuristic are both enabled, but the OpenVPN heuristic does NOT confirm in time
(num_messages is raised to 40, more than these flows carry): the TLS heuristic's result
must not be lost. The expected output is what nDPI produced before the arbitration change.

pcap/nordvpn.pcap, pcap/openvpn_obfuscated.pcapng : symlinks to the bundled captures.
pcap/nord995_first15.pcap : the first 15 packets of the nordvpn.pcap TCP/995 flow (a real
    prefix of the capture; the flow simply ends right after the TLS heuristic fires).
pcap/nord995_corrupted.pcap : SYNTHETIC. The TCP/995 flow of nordvpn.pcap
    with the OpenVPN opcode byte (payload[2]) of every payload packet after #15 overwritten
    with varying values (checksums recomputed), so the OpenVPN heuristic is excluded after
    the TLS heuristic has fired. Used only to test the deferral fallback, not as detection
    evidence.
