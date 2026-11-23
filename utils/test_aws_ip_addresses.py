#!/usr/bin/env python3
import ipaddress
import sys
import unittest

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import aws_ip_addresses


class AwsIpAddressesTest(unittest.TestCase):
    def test_lists_are_disjoint_and_follow_trie_precedence(self):
        entries = [
            {"ip_prefix": "10.0.0.0/24", "service": "AMAZON"},
            {"ip_prefix": "10.0.0.0/24", "service": "EC2"},
            {"ip_prefix": "10.0.1.0/24", "service": "AMAZON"},
            {"ip_prefix": "10.0.1.64/26", "service": "EC2"},
            {"ip_prefix": "10.0.2.0/24", "service": "API_GATEWAY"},
            {"ip_prefix": "10.0.2.0/24", "service": "S3"},
        ]
        lists = aws_ip_addresses.build_lists(entries, "ip_prefix")

        all_networks = [(service, network)
                        for service, networks in lists.items()
                        for network in networks]
        for index, (service, network) in enumerate(all_networks):
            for other_service, other_network in all_networks[index + 1:]:
                self.assertFalse(
                    network.overlaps(other_network),
                    f"{service} {network} overlaps {other_service} {other_network}",
                )

        self.assertEqual(
            lists["EC2"],
            [ipaddress.ip_network("10.0.0.0/24"),
             ipaddress.ip_network("10.0.1.64/26")],
        )
        self.assertEqual(lists["S3"], [ipaddress.ip_network("10.0.2.0/24")])
        self.assertEqual(lists["AMAZON_AWS"], [
            ipaddress.ip_network("10.0.1.0/26"),
            ipaddress.ip_network("10.0.1.128/25"),
        ])

    def test_ec2_instance_connect_uses_ec2_list(self):
        lists = aws_ip_addresses.build_lists([
            {"ip_prefix": "192.0.2.0/24", "service": "EC2_INSTANCE_CONNECT"},
        ], "ip_prefix")
        self.assertEqual(lists["EC2"], [ipaddress.ip_network("192.0.2.0/24")])
        self.assertFalse(lists["AMAZON_AWS"])

    def test_ipv6_is_supported(self):
        lists = aws_ip_addresses.build_lists([
            {"ipv6_prefix": "2001:db8::/32", "service": "AMAZON"},
            {"ipv6_prefix": "2001:db8::/48", "service": "CLOUDFRONT"},
        ], "ipv6_prefix")
        self.assertEqual(lists["CLOUDFRONT"], [ipaddress.ip_network("2001:db8::/48")])
        generic = lists["AMAZON_AWS"]
        self.assertTrue(any(ipaddress.ip_address("2001:db8:1::1") in network
                            for network in generic))
        self.assertTrue(any(ipaddress.ip_address("2001:db8:ffff::1") in network
                            for network in generic))
        self.assertFalse(any(network.overlaps(lists["CLOUDFRONT"][0])
                             for network in generic))

    def test_cli_paths_are_limited_to_temporary_workspace(self):
        with self.assertRaises(ValueError):
            aws_ip_addresses.validate_temp_path("/etc/passwd", is_directory=False)
        with self.assertRaises(ValueError):
            aws_ip_addresses.validate_temp_path("/tmp/does-not-exist", is_directory=True)


if __name__ == "__main__":
    unittest.main()
