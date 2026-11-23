#!/usr/bin/env python3
"""Create non-overlapping AWS address lists for nDPI.

The AWS ip-ranges file can assign more than one service tag to a prefix.
nDPI loads its AWS lists in this order (see src/lib/ndpi_main.c): generic,
API Gateway, Kinesis, EC2, S3, CloudFront, and DynamoDB.  A later insertion
wins for an equal Patricia-tree node.  This utility applies that same order
to the generated lists and removes overlaps introduced by CIDR aggregation.
"""

import argparse
import ipaddress
import json
import tempfile
from collections import defaultdict
from pathlib import Path

# Ordered from lowest to highest runtime precedence.  Both EC2 tags feed the
# same nDPI protocol list, as they do in aws_ip_addresses_download.sh today.
SERVICES = (
    "AMAZON_AWS",
    "API_GATEWAY",
    "KINESIS_VIDEO_STREAMS",
    "EC2",
    "S3",
    "CLOUDFRONT",
    "DYNAMODB",
)
SPECIFIC_TAGS = {
    "API_GATEWAY": "API_GATEWAY",
    "KINESIS_VIDEO_STREAMS": "KINESIS_VIDEO_STREAMS",
    "EC2": "EC2",
    "EC2_INSTANCE_CONNECT": "EC2",
    "S3": "S3",
    "CLOUDFRONT": "CLOUDFRONT",
    "DYNAMODB": "DYNAMODB",
}


def owner(tags):
    """Return the highest-precedence nDPI list for a set of AWS tags."""
    candidates = {SPECIFIC_TAGS[tag] for tag in tags if tag in SPECIFIC_TAGS}
    return max(candidates, key=SERVICES.index) if candidates else SERVICES[0]


def subtract(networks, excluded):
    """Return networks minus every network in excluded."""
    result = list(networks)
    for blocked in excluded:
        remaining = []
        for network in result:
            if network.overlaps(blocked):
                remaining.extend(network.address_exclude(blocked)
                                 if blocked.subnet_of(network) else [])
            else:
                remaining.append(network)
        result = remaining
    return result


def build_lists(entries, key):
    """Assign, aggregate, and make each service's networks disjoint."""
    tags_by_prefix = defaultdict(set)
    for entry in entries:
        tags_by_prefix[entry[key]].add(entry["service"])
    # Patricia lookup is longest-prefix first; only equal-length matches use
    # the list insertion order as a tie-breaker.  Allocate raw AWS prefixes
    # in that order before collapsing, otherwise a broad aggregate from one
    # service could incorrectly hide a more-specific prefix from another.
    candidates = sorted(
        ((ipaddress.ip_network(prefix, strict=False), owner(tags))
         for prefix, tags in tags_by_prefix.items()),
        key=lambda item: (-item[0].prefixlen, -SERVICES.index(item[1]),
                          item[0].network_address.packed),
    )
    buckets = defaultdict(list)
    protected = []
    for network, service in candidates:
        available = subtract([network], protected)
        buckets[service].extend(available)
        protected.extend(available)
    return {service: list(ipaddress.collapse_addresses(buckets[service]))
            for service in SERVICES}


def write_lists(data, output):
    for key, suffix in (("prefixes", ""), ("ipv6_prefixes", "6")):
        lists = build_lists(data[key], "ip_prefix" if suffix == "" else "ipv6_prefix")
        for service, networks in lists.items():
            with (output / f"{service}{suffix}").open("w", encoding="ascii") as stream:
                for network in sorted(networks, key=lambda net: (net.network_address.packed, net.prefixlen)):
                    stream.write(f"{network}\n")


def validate_temp_path(path, is_directory):
    """Allow only existing paths inside the system temporary directory."""
    resolved = Path(path).resolve()
    temp_root = Path(tempfile.gettempdir()).resolve()
    try:
        resolved.relative_to(temp_root)
    except ValueError as error:
        raise ValueError(f"path must be inside {temp_root}: {path}") from error
    if is_directory and not resolved.is_dir():
        raise ValueError(f"output directory does not exist: {path}")
    if not is_directory and not resolved.is_file():
        raise ValueError(f"input file does not exist: {path}")
    return resolved


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="AWS ip-ranges.json")
    parser.add_argument("output", type=Path, help="directory for generated lists")
    args = parser.parse_args()
    source = validate_temp_path(args.source, is_directory=False)
    output = validate_temp_path(args.output, is_directory=True)
    with source.open(encoding="utf-8") as stream:
        data = json.load(stream)
    write_lists(data, output)


if __name__ == "__main__":
    main()
