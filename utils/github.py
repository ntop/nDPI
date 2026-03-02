#!/usr/bin/env python3

import sys
import json
import urllib.request
import netaddr

GITHUB_META_URL = "https://api.github.com/meta"
#Ignore "actions" because there are lots of overlapping with Microsoft/Azure IPs. TODO: better solution?
services = ["hooks", "web", "api", "git", "github_enterprise_importer", "packages", "pages", "importer", "actions_macos", "codespaces", "copilot"]

def read_url(url):
    try:
        s = urllib.request.urlopen(url).read()
        return json.loads(s)
    except urllib.request.HTTPError:
        print("Invalid HTTP response from %s" % url)
        return {}
    except json.decoder.JSONDecodeError:
        print("Could not parse HTTP response from %s" % url)
        return {}


def main():
    ip_version = int(sys.argv[1])
    github_meta = read_url(GITHUB_META_URL)

    github_cidr = netaddr.IPSet()
    for service in services:
        for ipnet in github_meta[service]:
            if netaddr.IPNetwork(ipnet).version == ip_version:
                if ipnet not in github_cidr:
                    github_cidr.add(ipnet)

    for cidr in github_cidr.iter_cidrs():
        print(cidr)


if __name__ == '__main__':
    main()
