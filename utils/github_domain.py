#!/usr/bin/env python3

import sys
import json
import urllib.request

GITHUB_META_URL = "https://api.github.com/meta"

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

def get_domains(github_domains, service):
    website_domains = set(github_domains["website"])

    if service == "website":
        return website_domains
    
    return set(github_domains[service]) - website_domains



def main():
    service = sys.argv[1]
    github_meta = read_url(GITHUB_META_URL)

    service_domains = get_domains(github_meta["domains"], service)

    for domain in service_domains:
        print(domain)


if __name__ == '__main__':
    main()
