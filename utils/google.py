#!/usr/bin/env python3

import json
import urllib.request
import netaddr

GOOG_URL="https://www.gstatic.com/ipranges/goog.json"
CLOUD_URL="https://www.gstatic.com/ipranges/cloud.json"

def read_url(url):
   try:
      s = urllib.request.urlopen(url).read()
      return json.loads(s)
   except urllib.error.HTTPError:
      print("Invalid HTTP response from %s" % url)
      return {}
   except json.decoder.JSONDecodeError:
      print("Could not parse HTTP response from %s" % url)
      return {}

def main():
   goog_json=read_url(GOOG_URL)
   cloud_json=read_url(CLOUD_URL)

   if goog_json and cloud_json:
#      print("{} published: {}".format(GOOG_URL,goog_json.get('creationTime')))
#      print("{} published: {}".format(CLOUD_URL,cloud_json.get('creationTime')))
      goog_cidrs = netaddr.IPSet()
      for pref in goog_json['prefixes']:
         if pref.get('ipv4Prefix'):
            goog_cidrs.add(pref.get('ipv4Prefix'))
      cloud_cidrs = netaddr.IPSet()
      for pref in cloud_json['prefixes']:
         if pref.get('ipv4Prefix'):
            cloud_cidrs.add(pref.get('ipv4Prefix'))
#      print("IP ranges for Google APIs and services default domains:")
      for i in goog_cidrs.difference(cloud_cidrs).iter_cidrs():
         print(i)

if __name__=='__main__':
   main()
