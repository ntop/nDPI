#!/bin/bash


# Included:
#  * top domains from https://s3-us-west-1.amazonaws.com/umbrella-static/index.html (first 100k)
#  * domains from ./lists/100_malware.list (first 10k)
#  * ip4 and ip6 from lists/124_bots.list (without the netmask): to have some examples of literal ip addresses


rm -rf tmp
mkdir -p tmp
cd tmp;

curl -o top-1m.csv.zip s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip
unzip top-1m.csv.zip
awk -F',' 'NR < 100000 { f="site_" NR ".txt"; gsub(/\r|\n/, "", $2); printf "%s", $2 > f; close(f) }' ./top-1m.csv
rm -f top-1m*

awk 'NR < 10000 {sub(/\r$/, ""); f="malware_" NR ".txt"; printf "%s", $0 > f; close(f)}' ../../../lists/100_malware.list
awk 'NR >= 5 {sub(/\r$/, ""); sub(/\/.*/, ""); f="ip_" NR ".txt"; printf "%s", $0 > f; close(f)}' ../../../lists/124_bots.list

find . -name '*.txt' -print | zip -9 ../fuzz_match_custom_category_corpus.zip -@

cd ..
rm -rf tmp
