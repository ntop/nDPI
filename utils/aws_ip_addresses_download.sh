#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_amazon_aws_match.c.inc
DEST_API_GATEWAY=../src/lib/inc_generated/ndpi_amazon_aws_api_gateway_match.c.inc
DEST_KINESIS=../src/lib/inc_generated/ndpi_amazon_aws_kinesis_match.c.inc
DEST_EC2=../src/lib/inc_generated/ndpi_amazon_aws_ec2_match.c.inc
DEST_S3=../src/lib/inc_generated/ndpi_amazon_aws_s3_match.c.inc
DEST_CLOUDFRONT=../src/lib/inc_generated/ndpi_amazon_aws_cloudfront_match.c.inc
DEST_DYNAMODB=../src/lib/inc_generated/ndpi_amazon_aws_dynamodb_match.c.inc
TMP=/tmp/aws.json
LIST=/tmp/aws.list
LIST6=/tmp/aws.list6
LIST_MERGED=/tmp/aws.list_m
LIST6_MERGED=/tmp/aws.list6_m
ORIGIN=https://ip-ranges.amazonaws.com/ip-ranges.json


echo "(1) Downloading file..."
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${TMP}"

echo "(2) Processing IP addresses..."

#API_GATEWAY
jq -r '.prefixes[] | select(.service=="API_GATEWAY") | .ip_prefix' $TMP > $LIST
./mergeipaddrlist.py $LIST > $LIST_MERGED
jq -r '.ipv6_prefixes[] | select(.service=="API_GATEWAY") | .ipv6_prefix' $TMP > $LIST6
./mergeipaddrlist.py $LIST6 > $LIST6_MERGED
./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_AWS_API_GATEWAY $LIST6_MERGED > $DEST_API_GATEWAY
is_file_empty "${DEST_API_GATEWAY}"

#KINESIS
jq -r '.prefixes[] | select(.service=="KINESIS_VIDEO_STREAMS") | .ip_prefix' $TMP > $LIST
./mergeipaddrlist.py $LIST > $LIST_MERGED
jq -r '.ipv6_prefixes[] | select(.service=="KINESIS_VIDEO_STREAMS") | .ipv6_prefix' $TMP > $LIST6
./mergeipaddrlist.py $LIST6 > $LIST6_MERGED
./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_AWS_KINESIS $LIST6_MERGED > $DEST_KINESIS
is_file_empty "${DEST_KINESIS}"

#EC2
jq -r '.prefixes[] | select(.service=="EC2_INSTANCE_CONNECT" or .service=="EC2") | .ip_prefix' $TMP > $LIST
./mergeipaddrlist.py $LIST > $LIST_MERGED
jq -r '.ipv6_prefixes[] | select(.service=="EC2_INSTANCE_CONNECT" or .service=="EC2") | .ipv6_prefix' $TMP > $LIST6
./mergeipaddrlist.py $LIST6 > $LIST6_MERGED
./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_AWS_EC2 $LIST6_MERGED > $DEST_EC2
is_file_empty "${DEST_EC2}"

#S3
jq -r '.prefixes[] | select(.service=="S3") | .ip_prefix' $TMP > $LIST
./mergeipaddrlist.py $LIST > $LIST_MERGED
jq -r '.ipv6_prefixes[] | select(.service=="S3") | .ipv6_prefix' $TMP > $LIST6
./mergeipaddrlist.py $LIST6 > $LIST6_MERGED
./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_AWS_S3 $LIST6_MERGED > $DEST_S3
is_file_empty "${DEST_S3}"

#CLOUDFRONT
jq -r '.prefixes[] | select(.service=="CLOUDFRONT") | .ip_prefix' $TMP > $LIST
./mergeipaddrlist.py $LIST > $LIST_MERGED
jq -r '.ipv6_prefixes[] | select(.service=="CLOUDFRONT") | .ipv6_prefix' $TMP > $LIST6
./mergeipaddrlist.py $LIST6 > $LIST6_MERGED
./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_AWS_CLOUDFRONT $LIST6_MERGED > $DEST_CLOUDFRONT
is_file_empty "${DEST_CLOUDFRONT}"

#DYNAMODB
jq -r '.prefixes[] | select(.service=="DYNAMODB") | .ip_prefix' $TMP > $LIST
./mergeipaddrlist.py $LIST > $LIST_MERGED
jq -r '.ipv6_prefixes[] | select(.service=="DYNAMODB") | .ipv6_prefix' $TMP > $LIST6
./mergeipaddrlist.py $LIST6 > $LIST6_MERGED
./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_AWS_DYNAMODB $LIST6_MERGED > $DEST_DYNAMODB
is_file_empty "${DEST_DYNAMODB}"

#Generic
jq -r '.prefixes[] | select(.service | IN("API_GATEWAY","KINESIS_VIDEO_STREAMS","EC2_INSTANCE_CONNECT","EC2","S3","CLOUDFRONT","DYNAMODB") | not) | .ip_prefix' $TMP > $LIST
./mergeipaddrlist.py $LIST > $LIST_MERGED
jq -r '.ipv6_prefixes[] | select(.service | IN("API_GATEWAY","KINESIS_VIDEO_STREAMS","EC2_INSTANCE_CONNECT","EC2","S3","CLOUDFRONT","DYNAMODB") | not) | .ipv6_prefix' $TMP > $LIST6
./mergeipaddrlist.py $LIST6 > $LIST6_MERGED
./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_AMAZON_AWS $LIST6_MERGED > $DEST
is_file_empty "${DEST}"

rm -f ${TMP} ${LIST} ${LIST6} ${LIST_MERGED} ${LIST6_MERGED}

echo "(3) Amazon AWS IPs are available in $DEST, $DEST_API_GATEWAY, $DEST_KINESIS, $DEST_EC2, $DEST_S3, $DEST_CLOUDFRONT, $DEST_DYNAMODB"
exit 0
