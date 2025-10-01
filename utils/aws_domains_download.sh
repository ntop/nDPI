#!/usr/bin/env bash

set -e

cd "$(dirname "${0}")" || exit 1

DEST_COGNITO=../src/lib/inc_generated/ndpi_domains_aws_cognito_match.c.inc
DEST_API_GATEWAY=../src/lib/inc_generated/ndpi_domains_aws_api_gateway_match.c.inc
DEST_EC2=../src/lib/inc_generated/ndpi_domains_aws_ec2_match.c.inc
DEST_EMR=../src/lib/inc_generated/ndpi_domains_aws_emr_match.c.inc
DEST_S3=../src/lib/inc_generated/ndpi_domains_aws_s3_match.c.inc
DEST_CLOUDFRONT=../src/lib/inc_generated/ndpi_domains_aws_cloudfront_match.c.inc
TMP=/tmp/suffix.txt
LIST=/tmp/aws_domains.list
ORIGIN="https://publicsuffix.org/list/public_suffix_list.dat"

echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -L -s -o $TMP -w "%{http_code}" ${ORIGIN})
if [ $http_response != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    exit 1
fi

echo "(2) Processing domains..."

#COGNITO
grep "cognito" $TMP | sort -u | uniq > $LIST
./domains2list.py $LIST "AWS_Cognito" NDPI_PROTOCOL_AWS_COGNITO NDPI_PROTOCOL_CATEGORY_CLOUD NDPI_PROTOCOL_ACCEPTABLE > $DEST_COGNITO

#API GATEWAY
grep "execute-api" $TMP | sort -u | uniq > $LIST
./domains2list.py $LIST "AWS_API_Gateway" NDPI_PROTOCOL_AWS_API_GATEWAY NDPI_PROTOCOL_CATEGORY_CLOUD NDPI_PROTOCOL_ACCEPTABLE > $DEST_API_GATEWAY

#EC2
grep "compute" $TMP | grep "amazonaws" | sort -u | uniq > $LIST
./domains2list.py $LIST "AWS_EC2" NDPI_PROTOCOL_AWS_EC2 NDPI_PROTOCOL_CATEGORY_CLOUD NDPI_PROTOCOL_ACCEPTABLE > $DEST_EC2

#EMR
grep "emr" $TMP | grep "amazonaws" | sort -u | uniq > $LIST
./domains2list.py $LIST "AWS_EMR" NDPI_PROTOCOL_AWS_EMR NDPI_PROTOCOL_CATEGORY_CLOUD NDPI_PROTOCOL_ACCEPTABLE > $DEST_EMR

#S3
grep "s3" $TMP | grep "amazonaws" | sort -u | uniq > $LIST
./domains2list.py $LIST "AWS_S3" NDPI_PROTOCOL_AWS_S3 NDPI_PROTOCOL_CATEGORY_CLOUD NDPI_PROTOCOL_ACCEPTABLE > $DEST_S3

#CLOUDFRONT
grep "cloudfront" $TMP | sort -u | uniq > $LIST
./domains2list.py $LIST "AWS_Cloudfront" NDPI_PROTOCOL_AWS_CLOUDFRONT NDPI_PROTOCOL_CATEGORY_CLOUD NDPI_PROTOCOL_ACCEPTABLE > $DEST_CLOUDFRONT

rm -f $TMP $LIST

echo "(3) AWS domains are available in $DEST_COGNITO, $DEST_API_GATEWAY, $DEST_EC2, $DEST_EMR, $DEST_S3, $DEST_CLOUDFRONT"
exit 0
