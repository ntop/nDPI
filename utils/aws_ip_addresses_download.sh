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
TMP=$(mktemp)
LIST_DIR=$(mktemp -d)
ORIGIN=https://ip-ranges.amazonaws.com/ip-ranges.json

cleanup() {
    rm -f "${TMP}"
    rm -rf "${LIST_DIR}"
}
trap cleanup EXIT

echo "(1) Downloading file..."
http_response=$(curl --proto '=https' --proto-redir '=https' -L -s -o "${TMP}" -w "%{http_code}" "${ORIGIN}")
check_http_response "${http_response}"
is_file_empty "${TMP}"

echo "(2) Processing IP addresses..."
./aws_ip_addresses.py "${TMP}" "${LIST_DIR}"

./ipaddr2list.py "${LIST_DIR}/API_GATEWAY" NDPI_PROTOCOL_AWS_API_GATEWAY "${LIST_DIR}/API_GATEWAY6" > "${DEST_API_GATEWAY}"
is_file_empty "${DEST_API_GATEWAY}"
./ipaddr2list.py "${LIST_DIR}/KINESIS_VIDEO_STREAMS" NDPI_PROTOCOL_AWS_KINESIS "${LIST_DIR}/KINESIS_VIDEO_STREAMS6" > "${DEST_KINESIS}"
is_file_empty "${DEST_KINESIS}"
./ipaddr2list.py "${LIST_DIR}/EC2" NDPI_PROTOCOL_AWS_EC2 "${LIST_DIR}/EC26" > "${DEST_EC2}"
is_file_empty "${DEST_EC2}"
./ipaddr2list.py "${LIST_DIR}/S3" NDPI_PROTOCOL_AWS_S3 "${LIST_DIR}/S36" > "${DEST_S3}"
is_file_empty "${DEST_S3}"
./ipaddr2list.py "${LIST_DIR}/CLOUDFRONT" NDPI_PROTOCOL_AWS_CLOUDFRONT "${LIST_DIR}/CLOUDFRONT6" > "${DEST_CLOUDFRONT}"
is_file_empty "${DEST_CLOUDFRONT}"
./ipaddr2list.py "${LIST_DIR}/DYNAMODB" NDPI_PROTOCOL_AWS_DYNAMODB "${LIST_DIR}/DYNAMODB6" > "${DEST_DYNAMODB}"
is_file_empty "${DEST_DYNAMODB}"
./ipaddr2list.py "${LIST_DIR}/AMAZON_AWS" NDPI_PROTOCOL_AMAZON_AWS "${LIST_DIR}/AMAZON_AWS6" > "${DEST}"
is_file_empty "${DEST}"

echo "(3) Amazon AWS IPs are available in ${DEST}, ${DEST_API_GATEWAY}, ${DEST_KINESIS}, ${DEST_EC2}, ${DEST_S3}, ${DEST_CLOUDFRONT}, ${DEST_DYNAMODB}"
exit 0
