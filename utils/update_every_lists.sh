#/bin/sh

cd "$(dirname "${0}")" || return

RETVAL=0

./aws_ip_addresses_download.sh
RETVAL=$(( RETVAL + $? ))
./azure_ip_addresses_download.sh
RETVAL=$(( RETVAL + $? ))
./cloudflare_ip_addresses_download.sh
RETVAL=$(( RETVAL + $? ))
./ethereum_ip_addresses_download.sh
RETVAL=$(( RETVAL + $? ))
./microsoft_ip_addresses_download.sh
RETVAL=$(( RETVAL + $? ))
./tor_ip_addresses_download.sh
RETVAL=$(( RETVAL + $? ))
./whatsapp_ip_addresses_download.sh
RETVAL=$(( RETVAL + $? ))
./zoom_ip_addresses_download.sh
RETVAL=$(( RETVAL + $? ))
./google_cloud_ip_addresses_download.sh
RETVAL=$(( RETVAL + $? ))
./google_ip_addresses_download.sh
RETVAL=$(( RETVAL + $? ))
./icloud_private_relay_ip_addresses_download.sh
RETVAL=$(( RETVAL + $? ))

./asn_update.sh
RETVAL=$(( RETVAL + $? ))

test ${RETVAL} -ne 0 && printf '%s: %s\n' "${0}" "${RETVAL} scripts failed"
exit ${RETVAL}
