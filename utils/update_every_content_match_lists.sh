#/bin/sh

cd "$(dirname "${0}")"

./aws_ip_addresses_download.sh
./azure_ip_addresses_download.sh
./cloudflare_ip_addresses_download.sh
./ethereum_ip_addresses_download.sh
./microsoft_ip_addresses_download.sh
./tor_ip_addresses_download.sh
./whatsapp_ip_addresses_download.sh
./zoom_ip_addresses_download.sh
