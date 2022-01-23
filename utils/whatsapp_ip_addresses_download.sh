#!/bin/sh

cd "$(dirname "${0}")"

DEST=../src/lib/ndpi_whatsapp_match.c.inc
TMP=/tmp/wa.zip
LIST=/tmp/wa.list
# https://developers.facebook.com/docs/whatsapp/guides/network-requirements/
ORIGIN="https://scontent.fmxp6-1.fna.fbcdn.net/v/t39.8562-6/218944277_794653217800107_785885630662402277_n.zip?_nc_cat=102&ccb=1-5&_nc_sid=ae5e01&_nc_ohc=CxWH4uR6uPsAX-Yga3M&_nc_ht=scontent.fmxp6-1.fna&oh=00_AT9gC0NiHKwmgoBdNX9jbVbxtciJ8HzeGdOLj35n3kWeUw&oe=6201B6A9"


echo "(1) Downloading file..."
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
if [ $http_response != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    return
fi

echo "(2) Processing IP addresses..."
zcat $TMP > $LIST
./ipaddr2list.py $LIST NDPI_PROTOCOL_WHATSAPP > $DEST
rm -f $TMP $LIST

echo "(3) WhatsApp IPs are available in $DEST"



