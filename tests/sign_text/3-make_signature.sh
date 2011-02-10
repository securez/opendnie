#!/bin/bash
# read configuration data
. configuration.sh

echo -n "Computing hash..."
openssl sha1 -binary $DATA > $DATA.sha1  
echo "Done"

echo "Signing with DNIe authentication certificate"
pkcs15-crypt --key $CertAuthenticationID --sign --pkcs1 --sha-1 --input $DATA.sha1 $PIN --output $DATA.auth.sig
echo "Signing with DNIe signature certificate"
pkcs15-crypt --key $CertFirmaDigitalID --sign --pkcs1 --sha-1 --input $DATA.sha1 $PIN --output $DATA.sign.sig
