#!/bin/bash
# read configuration data
. configuration.sh

# compute sha1 hash
openssl sha1 -binary $DATA > $DATA.sha1  

#sign with DNIe signing certificate
pkcs15-crypt --key $CertFirmaDigitalID --sign --pkcs1 --sha-1 --input $DATA.sha1 $PIN --output $DATA.sig
