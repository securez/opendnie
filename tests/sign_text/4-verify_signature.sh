#!/bin/bash
# load configuration
. configuration.sh

echo -n "Extract public key from authentication certificate..."
openssl x509 -in userAuthCertificate.pem -pubkey -noout > userAuthPublicKey.pem
echo " Done."
echo -n "Extract public key from signature certificate..."
openssl x509 -in userSignCertificate.pem -pubkey -noout > userSignPublicKey.pem
echo " Done."
echo -n "Verify signature (auth): "
openssl dgst -sha1 -verify userAuthPublicKey.pem -signature $DATA.auth.sig $DATA
echo -n "Verify signature (sign): "
openssl dgst -sha1 -verify userSignPublicKey.pem -signature $DATA.sign.sig $DATA
