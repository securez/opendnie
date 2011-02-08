#!/bin/bash
# load configuration
. configuration.sh

#extract public key from user certificate
openssl x509 -in userSignCertificate.pem -pubkey -noout > userSignPublicKey.pem

#decrypt and check signature against original data
openssl dgst -sha1 -d -verify userSignPublicKey.pem -signature $DATA.sig $DATA
