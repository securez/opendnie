#!/bin/bash
#load configuration file
. configuration.sh

echo "Verifying User Authentication Certificate"
openssl verify -CAfile cacerts.pem userAuthCertificate.pem
echo "Verifying Signature Certificate"
openssl verify -CAfile cacerts.pem userSignCertificate.pem

