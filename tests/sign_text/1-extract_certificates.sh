#!/bin/bash
#load id's and pin
. configuration.sh

echo "Extract user certificate for authentication"
pkcs15-tool -v --verify-pin $PIN --read-certificate $CertAuthenticationID --output userAuthCertificate.pem 

echo "Extract user certificate for signing"
pkcs15-tool -v --verify-pin $PIN --read-certificate $CertFirmaDigitalID --output userSignCertificate.pem 

echo "Extract CA certificate"
pkcs15-tool -v --verify-pin $PIN --read-certificate $CertCAIntermediaDGP --output cardCACertificate.pem

echo "Generate cacerts.pem CA certstore"
cat ACRAIZ-SHA1.pem ACDNIE001-SHA1.pem ACDNIE002-SHA1.pem ACDNIE003-SHA1.pem cardCACertificate.pem > cacerts.pem
