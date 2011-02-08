#!/bin/bash
#load configuration file
. configuration.sh

#verify 
openssl verify -CAfile cacerts.pem userAuthCertificate.pem
openssl verify -CAfile cacerts.pem userSignCertificate.pem

