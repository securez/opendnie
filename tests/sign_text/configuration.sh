#!/bin/bash

#use pkcs15-tool -c to extract certificate id's from DNIe
CertAuthenticationID=4130364236323435383832383133323230313031313131313634303236
CertFirmaDigitalID=4630364236323435383832383133323230313031313131313634303236
CertCAIntermediaDGP=5330364236323435383832383133323230313031313131313634303236
#
# Set up properly or leave it empty
# PIN="--pin User_Pin"
PIN=""

#file to be signed
DATA=lorenipsum.txt
