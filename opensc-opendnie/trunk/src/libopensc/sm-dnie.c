/*
 * sm-dnie.c: Virtual channel for transparent sending of
 * APDU's throught secure messaging for Spanish DNIe card
 * 
 * Copyright (C) 2010 Juan Antonio Martinez <jonsito@terra.es>
 *
 * This work is derived from many sources at OpenSC Project site,
 * (see references) and the information made public by Spanish 
 * Direccion General de la Policia y de la Guardia Civil
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define __SM_DNIE_C__

#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "opensc.h"
#include "cardctl.h"
#include "internal.h"
#ifndef ENABLE_OPENSSL
#error "this module needs to be compiled with OpenSSL support enabled"
#endif
#include <openssl/x509.h>
#include "dnie.h"

/********************* Keys and certificates as published by DGP ********/

static const u8 ifd_modulus [] = {
   0xdb, 0x2c, 0xb4, 0x1e, 0x11, 0x2b, 0xac, 0xfa, 0x2b, 0xd7, 0xc3, 0xd3,
   0xd7, 0x96, 0x7e, 0x84, 0xfb, 0x94, 0x34, 0xfc, 0x26, 0x1f, 0x9d, 0x09,
   0x0a, 0x89, 0x83, 0x94, 0x7d, 0xaf, 0x84, 0x88, 0xd3, 0xdf, 0x8f, 0xbd,
   0xcc, 0x1f, 0x92, 0x49, 0x35, 0x85, 0xe1, 0x34, 0xa1, 0xb4, 0x2d, 0xe5,
   0x19, 0xf4, 0x63, 0x24, 0x4d, 0x7e, 0xd3, 0x84, 0xe2, 0x6d, 0x51, 0x6c,
   0xc7, 0xa4, 0xff, 0x78, 0x95, 0xb1, 0x99, 0x21, 0x40, 0x04, 0x3a, 0xac,
   0xad, 0xfc, 0x12, 0xe8, 0x56, 0xb2, 0x02, 0x34, 0x6a, 0xf8, 0x22, 0x6b,
   0x1a, 0x88, 0x21, 0x37, 0xdc, 0x3c, 0x5a, 0x57, 0xf0, 0xd2, 0x81, 0x5c,
   0x1f, 0xcd, 0x4b, 0xb4, 0x6f, 0xa9, 0x15, 0x7f, 0xdf, 0xfd, 0x79, 0xec,
   0x3a, 0x10, 0xa8, 0x24, 0xcc, 0xc1, 0xeb, 0x3c, 0xe0, 0xb6, 0xb4, 0x39,
   0x6a, 0xe2, 0x36, 0x59, 0x00, 0x16, 0xba, 0x69
};

static const u8 ifd_public_exponent [] = {
   0x01, 0x00, 0x01
};

static const u8 ifd_private_exponent [] = {
   0x18, 0xb4, 0x4a, 0x3d, 0x15, 0x5c, 0x61, 0xeb, 0xf4, 0xe3, 0x26, 0x1c,
   0x8b, 0xb1, 0x57, 0xe3, 0x6f, 0x63, 0xfe, 0x30, 0xe9, 0xaf, 0x28, 0x89,
   0x2b, 0x59, 0xe2, 0xad, 0xeb, 0x18, 0xcc, 0x8c, 0x8b, 0xad, 0x28, 0x4b,
   0x91, 0x65, 0x81, 0x9c, 0xa4, 0xde, 0xc9, 0x4a, 0xa0, 0x6b, 0x69, 0xbc,
   0xe8, 0x17, 0x06, 0xd1, 0xc1, 0xb6, 0x68, 0xeb, 0x12, 0x86, 0x95, 0xe5,
   0xf7, 0xfe, 0xde, 0x18, 0xa9, 0x08, 0xa3, 0x01, 0x1a, 0x64, 0x6a, 0x48,
   0x1d, 0x3e, 0xa7, 0x1d, 0x8a, 0x38, 0x7d, 0x47, 0x46, 0x09, 0xbd, 0x57,
   0xa8, 0x82, 0xb1, 0x82, 0xe0, 0x47, 0xde, 0x80, 0xe0, 0x4b, 0x42, 0x21,
   0x41, 0x6b, 0xd3, 0x9d, 0xfa, 0x1f, 0xac, 0x03, 0x00, 0x64, 0x19, 0x62,
   0xad, 0xb1, 0x09, 0xe2, 0x8c, 0xaf, 0x50, 0x06, 0x1b, 0x68, 0xc9, 0xca,
   0xbd, 0x9b, 0x00, 0x31, 0x3c, 0x0f, 0x46, 0xed
};

// Intermediate CA certificate in CVC format (Card verifiable certificate)
static const u8 C_CV_CA_CS_AUT_cert [] = {
  0x7f, 0x21, 0x81, 0xce, 0x5f, 0x37, 0x81, 0x80, 0x3c, 0xba, 0xdc, 0x36,
  0x84, 0xbe, 0xf3, 0x20, 0x41, 0xad, 0x15, 0x50, 0x89, 0x25, 0x8d, 0xfd,
  0x20, 0xc6, 0x91, 0x15, 0xd7, 0x2f, 0x9c, 0x38, 0xaa, 0x99, 0xad, 0x6c,
  0x1a, 0xed, 0xfa, 0xb2, 0xbf, 0xac, 0x90, 0x92, 0xfc, 0x70, 0xcc, 0xc0,
  0x0c, 0xaf, 0x48, 0x2a, 0x4b, 0xe3, 0x1a, 0xfd, 0xbd, 0x3c, 0xbc, 0x8c,
  0x83, 0x82, 0xcf, 0x06, 0xbc, 0x07, 0x19, 0xba, 0xab, 0xb5, 0x6b, 0x6e,
  0xc8, 0x07, 0x60, 0xa4, 0xa9, 0x3f, 0xa2, 0xd7, 0xc3, 0x47, 0xf3, 0x44,
  0x27, 0xf9, 0xff, 0x5c, 0x8d, 0xe6, 0xd6, 0x5d, 0xac, 0x95, 0xf2, 0xf1,
  0x9d, 0xac, 0x00, 0x53, 0xdf, 0x11, 0xa5, 0x07, 0xfb, 0x62, 0x5e, 0xeb,
  0x8d, 0xa4, 0xc0, 0x29, 0x9e, 0x4a, 0x21, 0x12, 0xab, 0x70, 0x47, 0x58,
  0x8b, 0x8d, 0x6d, 0xa7, 0x59, 0x22, 0x14, 0xf2, 0xdb, 0xa1, 0x40, 0xc7,
  0xd1, 0x22, 0x57, 0x9b, 0x5f, 0x38, 0x3d, 0x22, 0x53, 0xc8, 0xb9, 0xcb,
  0x5b, 0xc3, 0x54, 0x3a, 0x55, 0x66, 0x0b, 0xda, 0x80, 0x94, 0x6a, 0xfb,
  0x05, 0x25, 0xe8, 0xe5, 0x58, 0x6b, 0x4e, 0x63, 0xe8, 0x92, 0x41, 0x49,
  0x78, 0x36, 0xd8, 0xd3, 0xab, 0x08, 0x8c, 0xd4, 0x4c, 0x21, 0x4d, 0x6a,
  0xc8, 0x56, 0xe2, 0xa0, 0x07, 0xf4, 0x4f, 0x83, 0x74, 0x33, 0x37, 0x37,
  0x1a, 0xdd, 0x8e, 0x03, 0x00, 0x01, 0x00, 0x01, 0x42, 0x08, 0x65, 0x73,
  0x52, 0x44, 0x49, 0x60, 0x00, 0x06
};

// Terminal (IFD) certificate in CVC format (PK.IFD.AUT)
static const u8 C_CV_IFDuser_AUT_cert [] = {
  0x7f, 0x21, 0x81, 0xcd, 0x5f, 0x37, 0x81, 0x80, 0x82, 0x5b, 0x69, 0xc6,
  0x45, 0x1e, 0x5f, 0x51, 0x70, 0x74, 0x38, 0x5f, 0x2f, 0x17, 0xd6, 0x4d,
  0xfe, 0x2e, 0x68, 0x56, 0x75, 0x67, 0x09, 0x4b, 0x57, 0xf3, 0xc5, 0x78,
  0xe8, 0x30, 0xe4, 0x25, 0x57, 0x2d, 0xe8, 0x28, 0xfa, 0xf4, 0xde, 0x1b,
  0x01, 0xc3, 0x94, 0xe3, 0x45, 0xc2, 0xfb, 0x06, 0x29, 0xa3, 0x93, 0x49,
  0x2f, 0x94, 0xf5, 0x70, 0xb0, 0x0b, 0x1d, 0x67, 0x77, 0x29, 0xf7, 0x55,
  0xd1, 0x07, 0x02, 0x2b, 0xb0, 0xa1, 0x16, 0xe1, 0xd7, 0xd7, 0x65, 0x9d,
  0xb5, 0xc4, 0xac, 0x0d, 0xde, 0xab, 0x07, 0xff, 0x04, 0x5f, 0x37, 0xb5,
  0xda, 0xf1, 0x73, 0x2b, 0x54, 0xea, 0xb2, 0x38, 0xa2, 0xce, 0x17, 0xc9,
  0x79, 0x41, 0x87, 0x75, 0x9c, 0xea, 0x9f, 0x92, 0xa1, 0x78, 0x05, 0xa2,
  0x7c, 0x10, 0x15, 0xec, 0x56, 0xcc, 0x7e, 0x47, 0x1a, 0x48, 0x8e, 0x6f,
  0x1b, 0x91, 0xf7, 0xaa, 0x5f, 0x38, 0x3c, 0xad, 0xfc, 0x12, 0xe8, 0x56,
  0xb2, 0x02, 0x34, 0x6a, 0xf8, 0x22, 0x6b, 0x1a, 0x88, 0x21, 0x37, 0xdc,
  0x3c, 0x5a, 0x57, 0xf0, 0xd2, 0x81, 0x5c, 0x1f, 0xcd, 0x4b, 0xb4, 0x6f,
  0xa9, 0x15, 0x7f, 0xdf, 0xfd, 0x79, 0xec, 0x3a, 0x10, 0xa8, 0x24, 0xcc,
  0xc1, 0xeb, 0x3c, 0xe0, 0xb6, 0xb4, 0x39, 0x6a, 0xe2, 0x36, 0x59, 0x00,
  0x16, 0xba, 0x69, 0x00, 0x01, 0x00, 0x01, 0x42, 0x08, 0x65, 0x73, 0x53,
  0x44, 0x49, 0x60, 0x00, 0x06
};

/*********************** Internal authentication routines *******************/


/**
 * Used to verify CVC certificates in SM establishment process
 * by mean of 00 2A 00 AE (Perform Security Operation: Verify Certificate)
 *@param card pointer to card data
 *@param cert Certificate in CVC format
 *@param len  length of CVC certificate
 *@return SC_SUCCESS if ok; else error code
 */
static int dnie_sm_verify_cvc_certificate(
        sc_card_t *card,
        const u8 *cert,
        size_t len
        ) {
    sc_apdu_t apdu;
    int result=SC_SUCCESS;
    /* safety check */
    if( (card!=NULL) || (card->ctx!=NULL) ) return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    if (!cert || (len<=0) ) /* check received arguments */
        SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_NORMAL,SC_ERROR_INVALID_ARGUMENTS);

    /* compose apdu for Manage Security Environment cmd */
    sc_format_apdu(card,&apdu,SC_APDU_CASE_3_SHORT,0x2A,0x00,0xAE);
    apdu.data=cert;
    apdu.datalen=len;
    apdu.lc=len;
    apdu.resplen=0;

    /* send composed apdu and parse result */
    result=sc_transmit_apdu(card,&apdu);
    SC_TEST_RET(ctx,SC_LOG_DEBUG_NORMAL,result,"Verify CVC certificate failed");
    result=sc_check_sw(card,apdu.sw1,apdu.sw2); 
    SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_VERBOSE,result);
}

/**
 *  Used to handle raw apdu data in set_security_env() on SM stblishment
 *  Standard set_securiy_env() method has sc_security_env->buffer limited
 *  to 8 bytes; so cannot send some of required SM commands.
 *@param card pointer to card data 
 *@param p1 apdu P1 parameter
 *@param p2 apdu P2 parameter
 *@param buffer raw data to be inserted in apdu
 *@param length size of buffer
 *@return SC_SUCCESS if ok; else error code
 */
static int dnie_sm_set_security_env(
        sc_card_t *card,
        u8 p1,
        u8 p2,
        u8 *buffer,
        size_t length
        ) {
    sc_apdu_t apdu;
    int result=SC_SUCCESS;
    /* safety check */
    if( (card!=NULL) || (card->ctx!=NULL) ) return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    if (!buffer || (length<=0) ) /* check received arguments */
        SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_NORMAL,SC_ERROR_INVALID_ARGUMENTS);

    /* compose apdu for Manage Security Environment cmd */
    sc_format_apdu(card,&apdu,SC_APDU_CASE_3_SHORT,0x22,p1,p2);
    apdu.data=buffer;
    apdu.datalen=length;
    apdu.lc=length;
    apdu.resplen=0;

    /* send composed apdu and parse result */
    result=sc_transmit_apdu(card,&apdu);
    SC_TEST_RET(ctx,SC_LOG_DEBUG_NORMAL,result,"SM Set Security Environment failed");
    result=sc_check_sw(card,apdu.sw1,apdu.sw2); 
    SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_VERBOSE,result);
}

/**
 * SM internal authenticate
 *@param data apdu data content
 *@param datalen data length (16)
 *@param resp response buffer
 *@param resplen response bufferlen (128)
 *@return SC_SUCCESS if OK: else error code
 */
static int dnie_sm_internal_auth(
        sc_card_t *card,
        const u8 *data, size_t datalen,
        u8 *resp, size_t resplen
        ) {
    sc_apdu_t apdu;
    u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
    int result=SC_SUCCESS;
    /* safety check */
    if( (card!=NULL) || (card->ctx!=NULL) ) return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    if (!data||(datalen<=0)||!resp||(resplen<=0)) /* check received arguments */
        SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_NORMAL,SC_ERROR_INVALID_ARGUMENTS);

    /* compose apdu for Manage Security Environment cmd */
    sc_format_apdu(card,&apdu,SC_APDU_CASE_3_SHORT,0x88,0x00,0x00);
    apdu.data=data;
    apdu.datalen=datalen;
    apdu.lc=datalen;
    apdu.resp=rbuf;
    apdu.resplen=sizeof(rbuf);

    /* send composed apdu and parse result */
    result=sc_transmit_apdu(card,&apdu);
    SC_TEST_RET(ctx,SC_LOG_DEBUG_NORMAL,result,"SM internal auth failed");
    result=sc_check_sw(card,apdu.sw1,apdu.sw2); 
    SC_TEST_RET(ctx,SC_LOG_DEBUG_NORMAL,result,"SM internal auth invalid response");
    if (apdu.resplen!=resplen) /* invalid number of bytes received */
        SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_VERBOSE,SC_ERROR_UNKNOWN_DATA_RECEIVED);
    memcpy(resp,apdu.resp,resplen); /* copy result to buffer */
    SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
    
}

/* check the result of internal_authenticate operation
 *@param card Pointer to sc_card_t data
 *@param sigbuf received signature
 *@param siglen signature length; should be 128
 *@param rndifd ifd random generated data
 *@param rndlen rndifd length; should be 8
 *@param icc_pubkey icc public key
 *@param ifd_privkey ifd private key
 *@param kicc pointer to store resulting icc provided key
 *@return SC_SUCCESS if ok; else error code
 */
static int dnie_sm_verify_internal_auth(
        sc_card_t *card,
        u8 *sigbuf,
        size_t siglen,
        u8 *ifdbuf,
        size_t ifdlen,
	RSA *icc_pubkey,
        RSA *ifd_privkey,
        u8 *kicc
    ) {
    int res=SC_SUCCESS;
    u8 *decryptbuf; /* to store decrypted signature */
    if( (card!=NULL) || (card->ctx!=NULL) ) return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    if (!sigbuf || siglen!=128) res=SC_ERROR_INVALID_ARGUMENTS;
    if (!ifdbuf || ifdlen!=16) res=SC_ERROR_INVALID_ARGUMENTS;
    if (!icc_pubkey || !ifd_privkey || !kicc)  res=SC_ERROR_INVALID_ARGUMENTS;
    decryptbuf= (u8 *) calloc(128,sizeof(u8)); /* 128: RSA key len in bytes */
    if (!decryptbuf) res= SC_ERROR_OUT_OF_MEMORY;
    SC_TEST_RET(ctx,SC_LOG_DEBUG_NORMAL,res,"Verify Signature: invalid arguments");
    /* 
    We have received data with this format:
    sigbuf = E[PK.IFD.AUT](SIGMIN)
    SIGMIN = min ( SIG, N.ICC-SIG )
    SIG= DS[SK.ICC.AUT] (
        0x6A  ||
        PRND1 ||
        Kicc  ||
        sha1_hash(PRND1 || Kicc || RND.IFD || SN.IFD) ||
        0xBC 
    )
    So we have to reverse the process and try to get valid results
    */

    /* decrypt data with our ifd priv key */
    int len=RSA_private_decrypt(siglen,sigbuf,decryptbuf,ifd_privkey,RSA_NO_PADDING);
    res=(len<=0)?SC_ERROR_DECRYPT_FAILED:SC_SUCCESS;
    SC_TEST_RET(ctx,SC_LOG_DEBUG_NORMAL,res,"Verify Signature: decrypt failed");

    SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
}
    
/**
 * Create Secure channel
 * Based on Several documents:
 * "Understanding the DNIe"
 * "Manual de comandos del DNIe"
 * ISO7816-4 and CWA14890-{1,2}
 */
static int dnie_sm_create_secure_channel(
                sc_card_t *card, 
                dnie_sm_handler_t *handler) {
    int res=SC_SUCCESS;
    char *msg="Success";

    sc_serial_number_t *serial;

    /* data to get and parse certificates */
    X509 *icc_cert,*ca_cert;
    RSA *icc_pubkey=NULL;
    RSA *ifd_privkey=NULL;

    /* data to read certificates from card */
    sc_file_t *file=NULL;
    sc_path_t *path;
    u8 *buffer=NULL;
    size_t bufferlen=0;

    /* random numbers from icc and ifd */
    u8 rndicc[8];
    u8 rndifd[8];
    u8 kicc[32];

    if ( (card==NULL) || (card->ctx==NULL) || (handler==NULL) )
         return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;
    SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
    /* malloc required structures */
    serial= (sc_serial_number_t *)calloc(1,sizeof(sc_serial_number_t));
    path= (sc_path_t *) calloc(1,sizeof(sc_path_t));
    if ( (serial==NULL) || (path==NULL) )
        SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_VERBOSE,SC_ERROR_OUT_OF_MEMORY);
    /* ensure that our card is a DNIe */
    if (card->type!=SC_CARD_TYPE_DNIE_USER)
        SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_VERBOSE,SC_ERROR_INVALID_CARD);

    /* reset card (warm reset, do not unpower card) */
    sc_reset(card,0); 

    /* Retrieve Card serial Number */
    res=sc_card_ctl(card,SC_CARDCTL_GET_SERIALNR, serial);
    if (res!=SC_SUCCESS) { msg="Cannot get DNIe serialnr"; goto csc_end; }
    /* 
     * Manual says that we must read intermediate CA cert , Componente cert
     * And verify certificate chain
     */

    /* Read Intermediate CA from card File:3F006020 */
    sc_format_path("3F006020",path);
    res=dnie_read_file(card,path,&file,&buffer,&bufferlen);
    if (res!=SC_SUCCESS) { msg="Cannot get intermediate CA cert"; goto csc_end; }
    ca_cert= d2i_X509(NULL,(const unsigned char **)buffer,bufferlen);
    if (ca_cert==NULL) { /* received data is not a certificate */
        res=SC_ERROR_OBJECT_NOT_VALID;
        msg="Readed data is not a certificate";
        goto csc_end;
    }
    if (file) { sc_file_free(file); file=NULL;buffer=NULL; bufferlen=0; }

    /* Read Card certificate File:3F00601F */
    sc_format_path("3F00601F",path);
    res=dnie_read_file(card,path,&file,&buffer,&bufferlen);
    if (res!=SC_SUCCESS) { msg="Cannot get Component cert"; goto csc_end; }
    icc_cert= d2i_X509(NULL,(const unsigned char **) buffer,bufferlen);
    if (icc_cert==NULL) { /* received data is not a certificate */
        res=SC_ERROR_OBJECT_NOT_VALID;
        msg="Readed data is not a certificate";
        goto csc_end;
    }
    if (file) { sc_file_free(file); file=NULL;buffer=NULL; bufferlen=0; }

    /* TODO: Verify icc Card certificate chain */
    /* Notice that Official driver skips this step 
     * and simply verifies that icc_cert is a valid certificate */

    /* Extract public key from ICC certificate */
    EVP_PKEY *pk=X509_get_pubkey(icc_cert);
    icc_pubkey=pk->pkey.rsa;

    /* Select Root CA (key reference 0x020F according manual)
     * in card for ifd certificate verification */
    u8 root_ca_ref[] = {
        /* T */ 0x83,
        /* L */ 0x02,
        /* V */ 0x02,0x0F
    };
    res=dnie_sm_set_security_env(card,0x81,0xB6,root_ca_ref,sizeof(root_ca_ref));
    if (res!=SC_SUCCESS) { msg="Select Root CA failed"; goto csc_end; }

    /* Send IFD intermediate CA in CVC format C_CV_CA */
    res=dnie_sm_verify_cvc_certificate(card,C_CV_CA_CS_AUT_cert,sizeof(C_CV_CA_CS_AUT_cert));
    if (res!=SC_SUCCESS) { msg="Verify CVC CA failed"; goto csc_end; }

    /* select public key of sent certificate */
    u8 cvc_ca_ref[] = {
        /* T */ 0x83,
        /* L */ 0x08,
        /* V */ 0x65,0x73,0x53,0x44,0x49,0x60,0x00,0x06
    };
    res=dnie_sm_set_security_env(card,0x81,0xB6,cvc_ca_ref,sizeof(cvc_ca_ref));
    if (res!=SC_SUCCESS) { msg="Select CVC CA pubk failed"; goto csc_end; }

    /* Send IFD certiticate in CVC format C_CV_IFD */
    res=dnie_sm_verify_cvc_certificate(card,C_CV_IFDuser_AUT_cert,sizeof(C_CV_IFDuser_AUT_cert));
    if (res!=SC_SUCCESS) { msg="Verify CVC IFD failed"; goto csc_end; }

    /* select public key of ifd certificate and icc private key */ 
    u8 cvc_ifd_ref[] = {
        /* T */ 0x83,
        /* L */ 0x0C,
        /* V */ 0x00,0x00,0x00,0x00,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
        /* T */ 0x84,
        /* L */ 0x02,
        /* V */ 0x02,0x1f
    };
    res=dnie_sm_set_security_env(card,0x81,0xB6,cvc_ifd_ref,sizeof(cvc_ifd_ref));
    if (res!=SC_SUCCESS) { msg="Select CVC IFD pubk failed"; goto csc_end; }

    /* Internal (Card) authentication (let the card verify sent ifd certs) 
     SN.IFD equals 8 lsb bytes of ifd.pubk ref according cwa14890 sec 8.4.1 */
    u8 sigbuf[128]; /* buffer to store signature response */
    u8 rndbuf[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* RND.IFD (reserve 8 bytes) */
        0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x01  /* SN.IFD */
    };
    RAND_bytes(rndifd,8); /* generate 8 random bytes */
    memcpy(rndbuf,rndifd,8); /* insert into rndbuf */
    res=dnie_sm_internal_auth(card,rndbuf,sizeof(rndbuf),sigbuf,sizeof(sigbuf));
    if (res!=SC_SUCCESS) { msg="Internal auth cmd failed"; goto csc_end; }

    /* compose ifd_private key with data provided in Annex 3 of DNIe Manual */
    ifd_privkey = RSA_new(); /* create RSA struct */
    res=(ifd_privkey)?SC_SUCCESS:SC_ERROR_OUT_OF_MEMORY;
    if (res!=SC_SUCCESS) { msg="Evaluate RSA ifd priv key failed"; goto csc_end; }
    ifd_privkey->n =
        BN_bin2bn(ifd_modulus,sizeof(ifd_modulus),ifd_privkey->n);
    ifd_privkey->e = 
        BN_bin2bn(ifd_public_exponent,sizeof(ifd_public_exponent),ifd_privkey->e);
    ifd_privkey->d = 
        BN_bin2bn(ifd_private_exponent,sizeof(ifd_private_exponent),ifd_privkey->d);
    
    /* verify received signature */
    res=dnie_sm_verify_internal_auth(
        card,
        sigbuf,         /* received signature */
        sizeof(sigbuf), /* signature length; should be 128 */
        rndbuf,         /* RND.IFD || SN.IFD */
        sizeof(rndbuf), /* rndbuf length; should be 16 */
	icc_pubkey,     /* evaluated icc public key */
        ifd_privkey,    /* evaluated from DGP's Manual Annex 3 Data */
        kicc            /* to store resulting icc provided key */
    );    
    if (res!=SC_SUCCESS) { msg="Internal Auth Verify failed"; goto csc_end; }

    /* get challenge: retrieve 8 random bytes from card */
    res=card->ops->get_challenge(card,rndicc,8);
    SC_TEST_RET(ctx,SC_LOG_DEBUG_NORMAL,res,"Get Challenge failed");

    /* TODO: External (IFD)  authentication */
    /* TODO: Session key generation */

    /* arriving here means ok: cleanup */
    res=SC_SUCCESS;
csc_end:
    /* TODO: sm create Cleanup */
    if (serial)      free(serial);
    if (path)        free(path);
    if (buffer)      free(buffer);
    if (icc_pubkey)  RSA_free(icc_pubkey);
    if (ifd_privkey) RSA_free(ifd_privkey);
    if (res!=SC_SUCCESS) sc_debug(ctx,SC_LOG_DEBUG_NORMAL,msg);
    SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_VERBOSE,res);
}

/************************* public functions ***************/
int dnie_sm_init(
        struct sc_card *card,
        dnie_sm_handler_t **sm_handler,
        int final_state) {
    dnie_sm_handler_t *handler;
    int result;
    assert( (card!=NULL) && (card->ctx!=NULL) && (sm_handler!=NULL));
    sc_context_t *ctx=card->ctx;
    SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
    if (*sm_handler==NULL) {
        /* not initialized yet: time to do */
        handler=(dnie_sm_handler_t *) calloc(1,sizeof( dnie_sm_handler_t ));
        if (handler==NULL) return SC_ERROR_OUT_OF_MEMORY;
        handler->state=DNIE_SM_NONE;
        handler->deinit=NULL;
        handler->encode=NULL;
        handler->decode=NULL;
        *sm_handler=(void *) &handler; /* mark pointer as initialized */
    } else {
        /* already initialized: take pointer from parameters */
        handler=(dnie_sm_handler_t *) *sm_handler;
    }
    if (handler->state==final_state) {
        /* already done */
        SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
    }
    /* call de-init if required*/
    if ( handler->deinit!=NULL) {
        result=handler->deinit(card);
        SC_TEST_RET(ctx,SC_LOG_DEBUG_NORMAL,result,"SM Deinit() failed");
    }
    /* now initialize to requested state */
    switch(final_state) {
        case DNIE_SM_NONE: 
            handler->deinit = NULL;
            handler->encode = NULL;
            handler->encode = NULL;
            break;
        case DNIE_SM_INPROGRESS: /* work in progress; (what about locks?) */
            SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_NORMAL,SC_ERROR_NOT_ALLOWED);
        case DNIE_SM_INTERNAL:
            handler->state=DNIE_SM_INPROGRESS;
            result = dnie_sm_create_secure_channel(card,handler);
            if (result!=SC_SUCCESS) goto sm_init_error;
            break;
        case DNIE_SM_EXTERNAL:
            /* TODO: support for remote (SSL) APDU handling */ 
            SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_NORMAL,SC_ERROR_NOT_SUPPORTED);
        default:
            SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_NORMAL,SC_ERROR_INVALID_ARGUMENTS);
    }
    /* arriving here means success */
    handler->state=final_state;
    SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);

sm_init_error:
    /* error in init: back into non-sm mode */
    handler->state=DNIE_SM_NONE;
    handler->deinit = NULL;
    handler->encode = NULL;
    handler->encode = NULL;
    SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_NORMAL,result);
}

/**
 * See if apdu needs to be encoded/decoded
 *@param card card structure declaration
 *@param apdu apdu to check
 *@param flag 0:encode 1:decode
 *@return err code (<0) 0:no wrap needed 1:wrap needed
 */
static int dnie_sm_need_wrap(struct sc_card *card,
                      struct sc_apdu *apdu,
                      int flag
                     ) {
    switch (flag) {
      case 0: /* encode */
    	/* according iso7816-4 sec 5.1.1 
    	check CLA byte to see if apdu is encoded */
    	if ( (apdu->cla & 0x0C)==0) return 0; /* already encoded */
    	/* GET Response command should not to be encoded */
    	if ( apdu->ins == 0xC0 ) return 0;
        /* arriving here means encoding needed */
    	return 1;
      case 1: /* decode */
        if (apdu->resplen==0) return 0; /* response has only sw1 sw2 */
        /* acording to cwa-14890-1 sec 9.2 */
        switch (apdu->resp[0]) {
            case 0x81: /* plain value (to be protected by CC) */
            case 0x87: /* padding-content + cryptogram */
            case 0x8E: /* cryptographic checksum (MAC) */
            case 0x97: /* Le (to be protected by CC ) */
            case 0x99: /* processing status (SW1-SW2 protected by mac) */
               return 1;
            default:   /* else assume unencrypted */
               /* TODO: revise correctness */
               return 0;
        }
      default: return SC_ERROR_INTERNAL;
    } 
}

int dnie_sm_wrap_apdu(struct sc_card *card,/* card data */
                      dnie_sm_handler_t *sm_handler, /* sm_handler */
                      struct sc_apdu *from,/* apdu to be parsed */
                      struct sc_apdu *to,  /* apdu to store result */
                      int flag             /* 0:SM encode 1:SM decode */
                      ) {
    int result=SC_SUCCESS;
    dnie_sm_handler_t *handler=(dnie_sm_handler_t *) sm_handler;
    if ( (card==NULL) || (handler==NULL) ) return SC_ERROR_INVALID_ARGUMENTS;
    if ( (from==NULL) || (to==NULL) ) return SC_ERROR_INVALID_ARGUMENTS;
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    switch (handler->state) {
      case DNIE_SM_NONE:
      case DNIE_SM_INPROGRESS:
         /* just copy structure data */
         *to=*from; /* implicit memcpy() */
         SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
      case DNIE_SM_INTERNAL:
      case DNIE_SM_EXTERNAL:
         result=dnie_sm_need_wrap(card,from,flag);
         if (result<0) goto dnie_wrap_apdu_end; /* ERROR */
         if (result==0) { /* no wrap */
             *to=*from; 
             result=SC_SUCCESS; 
             goto dnie_wrap_apdu_end;
         } 
         if (flag==0) result=handler->encode(card,from,to); /* wrap */
         else         result=handler->decode(card,from,to); /* unwrap */
         break;
      default:
         SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_NORMAL,SC_ERROR_INTERNAL);
    }
dnie_wrap_apdu_end:
    SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_VERBOSE,result);
}

/* end of secure_messaging.c */
#undef __SM_DNIE_C__
