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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ENABLE_OPENSSL   /* empty file without openssl */

#include <stdlib.h>
#include <string.h>

#include "opensc.h"
#include "cardctl.h"
#include "internal.h"
#include <openssl/x509.h>
#include <openssl/des.h>
#include "dnie.h"

/********************* Keys and certificates as published by DGP ********/

static const u8 icc_root_ca_modulus[] = {
    0xEA, 0xDE, 0xDA, 0x45, 0x53, 0x32, 0x94, 0x50, 0x39, 0xDA, 0xA4, 0x04,
    0xC8, 0xEB, 0xC4, 0xD3, 0xB7, 0xF5, 0xDC, 0x86, 0x92, 0x83, 0xCD, 0xEA,
    0x2F, 0x10, 0x1E, 0x2A, 0xB5, 0x4F, 0xB0, 0xD0, 0xB0, 0x3D, 0x8F, 0x03,
    0x0D, 0xAF, 0x24, 0x58, 0x02, 0x82, 0x88, 0xF5, 0x4C, 0xE5, 0x52, 0xF8,
    0xFA, 0x57, 0xAB, 0x2F, 0xB1, 0x03, 0xB1, 0x12, 0x42, 0x7E, 0x11, 0x13,
    0x1D, 0x1D, 0x27, 0xE1, 0x0A, 0x5B, 0x50, 0x0E, 0xAA, 0xE5, 0xD9, 0x40,
    0x30, 0x1E, 0x30, 0xEB, 0x26, 0xC3, 0xE9, 0x06, 0x6B, 0x25, 0x71, 0x56,
    0xED, 0x63, 0x9D, 0x70, 0xCC, 0xC0, 0x90, 0xB8, 0x63, 0xAF, 0xBB, 0x3B,
    0xFE, 0xD8, 0xC1, 0x7B, 0xE7, 0x67, 0x30, 0x34, 0xB9, 0x82, 0x3E, 0x97,
    0x7E, 0xD6, 0x57, 0x25, 0x29, 0x27, 0xF9, 0x57, 0x5B, 0x9F, 0xFF, 0x66,
    0x91, 0xDB, 0x64, 0xF8, 0x0B, 0x5E, 0x92, 0xCD
};

static const u8 icc_root_ca_public_exponent[] = {
   0x01, 0x00, 0x01
};

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
 * Routine to verify certificates provided by card
 * This routine uses Root CA public key data From Annex III of manual
 * to verify intermediate CA icc certificate provided by card
 * if verify sucess, then extract public keys from intermediate CA
 * and verify icc certificate
 *@param card pointer to sc_card_contex
 *@param sub_ca_cert icc intermediate CA certificate readed from card
 *@param icc_ca icc certificate from card
 *@return SC_SUCCESS if verification is ok; else error code
 */
static int dnie_sm_verify_icc_certificates(
       sc_card_t *card,
       X509 *sub_ca_cert,
       X509 *icc_cert
    ) {
    char *msg;
    int res=SC_SUCCESS;
    EVP_PKEY *root_ca_key=NULL;
    EVP_PKEY *sub_ca_key=NULL;
    RSA *root_ca_rsa=NULL;
    /* safety check */
    if( (card!=NULL) || (card->ctx!=NULL) ) return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;
    LOG_FUNC_CALLED(ctx);
    if (!sub_ca_cert || !icc_cert ) /* check received arguments */
        LOG_FUNC_RETURN(ctx,SC_ERROR_INVALID_ARGUMENTS);

    /* compose root_ca_public key with data provided by Dnie Manual */
    root_ca_key= EVP_PKEY_new(); 
    root_ca_rsa = RSA_new();
    if ( !root_ca_key || !root_ca_rsa ) 
        LOG_FUNC_RETURN(ctx,SC_ERROR_OUT_OF_MEMORY);
    root_ca_rsa->n=BN_bin2bn(icc_root_ca_modulus,
                             sizeof(icc_root_ca_modulus),
                             root_ca_rsa->n);
    root_ca_rsa->e=BN_bin2bn(icc_root_ca_public_exponent,
                             sizeof(icc_root_ca_public_exponent),
                             root_ca_rsa->e);
    res=EVP_PKEY_assign_RSA(root_ca_key,root_ca_rsa);
    if (!res) {
        msg="Cannot compose root CA public key";
        res=SC_ERROR_INTERNAL;
        goto verify_icc_certificates_end;
    }

    /* verify sub_ca_cert against root_ca_key */
    res=X509_verify(sub_ca_cert,root_ca_key);
    if (!res) {
        msg="Cannot verify icc Sub-CA certificate";
        res=SC_ERROR_INTERNAL;
        goto verify_icc_certificates_end;
    }

    /* extract sub_ca_key from sub_ca_cert */
    sub_ca_key=X509_get_pubkey(sub_ca_cert);

    /* verify icc_cert against sub_ca_key */
    res=X509_verify(icc_cert,sub_ca_key);
    if (!res) {
        msg="Cannot verify icc certificate";
        res=SC_ERROR_INTERNAL;
        goto verify_icc_certificates_end;
    }

    /* arriving here means certificate verification success */
    res=SC_SUCCESS;
verify_icc_certificates_end:
    if (root_ca_key) EVP_PKEY_free(root_ca_key); /*implies root_ca_rsa free()*/
    if (sub_ca_key) EVP_PKEY_free(sub_ca_key);
    if (res!=SC_SUCCESS) sc_log(ctx,msg);
    LOG_FUNC_RETURN(ctx,res);
}

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
    LOG_FUNC_CALLED(ctx);
    if (!cert || (len<=0) ) /* check received arguments */
        LOG_FUNC_RETURN(ctx,SC_ERROR_INVALID_ARGUMENTS);

    /* compose apdu for Perform Security Operation (Verify cert) cmd */
    sc_format_apdu(card,&apdu,SC_APDU_CASE_3_SHORT,0x2A,0x00,0xAE);
    apdu.data=cert;
    apdu.datalen=len;
    apdu.lc=len;
    apdu.resplen=0;

    /* send composed apdu and parse result */
    result=sc_transmit_apdu(card,&apdu);
    LOG_TEST_RET(ctx,result,"Verify CVC certificate failed");
    result=sc_check_sw(card,apdu.sw1,apdu.sw2); 
    LOG_FUNC_RETURN(ctx,result);
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
    LOG_FUNC_CALLED(ctx);
    if (!buffer || (length<=0) ) /* check received arguments */
        LOG_FUNC_RETURN(ctx,SC_ERROR_INVALID_ARGUMENTS);

    /* compose apdu for Manage Security Environment cmd */
    sc_format_apdu(card,&apdu,SC_APDU_CASE_3_SHORT,0x22,p1,p2);
    apdu.data=buffer;
    apdu.datalen=length;
    apdu.lc=length;
    apdu.resplen=0;

    /* send composed apdu and parse result */
    result=sc_transmit_apdu(card,&apdu);
    LOG_TEST_RET(ctx,result,"SM Set Security Environment failed");
    result=sc_check_sw(card,apdu.sw1,apdu.sw2); 
    LOG_FUNC_RETURN(ctx,result);
}

/**
 * SM internal authenticate
 *@param card pointer to card data 
 *@param sm   secure message data pointer
 *@param data data to be sent in apdu
 *@param datalen length of data to send
 *@return SC_SUCCESS if OK: else error code
 */
static int dnie_sm_internal_auth( 
        sc_card_t *card,
        dnie_internal_sm_t *sm,
        u8 *data,
        size_t datalen) {
    sc_apdu_t apdu;
    u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
    int result=SC_SUCCESS;
    /* safety check */
    if( (card!=NULL) || (card->ctx!=NULL) ) return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;
    LOG_FUNC_CALLED(ctx);
    if ( !data || (datalen<=0) ) /* check received arguments */
        LOG_FUNC_RETURN(ctx,SC_ERROR_INVALID_ARGUMENTS);

    /* compose apdu for Internal Authenticate cmd */
    sc_format_apdu(card,&apdu,SC_APDU_CASE_3_SHORT,0x88,0x00,0x00);
    apdu.data=data;
    apdu.datalen=datalen;
    apdu.lc=datalen;
    apdu.resp=rbuf;
    apdu.resplen=sizeof(rbuf);

    /* send composed apdu and parse result */
    result=sc_transmit_apdu(card,&apdu);
    LOG_TEST_RET(ctx,result,"SM internal auth failed");
    result=sc_check_sw(card,apdu.sw1,apdu.sw2); 
    LOG_TEST_RET(ctx,result,"SM internal auth invalid response");
    if (apdu.resplen!=sizeof(sm->sig)) /* invalid number of bytes received */
        LOG_FUNC_RETURN(ctx,SC_ERROR_UNKNOWN_DATA_RECEIVED);
    memcpy(sm->sig,apdu.resp,apdu.resplen); /* copy result to buffer */
    LOG_FUNC_RETURN(ctx,SC_SUCCESS);
}

/**
 * Compose signature data for external auth according CWA-14980
 * Store resulting data  into sm->sig
 *@param card pointer to st_card_t card data information
 *@param icc_pubkey public key of card
 *@param ifd_privkey private RSA key of ifd
 *@param serial card serial number
 *@param sm pointer to dnie_sm_internal_t data
 *@return SC_SUCCESS if ok; else errorcode
 */
static int dnie_sm_prepare_external_auth(
        sc_card_t *card,
        RSA *icc_pubkey,
        RSA *ifd_privkey,
        sc_serial_number_t *serial,
        dnie_internal_sm_t *sm
    ) {
    /* we have to compose following message:
    data = E[PK.ICC.AUT](SIGMIN)
    SIGMIN = min ( SIG, N.IFD-SIG )
    SIG= DS[SK.IFD.AUT] (
        0x6A  || - padding according iso 9796-2
        PRND2 || - (74 bytes) random data to make buffer 128 bytes length
        Kifd  || - (32 bytes)- ifd random generated key
        sha1_hash(
             PRND2   ||  
             Kifd    || 
             RND.ICC || - (8 bytes) response to get_challenge() cmd
             SN.ICC  - (8 bytes) serial number from get_serialnr() cmd
        ) || 
        0xBC - iso 9796-2 padding
    ) - total: 128 bytes
    
    then, we should encrypt with our private key and then with icc pub key
    returning resulting data
    */
    char *msg; /* to store error messages */ 
    int res=SC_SUCCESS;
    u8 *buf1; /* where to encrypt with icc pub key */
    u8 *buf2; /* where to encrypt with ifd pub key */
    u8 *buf3; /* where to compose message to be encrypted */
    size_t len1,len2,len3;
    u8 *sha_buf; /* to compose message to be sha'd */
    u8 *sha_data; /* sha signature data */
    BIGNUM *bn = NULL;
    BIGNUM *bnsub = NULL;
    BIGNUM *bnres = NULL;

    /* safety check */
    if( (card!=NULL) || (card->ctx!=NULL) ) return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;
    LOG_FUNC_CALLED(ctx);
     /* check received arguments */
    if ( !icc_pubkey || !ifd_privkey || !serial || !sm )
        LOG_FUNC_RETURN(ctx,SC_ERROR_INVALID_ARGUMENTS);
    buf1=calloc(128, sizeof(u8));
    buf2=calloc(128, sizeof(u8));
    buf3=calloc(128, sizeof(u8));
    sha_buf=calloc(74+32+8+1+7,sizeof(u8));
    sha_data=calloc(SHA_DIGEST_LENGTH,sizeof(u8));
    /* alloc() resources */
    if (!buf1 || !buf2 || !buf3 || !sha_buf || !sha_data) {
        msg="prepare external auth: calloc error";
        res=SC_ERROR_OUT_OF_MEMORY;
        goto prepare_external_auth_end;
    } 

    /* compose buffer data */
    buf3[0]= 0x6A; /* iso padding */
    RAND_bytes(buf3+1,74); /* pRND */
    RAND_bytes(sm->kifd,32); /* Kifd */
    memcpy(buf3+1+74,sm->kifd,32); /* copy Kifd into buffer */
    /* prepare data to be hashed */
    memcpy(sha_buf,buf3+1,74); /* copy pRND into sha_buf */
    memcpy(sha_buf+74,buf3+75,32); /* copy kifd into sha_buf */
    memcpy(sha_buf+74+32,sm->rndicc,8); /* copy 8 byte icc challenge */
    memcpy(sha_buf+74+32+8+1,serial->value,7); /* copy serialnr, 1 byte pad */
    SHA1(sha_buf,74+32+8+1+7,sha_data);
    /* copy hashed data into buffer */
    memcpy(sha_data,buf3+1+74+32,SHA_DIGEST_LENGTH);
    buf3[127]= 0xBC; /* iso padding */
 
    /* encrypt with ifd private key */
    len2= RSA_private_decrypt(128,buf3,buf2,ifd_privkey,RSA_NO_PADDING);
    if (len2<0) {
        msg="Prepare external auth: ifd_privk encrypt failed";
        res=SC_ERROR_DECRYPT_FAILED;
        goto prepare_external_auth_end;
    }

    /* evaluate value of minsig and store into buf3 */
    bn= BN_bin2bn(buf2,len2, NULL);
    bnsub= BN_new();
    if (!bn || !bnsub) {
        msg="Prepare external auth: BN creation failed";
        res=SC_ERROR_INTERNAL;
        goto prepare_external_auth_end;
    }
    res=BN_sub(bnsub,ifd_privkey->n,bn); /* eval N.IFD-SIG */
    if (res!=0) {
        msg="Prepare external auth: BN sigmin evaluation failed";
        res=SC_ERROR_INTERNAL;
        goto prepare_external_auth_end;
    }
    bnres=(BN_cmp(bn,bnsub)<0)?bn:bnsub; /* choose min(SIG,N.IFD-SIG) */
    if (BN_numbytes(bnres)>128) {
        msg="Prepare external auth: BN sigmin result is too big";
        res=SC_ERROR_INTERNAL;
        goto prepare_external_auth_end;
    }
    res=BN_bn2bin(bnres,buf3); /* convert result back into buf3 */
    if (res<=0) {
        msg="Prepare external auth: BN to buffer conversion failed";
        res=SC_ERROR_INTERNAL;
        goto prepare_external_auth_end;
    }

    /* re-encrypt result with icc public key */
    len1=RSA_private_decrypt(128,buf3,buf1,icc_pubkey,RSA_NO_PADDING);
    if (len1<=0) {
        msg="Prepare external auth: icc_pubk encrypt failed";
        res=SC_ERROR_DECRYPT_FAILED;
        goto prepare_external_auth_end;
    }

    /* process done: copy result into sm_internal buffer and return success */
    memcpy(sm->sig,buf1,len1);
    res=SC_SUCCESS;

prepare_external_auth_end:
    if (bn)    BN_free(bn);
    if (bnsub) BN_free(bnsub);
    if (buf1) { memset(buf1,0,128); free(buf1); }
    if (buf2) { memset(buf2,0,128); free(buf2); }
    if (buf3) { memset(buf3,0,128); free(buf3); }
    if (sha_buf) { memset(sha_buf,0,74+32+8+1+7); free(sha_buf); }
    if (sha_data) { memset(sha_data,0,SHA_DIGEST_LENGTH); free(sha_data); }

    if (res!=SC_SUCCESS) sc_log(ctx,msg);
    LOG_FUNC_RETURN(ctx,res);
}

/**
 * SM external authenticate
 *@param data apdu signature content
 *@param datalen signature length (128)
 *@return SC_SUCCESS if OK: else error code
 */
static int dnie_sm_external_auth( sc_card_t *card, dnie_internal_sm_t *sm) {
    sc_apdu_t apdu;
    int result=SC_SUCCESS;
    /* safety check */
    if( (card!=NULL) || (card->ctx!=NULL) ) return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;
    LOG_FUNC_CALLED(ctx);

    /* compose apdu for External Authenticate cmd */
    sc_format_apdu(card,&apdu,SC_APDU_CASE_3_SHORT,0x82,0x00,0x00);
    apdu.data=sm->sig;
    apdu.datalen=sizeof(sm->sig);
    apdu.le=0;
    apdu.resp=NULL;
    apdu.resplen=0;

    /* send composed apdu and parse result */
    result=sc_transmit_apdu(card,&apdu);
    LOG_TEST_RET(ctx,result,"SM external auth failed");
    result=sc_check_sw(card,apdu.sw1,apdu.sw2);
    LOG_TEST_RET(ctx,result,"SM external auth invalid response");
    LOG_FUNC_RETURN(ctx,SC_SUCCESS);
}

/**
 * SM creation of session keys
 *@param card pointer to sc_card_t data
 *@param sm pointer to dnie_sm_internal_t data
 *@return SC_SUCCESS if ok; else error code
 */
static int dnie_sm_compute_session_keys(
        sc_card_t *card,
        dnie_internal_sm_t *sm ) {

    char *msg=NULL;
    int n=0;
    int res=SC_SUCCESS;
    u8 *kseed; /* to compose kifd ^ kicc */
    u8 *data;  /* to compose kenc and kmac to be hashed */
    u8 *sha_data; /* to store hash result */

    /* safety check */
    if( (card!=NULL) || (card->ctx!=NULL) ) return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;
    LOG_FUNC_CALLED(ctx);
    /* Just a literal transcription of cwa14890-1 sections 8.7.2 to 8.9 */
    kseed=calloc(32,sizeof(u8));
    data=calloc(32+4,sizeof(u8));
    sha_data=calloc(SHA_DIGEST_LENGTH,sizeof(u8));
    if (!kseed || !data || !sha_data) {
        msg="Compute Session Keys: calloc() failed";
        res=SC_ERROR_OUT_OF_MEMORY;
        goto compute_session_keys_end;
    }
    /* compose kseed  (cwa-14980-1 sect 8.7.2) */
    for (n=0;n<32;n++) *(kseed+n)= *(sm->kicc+n) ^ *(sm->kifd+n);

    /* evaluate kenc (cwa-14980-1 sect 8.8) */
    memcpy(data,kseed,32);
    *(data+35)=0x01; /* data = kseed || 0x00 0x00 0x00 0x01 */
    SHA1(data,32+4,sha_data);
    memcpy(sm->kenc,sha_data,16); /* 16 MS bytes  of sha result */

    /* evaluate kmac */
    memset(data,0,32+4);
    memset(sha_data,0,SHA_DIGEST_LENGTH); /* clear buffers */

    memcpy(data,kseed,32);
    *(data+35)=0x02; /* data = kseed || 0x00 0x00 0x00 0x02 */ 
    SHA1(data,32+4,sha_data);
    memcpy(sm->kmac,sha_data,16);

    /* evaluate send sequence counter  (cwa-14980-1 sect 8.9 & 9.6 */
    memcpy(sm->ssc,sm->rndicc+4,4); /* 4 least significant bytes of rndicc */
    memcpy(sm->ssc+4,sm->rndifd+4,4); /* 4 least significant bytes of rndifd */

    /* arriving here means process ok */
    res=SC_SUCCESS;

compute_session_keys_end:
    if (kseed) { memset(kseed,0,32); free(kseed); }
    if (data) { memset(data,0,32+4); free(data); }
    if (sha_data) { memset(sha_data,0,SHA_DIGEST_LENGTH); free(sha_data); }
    if (res!=SC_SUCCESS) sc_log(ctx,msg);
    LOG_FUNC_RETURN(ctx,res);
}

/*
 * Compare signature for internal auth procedure
 * returns SC_SUCCESS or error code
 */
static int dnie_sm_compare_signature(
        u8 *data,
        size_t dlen,
        u8 *ifd_data
        ) {
    u8 *buf=calloc(74+32+32,sizeof(u8));
    u8 *sha=calloc(SHA_DIGEST_LENGTH,sizeof(u8));
    int res=SC_SUCCESS;
    if (!buf || !sha) {
        res=SC_ERROR_OUT_OF_MEMORY;
        goto compare_signature_end;
    }
    res=SC_ERROR_INVALID_DATA;
    if (dlen!=128)       goto compare_signature_end; /* check length */
    if (data[0]!=0x6a)   goto compare_signature_end; /* iso 9796-2 padding */ 
    if (data[127]!=0xBC) goto compare_signature_end; /* iso 9796-2 padding */
    memcpy(buf,data+1,74+32);
    memcpy(buf+74+32,ifd_data,16);
    SHA1(buf,74+32+16,sha);
    if (memcmp(data+127-SHA_DIGEST_LENGTH,sha,SHA_DIGEST_LENGTH)==0) res=SC_SUCCESS;
compare_signature_end:
    if (buf) free(buf);
    if (sha) free(sha);
    return res;
}

/** check the result of internal_authenticate operation
 *@param card Pointer to sc_card_t data
 *@param icc_pubkey icc public key
 *@param ifd_privkey ifd private key
 *@param ifdbuf buffer containing ( RND.IFD || SN.IFD )
 *@param ifdlen buffer length; should be 16
 *@param sm secure messaging internal data
 *@return SC_SUCCESS if ok; else error code
 */
static int dnie_sm_verify_internal_auth(
        sc_card_t *card,
	RSA *icc_pubkey,
        RSA *ifd_privkey,
        u8 *ifdbuf,
        size_t ifdlen,
        dnie_internal_sm_t *sm
    ) {
    int res=SC_SUCCESS;
    char *msg;
    u8 *buf1; /* to decrypt with our private key */
    u8 *buf2; /* to try SIGNUM==SIG */
    u8 *buf3; /* to try SIGNUM==N.ICC-SIG */
    size_t len1,len2,len3;
    BIGNUM *bn;
    BIGNUM *sigbn;
    if( (card!=NULL) || (card->ctx!=NULL) ) return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;
    LOG_FUNC_CALLED(ctx);
    if (!ifdbuf || ifdlen!=16) res=SC_ERROR_INVALID_ARGUMENTS;
    if (!icc_pubkey || !ifd_privkey)  res=SC_ERROR_INVALID_ARGUMENTS;
    buf1= (u8 *) calloc(128,sizeof(u8)); /* 128: RSA key len in bytes */
    buf2= (u8 *) calloc(128,sizeof(u8)); 
    buf3= (u8 *) calloc(128,sizeof(u8)); 
    if ( !buf1 || !buf2 || !buf3 ) {
        msg= "Verify Signature: calloc() error";
        res= SC_ERROR_OUT_OF_MEMORY;
        goto verify_internal_done;
    }

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
    So we should reverse the process and try to get valid results
    */
    
    /* decrypt data with our ifd priv key */
    len1=RSA_private_decrypt(sizeof(sm->sig),sm->sig,buf1,ifd_privkey,RSA_NO_PADDING);
    if (len1<=0) {
        msg="Verify Signature: decrypt with ifd privk failed";
        res=SC_ERROR_DECRYPT_FAILED;
        goto verify_internal_done;
    }

    /* OK: now we have SIGMIN in buf1 */
    /* check if SIGMIN data matches SIG or N.ICC-SIG */
    /* evaluate DS[SK.ICC.AUTH](SIG) trying to decrypt with icc pubk */
    len3=RSA_public_encrypt(len1,buf1,buf3,icc_pubkey,RSA_NO_PADDING);
    if (len3<=0) goto verify_nicc_sig; /* evaluate N.ICC-SIG and retry */
    res=dnie_sm_compare_signature(buf2,len2,ifdbuf);
    if (res==SC_SUCCESS) goto verify_internal_ok;

verify_nicc_sig: 
   /* 
    * Arriving here means need to evaluate N.ICC-SIG 
    * So convert buffers to bignums to operate
    */
    bn=BN_bin2bn(buf1,len1,NULL); /* create BN data */
    sigbn=BN_new();
    if (!bn || !sigbn) {
        msg="Verify Signature: cannot bignums creation error";
        res=SC_ERROR_OUT_OF_MEMORY;
        goto verify_internal_done;
    }
    res=BN_sub(sigbn,icc_pubkey->n,bn); /* eval N.ICC-SIG */
    if(!res) {
        msg="Verify Signature: evaluation of N.ICC-SIG failed";
        res=SC_ERROR_INTERNAL;
        goto verify_internal_done;
    }
    len2=BN_bn2bin(sigbn,buf2); /* copy result to buffer */
    if (len2<=0) {
        msg="Verify Signature: cannot conver bignum to buffer";
        res=SC_ERROR_INTERNAL;
        goto verify_internal_done;
    }
    /* ok: check again with new data */     
    /* evaluate DS[SK.ICC.AUTH](I.ICC-SIG) trying to decrypt with icc pubk */
    len3=RSA_public_encrypt(len2,buf2,buf3,icc_pubkey,RSA_NO_PADDING);
    if (len3<=0) {
        msg="Verify Signature: cannot get valid SIG data";
        res=SC_ERROR_INVALID_DATA;
        goto verify_internal_done;
    }
    res=dnie_sm_compare_signature(buf3,len3,ifdbuf);
    if (res!=SC_SUCCESS) {
        msg="Verify Signature: cannot get valid SIG data";
        res=SC_ERROR_INVALID_DATA;
        goto verify_internal_done;
    } 
    /* arriving here means OK: complete data structures */
verify_internal_ok:
    memcpy(sm->kicc,buf3+1+74,32); /* extract Kicc from buf3 */
    res=SC_SUCCESS;
verify_internal_done:
    if (buf1) free(buf1);
    if (buf2) free(buf2);
    if (buf3) free(buf3);
    if (bn) BN_free(bn);
    if (sigbn) BN_free(sigbn);
    if (res!=SC_SUCCESS) sc_log(ctx,msg);    
    LOG_FUNC_RETURN(ctx,SC_SUCCESS);
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

    /* preliminary checks */
    if ( !card || !card->ctx || !handler || !handler->sm_internal ) 
         return SC_ERROR_INVALID_ARGUMENTS;

    /* comodity vars */
    sc_context_t *ctx=card->ctx; 
    dnie_internal_sm_t *sm=handler->sm_internal;

    LOG_FUNC_CALLED(ctx);
    /* malloc required structures */
    serial= (sc_serial_number_t *)calloc(1,sizeof(sc_serial_number_t));
    path= (sc_path_t *) calloc(1,sizeof(sc_path_t));
    if ( (serial==NULL) || (path==NULL) )
        LOG_FUNC_RETURN(ctx,SC_ERROR_OUT_OF_MEMORY);

    /* ensure that our card is a DNIe */
    if (card->type!=SC_CARD_TYPE_DNIE_USER)
        LOG_FUNC_RETURN(ctx,SC_ERROR_INVALID_CARD);

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

    /* Verify icc Card certificate chain */
    /* Notice that Official driver skips this step 
     * and simply verifies that icc_cert is a valid certificate */
    res=dnie_sm_verify_icc_certificates(card,ca_cert,icc_cert);
    if (res!=SC_SUCCESS) {
        res=SC_ERROR_OBJECT_NOT_VALID;
        msg="Icc Certificates verification failed";
        goto csc_end;
    }

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
    u8 rndbuf[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /* RND.IFD (reserve 8 bytes) */
        0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x01  /* SN.IFD */
    };
    RAND_bytes(sm->rndifd,8); /* generate 8 random bytes */
    memcpy(rndbuf,sm->rndifd,8); /* insert into rndbuf */
    res=dnie_sm_internal_auth(card,sm,rndbuf,sizeof(rndbuf));
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
	icc_pubkey,     /* evaluated icc public key */
        ifd_privkey,    /* evaluated from DGP's Manual Annex 3 Data */
        rndbuf,         /* RND.IFD || SN.IFD */
        sizeof(rndbuf), /* rndbuf length; should be 16 */
        sm              /* sm data */
    );    
    if (res!=SC_SUCCESS) { msg="Internal Auth Verify failed"; goto csc_end; }

    /* get challenge: retrieve 8 random bytes from card */
    res=card->ops->get_challenge(card,sm->rndicc,sizeof(sm->rndicc));
    if (res!=SC_SUCCESS) { msg="Get Challenge failed"; goto csc_end; }

    /* compose signature data for external auth */
    res=dnie_sm_prepare_external_auth(
        card,
        icc_pubkey,
        ifd_privkey,
        serial,
        sm
    );
    if (res!=SC_SUCCESS) { msg="Prepare external auth failed"; goto csc_end; }

    /* External (IFD)  authentication */
    res=dnie_sm_external_auth(card,sm);
    if (res!=SC_SUCCESS) { msg="External auth cmd failed"; goto csc_end; }

    /* Session key generation */
    res=dnie_sm_compute_session_keys(card,sm);
    if (res!=SC_SUCCESS) { msg="Session Key generation failed"; goto csc_end; }

    /* arriving here means ok: cleanup */
    res=SC_SUCCESS;
csc_end:
    if (serial)  { memset(serial,0,sizeof(sc_serial_number_t)); free(serial); }
    if (path)    { memset(path,0,sizeof(sc_path_t)); free(path); } 
    if (buffer)      free(buffer); /* no need to memset */
    if (icc_pubkey)  RSA_free(icc_pubkey);
    if (ifd_privkey) RSA_free(ifd_privkey);
    if (res!=SC_SUCCESS) sc_log(ctx,msg);
    LOG_FUNC_RETURN(ctx,res);
}

/******************* SM internal APDU encoding / decoding functions ******/

/**
 * Increase send sequence counter SSC
 *
 *@param card smart card info structure
 *@param sm Secure Message handling data structure
 *@return SC_SUCCESS if ok; else error code
 *
 * to further study: what about using bignum arithmetics?
 */
static int dnie_sm_increase_ssc(
    sc_card_t *card,
    dnie_internal_sm_t *sm) {
    int n;
    /* preliminary checks */
    if ( !card || !card->ctx || !sm ) return SC_ERROR_INVALID_ARGUMENTS;
    /* comodity vars */
    sc_context_t *ctx=card->ctx; 

    LOG_FUNC_CALLED(ctx);
    /* u8 arithmetic; exit loop if no carry */
    for(n=7;n>=0;n--) { sm->ssc[n]++; if ( (sm->ssc[n]) != 0x00 ) break; }
    sc_log(ctx,"Next SSC: '%s'",sc_dump_hex(sm->ssc,8));
    LOG_FUNC_RETURN(ctx,SC_SUCCESS);
}

/**
 * ISO 7816 padding
 * Adds an 0x80 at the end of buffer and as many zeroes to get len 
 * multiple of 8
 * Buffer must be long enougth to store additional bytes
 *
 *@param buffer where to compose data
 *@param len pointer to buffer length
 */
static void dnie_sm_iso7816_padding(u8 *buffer,size_t *len) {
    *(buffer+*len++)=0x80;
    for(; (*len & 0x07)==0x00; *len++) *(buffer+*len)=0x00;
}

/**
 * Parse and APDU Response and extract specific BER-TLV data
 * If Tag not found in response returns SC_SUCESS, but empty TLV data result
 *
 * NOTICE that iso7816 sect 5.2.2 states that Tag length may be 1 to n bytes
 * length. In this code we'll assume allways tag lenght = 1 byte
 *@param card card info structure
 *@param apdu APDU data to extract response from
 *@param tag  TLV tag to search for
 *@param tlv  TLV structure to store result into
 *@return SC_SUCCESS if OK; else error code
 */
static int dnie_sm_find_tlv(
   sc_card_t *card,
   sc_apdu_t *apdu,
   unsigned int tag,
   struct sc_tlv_data *tlv 
   ) {
    size_t tlen=0;
    /* preliminary checks */
    if ( !card || !card->ctx ) return SC_ERROR_INVALID_ARGUMENTS;
    /* comodity vars */
    sc_context_t *ctx=card->ctx; 

    LOG_FUNC_CALLED(ctx);
    if (!apdu || !tlv || tag==0x00) 
        LOG_FUNC_RETURN(ctx,SC_ERROR_INVALID_ARGUMENTS);
    u8 *pt=apdu->resp;
    u8 *last=apdu->resp+apdu->resplen;
    /* jump from tlv to tlv till find requested tag */
    for (;pt<last;pt+=tlen) {
        memset(tlv,0,sizeof(struct sc_tlv_data)); /* clear info */
        /* set tag. Assume tag length is 1 byte */
        tlv->tag=*pt++;
        /* evaluate length according iso7816 sect 5.2.2.2 */
        switch(*pt) {
            case 0x84: pt++; tlen=             (0xff & (size_t) *pt);
            case 0x83: pt++; tlen= (tlen<<8) + (0xff & (size_t) *pt);
            case 0x82: pt++; tlen= (tlen<<8) + (0xff & (size_t) *pt);
            case 0x81: pt++; tlen= (tlen<<8) + (0xff & (size_t) *pt);
            case 0x80: pt++; break;
            default:
                if (*pt<0x80) {
                    tlen= (0xff & (size_t) *pt); pt++;
                } else {
                    sc_log(ctx,"Invalid tag length indicator: %d",(size_t)*pt);
                    LOG_FUNC_RETURN(ctx,SC_ERROR_WRONG_LENGTH);
                }
        }
        if (tlv->tag!=tag) continue; /* tag not found: jump to next tlv */
        /* tag found: fill data and return OK */
        tlv->len=tlen;
        tlv->value=pt;
        LOG_FUNC_RETURN(ctx,SC_SUCCESS);
    }
    /* arriving here means requested tlv not found */
    memset(tlv,0,sizeof(struct sc_tlv_data)); /* clear info */
    LOG_FUNC_RETURN(ctx,SC_SUCCESS);
}

/**
 * Encode an APDU
 * Calling this functions means that It's has been verified
 * That source apdu needs encoding
 * Based on section 9 of CWA-14890 and Sect 6 of iso7816-4 standards
 * And DNIe's manual
 *
 *@param card card info structure
 *@param from APDU to be encoded
 *@param to Where to store encoded apdu
 *@return SC_SUCCESS if ok; else error code
 */
static int dnie_sm_internal_encode_apdu(
    sc_card_t *card,
    sc_apdu_t *from,
    sc_apdu_t *to
    ) {
    u8 *apdubuf; /* to store resulting apdu */
    size_t apdulen;
    u8 *ccbuf; /* where to store data to eval cryptographic checksum CC */
    u8 macbuf[8]; /* to store and compute CC */
    DES_key_schedule k1;
    DES_key_schedule k2;
    int i,j; /* for xor loops */
    int len=0;
    int res=SC_SUCCESS;
    /* mandatory check */
    if( (card==NULL) || (card->ctx==NULL)) return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;
    dnie_private_data_t *priv= (dnie_private_data_t *) card->drv_data;
    LOG_FUNC_CALLED(ctx);
    /* check remaining arguments */
    if ((from==NULL) || (to==NULL)|| (priv==NULL)) 
            LOG_FUNC_RETURN(ctx,SC_ERROR_INVALID_ARGUMENTS);
    if ( /* check for properly initialized SM status */
         (priv->sm_handler==NULL) || 
         (priv->sm_handler->state!=DNIE_SM_INTERNAL ) ||
         (priv->sm_handler->sm_internal==NULL) )
            LOG_FUNC_RETURN(ctx,SC_ERROR_INTERNAL);
    /* retrieve sm channel data */
    dnie_internal_sm_t *sm=priv->sm_handler->sm_internal;

    /* compose new header */
    to->cla=from->cla | 0x0C; /* mark apdu as encoded */
    to->ins=from->ins;
    to->p1=from->p1;
    to->p2=from->p2;

    /* allocate result apdu data buffer */
    apdubuf=calloc(SC_MAX_APDU_BUFFER_SIZE,sizeof(u8));
    ccbuf=calloc(SC_MAX_APDU_BUFFER_SIZE,sizeof(u8));
    if (!apdubuf || !ccbuf ) LOG_FUNC_RETURN(ctx,SC_ERROR_OUT_OF_MEMORY);

    /* fill buffer with header info */
    *(ccbuf+len++)=to->cla;
    *(ccbuf+len++)=to->ins;
    *(ccbuf+len++)=to->p1;
    *(ccbuf+len++)=to->p2;
    dnie_sm_iso7816_padding(ccbuf,&len); /* pad header (4 bytes pad) */

    /* if no data, skip data encryption step */
    if (from->lc!=0) {
        size_t dlen=from->datalen;
        u8 msgbuf[SC_MAX_APDU_BUFFER_SIZE];
        u8 cryptbuf[SC_MAX_APDU_BUFFER_SIZE];
        /* prepare keys */
        DES_cblock iv={0,0,0,0,0,0,0,0};
        DES_set_key_unchecked((const_DES_cblock *)&(sm->kenc[0]), &k1);
        DES_set_key_unchecked((const_DES_cblock *)&(sm->kenc[8]), &k2);
        /* pad message */
        memcpy (msgbuf,from->data,dlen);
        dnie_sm_iso7816_padding(msgbuf,&dlen);
        /* aply TDES + CBC with kenc and iv=(0,..,0) */
        DES_ede3_cbc_encrypt(msgbuf,cryptbuf,dlen,&k1,&k2,&k1,&iv,DES_ENCRYPT);
        /* compose data TLV and add to result buffer */
        *(ccbuf+len++)=0x87; /* padding content indicator + cryptogram tag */
        *(ccbuf+len++)=dlen+1; /* len is dlen + iso padding indicator */
        *(ccbuf+len++)=0x01;   /* iso padding type indicator */
        memcpy(ccbuf+len,cryptbuf,dlen);
        len+=dlen;
    }

    /* if le byte is declared, compose and add Le TLV */
    /* TODO: study why original driver checks for le>=256? */
    if (from->le>0) {
        *(ccbuf+len++)=0x97; /* TLV tag for CC protected Le */
        *(ccbuf+len++)=0x01; /* length=1 byte */
        *(ccbuf+len++)=from->le;
    }
    /* copy current data to apdu buffer (skip header and header padding) */
    memcpy(apdubuf,ccbuf+8,len-8);
    apdulen=len-8;
    /* pad again ccbuffer to compute CC */
    dnie_sm_iso7816_padding(ccbuf,&len);

    /* compute MAC Cryptographic Checksum using kmac and increased SSC */
    res=dnie_sm_increase_ssc(card,sm); /* increase send sequence counter */
    if (res!=SC_SUCCESS) {
    	sc_log(ctx,"Error in computing SSC");
        free(ccbuf);
        LOG_FUNC_RETURN(ctx,res);
    }
    /* set up keys for mac computing */
    DES_set_key_unchecked((const_DES_cblock *)&(sm->kmac[0]), &k1);
    DES_set_key_unchecked((const_DES_cblock *)&(sm->kmac[8]), &k2);

    memcpy(macbuf,sm->ssc,8); /* start with computed SSC */
    for (i=0;i<len;i+=8) { /* divide data in 8 byte blocks */
        /* compute DES */
        DES_ecb_encrypt((const_DES_cblock *)macbuf, (DES_cblock *)macbuf, &k1, DES_ENCRYPT);
        /* XOR with data and repeat */
        for (j=0;j<8;j++) macbuf[j] ^= ccbuf[i+j];
    }
    /* and apply 3DES to result */
    DES_ecb2_encrypt((const_DES_cblock *)macbuf, (DES_cblock *)macbuf, &k1, &k2, DES_ENCRYPT);
    free(ccbuf); /* ccbuf is no longer needed */

    /* compose and add computed MAC TLV to result buffer */
    *(apdubuf+apdulen++)=0x8E; /* TLV tag for MAC Cryptographic checksum */
    *(apdubuf+apdulen++)=0x04; /* len= 4 bytes */
    memcpy(apdubuf+apdulen,macbuf,4); /* 4 first bytes of computed mac */
    apdulen+=4;

    /* finally evaluate remaining apdu data */
    to->le=from->le;
    to->lc=apdulen;
    to->data=apdubuf;
    to->datalen=apdulen;

    /* that's all folks */
    LOG_FUNC_RETURN(ctx,SC_SUCCESS);
}

/**
 * Decode an APDU response
 * Calling this functions means that It's has been verified
 * That apdu response comes in CWA TLV encoded format and needs decoding
 * Based on section 9 of CWA-14890 and Sect 6 of iso7816-4 standards
 * And DNIe's manual
 *
 *@param card card info structure
 *@param from APDU with response to be decoded
 *@param to Where to store apdu with decoded response
 *@return SC_SUCCESS if ok; else error code
 */
static int dnie_sm_internal_decode_apdu(
    sc_card_t *card,
    sc_apdu_t *from,
    sc_apdu_t *to
    ) {
    struct sc_tlv_data d_tlv; /* to store plain data (Tag 0x81) */
    struct sc_tlv_data p_tlv; /* to store padded encoded data (Tag 0x87) */
    struct sc_tlv_data m_tlv; /* to store mac CC (Tag 0x97) */
    struct sc_tlv_data s_tlv; /* to store sw1-sw2 status (Tag 0x99) */
    int res=SC_SUCCESS;
    int flag=0;
    /* mandatory check */
    if( (card==NULL) || (card->ctx==NULL)) return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;
    dnie_private_data_t *priv= (dnie_private_data_t *) card->drv_data;
    LOG_FUNC_CALLED(ctx);
    /* check remaining arguments */
    if ((from==NULL) || (to==NULL)|| (priv==NULL)) 
            LOG_FUNC_RETURN(ctx,SC_ERROR_INVALID_ARGUMENTS);
    if ( /* check for properly initialized SM status */
         (priv->sm_handler==NULL) || 
         (priv->sm_handler->state!=DNIE_SM_INTERNAL ) ||
         (priv->sm_handler->sm_internal==NULL) )
            LOG_FUNC_RETURN(ctx,SC_ERROR_INTERNAL);
    /* retrieve sm channel data */
    dnie_internal_sm_t *sm=priv->sm_handler->sm_internal;

    /* parse response to find TLV data */
    dnie_sm_find_tlv(card,from,0x99,&s_tlv); /* status data (optional) */
    dnie_sm_find_tlv(card,from,0x87,&p_tlv); /* encoded data */
    dnie_sm_find_tlv(card,from,0x81,&d_tlv); /* plain data */
    if (p_tlv.value && d_tlv.value) /* encoded & plain are mutually exclusive */
       LOG_FUNC_RETURN(ctx,SC_ERROR_UNKNOWN_DATA_RECEIVED);
    res = dnie_sm_find_tlv(card,from,0x97,&m_tlv); /* MAC data (mandatory) */
    LOG_TEST_RET(ctx,res,"MAC CC TLV not found in response apdu");
    /* compose buffer to evaluate mac */
    /* TODO: write */
    /* evaluate mac by mean of kmac and increased SendSequence Counter SSC */
    /* TODO: write */
    /* check evaluated mac with provided by apdu response */
    /* TODO: write */
    if (p_tlv.value) { /* plain data */
        /* copy to response buffer */
        /* TODO: write */
    }
    if (d_tlv.value) { /* encoded data */
        /* decrypt by mean of kenc and iv={0,...0} */
        /* TODO: write */
        /* copy decrypted data to response buffer */
        /* TODO: write */
    }
    /* copy SW bytes. As CWA states, don't use s_tlv, as may not be present */
    /* TODO: write */
    /* finally compose rest of destination apdu */
    /* TODO: write */

    /* that's all folks */
    LOG_FUNC_RETURN(ctx,SC_SUCCESS);
}

/************************* public functions ***************/
int dnie_sm_init(
        struct sc_card *card,
        dnie_sm_handler_t **sm_handler,
        int final_state) {
    dnie_sm_handler_t *handler;
    int result;
    if( (card==NULL) || (card->ctx==NULL) || (sm_handler==NULL))
        return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;
    LOG_FUNC_CALLED(ctx);
    if (*sm_handler==NULL) {
        /* not initialized yet: time to do */
        handler=(dnie_sm_handler_t *) calloc(1,sizeof( dnie_sm_handler_t ));
        if (handler==NULL) return SC_ERROR_OUT_OF_MEMORY;
        handler->sm_internal=(dnie_internal_sm_t *) 
            calloc(1,sizeof( dnie_internal_sm_t ));
        if (handler->sm_internal==NULL) return SC_ERROR_OUT_OF_MEMORY;
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
        LOG_FUNC_RETURN(ctx,SC_SUCCESS);
    }
    /* call de-init if required*/
    if ( handler->deinit!=NULL) {
        result=handler->deinit(card);
        LOG_TEST_RET(ctx,result,"SM Deinit() failed");
    }
    /* now initialize to requested state */
    switch(final_state) {
        case DNIE_SM_NONE: 
            handler->deinit = NULL;
            handler->encode = NULL;
            handler->encode = NULL;
            break;
        case DNIE_SM_INPROGRESS: /* work in progress; (what about locks?) */
            LOG_FUNC_RETURN(ctx,SC_ERROR_NOT_ALLOWED);
        case DNIE_SM_INTERNAL:
            handler->state=DNIE_SM_INPROGRESS;
            result = dnie_sm_create_secure_channel(card,handler);
            if (result!=SC_SUCCESS) goto sm_init_error;
            handler->encode = dnie_sm_internal_encode_apdu;
            handler->decode = dnie_sm_internal_decode_apdu;
            /* TODO: write and uncomment */
            /* handler->deinit = dmie_sm_internal_deinit; */
            break;
        case DNIE_SM_EXTERNAL:
            /* TODO: support for remote (SSL) APDU handling */ 
            LOG_FUNC_RETURN(ctx,SC_ERROR_NOT_SUPPORTED);
        default:
            LOG_FUNC_RETURN(ctx,SC_ERROR_INVALID_ARGUMENTS);
    }
    /* arriving here means success */
    handler->state=final_state;
    LOG_FUNC_RETURN(ctx,SC_SUCCESS);

sm_init_error:
    /* error in init: back into non-sm mode */
    handler->state=DNIE_SM_NONE;
    handler->deinit = NULL;
    handler->encode = NULL;
    handler->encode = NULL;
    LOG_FUNC_RETURN(ctx,result);
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
    LOG_FUNC_CALLED(card->ctx);
    switch (handler->state) {
      case DNIE_SM_NONE:
      case DNIE_SM_INPROGRESS:
         /* just copy structure data */
         *to=*from; /* implicit memcpy() */
         LOG_FUNC_RETURN(card->ctx,SC_SUCCESS);
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
         LOG_FUNC_RETURN(card->ctx,SC_ERROR_INTERNAL);
    }
dnie_wrap_apdu_end:
    LOG_FUNC_RETURN(card->ctx,result);
}

/* end of secure_messaging.c */
#undef __SM_DNIE_C__

#endif /* ENABLE_OPENSSL */

