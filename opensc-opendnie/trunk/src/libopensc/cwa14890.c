/*
 * cwa14890.c: Implementation of Secure Messaging 
 * according CWA-14890-1 and CWA-14890-2 standards
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

#define __CWA14890_C__
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

#include "cwa14890.h"

/*********************** utility functions ************************/

/**
 * Increase send sequence counter SSC
 *
 *@param card smart card info structure
 *@param sm Secure Message handling data structure
 *@return SC_SUCCESS if ok; else error code
 *
 * to further study: what about using bignum arithmetics?
 */
static int cwa_increase_ssc(
    sc_card_t *card,
    cwa_sm_status_t *sm) {
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
static void cwa_iso7816_padding(u8 *buffer,size_t *len) {
    *(buffer+*len++)=0x80;
    for(; (*len & 0x07)==0x00; *len++) *(buffer+*len)=0x00;
}

/**
 * compose a BER-TLV data in provided buffer 
 * Multybyte tag id are not supported
 * Also multibyte id 0x84 is unhandled
 *
 * Notice that TLV is composed starting at offset lenght from
 * the buffer. Consecutive calls to cwa_add_tlv, appends a new
 * TLV at the end of the buffer
 *
 *@param card card info structure
 *@param tag tag id
 *@param len data length
 *@param value data buffer
 *@param out pointer to dest data
 *@param outlen length of composed tlv data
 *@return SC_SUCCESS if ok; else error
 */
static int cwa_compose_tlv(
        sc_card_t *card,
        u8 tag,
        size_t len,
        u8 *data,
        u8 **out,
        size_t *outlen) {
    /* preliminary checks */
    if ( !card || !card->ctx || !out || !outlen) 
        return SC_ERROR_INVALID_ARGUMENTS;
    /* comodity vars */
    sc_context_t *ctx=card->ctx; 
    LOG_FUNC_CALLED(ctx);

    /* assume tag id is not multibyte */
    *(*out+*outlen++)=tag;
    /* evaluate tag length value according iso7816-4 sect 5.2.2 */
    if (len<0x80) {
        *(*out+*outlen++)=len; 
    } else if (len<0x00000100) {
        *(*out+*outlen++)=0x81;
        *(*out+*outlen++)=0xff & len; 
    } else if (len<0x00010000) {
        *(*out+*outlen++)=0x82;
        *(*out+*outlen++)=0xff & (len>> 8);
        *(*out+*outlen++)=0xff & len;
    } else if (len<0x01000000) {
        *(*out+*outlen++)=0x83;
        *(*out+*outlen++)=0xff & (len>>16);
        *(*out+*outlen++)=0xff & (len>> 8);
        *(*out+*outlen++)=0xff & len;
    } else { /* do not handle tag length 0x84 */
        LOG_FUNC_RETURN(ctx,SC_ERROR_INVALID_ARGUMENTS);
    }
    /* copy remaining data to buffer */
    if (len!=0) memcpy(*out+*outlen,data,len);
    *outlen+=len;
    LOG_FUNC_RETURN(ctx,SC_SUCCESS);
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
static int cwa_find_tlv(
   sc_card_t *card,
   sc_apdu_t *apdu,
   unsigned int tag,
   cwa_tlv_t *tlv 
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
        tlv->tlv_start=pt;
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
        tlv->len     = tlen;
        tlv->data    = pt;
        tlv->tlv_len = (pt+tlen) - tlv->tlv_start;
        LOG_FUNC_RETURN(ctx,SC_SUCCESS);
    }
    /* arriving here means requested tlv not found */
    memset(tlv,0,sizeof(struct sc_tlv_data)); /* clear info */
    LOG_FUNC_RETURN(ctx,SC_SUCCESS);
}

/*********************** authentication routines *******************/

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
static int cwa_verify_icc_certificates(
       sc_card_t *card,
       cwa_provider_t *provider,
       X509 *sub_ca_cert,
       X509 *icc_cert
    ) {
    char *msg;
    int res=SC_SUCCESS;
    EVP_PKEY *root_ca_key=NULL;
    EVP_PKEY *sub_ca_key=NULL;
    /* safety check */
    if( (card!=NULL) || (card->ctx!=NULL) || (!provider ) )
        return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;
    LOG_FUNC_CALLED(ctx);
    if (!sub_ca_cert || !icc_cert ) /* check received arguments */
        LOG_FUNC_RETURN(ctx,SC_ERROR_INVALID_ARGUMENTS);

    /* retrieve root ca pkey from provider */
    res=provider->cwa_get_root_ca_pubkey(card,&root_ca_key);
    if (res!=SC_SUCCESS) {
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
    if (root_ca_key) EVP_PKEY_free(root_ca_key); 
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
static int cwa_verify_cvc_certificate(
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
static int cwa_set_security_env(
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
static int cwa_internal_auth( 
        sc_card_t *card,
        cwa_sm_status_t *sm,
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
 * Compose signature data for external auth according CWA-14890
 * Store resulting data  into sm->sig
 *@param card pointer to st_card_t card data information
 *@param icc_pubkey public key of card
 *@param ifd_privkey private RSA key of ifd
 *@param serial card serial number
 *@param sm pointer to cwa_internal_t data
 *@return SC_SUCCESS if ok; else errorcode
 */
static int cwa_prepare_external_auth(
        sc_card_t *card,
        RSA *icc_pubkey,
        RSA *ifd_privkey,
        sc_serial_number_t *serial,
        cwa_sm_status_t *sm
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
    if (BN_num_bytes(bnres)>128) {
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

    /* process done: copy result into cwa_internal buffer and return success */
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
static int cwa_external_auth( sc_card_t *card, cwa_sm_status_t *sm) {
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
 *@param sm pointer to cwa_internal_t data
 *@return SC_SUCCESS if ok; else error code
 */
static int cwa_compute_session_keys(
        sc_card_t *card,
        cwa_sm_status_t *sm ) {

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
    /* compose kseed  (cwa-14890-1 sect 8.7.2) */
    for (n=0;n<32;n++) *(kseed+n)= *(sm->kicc+n) ^ *(sm->kifd+n);

    /* evaluate kenc (cwa-14890-1 sect 8.8) */
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

    /* evaluate send sequence counter  (cwa-14890-1 sect 8.9 & 9.6 */
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
static int cwa_compare_signature(
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
static int cwa_verify_internal_auth(
        sc_card_t *card,
	RSA *icc_pubkey,
        RSA *ifd_privkey,
        u8 *ifdbuf,
        size_t ifdlen,
        cwa_sm_status_t *sm
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
    res=cwa_compare_signature(buf2,len2,ifdbuf);
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
    res=cwa_compare_signature(buf3,len3,ifdbuf);
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
 *@param card card info structure
 *@param provider cwa14890 info provider
 *@param flag requested init method ( OFF, COLD, WARM )
 *@return SC_SUCCESS if OK; else error code
 */
int cwa_create_secure_channel( 
        sc_card_t *card,
        cwa_provider_t *provider,
        int flag ) {
    u8 *cert;
    size_t certlen;

    int res=SC_SUCCESS;
    char *msg="Success";

    sc_serial_number_t *serial;

    /* data to get and parse certificates */
    X509 *icc_cert=NULL;
    X509 *ca_cert=NULL;
    EVP_PKEY *icc_pubkey=NULL;
    EVP_PKEY *ifd_privkey=NULL;

    
    /* several buffer and buffer pointers */
    u8 *buffer;
    size_t bufferlen;
    u8 *tlv=NULL; /* buffer to compose TLV messages */
    size_t tlvlen=0;

    /* preliminary checks */
    if ( !card || !card->ctx || !provider ) return SC_ERROR_INVALID_ARGUMENTS;

    /* comodity vars */
    sc_context_t *ctx=card->ctx; 
    cwa_sm_status_t *sm=&(provider->status);

    LOG_FUNC_CALLED(ctx);

    /* check requested initialization method */
    switch (flag) {
        case CWA_SM_OFF: /* disable SM */
            provider->status.state=CWA_SM_NONE; /* just mark channel inactive */
            sc_log(ctx,"Setting CWA SM status to none");
            LOG_FUNC_RETURN(ctx,SC_SUCCESS);
        case CWA_SM_WARM: /* only initialize if not already done */
            if (provider->status.state!=CWA_SM_NONE) {
                sc_log(ctx,"Warm CWA SM requested: already in SM state");
                LOG_FUNC_RETURN(ctx,SC_SUCCESS);
            }
        case CWA_SM_COLD: /* force sm initialization process */
            sc_log(ctx,"CWA SM initialization requested");
            break;
        default:
            sc_log(ctx,"Invalid provided SM initialization flag");
            LOG_FUNC_RETURN(ctx,SC_ERROR_INVALID_ARGUMENTS);
    }

    /* call provider pre-operation method */
    sc_log(ctx,"CreateSecureChannel pre-operations");
    if (provider->cwa_create_pre_ops) {
        res=provider->cwa_create_pre_ops(card,provider);
        if (res!=SC_SUCCESS) {
            sc_log(ctx,"Create SM: provider pre_ops() failed");
            goto csc_end;
        }
    }

    /* reset card (warm reset, do not unpower card) */
    sc_log(ctx,"Resseting card");
    sc_reset(card,0); 

    /* Retrieve Card serial Number */
    sc_log(ctx,"Retrieving ICC Serial Number");
    serial= (sc_serial_number_t *)calloc(1,sizeof(sc_serial_number_t));
    if (!serial) {
        sc_log(ctx,"Cannot allocate space for serial_nr data");
        LOG_FUNC_RETURN(ctx,SC_ERROR_OUT_OF_MEMORY);
    }
    res=provider->cwa_get_sn_icc(card,&serial);
    if (res!=SC_SUCCESS) { msg="CWA Cannot get ICC serialnr"; goto csc_end; }

    /* 
    * Notice that this code inverts ICC and IFD certificate standard
    * checking sequence.
    */

    /* Read Intermediate CA from card */
    if (!provider->cwa_get_icc_intermediate_ca_cert) {
        sc_log(ctx,"Step 8.4.1.6: Skip Retrieveing ICC intermediate CA");
        ca_cert=NULL;
    } else {
        sc_log(ctx,"Step 8.4.1.7: Retrieving ICC intermediate CA");
        res=provider->cwa_get_icc_intermediate_ca_cert(card,&ca_cert);
        if (res!=SC_SUCCESS) { 
            msg="Cannot get ICC intermediate CA certificate from provider";
            goto csc_end;
        }
    }

    /* Read ICC certificate from card */ 
    sc_log(ctx,"Step 8.4.1.8: Retrieve ICC certificate");
    res=provider->cwa_get_icc_cert(card,&icc_cert);
    if (res!=SC_SUCCESS) { 
        msg="Cannot get ICC certificate from provider";
        goto csc_end;
    }

    /* Verify icc Card certificate chain */
    /* Notice that Some implementations doesn't verify cert chain
     * but simply verifies that icc_cert is a valid certificate */
    if (ca_cert) {
        sc_log(ctx,"Verifying ICC certificate chain");
        res=cwa_verify_icc_certificates(card,provider,ca_cert,icc_cert);
        if (res!=SC_SUCCESS) {
            res=SC_ERROR_OBJECT_NOT_VALID;
            msg="Icc Certificates verification failed";
            goto csc_end;
        }
    } else {
        sc_log(ctx,"Cannot verify Certificate chain. skip step");
    }

    /* Extract public key from ICC certificate */
    icc_pubkey=X509_get_pubkey(icc_cert);

    /* Select Root CA in card for ifd certificate verification */
    sc_log(ctx,"Step 8.4.1.2: Select Root CA in card for IFD cert verification");
    res=provider->cwa_get_root_ca_pubkey_ref(card,&buffer,&bufferlen);
    if (res!=SC_SUCCESS) { 
        msg="Cannot get Root CA key reference from provider";
        goto csc_end;
    }
    tlvlen=0;
    tlv=calloc(10+bufferlen,sizeof(u8));
    if (!tlv) { msg="calloc error"; res=SC_ERROR_OUT_OF_MEMORY; goto csc_end; }
    res =cwa_compose_tlv(card,0x83,bufferlen,buffer,&tlv,&tlvlen);
    if (res!=SC_SUCCESS) {
        msg="Cannot compose tlv for setting Root CA key reference";
        goto csc_end;
    }
    res=cwa_set_security_env(card,0x81,0xB6,tlv,tlvlen);
    if (res!=SC_SUCCESS) { msg="Select Root CA key ref failed"; goto csc_end; }

    /* Send IFD intermediate CA in CVC format C_CV_CA */
    sc_log(ctx,"Step 8.4.1.3: Send CVC IFD intermediate CA Cert for ICC verification");
    res=provider->cwa_get_cvc_ca_cert(card,&cert,&certlen);
    if (res!=SC_SUCCESS) { 
        msg="Get CVC CA cert from provider failed";
        goto csc_end;
    }
    res=cwa_verify_cvc_certificate(card,cert,certlen);
    if (res!=SC_SUCCESS) { msg="Verify CVC CA failed"; goto csc_end; }

    /* select public key reference for sent IFD intermediate CA certificate */
    sc_log(ctx,"Step 8.4.1.4: Select Intermediate CA pubkey ref for ICC verification");
    res=provider->cwa_get_intermediate_ca_pubkey_ref(card,&buffer,&bufferlen);
    if (res!=SC_SUCCESS) { 
        msg="Cannot get intermediate CA key reference from provider";
        goto csc_end;
    }
    tlvlen=0;
    free(tlv);
    tlv=calloc(10+bufferlen,sizeof(u8));
    if (!tlv) { msg="calloc error"; res=SC_ERROR_OUT_OF_MEMORY; goto csc_end; }
    res =cwa_compose_tlv(card,0x83,bufferlen,buffer,&tlv,&tlvlen);
    if (res!=SC_SUCCESS) {
        msg="Cannot compose tlv for setting intermeditate CA key reference";
        goto csc_end;
    }
    res=cwa_set_security_env(card,0x81,0xB6,tlv,tlvlen);
    if (res!=SC_SUCCESS) { msg="Select CVC CA pubk failed"; goto csc_end; }

    /* Send IFD certiticate in CVC format C_CV_IFD */
    sc_log(ctx,"Step 8.4.1.5: Send CVC IFD Certificate for ICC verification");
    res=provider->cwa_get_cvc_ifd_cert(card,&cert,&certlen);
    if (res!=SC_SUCCESS) { 
        msg="Get CVC IFD cert from provider failed";
        goto csc_end;
    }
    res=cwa_verify_cvc_certificate(card,cert,certlen);
    if (res!=SC_SUCCESS) { msg="Verify CVC IFD failed"; goto csc_end; }

    /* remember that this code changes IFD and ICC Cert verification steps */

    /* select public key of ifd certificate and icc private key */ 
    sc_log(ctx,"Step 8.4.1.9: Send IFD pubk and ICC privk key references for Internal Auth");
    res=provider->cwa_get_ifd_pubkey_ref(card,&buffer,&bufferlen);
    if (res!=SC_SUCCESS) { 
        msg="Cannot get ifd public key reference from provider";
        goto csc_end;
    }
    tlvlen=0;
    free(tlv);
    tlv=calloc(10+bufferlen,sizeof(u8));
    if (!tlv) { msg="calloc error"; res=SC_ERROR_OUT_OF_MEMORY; goto csc_end; }
    res =cwa_compose_tlv(card,0x83,bufferlen,buffer,&tlv,&tlvlen);
    if (res!=SC_SUCCESS) {
        msg="Cannot compose tlv for setting ifd pubkey reference";
        goto csc_end;
    }
    res=provider->cwa_get_icc_privkey_ref(card,&buffer,&bufferlen);
    if (res!=SC_SUCCESS) { 
        msg="Cannot get icc private key reference from provider";
        goto csc_end;
    }
    /* add this tlv to old one; do not call calloc */
    res =cwa_compose_tlv(card,0x84,bufferlen,buffer,&tlv,&tlvlen);
    if (res!=SC_SUCCESS) {
        msg="Cannot compose tlv for setting ifd pubkey reference";
        goto csc_end;
    }

    res=cwa_set_security_env(card,0x81,0xB6,tlv,tlvlen);
    if (res!=SC_SUCCESS) { msg="Select CVC IFD pubk failed"; goto csc_end; }

    /* Internal (Card) authentication (let the card verify sent ifd certs) 
     SN.IFD equals 8 lsb bytes of ifd.pubk ref according cwa14890 sec 8.4.1 */
    sc_log(ctx,"Step 8.4.1.10: Perform Internal authentication");
    res=provider->cwa_get_sn_ifd(card,&buffer,&bufferlen);
    if (res!=SC_SUCCESS) { 
        msg="Cannot get ifd serial number from provider";
        goto csc_end;
    }
    u8 *rndbuf=calloc(8 /*RND.IFD*/+ 8 /*SN.IFD*/ , sizeof(u8) );
    if (!rndbuf) {
        msg="Cannot calloc for RND.IFD+SN.IFD";
        res=SC_ERROR_OUT_OF_MEMORY;
        goto csc_end;
    }
    RAND_bytes(sm->rndifd,8); /* generate 8 random bytes */
    memcpy(rndbuf,sm->rndifd,8); /* insert RND.IFD into rndbuf */
    memcpy(rndbuf+8,buffer,8); /* insert SN.IFD into rndbuf */
    res=cwa_internal_auth(card,sm,rndbuf,sizeof(rndbuf));
    if (res!=SC_SUCCESS) { 
        msg="Internal auth cmd failed"; 
        goto csc_end;
    }

    /* retrieve ifd private key from provider */
    res=provider->cwa_get_ifd_privkey(card,&ifd_privkey);
    if (res!=SC_SUCCESS) {
        msg="Cannot retrieve IFD private key from provider";
        res=SC_ERROR_INTERNAL;
        goto csc_end;
    }
    
    /* verify received signature */
    sc_log(ctx,"Verify Internal Auth command response");
    res=cwa_verify_internal_auth(
        card,
	icc_pubkey->pkey.rsa,     /* evaluated icc public key */
        ifd_privkey->pkey.rsa,    /* evaluated from DGP's Manual Annex 3 Data */
        rndbuf,         /* RND.IFD || SN.IFD */
        sizeof(rndbuf), /* rndbuf length; should be 16 */
        sm              /* sm data */
    );    
    if (res!=SC_SUCCESS) { msg="Internal Auth Verify failed"; goto csc_end; }

    /* get challenge: retrieve 8 random bytes from card */
    sc_log(ctx,"Step 8.4.1.11: Prepare External Auth: Get Challenge");
    res=card->ops->get_challenge(card,sm->rndicc,sizeof(sm->rndicc));
    if (res!=SC_SUCCESS) { msg="Get Challenge failed"; goto csc_end; }

    /* compose signature data for external auth */
    res=cwa_prepare_external_auth(
        card,
        icc_pubkey->pkey.rsa,
        ifd_privkey->pkey.rsa,
        serial,
        sm
    );
    if (res!=SC_SUCCESS) { msg="Prepare external auth failed"; goto csc_end; }

    /* External (IFD)  authentication */
    sc_log(ctx,"Step 8.4.1.12: Perform External (IFD) Authentication");
    res=cwa_external_auth(card,sm);
    if (res!=SC_SUCCESS) { msg="External auth cmd failed"; goto csc_end; }

    /* Session key generation */
    sc_log(ctx,"Step 8.4.2: Compute Session Keys");
    res=cwa_compute_session_keys(card,sm);
    if (res!=SC_SUCCESS) { msg="Session Key generation failed"; goto csc_end; }

    /* call provider post-operation method */
    sc_log(ctx,"CreateSecureChannel post-operations");
    if (provider->cwa_create_post_ops) {
        res=provider->cwa_create_post_ops(card,provider);
        if (res!=SC_SUCCESS) {
            sc_log(ctx,"Create SM: provider post_ops() failed");
            goto csc_end;
        }
    }

    /* arriving here means ok: cleanup */
    res=SC_SUCCESS;
csc_end:
    if (serial)  { memset(serial,0,sizeof(sc_serial_number_t)); free(serial); }
    if (buffer)      free(buffer); /* no need to memset */
    if (icc_pubkey)  EVP_PKEY_free(icc_pubkey);
    if (ifd_privkey) EVP_PKEY_free(ifd_privkey);
    if (res!=SC_SUCCESS) sc_log(ctx,msg);
    LOG_FUNC_RETURN(ctx,res);
}

/******************* SM internal APDU encoding / decoding functions ******/

/**
 * Encode an APDU
 * Calling this functions means that It's has been verified
 * That source apdu needs encoding
 * Based on section 9 of CWA-14890 and Sect 6 of iso7816-4 standards
 * And DNIe's manual
 *
 *@param card card info structure
 *@param sm Secure Messaging state information
 *@param apdu APDU to be encoded
 *@return SC_SUCCESS if ok; else error code
 */
int cwa_encode_apdu(
    sc_card_t *card,
    cwa_provider_t *provider,
    sc_apdu_t *apdu
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
    if( !card || !card->ctx || !provider) return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;
    cwa_sm_status_t *sm=&(provider->status);

    LOG_FUNC_CALLED(ctx);
    /* check remaining arguments */
    if ((apdu==NULL) || (sm==NULL)) 
            LOG_FUNC_RETURN(ctx,SC_ERROR_INVALID_ARGUMENTS);
    if (sm->state != CWA_SM_ACTIVE) LOG_FUNC_RETURN(ctx,SC_ERROR_INTERNAL);

    /* check if APDU is already encoded */
    if ((apdu->cla & 0x0C)==0) return SC_SUCCESS; /* already encoded */
    if (apdu->ins == 0xC0) return SC_SUCCESS; /* dont encode GET Response cmd */
 
    /* call provider pre-operation method */
    if (provider->cwa_encode_pre_ops) {
        res=provider->cwa_encode_pre_ops(card,provider,apdu);
        if (res!=SC_SUCCESS) {
            sc_log(ctx,"Encode APDU: provider pre_ops() failed");
            LOG_FUNC_RETURN(ctx,res);
        }
    }

    /* allocate result apdu data buffer */
    apdubuf=calloc(SC_MAX_APDU_BUFFER_SIZE,sizeof(u8));
    ccbuf=calloc(SC_MAX_APDU_BUFFER_SIZE,sizeof(u8));
    if (!apdubuf || !ccbuf ) LOG_FUNC_RETURN(ctx,SC_ERROR_OUT_OF_MEMORY);

    /* fill buffer with header info */
    *(ccbuf+len++)=apdu->cla;
    *(ccbuf+len++)=apdu->ins;
    *(ccbuf+len++)=apdu->p1;
    *(ccbuf+len++)=apdu->p2;
    cwa_iso7816_padding(ccbuf,&len); /* pad header (4 bytes pad) */

    /* if no data, skip data encryption step */
    if (apdu->lc!=0) {
        size_t dlen=apdu->datalen;
        u8 msgbuf[SC_MAX_APDU_BUFFER_SIZE];
        u8 cryptbuf[SC_MAX_APDU_BUFFER_SIZE];

        /* prepare keys */
        DES_cblock iv={0,0,0,0,0,0,0,0};
        DES_set_key_unchecked((const_DES_cblock *)&(sm->kenc[0]), &k1);
        DES_set_key_unchecked((const_DES_cblock *)&(sm->kenc[8]), &k2);

        /* pad message */
        memcpy (msgbuf,apdu->data,dlen);
        cwa_iso7816_padding(msgbuf,&dlen);

        /* aply TDES + CBC with kenc and iv=(0,..,0) */
        DES_ede3_cbc_encrypt(msgbuf,cryptbuf,dlen,&k1,&k2,&k1,&iv,DES_ENCRYPT);

        /* compose data TLV and add to result buffer */
        /* assume tag id is not multibyte */
        *(ccbuf+len++)=0x87; /* padding content indicator + cryptogram tag */
        /* evaluate tag length value according iso7816-4 sect 5.2.2 */
        if ((dlen+1)<0x80) {
            *(ccbuf+len++)=dlen+1; /* len is dlen + iso padding indicator */
        } else if ((dlen+1)<0x00000100) {
            *(ccbuf+len++)=0x81;
            *(ccbuf+len++)=0xff & (dlen+1); /* dlen +  padding indicator byte */
        } else if ((dlen+1)<0x00010000) {
            *(ccbuf+len++)=0x82;
            *(ccbuf+len++)=0xff & ( (dlen+1) >> 8);
            *(ccbuf+len++)=0xff & (dlen+1); 
        } else if ((dlen+1)<0x01000000) {
            *(ccbuf+len++)=0x83;
            *(ccbuf+len++)=0xff & ( (dlen+1) >>16);
            *(ccbuf+len++)=0xff & ( (dlen+1) >> 8);
            *(ccbuf+len++)=0xff & (dlen+1); 
        } else { /* do not handle tag length 0x84 */
            LOG_FUNC_RETURN(ctx,SC_ERROR_INVALID_ARGUMENTS);
        }

        /* add iso padding type indicator */
        *(ccbuf+len++)=0x01;   

        /* copy remaining data to buffer */
        memcpy(ccbuf+len,cryptbuf,dlen);
        len+=dlen;
    }

    /* if le byte is declared, compose and add Le TLV */
    /* TODO: study why original driver checks for le>=256? */
    if (apdu->le>0) {
        *(ccbuf+len++)=0x97; /* TLV tag for CC protected Le */
        *(ccbuf+len++)=0x01; /* length=1 byte */
        *(ccbuf+len++)=apdu->le;
    }
    /* copy current data to apdu buffer (skip header and header padding) */
    memcpy(apdubuf,ccbuf+8,len-8);
    apdulen=len-8;
    /* pad again ccbuffer to compute CC */
    cwa_iso7816_padding(ccbuf,&len);

    /* compute MAC Cryptographic Checksum using kmac and increased SSC */
    res=cwa_increase_ssc(card,sm); /* increase send sequence counter */
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

    /* rewrite resulting header */
    apdu->cla |= 0x0C; /* mark apdu as encoded */
    apdu->lc=apdulen;
    apdu->data=apdubuf;
    apdu->datalen=apdulen;

    /* call provider post-operation method */
    if (provider->cwa_encode_post_ops) {
        res=provider->cwa_encode_post_ops(card,provider,apdu);
        if (res!=SC_SUCCESS) {
            sc_log(ctx,"Encode APDU: provider post_ops() failed");
            LOG_FUNC_RETURN(ctx,res);
        }
    }

    /* that's all folks */
    LOG_FUNC_RETURN(ctx,SC_SUCCESS);
}

/**
 * Decode an APDU response
 * Calling this functions means that It's has been verified
 * That apdu response comes in TLV encoded format and needs decoding
 * Based on section 9 of CWA-14890 and Sect 6 of iso7816-4 standards
 * And DNIe's manual
 *
 *@param card card info structure
 *@param sm Secure Messaging state information
 *@param apdu APDU with response to be decoded
 *@return SC_SUCCESS if ok; else error code
 */
int cwa_decode_response(
    sc_card_t *card,
    cwa_provider_t *provider,
    sc_apdu_t *apdu
    ) {
    int i,j;
    cwa_tlv_t p_tlv; /* to store plain data (Tag 0x81) */
    cwa_tlv_t e_tlv; /* to store padded encoded data (Tag 0x87) */
    cwa_tlv_t m_tlv; /* to store mac CC (Tag 0x97) */
    cwa_tlv_t s_tlv; /* to store sw1-sw2 status (Tag 0x99) */
    u8 *ccbuf;      /* buffer for mac CC calculation */
    size_t cclen;   /* ccbuf len */
    u8 macbuf[8];   /* where to calculate mac */
    u8 *respbuf;    /* where to store decoded response */
    size_t resplen; /* respbuf length */
    DES_key_schedule k1, k2;
    int res=SC_SUCCESS;
    char *msg=NULL;             /* to store error messages */

    /* mandatory check */
    if( !card || !card->ctx || !provider ) return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;
    cwa_sm_status_t *sm=&(provider->status);

    LOG_FUNC_CALLED(ctx);

    /* check remaining arguments */
    if ((apdu==NULL) || (sm==NULL)) 
            LOG_FUNC_RETURN(ctx,SC_ERROR_INVALID_ARGUMENTS);
    if ( sm->state != CWA_SM_ACTIVE ) LOG_FUNC_RETURN(ctx,SC_ERROR_INTERNAL);

    /* cwa14890 sect 9.3: check SW1 or SW2 for SM related errors */
    if (apdu->sw1==0x69) {
        if ( (apdu->sw2==0x88) || (apdu->sw2==0x87) ) {
            msg="SM related errors in APDU response";
            res=SC_ERROR_INTERNAL; /* tell driver to restart SM */
            goto response_decode_end;
        }
    }

    /* checks if apdu response needs decoding by checking tags in response*/
    switch (apdu->resp[0]) {
        case CWA_SM_PLAIN_TAG: 
        case CWA_SM_CRYPTO_TAG: 
        case CWA_SM_MAC_TAG: 
        case CWA_SM_LE_TAG: 
        case CWA_SM_STATUS_TAG: break; /* cwa tags found: continue decoding */
        default:   /* else apdu response seems not to be cwa encoded */
           sc_log(card->ctx,"APDU Response seems not to be cwa encoded");
           return SC_SUCCESS; /* let process continue */
    }

    /* call provider pre-operation method */
    if (provider->cwa_decode_pre_ops) {
        res=provider->cwa_decode_pre_ops(card,provider,apdu);
        if (res!=SC_SUCCESS) {
            sc_log(ctx,"Decode APDU: provider pre_ops() failed");
            LOG_FUNC_RETURN(ctx,res);
        }
    }

    /* parse response to find TLV data and check results */
    cwa_find_tlv(card,apdu,0x99,&s_tlv); /* status data (optional) */
    cwa_find_tlv(card,apdu,0x87,&e_tlv); /* encoded data (optional) */
    cwa_find_tlv(card,apdu,0x81,&p_tlv); /* plain data (optional) */
    cwa_find_tlv(card,apdu,0x97,&m_tlv); /* MAC data (mandatory) */
    if (p_tlv.data && e_tlv.data) { /* encoded & plain are exclusive */
        msg="Plain and Encoded data are mutually exclusive in apdu response";
        res=SC_ERROR_INVALID_DATA;
        goto response_decode_end;
    }
    if (!m_tlv.data) {
        msg="No MAC TAG found in apdu response";
        res=SC_ERROR_INVALID_DATA;
        goto response_decode_end;
    }
    if (m_tlv.len != 4) {
        msg="Invalid MAC TAG Length";
        res=SC_ERROR_INVALID_DATA;
        goto response_decode_end;
    }

    /* compose buffer to evaluate mac */

    /* reserve enought space for data+status+padding */
    ccbuf=calloc(e_tlv.tlv_len + s_tlv.tlv_len + p_tlv.tlv_len + 8,sizeof(u8));
    if (!ccbuf) {
        msg="Cannot allocate space for mac checking";
        res=SC_ERROR_OUT_OF_MEMORY;
        goto response_decode_end;
    }
    /* copy data into buffer */
    cclen=0;
    if (e_tlv.data) { /* encoded data */
        memcpy(ccbuf,e_tlv.tlv_start,e_tlv.tlv_len);
        cclen = e_tlv.tlv_len;
    }
    if (p_tlv.data) { /* plain data */
        memcpy(ccbuf,p_tlv.tlv_start,p_tlv.tlv_len);
        cclen = p_tlv.tlv_len;
    }
    if (s_tlv.data) { /* response status */
        if (s_tlv.len!=2) {
            msg="Invalid SW TAG length";
            res=SC_ERROR_INVALID_DATA;
            goto response_decode_end;
        }
        memcpy(ccbuf+cclen,s_tlv.tlv_start,s_tlv.tlv_len);
        cclen += s_tlv.tlv_len;
    }
    /* add iso7816 padding */
    cwa_iso7816_padding(ccbuf,&cclen);

    /* evaluate mac by mean of kmac and increased SendSequence Counter SSC */

    /* increase SSC */
    res=cwa_increase_ssc(card,sm); /* increase send sequence counter */
    if (res!=SC_SUCCESS) {
        msg="Error in computing SSC";
        goto response_decode_end;
    }
    /* set up keys for mac computing */
    DES_set_key_unchecked((const_DES_cblock *)&(sm->kmac[0]), &k1);
    DES_set_key_unchecked((const_DES_cblock *)&(sm->kmac[8]), &k2);

    memcpy(macbuf,sm->ssc,8); /* start with computed SSC */
    for (i=0;i<cclen;i+=8) { /* divide data in 8 byte blocks */
        /* compute DES */
        DES_ecb_encrypt((const_DES_cblock *)macbuf, (DES_cblock *)macbuf, &k1, DES_ENCRYPT);
        /* XOR with data and repeat */
        for (j=0;j<8;j++) macbuf[j] ^= ccbuf[i+j];
    }
    /* finally apply 3DES to result */
    DES_ecb2_encrypt((const_DES_cblock *)macbuf, (DES_cblock *)macbuf, &k1, &k2, DES_ENCRYPT);

    /* check evaluated mac with provided by apdu response */

    res=memcmp(m_tlv.data,macbuf,4); /* check first 4 bytes */
    if (res!=0) {
        msg="Error in MAC CC checking: value doesn't match";
        res=SC_ERROR_INVALID_DATA;
        goto response_decode_end;
    }

    /* allocate response buffer */
    resplen= 10 + MAX(p_tlv.len,e_tlv.len); /* estimate response buflen */
    if (apdu->resp) { /* if response apdu provides buffer, try to use it */
        if(apdu->resplen<resplen) {
            msg="Provided buffer has not enought size to store response";
            res=SC_ERROR_OUT_OF_MEMORY;
            goto response_decode_end;
        }
    } else { /* buffer not provided: create and assing to response apdu */
        apdu->resp=calloc(p_tlv.len,sizeof(u8));
        if (!apdu->resp) {
            msg="Cannot allocate buffer to store response";
            res=SC_ERROR_OUT_OF_MEMORY;
            goto response_decode_end;
        }
    }
    apdu->resplen=resplen;
    
    /* fill destination response apdu buffer with data */

    /* if plain data, just copy TLV data into apdu response */
    if (p_tlv.data) { /* plain data */
        memcpy(apdu->resp,p_tlv.data,p_tlv.len);
        apdu->resplen=p_tlv.len;
    }

    /* if encoded data, decode and store into apdu response */
    if (e_tlv.data) { /* encoded data */
        DES_cblock iv = {0,0,0,0,0,0,0,0};
        /* check data len */
        if ( (e_tlv.len<9) || ((e_tlv.len-1)%8)!=0) {
            msg="Invalid length for Encoded data TLV";
            res=SC_ERROR_INVALID_DATA;
            goto response_decode_end;
        }
        /* first byte is padding info; check value */
        if (e_tlv.data[0]!=0x01) {
            msg="Encoded TLV: Invalid padding info value";
            res=SC_ERROR_INVALID_DATA;
            goto response_decode_end;
        }
        /* prepare keys to decode */
        DES_set_key_unchecked((const_DES_cblock *)&(sm->kenc[0]), &k1);
        DES_set_key_unchecked((const_DES_cblock *)&(sm->kenc[8]), &k2);
        /* decrypt into response buffer
         * by using 3DES CBC by mean of kenc and iv={0,...0} */
        DES_ede3_cbc_encrypt(&e_tlv.data[1],apdu->resp,e_tlv.len-1,&k1,&k2,&k1,&iv, DES_DECRYPT);
        apdu->resplen=e_tlv.len-1;
        /* remove iso padding from response length */
        for(; (apdu->resplen > 0)  && (*(apdu->resp+apdu->resplen)==0x00) ; apdu->resplen-- ); /* empty loop */
        if (apdu->resplen==0) { /* assure some data remains available */
            msg="Encoded TLV: Decrypt returns no data !";
            res=SC_ERROR_INVALID_DATA;
            goto response_decode_end;
        }
        if ( *(apdu->resp+apdu->resplen) != 0x80 ) { /* check padding byte */
            msg="Decrypted TLV has no 0x80 iso padding indicator!";
            res=SC_ERROR_INVALID_DATA;
            goto response_decode_end;
        }
        /* everything ok: remove ending 0x80 from response */
        apdu->resplen--;
    }

    /* call provider post-operation method */
    if (provider->cwa_decode_post_ops) {
        res=provider->cwa_decode_post_ops(card,provider,apdu);
        if (res!=SC_SUCCESS) {
            sc_log(ctx,"Decode APDU: provider post_ops() failed");
            LOG_FUNC_RETURN(ctx,res);
        }
    }

    /* that's all folks */
    res=SC_SUCCESS;

response_decode_end:
    if (ccbuf) free(ccbuf);
    if (msg)    sc_log(ctx,msg);
    LOG_FUNC_RETURN(ctx,res);
}

/********************* default provider for cwa14890 ****************/

/* pre and post operations */
static int default_create_pre_ops(sc_card_t *card, cwa_provider_t *provider) {
    return SC_SUCCESS;
}

static int default_create_post_ops(sc_card_t *card, cwa_provider_t *provider) {
    return SC_SUCCESS;
}

static int default_get_root_ca_pubkey( sc_card_t *card, EVP_PKEY **root_ca_key) {
    return SC_ERROR_NOT_SUPPORTED;
}

/* retrieve CVC intermediate CA certificate and length */
static int default_get_cvc_ca_cert(sc_card_t *card, u8 **cert, size_t *length) {
    return SC_ERROR_NOT_SUPPORTED;
}

/* retrieve CVC IFD certificate and length */
static int default_get_cvc_ifd_cert(sc_card_t *card, u8 **cert, size_t *length) {
    return SC_ERROR_NOT_SUPPORTED;
}

static int default_get_ifd_privkey( sc_card_t *card, EVP_PKEY **ifd_privkey) {
    return SC_ERROR_NOT_SUPPORTED;
}

/* get ICC intermediate CA  path */
static int default_get_icc_intermediate_ca_cert(sc_card_t *card, X509 **cert){
    return SC_ERROR_NOT_SUPPORTED;
}

/* get ICC certificate path */
static int default_get_icc_cert(sc_card_t *card, X509 **cert){
    return SC_ERROR_NOT_SUPPORTED;
}

/* Retrieve key reference for Root CA to validate CVC intermediate CA certs */
static int default_get_root_ca_pubkey_ref(sc_card_t *card, u8 **buf, size_t *len) {
    return SC_ERROR_NOT_SUPPORTED;
}

/* Retrieve key reference for intermediate CA to validate IFD certs */
static int default_get_intermediate_ca_pubkey_ref(sc_card_t *card, u8 **buf, size_t *len) {
    return SC_ERROR_NOT_SUPPORTED;
}

/* Retrieve key reference for IFD certificate */
static int default_get_ifd_pubkey_ref(sc_card_t *card, u8 **buf, size_t *len) {
    return SC_ERROR_NOT_SUPPORTED;
}

/* Retrieve key reference for ICC privkey */
static int default_get_icc_privkey_ref(sc_card_t *card, u8 **buf, size_t *len) {
    return SC_ERROR_NOT_SUPPORTED;
}

/* Retrieve SN.IFD */
static int default_get_sn_ifd(sc_card_t *card, u8 **buf, size_t *len) {
    return SC_ERROR_NOT_SUPPORTED;
}

/* Retrieve SN.ICC */
static int default_get_sn_icc(sc_card_t *card, sc_serial_number_t **serial) {
   return sc_card_ctl(card,SC_CARDCTL_GET_SERIALNR, *serial);
}

/************** operations related with APDU encoding ******************/

/* pre and post operations */
static int default_encode_pre_ops( sc_card_t *card, cwa_provider_t *provider, sc_apdu_t *apdu) {
    return SC_SUCCESS;
}
static int default_encode_post_ops( sc_card_t *card, cwa_provider_t *provider, sc_apdu_t *apdu) {
    return SC_SUCCESS;
}

/************** operations related APDU response decoding **************/

/* pre and post operations */
static int default_decode_pre_ops( sc_card_t *card, cwa_provider_t *provider, sc_apdu_t *apdu) {
    return SC_SUCCESS;
}
static int default_decode_post_ops( sc_card_t *card, cwa_provider_t *provider, sc_apdu_t *apdu) {
    return SC_SUCCESS;
}

static cwa_provider_t default_cwa_provider = {

    /************ data related with SM operations *************************/
    {
         CWA_SM_NONE, /* state */
         {   /* KICC */
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
         },
         {   /* KIFD */
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
         },
         {   /* RND.ICC */
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
         },
         {   /* RND.IFD */
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
         },
         {   /* SigBuf*/
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
         },
         {   /* Kenc */
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
         },
         {   /* Kmac */
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
         },
         {   /* SSC Send Sequence counter */
             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
         }
    },

    /************ operations related with secure channel creation *********/

    /* pre and post operations */
    default_create_pre_ops,
    default_create_post_ops,

    /* Get ICC intermediate CA  path */
    default_get_icc_intermediate_ca_cert,
    /* Get ICC certificate path */
    default_get_icc_cert,

    /* Obtain RSA public key from RootCA*/
    default_get_root_ca_pubkey,
    /* Obtain RSA IFD private key */
    default_get_ifd_privkey,

    /* Retrieve CVC intermediate CA certificate and length */
    default_get_cvc_ca_cert,
    /* Retrieve CVC IFD certificate and length */
    default_get_cvc_ifd_cert,

    /* Get public key references for Root CA to validate intermediate CA cert */
    default_get_root_ca_pubkey_ref,

    /* Get public key reference for IFD intermediate CA certificate */
    default_get_intermediate_ca_pubkey_ref,

    /* Get public key reference for IFD CVC certificate */
    default_get_ifd_pubkey_ref,

    /* Get ICC private key reference */
    default_get_icc_privkey_ref,

    /* Get IFD Serial Number */
    default_get_sn_ifd,

    /* Get ICC Serial Number */
    default_get_sn_icc,

    /************** operations related with APDU encoding ******************/

    /* pre and post operations */
    default_encode_pre_ops,
    default_encode_post_ops,

    /************** operations related APDU response decoding **************/

    /* pre and post operations */
    default_decode_pre_ops,
    default_decode_post_ops,
};

/**
 *Get a copy of default cwa provider 
 *@param card pointer to card info structure
 *@return copy of default provider or null on error
 */
cwa_provider_t *cwa_get_default_provider(sc_card_t *card) {
    if( !card || !card->ctx) return NULL;
    LOG_FUNC_CALLED(card->ctx);
    cwa_provider_t *res=calloc(1,sizeof(cwa_provider_t));
    if (!res) {
        sc_log(card->ctx,"Cannot allocate space for cwa_provider");
        return NULL;
    }
    memcpy(res,&default_cwa_provider,sizeof(cwa_provider_t));
    return res;
}

/* end of cwa14890.c */
#undef __CWA14890_C__

#endif /* ENABLE_OPENSSL */

