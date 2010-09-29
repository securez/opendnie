/*
 * trusted_channel_card.c: Support for trusted channel for the DNIe card
 *
 * Copyright (C) 2006-2010 Dirección General de la Policía y de la Guardia Civil
 *
 * This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/des.h>
#include "../include/internal.h" 
#include <opensc/opensc.h>
#include <opensc/cardctl.h>
#include <opensc/log.h>
#include <opensc/asn1.h>
#include "base_card.h"
#include "card_helper.h"

/* tags for secure channel data */
#define TAG_PICG 0x87
#define TAG_CC 0x8e
#define TAG_LE 0x97
#define TAG_SW 0x99


/* use test keys */
#define TEST_KEYS 0



 /* Here go private and public keys */



/* function copied from libopensc/pkcs15-cert.c */
static int parse_x509_cert(sc_context_t *ctx, const u8 *buf, size_t buflen, struct sc_pkcs15_cert *cert)
{
        int r;
        struct sc_algorithm_id pk_alg, sig_alg;
        sc_pkcs15_der_t pk = { NULL, 0 };
        struct sc_asn1_entry asn1_version[] = {
                { "version", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, &cert->version, NULL },
                { NULL, 0, 0, 0, NULL, NULL }
        };
        struct sc_asn1_entry asn1_pkinfo[] = {
                { "algorithm",          SC_ASN1_ALGORITHM_ID,  SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, &pk_alg, NULL },
                { "subjectPublicKey",   SC_ASN1_BIT_STRING_NI, SC_ASN1_TAG_BIT_STRING, SC_ASN1_ALLOC, &pk.value, &pk.len },
                { NULL, 0, 0, 0, NULL, NULL }
        };
        struct sc_asn1_entry asn1_x509v3[] = {
                { "certificatePolicies",        SC_ASN1_OCTET_STRING, SC_ASN1_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
                { "subjectKeyIdentifier",       SC_ASN1_OCTET_STRING, SC_ASN1_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
                { "crlDistributionPoints",      SC_ASN1_OCTET_STRING, SC_ASN1_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, &cert->crl, &cert->crl_len },
                { "authorityKeyIdentifier",     SC_ASN1_OCTET_STRING, SC_ASN1_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
                { "keyUsage",                   SC_ASN1_BOOLEAN, SC_ASN1_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
                { NULL, 0, 0, 0, NULL, NULL }
        };
        struct sc_asn1_entry asn1_extensions[] = {
                { "x509v3",             SC_ASN1_STRUCT,    SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, asn1_x509v3, NULL },
                { NULL, 0, 0, 0, NULL, NULL }
        };
        struct sc_asn1_entry asn1_tbscert[] = {
                { "version",            SC_ASN1_STRUCT,    SC_ASN1_CTX | 0 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, asn1_version, NULL },
                { "serialNumber",       SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC, &cert->serial, &cert->serial_len },
                { "signature",          SC_ASN1_STRUCT,    SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
                { "issuer",             SC_ASN1_OCTET_STRING, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_ALLOC, &cert->issuer, &cert->issuer_len },
                { "validity",           SC_ASN1_STRUCT,    SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
                { "subject",            SC_ASN1_OCTET_STRING, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_ALLOC, &cert->subject, &cert->subject_len },
                { "subjectPublicKeyInfo",SC_ASN1_STRUCT,   SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, asn1_pkinfo, NULL },
                { "extensions",         SC_ASN1_STRUCT,    SC_ASN1_CTX | 3 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, asn1_extensions, NULL },
                { NULL, 0, 0, 0, NULL, NULL }
        };
        struct sc_asn1_entry asn1_cert[] = {
                { "tbsCertificate",     SC_ASN1_STRUCT,    SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, asn1_tbscert, NULL },
                { "signatureAlgorithm", SC_ASN1_ALGORITHM_ID, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, &sig_alg, NULL },
                { "signatureValue",     SC_ASN1_BIT_STRING, SC_ASN1_TAG_BIT_STRING, 0, NULL, NULL },
                { NULL, 0, 0, 0, NULL, NULL }
        };
        const u8 *obj;
        size_t objlen;

        memset(cert, 0, sizeof(*cert));
        obj = sc_asn1_verify_tag(ctx, buf, buflen, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS,
                                 &objlen);
        if (obj == NULL) {
                sc_error(ctx, "X.509 certificate not found\n");
                return SC_ERROR_INVALID_ASN1_OBJECT;
        }
        cert->data_len = objlen + (obj - buf);
        r = sc_asn1_decode(ctx, asn1_cert, obj, objlen, NULL, NULL);
        SC_TEST_RET(ctx, r, "ASN.1 parsing of certificate failed");

        cert->version++;

        cert->key.algorithm = pk_alg.algorithm;
        pk.len >>= 3;   /* convert number of bits to bytes */
        cert->key.data = pk;

        r = sc_pkcs15_decode_pubkey(ctx, &cert->key, pk.value, pk.len);
        if (r < 0)
                free(pk.value);
        sc_asn1_clear_algorithm_id(&pk_alg);
        sc_asn1_clear_algorithm_id(&sig_alg);

        return r;
}

static int card_extract_signature_data(sc_context_t *ctx,
				       const u8* data,
				       size_t data_length,
				       const u8* ifd_data,
				       u8* kicc)
{
  u8 to_be_hashed[74+32+32];
  u8 digest[SHA_DIGEST_LENGTH];

  if (ctx->debug) sc_debug(ctx, "Entering function card_compare_signature_data\n");

  if (data_length != 128) {
    if (ctx->debug) sc_debug(ctx, "data should be 128-byte long.\n");
    return SC_ERROR_INVALID_CARD;
  }
  
  if (data[0]!=0x6a || data[127]!=0xbc) {
    if (ctx->debug) sc_debug(ctx, "data doesn't match 6A ... BC\n");
    return SC_ERROR_INVALID_CARD;
  }

  memcpy(to_be_hashed, data+1, 74+32);
  memcpy(to_be_hashed+74+32, ifd_data, 16);
  SHA1(to_be_hashed, 74+32+16, digest);

  if (memcmp(data+127-SHA_DIGEST_LENGTH, digest, SHA_DIGEST_LENGTH) != 0) {
    if (ctx->debug) sc_debug(ctx, "hashes doesn't match\n");
    return SC_ERROR_INVALID_CARD;
  }

  memcpy(kicc, data+1+74, 32);

  if (ctx->debug) sc_debug(ctx, "card_compare_signature_data ok!\n");
  return SC_SUCCESS;
}

static int card_verify_signature(sc_context_t *ctx,
				 u8* signature,
				 int signature_length,
				 const u8* ifd_data,
				 int ifd_data_length,
				 RSA* ifd_private_key,
				 RSA* icc_public_key,
				 u8* kicc)
{
  int r = SC_SUCCESS;
  u8 decrypted[CARD_SCHANNEL_KEYLEN_IN_BYTES];
  int decrypted_length;
  u8 encrypted[CARD_SCHANNEL_KEYLEN_IN_BYTES];
  int encrypted_length;
  u8 min_sig[CARD_SCHANNEL_KEYLEN_IN_BYTES];
  int min_sig_length;
  BIGNUM *min_sig_bignum = NULL;
  BIGNUM *decrypted_bignum = NULL;


  if (ctx->debug) sc_debug(ctx, "Entering function card_verify_signature\n");

  if(signature_length != 128) {
    if (ctx->debug) sc_debug(ctx, "Signature should be 128-byte long\n");
    r = SC_ERROR_INVALID_CARD;
  }

  if(ifd_data_length != 0x10) {
    if (ctx->debug) sc_debug(ctx, "ifd_data should be 0x10-byte long\n");
    r = SC_ERROR_INVALID_CARD;
  }

  if ((decrypted_length = RSA_private_decrypt(signature_length,
					      signature,
					      decrypted,
					      ifd_private_key,				   
					      RSA_NO_PADDING)) <= 0) {
    if (ctx->debug) sc_debug(ctx, "Error in decryption RSA routine.\n");
    r = SC_ERROR_DECRYPT_FAILED;
    goto dvs_end; /* to deallocate resources */
  }
  
  if ((encrypted_length = RSA_public_encrypt(decrypted_length,
					      decrypted,
					      encrypted,
					      icc_public_key,				   
					      RSA_NO_PADDING)) <= 0) {
    if (ctx->debug) sc_debug(ctx, "Error in encryption RSA routine.\n");
    r = SC_ERROR_INVALID_CARD;
    goto dvs_end; /* to deallocate resources */
  }

  r = card_extract_signature_data(ctx, encrypted, encrypted_length, ifd_data, kicc);
  if (r != SC_SUCCESS) {
    decrypted_bignum = BN_bin2bn(decrypted, decrypted_length, NULL);
    min_sig_bignum = BN_new();
    if(!decrypted_bignum || !min_sig_bignum) {
      r = SC_ERROR_INVALID_CARD;
      goto dvs_end; /* to deallocate resources */
    }

    if(!BN_sub(min_sig_bignum, icc_public_key->n, decrypted_bignum)) {
      r = SC_ERROR_INVALID_CARD;
      goto dvs_end; /* to deallocate resources */
    }

    if((min_sig_length = BN_bn2bin(min_sig_bignum, min_sig)) <= 0) {
      if (ctx->debug) sc_debug(ctx, "Error in converting min_sig_bignum to min_sig.\n");
      r= SC_ERROR_INVALID_CARD;
      goto dvs_end; /* to deallocate resources */
    }

    if ((encrypted_length = RSA_public_encrypt(min_sig_length,
					      min_sig,
					      encrypted,
					      icc_public_key,				   
					      RSA_NO_PADDING)) == -1) {
      if (ctx->debug) sc_debug(ctx, "Error in encryption RSA routine.\n");
      r = SC_ERROR_INVALID_CARD;
      goto dvs_end; /* to deallocate resources */
    }
 
    r = card_extract_signature_data(ctx, encrypted, encrypted_length, ifd_data, kicc);
  }
    
 dvs_end:
  if(min_sig_bignum)
    BN_free(min_sig_bignum);
  if(decrypted_bignum)
    BN_free(decrypted_bignum);
 
  if (ctx->debug) sc_debug(ctx, "Leaving function card_verify_signature 0x%X\n", r);

  return r;
}

static int card_sign_authentication_data(sc_context_t *ctx,
					 const sc_serial_number_t *serial_number,
					 const u8 *challenge,
					 RSA* ifd_private_key,
					 RSA* icc_public_key,
					 u8 *kifd, /* 32-byte long  buffer that this function will fill */
					 u8 *signature /* 128-byte long buffer with signature used in external authenticate */
					 )
{
  int r = SC_SUCCESS;
  u8 decrypted[128];
  u8 to_be_signed[128];
  u8 min_sig[128];
  u8 rnd[74];
  u8 to_be_hashed[74+32+8+8];
  u8 digest[SHA_DIGEST_LENGTH];
  int decrypted_length;
  int encrypted_length;
  int min_sig_length;
  BIGNUM *decrypted_bignum = NULL;
  BIGNUM *min_sig_bignum = NULL;
  BIGNUM *sub_bignum = NULL;


  if (ctx->debug) sc_debug(ctx, "Entering function card_prepare_authenticate_data\n");

  /* I: PREPARE DATA TO BE SIGNED */
  
  /* 1: 6A */
  to_be_signed[0] = 0x6a;
  
  /* 2: pRND */
  RAND_bytes(rnd, sizeof(rnd));
  memcpy(to_be_signed+1, rnd, sizeof(rnd));

  /* 3: kIFD */
  RAND_bytes(kifd, 32);
  memcpy(to_be_signed+1+sizeof(rnd), kifd, 32);

  /* 4: hash */
  memcpy(to_be_hashed, rnd, 74);
  memcpy(to_be_hashed+74, kifd, 32);
  memcpy(to_be_hashed+74+32, challenge, 8);
  to_be_hashed[74+32+8] = 0; /* algorithm expects 8 byte serial number, so we prepend a 0 */
  memcpy(to_be_hashed+74+32+8+1, serial_number->value, 7);
  SHA1(to_be_hashed, 74+32+16, digest);
    
  memcpy(to_be_signed+1+sizeof(rnd)+32, digest, sizeof(digest));

  /* 5: BC */
  to_be_signed[127] = 0xbc;


  /* II: GENERATE SIGNATURE */
  if ((decrypted_length = RSA_private_decrypt(sizeof(to_be_signed),
					      to_be_signed,
					      decrypted,
					      ifd_private_key,				   
					      RSA_NO_PADDING)) <= 0) {
    if (ctx->debug) sc_debug(ctx, "Error in decryption RSA routine.\n");
    r = SC_ERROR_DECRYPT_FAILED;
    goto dsad_end; /* to deallocate resources */
  }

  decrypted_bignum = BN_bin2bn(decrypted, decrypted_length, NULL);
  sub_bignum = BN_new();
  if(!decrypted_bignum || !sub_bignum) {
    r = SC_ERROR_INVALID_CARD;
    goto dsad_end; /* to deallocate resources */
  }

  if(!BN_sub(sub_bignum, ifd_private_key->n, decrypted_bignum)) {
    if (ctx->debug) sc_debug(ctx, "Error in calculating sub_bignum.\n");
    r = SC_ERROR_INVALID_CARD;
    goto dsad_end; /* to deallocate resources */
  }

  if(BN_cmp(decrypted_bignum, sub_bignum) < 0) {
    min_sig_bignum = decrypted_bignum;
  } else {
    min_sig_bignum = sub_bignum;
  }

  if(BN_num_bytes(min_sig_bignum) > sizeof(min_sig)) {
    if (ctx->debug) sc_debug(ctx, "Error in min_sig... it's too big.\n");
    goto dsad_end; /* to deallocate resources */
  }
  
  if((min_sig_length = BN_bn2bin(min_sig_bignum, min_sig)) <= 0) {
    if (ctx->debug) sc_debug(ctx, "Error in converting min_sig_bignum to min_sig.\n");
    r= SC_ERROR_INVALID_CARD;
    goto dsad_end; /* to deallocate resources */
  }

  if ((encrypted_length = RSA_public_encrypt(min_sig_length,
					     min_sig,
					     signature,
					     icc_public_key,				   
					     RSA_NO_PADDING)) <= 0) {
    if (ctx->debug) sc_debug(ctx, "Error in encryption RSA routine.\n");
    r = SC_ERROR_INVALID_CARD;
    goto dsad_end; /* to deallocate resources */
  }
    
 dsad_end:
  /* zero all buffers */
  memset(decrypted, 0, sizeof(decrypted));
  memset(to_be_signed, 0, sizeof(to_be_signed));
  memset(min_sig, 0, sizeof(min_sig));
  memset(rnd, 0, sizeof(rnd));
  memset(to_be_hashed, 0, sizeof(to_be_hashed));
  memset(digest, 0, sizeof(digest));

  /* deallocate BIGNUMs */
  /* min_sig_bignum is just a weak pointer. don't deallocate it! */
  if(sub_bignum)
    BN_free(sub_bignum);
  if(decrypted_bignum)
    BN_free(decrypted_bignum);
  
  if (ctx->debug) sc_debug(ctx, "Leaving function card_prepare_authenticate_data 0x%X\n", r);
  
  return r;
}

static void card_compute_hashed_key(sc_context_t *ctx,
				    const u8 *kseed, /* 32-byte long buffer */
				    const u8 *counter, /* 4-byte long buffer */
				    u8 *key /* 16-byte long buffer */
				    )
{
  u8 data[32+4];
  u8 digest[SHA_DIGEST_LENGTH];
  if (ctx->debug) sc_debug(ctx, "Entering function card_compute_hashed_key\n");

  memcpy(data, kseed, 32);
  memcpy(data+32, counter, 4);
  SHA1(data, 32+4, digest);

  /* the key is the 16 first bytes of the digest */
  memcpy(key, digest, 16);
  
  if (ctx->debug) sc_debug(ctx, "Leaving function card_compute_hashed_key\n");
}

static int card_compute_session_keys(sc_context_t *ctx,
				     const u8 *kicc, /* 32-byte long buffer */
				     const u8 *kifd, /* 32-byte long buffer */
				     const u8 *rndicc, /* 8-byte long buffer */
				     const u8 *rndifd, /* 8-byte long buffer */
				     u8 *kenc, /* 16-byte long buffer */
				     u8 *kmac, /* 16-byte long buffer */
				     u8 *ssc) /* 8-byte long buffer */
{
  int r = SC_SUCCESS;
  u8 kseed[32];
  int ii;
  static const u8 counter_kenc[] = {0,0,0,1};
  static const u8 counter_kmac[] = {0,0,0,2};

  if (ctx->debug) sc_debug(ctx, "Entering function card_compute_session_keys\n");

  /* calculate kseed */
  for(ii=0; ii<sizeof(kseed); ii++)
    kseed[ii] = kicc[ii] ^ kifd[ii];
  
  /* calculate kenc */
  card_compute_hashed_key(ctx, kseed, counter_kenc, kenc);

  /* calculate kmac */
  card_compute_hashed_key(ctx, kseed, counter_kmac, kmac);

  /* calculate ssc */
  memcpy(ssc, rndicc+4, 4);
  memcpy(ssc+4, rndifd+4, 4);

  if (ctx->debug) sc_debug(ctx, "Leaving function card_compute_session_keys 0x%X\n", r);
  return r;
}

static void card_calculate_mac(sc_context_t *ctx,
			       const u8 *data,
			       int data_length,
			       const u8 *key, /* 16-byte buffer */
			       u8 *ssc, /* 8-byte long buffer containing ssc */
			       u8 *mac /* 4-byte long buffer containing MAC */
			      )
{
  int ii, jj;
  DES_key_schedule k1, k2;
  u8 buffer[8];
  
  /* preconditions */
  assert((data_length%8) == 0); /* data must be padded */

  /* prepare encryption keys */
  DES_set_key_unchecked((const_DES_cblock *)key, &k1);
  DES_set_key_unchecked((const_DES_cblock *)(key+8), &k2);

  /* calculate ssc */
  for(ii=7; ii>=0; ii--) {
    ssc[ii]++;
    if(ssc[ii])
      break; /* stop if no carry */
  }

  /* first block inits with ssc */
  memcpy(buffer, ssc, 8);

  /* 
     for each block we encrypt input, xor with
     data block and feed output to next iteration
  */
  for(ii=0; ii<data_length; ii+=8) {
    DES_ecb_encrypt((const_DES_cblock *)buffer, (DES_cblock *)buffer, &k1, DES_ENCRYPT);
    for(jj=0; jj<8; jj++)
      buffer[jj] ^= data[ii+jj];
  }
  
  /* final 3DES */
  DES_ecb2_encrypt((const_DES_cblock *)buffer, (DES_cblock *)buffer, &k1, &k2, DES_ENCRYPT);

  /* copy to output */
  memcpy(mac, buffer, 4);
}

/*
  buffer must have room for at least 8 bytes more
  new length will be returned in len
*/
static void card_add_7816_padding( u8 *buffer, size_t *len )
{
  int zeroes;
  buffer[(*len)++] = 0x80;
  zeroes = (8-((*len)%8))%8;
  if(zeroes)
    memset(buffer+(*len), 0, zeroes);
  (*len)+=zeroes;
}

static int card_add_tlv( u8 tag, u8* buffer, size_t* length )
{
  u8 header[4];
  size_t header_length = 0;
  
  header[header_length++] = tag;
  if(*length < 0x80) {
    header[header_length++] = *length;
  } else if(*length < 0x100) {
    header[header_length++] = 0x81;
    header[header_length++] = *length;
  } else if(*length < 0x10000) {
    header[header_length++] = 0x82;
    header[header_length++] = ((*length)>>8)&0xff;
    header[header_length++] = (*length)&0xff;
  } else {
    return SC_ERROR_INTERNAL;
  }

  memmove(buffer+header_length, buffer, *length);
  memcpy(buffer, header, header_length);
  *length += header_length;

  return SC_SUCCESS;
}

int card_prepare_secure_tx(struct sc_card *card,
				  const sc_apdu_t *orig_apdu,
				  sc_apdu_t *secure_apdu
				  )
{
  u8 mac_data[1024];
  size_t mac_data_length = 0;
  u8 temp[1024];
  u8 encrypted[1024];
  u8 tlv_le[3];
  size_t temp_length, encrypted_length;
  static const u8 header_padding[] = {0x80, 0x00, 0x00, 0x00};
  DES_cblock iv = {0,0,0,0,0,0,0,0};
  DES_key_schedule k1, k2;
  

  if (card->ctx->debug) sc_debug(card->ctx, "Entering function card_prepare_secure_tx\n");
  
  secure_apdu->cse = SC_APDU_CASE_3_SHORT;
  secure_apdu->cla = orig_apdu->cla | 0x0c; /* flag this message is secured */
  secure_apdu->ins = orig_apdu->ins;
  secure_apdu->p1 = orig_apdu->p1;
  secure_apdu->p2 = orig_apdu->p2;
  secure_apdu->lc = 0;
  secure_apdu->le = 0;

  /* prepare mac */
  mac_data[mac_data_length++] = secure_apdu->cla;
  mac_data[mac_data_length++] = secure_apdu->ins;
  mac_data[mac_data_length++] = secure_apdu->p1;
  mac_data[mac_data_length++] = secure_apdu->p2;
  
  memcpy(mac_data+mac_data_length, header_padding, sizeof(header_padding));
  mac_data_length += sizeof(header_padding);

  if(orig_apdu->lc>0) {
    /* copy data */
    memcpy(temp, orig_apdu->data, orig_apdu->lc);
    temp_length = orig_apdu->lc;
 
    /* pad data using 7816 padding */
    card_add_7816_padding(temp, &temp_length);

    /* prepare keys */
    DES_set_key_unchecked((const_DES_cblock *)(DRVDATA(card)->kenc), &k1);
    DES_set_key_unchecked((const_DES_cblock *)(DRVDATA(card)->kenc+8), &k2);

    /* add info about padding in encrypted buffer */
    encrypted[0] = 1;
    
    if (card->ctx->debug) sc_debug(card->ctx, "temp_length = 0x%X\n", temp_length);
    /* encrypt using 3DES CBC */
    DES_ede3_cbc_encrypt(temp,
			 &encrypted[1],
			 temp_length,
			 &k1,
			 &k2,
			 &k1,
			 &iv,
			 DES_ENCRYPT);
    encrypted_length = temp_length+1; /* length is increased in 1 for the padding info byte */
    
    if(card_add_tlv(TAG_PICG, encrypted, &encrypted_length) != SC_SUCCESS) {
      if (card->ctx->debug) sc_debug(card->ctx, "Error while adding tlv to encrypted data\n");
      return SC_ERROR_INTERNAL;
    }

    /* copy tlv encrypted data to data to calculate mac */
    memcpy(mac_data+mac_data_length, encrypted, encrypted_length);
    mac_data_length += encrypted_length;

    /* copy tlv encrypted data to destination */
    memcpy((u8 *)secure_apdu->data, /* this can be modified since it's created
				       as a static variable so we un-const it */
	   encrypted,
	   encrypted_length);
    secure_apdu->lc += encrypted_length;
  }

  if((orig_apdu->le>0) && (orig_apdu->le<=0x100)) {
    /* code TLV */
    tlv_le[0] = TAG_LE;
    tlv_le[1] = 1;
    tlv_le[2] = orig_apdu->le;
    
    memcpy(mac_data+mac_data_length, tlv_le, sizeof(tlv_le));
    mac_data_length += sizeof(tlv_le);

    /* copy tlv le data to destination */
    memcpy((u8 *)secure_apdu->data+secure_apdu->lc, /* this can be modified since it's created
						       as a static variable so we un-const it */
	   tlv_le, 
	   sizeof(tlv_le));
    secure_apdu->lc += sizeof(tlv_le);
  }

  if((orig_apdu->lc>0) ||
     ((orig_apdu->le>0) && (orig_apdu->le<=0x100))) {
    card_add_7816_padding(mac_data, &mac_data_length);
  }  

  /* calculate and append mac */
  /* secure_apdu->data can be modified since it's created
     as a static variable so we un-const it */
  ((u8 *)secure_apdu->data)[secure_apdu->lc++] = TAG_CC; /* tag */
  ((u8 *)secure_apdu->data)[secure_apdu->lc++] = 4; /* length */
  card_calculate_mac(card->ctx,
		     mac_data, 
		     mac_data_length, 
		     DRVDATA(card)->kmac, 
		     DRVDATA(card)->ssc,
		     (u8 *)&secure_apdu->data[secure_apdu->lc]); /* this can be modified since it's created
								    as a static variable so we un-const it */
  
  /* mac is 4-byte long */
  secure_apdu->lc += 4;

  /* update datalen */
  secure_apdu->datalen = secure_apdu->lc;

  if (card->ctx->debug) sc_debug(card->ctx, "Leaving function card_prepare_secure_tx\n");
  return SC_SUCCESS;
}			  


 
static int card_decode_next_tlv(sc_context_t *ctx,
				const u8 *buffer,
				size_t buffer_length,
				u8 *tag,
				size_t *length,
				const u8 **value,
				const u8 **next_pos
				)
{
  if(buffer_length<2) {
    if (ctx->debug) sc_debug(ctx, "Expecting at least 2 bytes: returning SC_ERROR_INVALID_DATA\n");
    return SC_ERROR_INVALID_DATA;
  }

  /* get tag */
  *tag = buffer[0];

  if(buffer[1]<0x80) {
    *length = buffer[1]&0x7f;
    *value = buffer+2;
  } else if(buffer[1]==0x80) {
    *length = 0;
    *value = buffer+2;
  } else if(buffer[1]==0x81) {
    *length = buffer[2];
    *value = buffer+3;
  } else if(buffer[1]==0x82) {
    *length = ((size_t)buffer[2]<<8)|buffer[3];
    *value = buffer+4;
  } else {
    if (ctx->debug) sc_debug(ctx, "Invalid length byte 0x%X\n", buffer[1]);
    return SC_ERROR_INVALID_DATA;
  }

  /* update next_pos */
  *next_pos = *value + *length;
  
  return SC_SUCCESS;
}				

/*
  this function updates apdu->resp, apdu->resplen, apdu->sw1 and apdu->sw2
  decoding and checking data from secure_apdu
*/

static int card_parse_secure_rx(struct sc_card *card,
				const sc_apdu_t *secure_apdu,
				sc_apdu_t *apdu
				)
{
  int r = SC_SUCCESS;
  const u8 *p = secure_apdu->resp;
  const u8 *pf = secure_apdu->resp + secure_apdu->resplen;
  u8 tag;
  size_t length;
  const u8 *value = NULL;
  DES_cblock iv = {0,0,0,0,0,0,0,0};
  DES_key_schedule k1, k2;
  int ii;
  int tags_checked = 0;
  u8 temp[1024];
  size_t temp_length;
  u8 mac[4];
  int resplen = apdu->resplen;


  /* init apdu->resplen */
  apdu->resplen = 0;

  if (card->ctx->debug) sc_debug(card->ctx, "Entering function card_parse_secure_rx\n");
  while(p<pf) {
    if((r = card_decode_next_tlv(card->ctx, p, pf-p, &tag, &length, &value, &p)) != SC_SUCCESS) {
      if (card->ctx->debug) sc_debug(card->ctx, "Error in card_decode_next_tlv. Returning 0x%X\n", r);
      return r;
    }

    switch(tag) {
    case TAG_PICG:
      /* gets encrypted data and inserts it in apdu->resp if present...
	 also updates apdu->resplen */
      if(!apdu->resp) {
	apdu->resplen = 0;
      } else {
	if((length<9) || (length>512) || ((length-1)%8)!=0) {
	  /* minimmum message is pad info byte plus 1 block (8 bytes) */
	  /* second comparison protects from buffer overflows */
	  /* third comparison assures that data is pad info
	     byte plus result of a 3DES CBC (multiple of 8) */
	  if (card->ctx->debug) sc_debug(card->ctx, "ERROR: Invalid PIGC length\n");
	  return SC_ERROR_INVALID_DATA;
	}
	if(value[0]!=1) {
	  /* pad info byte MUST be 1 */
	  if (card->ctx->debug) sc_debug(card->ctx, "ERROR: Invalid pad info byte\n");
	  return SC_ERROR_INVALID_DATA;
	}
	/* prepare keys */
	DES_set_key_unchecked((const_DES_cblock *)(DRVDATA(card)->kenc), &k1);
	DES_set_key_unchecked((const_DES_cblock *)(DRVDATA(card)->kenc+8), &k2);
	
	/* decrypt using 3DES CBC */
	DES_ede3_cbc_encrypt(value+1,
			     temp,
			     length-1,
			     &k1,
			     &k2, 
			     &k1,
			     &iv, 
			     DES_DECRYPT);
	
	/* a pad info byte has to be substracted from length */
	length--;

	if(length<8) {
	  if (card->ctx->debug) sc_debug(card->ctx, "ERROR: Invalid length. Can't have a proper padding\n");
	  return SC_ERROR_INVALID_DATA;
	}

	/* substract 0 in padding. */
	for(ii=0; (temp[--length] == 0)&&(ii<8); ii++); /* do nothing inside the for */
	
	if(ii>7) {
	  if (card->ctx->debug) sc_debug(card->ctx, "ERROR: Invalid padding (too much 0)\n");
	  /* at least 8 bytes needed to check the padding */
	  return SC_ERROR_INVALID_DATA;
	}

	/* assure last byte from padding is a 0x80.
	   No decrement needed here, we are comparing the same byte that ended the for,
	   which is already excluded from data! */
	if(temp[length] != 0x80) {
	  if (card->ctx->debug) sc_debug(card->ctx, "ERROR: Invalid padding (0x80 missing)\n");
	  return SC_ERROR_INVALID_DATA;
	}

	if(length>resplen) {
	  if (card->ctx->debug) sc_debug(card->ctx, "ERROR: Buffer too small\n");
	  return SC_ERROR_INVALID_DATA;
	}
	
	memcpy(apdu->resp, temp, length);
	resplen = length;
	apdu->resplen = length;

	tags_checked |= 1; /* flag we checked TAG_PIGC */
      }
      break;

    case TAG_SW:
      /* we process sw data and set apdu->sw1 and apdu->sw2 accordingly */
      if(length!=2) {
	/* we expect 2 bytes: sw1 and sw2 */
	if (card->ctx->debug) sc_debug(card->ctx, "ERROR: Invalid TAG_SW length\n");
	return SC_ERROR_INVALID_DATA;
      }
      apdu->sw1 = value[0];
      apdu->sw2 = value[1];

      tags_checked |= 2; /* flag we checked TAG_SW */
      break;

    case TAG_CC:
      /* we check mac */

      if(length!=4) {
	/* we expect 4 bytes*/
	if (card->ctx->debug) sc_debug(card->ctx, "ERROR: Invalid TAG_CC length\n");
	return SC_ERROR_INVALID_DATA;
      }

      /* we compute mac usign data from secure_apdu->resp to value-1(for the tag)-1(the length)
	 which is the data before TAG_CC
      */

      /* calculate length (cc value) - (cc tag) - (cc length byte) */
      temp_length = value-1-1-secure_apdu->resp;
      if(temp_length>(sizeof(temp)-8)) {
	/* too long for temp. protect from buffer overflows. This can't happen */
	/* we leave 8 extra bytes to make room for padding */
	if (card->ctx->debug) sc_debug(card->ctx, "ERROR: Too much data to calculate mac\n");
	return SC_ERROR_INVALID_DATA;
      }
      
      /* copy data to calculate mac */
      memcpy(temp, secure_apdu->resp, temp_length);
      card_add_7816_padding(temp, &temp_length);
      /* calculate mac */
      card_calculate_mac(card->ctx,
			 temp, 
			 temp_length, 
			 DRVDATA(card)->kmac, 
			 DRVDATA(card)->ssc,
			 mac);
      
      /* check mac */
      if(memcmp(value, mac, sizeof(mac)) != 0) {
	if (card->ctx->debug) sc_debug(card->ctx, "ERROR: macs don't match\n");
	return SC_ERROR_INVALID_DATA;
      }
      tags_checked |= 4; /* flag we checked TAG_CC */
      break;
     
    }
  }

  if((tags_checked&0x6) != 0x6) {
    /* at least TAG_SW and TAG_CC compulsory */
    if (card->ctx->debug) sc_debug(card->ctx, "ERROR: missing TAG_SW or TAG_CC\n");
    //We check if the error is the typical securityd error: 69 88 or 69 87
    if (secure_apdu->sw1 == 0x69 && (secure_apdu->sw2 == 0x88 || secure_apdu->sw2 == 0x87) && DRVDATA(card)->trusted_channel_err < 10){
        card_card_create_secure_channel(card);
        DRVDATA(card)->trusted_channel_err = DRVDATA(card)->trusted_channel_err + 1;
    }

    return SC_ERROR_INVALID_DATA;
  }
  
  if (card->ctx->debug) sc_debug(card->ctx, "Leaving function card_parse_secure_rx\n");
  return SC_SUCCESS;
}


int card_assure_secure_channel(struct sc_card *card)
{
  if(!card->drv_data)
    return SC_ERROR_INTERNAL;

  /* we create secure channel if it hasn't been created */
  if(((struct card_priv_data *) card->drv_data)->secure_channel_state == secure_channel_not_created){
    return card_card_create_secure_channel(card);
}
  /* if secure channel is being created or created we just return */
  return SC_SUCCESS;  
}

int card_card_create_secure_channel(struct sc_card *card)
{
  int r = SC_SUCCESS;
  sc_serial_number_t serial;
  struct sc_pkcs15_cert cert;
  struct sc_file *file = NULL;
  struct sc_path path;
  u8 *buffer=NULL;
  size_t buflen=0;
  RSA *icc_public_key = NULL;
  RSA *ifd_private_key = NULL;
  u8 kicc[32];
  u8 kifd[32];
  u8 rndicc[8];
  u8 rndifd[8];
  static const u8 select_ca_root_data[]={0x83,0x02,0x02,0x0F};
#if TEST_KEYS
  static const u8 select_key_verification_data[]={0x83,0x08,0x65,0x73,0x54,0x43,0x41,0x60,0x00,0x05};
  static const u8 select_two_keys_data[]={0x84, 0x02, 0x02, 0x1F, 0x83, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};                   

#else /* TEST KEYS */
  static const u8 select_key_verification_data[]={0x83,0x08,0x65,0x73,0x53,0x44,0x49,0x60,0x00,0x06};
  static const u8 select_two_keys_data[]={0x84,0x02,0x02,0x1F,0x83,0x0C,0x00,0x00,0x00,0x00,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
#endif /* TEST KEYS */

#if TEST_KEYS
  static const u8 ifd_serial_data[] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
#else /* TEST_KEYS */
  static const u8 ifd_serial_data[] = {0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
#endif /* TEST_KEYS */
  u8 bufferrnd[0x10];
  u8 signature[128];
  sc_apdu_t apdu;

  if (card->ctx->debug) sc_debug(card->ctx, "Entering function card_card_create_secure_channel\n");

  /* reset card */
  (void) sc_reset(card);

  /* flag secure channel as being created */
  ((struct card_priv_data *) card->drv_data)->secure_channel_state = secure_channel_creating;
  
  /* initialize serial number from the card */
  memset(&serial, 0, sizeof(serial));
  if((r = card_get_serialnr(card, &serial)) != SC_SUCCESS)
    goto dccsc_end; 

  /* Stage 2: we invert order */
  
  /* step H: read icc certificate */
  if (card->ctx->debug) sc_debug(card->ctx, "Entering Step H\n");
  sc_format_path("3F00601F", &path);
  
  r = card_helper_read_file( card, &path, &buffer, &buflen);
  if (r!=SC_SUCCESS && r!=buflen)
    goto dccsc_end; /* this goto lets the function clean up */

  if((r = parse_x509_cert(card->ctx, buffer, buflen, &cert)) != SC_SUCCESS)
    goto dccsc_end; /* this goto lets the function clean up */
  
  if(file) {
    sc_file_free(file);
    file = NULL;
  }

  icc_public_key = RSA_new();
  if(!icc_public_key)
    goto dccsc_end; /* this goto lets the function clean up */

  icc_public_key->n = BN_bin2bn(cert.key.u.rsa.modulus.data, 
				cert.key.u.rsa.modulus.len,
				icc_public_key->n);
  icc_public_key->e = BN_bin2bn(cert.key.u.rsa.exponent.data,
				cert.key.u.rsa.exponent.len, 
				icc_public_key->e);

  ifd_private_key = RSA_new();
  if(!ifd_private_key)
    goto dccsc_end; /* this goto lets the function clean up */

  ifd_private_key->n = BN_bin2bn(ifd_modulus, sizeof(ifd_modulus), ifd_private_key->n);
  ifd_private_key->e = BN_bin2bn(ifd_public_exponent, sizeof(ifd_public_exponent), ifd_private_key->e);
  ifd_private_key->d = BN_bin2bn(ifd_private_exponent, sizeof(ifd_private_exponent), ifd_private_key->d);

  if (card->ctx->debug) sc_debug(card->ctx, "Leaving Step H\n");

  /* Stage 1 */

  /* Step A: */
  /* Step B: Select CA Root public key on smart card*/
  if (card->ctx->debug) sc_debug(card->ctx, "Entering Step B\n");
  sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 
                                              0x22,/*Manage Security Environment*/
                                              0x81,
                                              0xB6);
  apdu.lc=sizeof(select_ca_root_data);
  apdu.data=select_ca_root_data;
  apdu.datalen=sizeof(select_ca_root_data);
  
  r = card_transmit_apdu(card,&apdu);

  SC_TEST_RET(card->ctx, r, "Card returned error");

  if (card->ctx->debug) sc_debug(card->ctx, "Leaving Step B\n");

  /* Step C: Verify the certificate of a CA's public key C_CV.CA.CS_AUT */
  if (card->ctx->debug) sc_debug(card->ctx, "Entering Step C\n");

  sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 
                                              0x2A,/*Perform Security Operation*/
                                              0x00,
                                              0xAE);/*Verify Certificate*/
  apdu.lc=sizeof(C_CV_CA_CS_AUT_cert);
  apdu.data=C_CV_CA_CS_AUT_cert;
  apdu.datalen=sizeof(C_CV_CA_CS_AUT_cert);

  r = card_transmit_apdu(card,&apdu);
  SC_TEST_RET(card->ctx, r, "Card returned error");

  if (card->ctx->debug) sc_debug(card->ctx, "Leaving Step C\n");

  /* Step D: Select key verification*/
  
  if (card->ctx->debug) sc_debug(card->ctx, "Entering Step D\n");

  sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 
                                              0x22,/*Manage Security Environment*/
                                              0x81,/*Set for verfication*/
                                              0xB6);/*DST*/
  apdu.lc=sizeof(select_key_verification_data);
  apdu.data=select_key_verification_data;
  apdu.datalen=sizeof(select_key_verification_data);
  
  r = card_transmit_apdu(card,&apdu);
  SC_TEST_RET(card->ctx, r, "Card returned error");

  if (card->ctx->debug) sc_debug(card->ctx, "Leaving Step D\n");

  /* Step E: Verify CA Certificate*/

  if (card->ctx->debug) sc_debug(card->ctx, "Entering Step E\n");

  sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 
                                              0x2A,/*Perform Security Operation*/
                                              0x00,
                                              0xAE);/*Verify Certificate*/
  apdu.lc=sizeof(C_CV_IFDuser_AUT_cert);
  apdu.data=C_CV_IFDuser_AUT_cert;
  apdu.datalen=sizeof(C_CV_IFDuser_AUT_cert);

  r = card_transmit_apdu(card,&apdu);
  SC_TEST_RET(card->ctx, r, "Card returned error");

  if (card->ctx->debug) sc_debug(card->ctx, "Leaving Step E\n");
  
  /* Stage 3 */

  /* Step I: Select two keys for verification */

  if (card->ctx->debug) sc_debug(card->ctx, "Entering Step I\n");

  sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 
                                              0x22, /*Manage Security Environment*/
                                              0xC1, /*Set for internal and external verfication*/
                                              0xA4);/*AUT*/
  apdu.lc=sizeof(select_two_keys_data);
  apdu.data=select_two_keys_data;
  apdu.datalen=sizeof(select_two_keys_data);
  
  r = card_transmit_apdu(card,&apdu);
  SC_TEST_RET(card->ctx, r, "Card returned error");

  if (card->ctx->debug) sc_debug(card->ctx, "Leaving Step I\n");

  /* Step J: Internal Authenticate*/

  if (card->ctx->debug) sc_debug(card->ctx, "Entering Step J\n");

  RAND_bytes(bufferrnd, 8); /*data is 8 bytes of random data */
  memcpy(rndifd,bufferrnd,8);
  memcpy(bufferrnd+8,ifd_serial_data,8);
  
  sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 
                                              0x88, /*Internal Authenticate*/
                                              0x00, /*Set for verfication*/
                                              0x00);/*DST*/
  apdu.lc=sizeof(bufferrnd);
  apdu.resp=signature;
  apdu.resplen=sizeof(signature);
  apdu.le=sizeof(signature);
  apdu.data=bufferrnd;
  apdu.datalen=sizeof(bufferrnd);
  
  r = card_transmit_apdu(card,&apdu);
  SC_TEST_RET(card->ctx, r, "Card returned error"); 
  
  if((r = card_verify_signature(card->ctx,
                                signature, 
				sizeof(signature), 
				bufferrnd, 
				sizeof(bufferrnd),
				ifd_private_key,
				icc_public_key,
				kicc) ) != SC_SUCCESS) {
    if (card->ctx->debug) sc_debug(card->ctx, "card_verify_signature failed");
    goto dccsc_end;
  }
  
   if (card->ctx->debug) sc_debug(card->ctx, "Leaving Step I\n");

  /* Stage 4 */
  /* Step K Get challenge*/

  if (card->ctx->debug) sc_debug(card->ctx, "Entering Step K\n");

  sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 
                                              0x84, /*Get Challenge*/
                                              0x00, 
                                              0x00);
  apdu.resp=rndicc;
  apdu.resplen=sizeof(rndicc);
  apdu.le=sizeof(rndicc);
  
  r = card_transmit_apdu(card,&apdu);
  SC_TEST_RET(card->ctx, r, "Card returned error");
  if (apdu.resplen <= sizeof(rndicc)){
    memcpy(rndicc,apdu.resp,apdu.resplen);
  }

  if (card->ctx->debug) sc_debug(card->ctx, "Leaving Step I\n");

  /* Step L External Authenticate*/

  if (card->ctx->debug) sc_debug(card->ctx, "Entering Step L\n");

  if ((r = card_sign_authentication_data(card->ctx,
                                           &serial,
                                            rndicc,
                                   ifd_private_key,
                                    icc_public_key,
                                              kifd,
                                         signature)) != SC_SUCCESS){
    if (card->ctx->debug) sc_debug(card->ctx, "card_sign_authentication_data failed");
    goto dccsc_end;
  }

  sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 
                                              0x82, /*External Authenticate*/
                                              0x00, 
                                              0x00);
  apdu.lc=sizeof(signature);
  apdu.data=signature;
  apdu.datalen=sizeof(signature);
  apdu.le=0;
  apdu.resplen=0;
  apdu.resp=NULL;
  
  r = card_transmit_apdu(card,&apdu);
  SC_TEST_RET(card->ctx, r, "Card returned error"); 

  if((r=card_compute_session_keys(card->ctx, 
				  kicc,
				  kifd,
				  rndicc,
				  rndifd,
				  DRVDATA(card)->kenc,
				  DRVDATA(card)->kmac,
				  DRVDATA(card)->ssc
				  )) != SC_SUCCESS) {
    if (card->ctx->debug) sc_debug(card->ctx, "card_compute_session_keys failed!");
    goto dccsc_end;
  }

  if (card->ctx->debug) sc_debug(card->ctx, "Leaving Step L\n");

 dccsc_end:
  if(buffer) {
    free(buffer);
    buffer = NULL;
  }    
  if(icc_public_key) {
    RSA_free(icc_public_key);
    icc_public_key = NULL;
  }
  if(ifd_private_key) {
    RSA_free(ifd_private_key);
    ifd_private_key = NULL;
  }
  if(file) {
    sc_file_free(file);
    file = NULL;
  }
  if(r == SC_SUCCESS) {
    /* flag secure channel as created */
    ((struct card_priv_data *) card->drv_data)->secure_channel_state = secure_channel_created;
  } else {
    /* flag secure channel as NOT created */
    ((struct card_priv_data *) card->drv_data)->secure_channel_state = secure_channel_not_created;
  }

  if (card->ctx->debug) sc_debug(card->ctx, "Leaving function card_card_create_secure_channel with errorcode 0x%X\n", r);
  return r;
}

int card_secure_transmit(sc_card_t *card, sc_apdu_t *tx) 
{
  int r=0;
  sc_apdu_t secure_tx;
  u8 txbuf[1024], rxbuf[1024];
  
  /* card_prepare_secure_tx will fill secure_tx, we just prepare buffers here */
  memset(&secure_tx, 0, sizeof(secure_tx));
  secure_tx.data = txbuf;
  secure_tx.datalen = sizeof(txbuf);
  secure_tx.resp = rxbuf;
  secure_tx.resplen = sizeof(rxbuf);

  /* prepare secure channel transmission */
  r = card_prepare_secure_tx(card, tx, &secure_tx);
  if (r!=SC_SUCCESS)
    return r;

  /* envelope data and transmit */
  r = card_envelope_transmit(card, &secure_tx);
  if (r!=SC_SUCCESS)
    return r;

  /* retrieve secure channel reception bytes */
  r = card_parse_secure_rx(card, &secure_tx, tx);
  if (r!=SC_SUCCESS)
    return r;

  return r;
}

