/*
 * base_card.c: Support for DNI-e card 
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


#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <zlib.h>
#include "libopensc/internal.h" 
#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/log.h"
#include "libopensc/asn1.h"
#include "libopensc/pkcs15.h"
#include "base_card.h"
#include "pkcs15_default.h"
#include "pkcs15_standard.h"
#include "util.h"
#include "virtual_fs.h"
#include "virtual_pkcs15_fs.h"
#include "card_sync.h"

static struct sc_atr_table card_atrs[] = {
  /* ATR DNIe perso 1.0 */
  /*  { "3B:7F:38:00:00:00:6A:44:4E:49:65:10:02:4C:34:01:10:03:90:00", NULL, DNIE_CHIP_NAME , SC_CARD_TYPE_DNIE, 0, NULL } */
  {
    "3B:7F:00:00:00:00:6A:44:4E:49:65:00:00:00:00:00:00:00:90:00",
    "FF:FF:00:FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:00:FF:FF",
    CARD_CHIP_NAME, 
    SC_CARD_TYPE_DNIE_USER,
    0,
    NULL
  },
  { /* card invalidated */
    "3B:7F:00:00:00:00:6A:44:4E:49:65:00:00:00:00:00:00:0F:65:81",
    "FF:FF:00:FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:FF:FF:FF",
    CARD_CHIP_NAME, 
    SC_CARD_TYPE_DNIE_TERMINATED,
    0,
    NULL
  },
  { NULL, NULL, NULL, 0, 0, NULL }
};

static struct sc_card_operations card_ops;
static const struct sc_card_operations *iso_ops = NULL;

static struct sc_card_driver card_drv = {
  MODULE_DESC,
  MODULE_NAME,
  &card_ops,
  NULL, 0, NULL
};

int _dnie_add_algorithm(sc_card_t *card, const sc_algorithm_info_t *info)
{
        sc_algorithm_info_t *p;
        // from rev r4785 sc_card_valid(card) is removed
        assert( (card != NULL) && (info != NULL) );
        p = (sc_algorithm_info_t *) realloc(card->algorithms, (card->algorithm_count + 1) * sizeof(*info));
        if (!p) {
                if (card->algorithms)
                        free(card->algorithms);
                card->algorithms = NULL;
                card->algorithm_count = 0;
                return SC_ERROR_OUT_OF_MEMORY;
        }
        card->algorithms = p;
        p += card->algorithm_count;
        card->algorithm_count++;
        *p = *info;
        return 0;
}


int _dnie_add_rsa_alg(sc_card_t *card, unsigned int key_length,
                         unsigned long flags, unsigned long exponent)
{
        sc_algorithm_info_t info;

        memset(&info, 0, sizeof(info));
        info.algorithm = SC_ALGORITHM_RSA;
        info.key_length = key_length;
        info.flags = flags;
        info.u._rsa.exponent = exponent;

        return _dnie_add_algorithm(card, &info);
}


static int dnie_match_atr_table(sc_context_t *ctx, struct sc_atr_table *table, u8 *atr, size_t atr_len)
{
        u8 *card_atr_bin = atr;
        size_t card_atr_bin_len = atr_len;
        char card_atr_hex[3 * SC_MAX_ATR_SIZE];
        size_t card_atr_hex_len;
        unsigned int i = 0;

        if (ctx == NULL || table == NULL || atr == NULL)
                return -1;
        sc_bin_to_hex(card_atr_bin, card_atr_bin_len, card_atr_hex, sizeof(card_atr_hex), ':');
        card_atr_hex_len = strlen(card_atr_hex);

        sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "ATR     : %s\n", card_atr_hex);

        for (i = 0; table[i].atr != NULL; i++) {
                const char *tatr = table[i].atr;
                const char *matr = table[i].atrmask;
                size_t tatr_len = strlen(tatr);
                u8 mbin[SC_MAX_ATR_SIZE], tbin[SC_MAX_ATR_SIZE];
                size_t mbin_len, tbin_len, s, matr_len;
                size_t fix_hex_len = card_atr_hex_len;
                size_t fix_bin_len = card_atr_bin_len;
                sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "ATR try : %s\n", tatr);

                if (tatr_len != fix_hex_len) {
                        sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "ignored - wrong length\n", tatr);
                        continue;
                }
                if (matr != NULL) {
                        sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "ATR mask: %s\n", matr);

                        matr_len = strlen(matr);
                        if (tatr_len != matr_len)
                                continue;
                        tbin_len = sizeof(tbin);
                        sc_hex_to_bin(tatr, tbin, &tbin_len);
                        mbin_len = sizeof(mbin);
                        sc_hex_to_bin(matr, mbin, &mbin_len);
                        if (mbin_len != fix_bin_len) {
                                sc_debug(ctx,SC_LOG_DEBUG_VERBOSE, "length of atr and atr mask do not match - ignored: %s - %s", tatr, matr);
                                continue;
                        }
                        for (s = 0; s < tbin_len; s++) {
                                /* reduce tatr with mask */
                                tbin[s] = (tbin[s] & mbin[s]);
                                /* create copy of card_atr_bin masked) */
                                mbin[s] = (card_atr_bin[s] & mbin[s]);
                        }
                        if (memcmp(tbin, mbin, tbin_len) != 0)
                                continue;
                } else {
                        if (strncasecmp(tatr, card_atr_hex, tatr_len) != 0)
                                continue;
                }
                return i;
        }
        return -1;
}


int _dnie_match_atr(sc_card_t *card, struct sc_atr_table *table, int *type_out)
{
        int res;

        if (card == NULL)
                return -1;
        res = dnie_match_atr_table(card->ctx, table, card->atr, card->atr_len);
        if (res < 0)
                return res;
        if (type_out != NULL)
                *type_out = table[res].type;
        return res;
}

static int card_match_card(struct sc_card *card)
{   
  int r = SC_SUCCESS;;

  SC_FUNC_CALLED(card->ctx, 1);
	
  r = _dnie_match_atr(card, card_atrs, &card->type);
  if (card->ctx->debug && (card->type==SC_CARD_TYPE_DNIE_TERMINATED))
    sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "ATR Matches invalidated DNIe\n"); 
  if (r<0)
    r = 0; /* error */
  else
    r = 1; /* ok! */

  SC_FUNC_RETURN(card->ctx, 1, r);
}


static int card_init(struct sc_card *card)
{ 
  struct card_priv_data * priv;
  int i, id, r=0;
  unsigned long flags;

  SC_FUNC_CALLED(card->ctx, 1);

  /* if recognized an invalidated DNIe card, return error */
  if (card->type==SC_CARD_TYPE_DNIE_TERMINATED) {
    card->drv_data = priv = NULL;
    r = SC_ERROR_MEMORY_FAILURE;
    goto ci_err;
  }

  card->drv_data = priv = (struct card_priv_data *) malloc(sizeof(struct card_priv_data));
  if (card->drv_data == NULL) {    
    r = SC_ERROR_OUT_OF_MEMORY;
    goto ci_err;
  }

  memset( priv, 0, sizeof( *priv ) );
  priv->secure_channel_state = secure_channel_not_created;
  priv->trusted_channel_err = 0;
  /* Maps a path from virtual_fs to card */
  priv->virtual_fs_to_card_path_map = map_path_to_path_new();
  if(!priv->virtual_fs_to_card_path_map) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto ci_err;
  }

  /* Maps a ckaid from virtual_fs to card */
  priv->virtual_fs_to_card_ckaid_map = map_id_to_id_new();
  if(!priv->virtual_fs_to_card_ckaid_map) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto ci_err;
  }

  /* Maps a card ckaid to der encoding for cdf */
  priv->cdf_card_ckaid_to_card_der_map = map_id_to_der_new();
  if(!priv->cdf_card_ckaid_to_card_der_map) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto ci_err;
  }

  /* Maps a card ckaid to der encoding for prkdf */
  priv->prkdf_card_ckaid_to_card_der_map = map_id_to_der_new();
  if(!priv->prkdf_card_ckaid_to_card_der_map) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto ci_err;
  }

  /* Maps a card ckaid to der encoding for pukdf */
  priv->pukdf_card_ckaid_to_card_der_map = map_id_to_der_new();
  if(!priv->pukdf_card_ckaid_to_card_der_map) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto ci_err;
  }

  /* Maps a card certificate file path to card certificate ckaid */
  priv->card_path_to_card_ckaid_map = map_path_to_id_new();
  if(!priv->card_path_to_card_ckaid_map) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto ci_err;
  }

  sc_format_path("3F00", &priv->current_path); /* set current path to 3F00 */
  priv->virtual_fs = virtual_fs_new();
  if(!priv->virtual_fs) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto ci_end;
  }

  /* activate virtual_fs */
  card_set_virtual_fs_state(card, 1);
  
  r = virtual_pkcs15_fs_init(priv->virtual_fs);
  if (r!=SC_SUCCESS) {
    sc_debug (card->ctx,SC_LOG_DEBUG_VERBOSE,  "Couldn't initialize PKCS#15 virtual fs\n");
    goto ci_end;
  }

  i = _dnie_match_atr(card, card_atrs, &id);
  if (i < 0) {
    sc_debug (card->ctx,SC_LOG_DEBUG_VERBOSE,  "no correct id parsed!! Id:%d\n", id);
    goto ci_err;
  }

  card->name = "dnie";

  flags = SC_ALGORITHM_RSA_RAW;
  flags |= SC_ALGORITHM_RSA_HASH_NONE;

  _dnie_add_rsa_alg(card, 1024, flags, 0);
  _dnie_add_rsa_alg(card, 2048, flags, 0);

  card->type=id;
  priv->card_type = id;		

  card->cla = 0x00;	


  /* State that we have an RNG */
  card->caps |= SC_CARD_CAP_RNG;

 ci_err:
 ci_end:
  if(r != SC_SUCCESS) {
    if(priv) {
      if(priv->virtual_fs_to_card_path_map) {
	map_free(priv->virtual_fs_to_card_path_map);
	priv->virtual_fs_to_card_path_map = NULL;
      }

      if(priv->virtual_fs_to_card_ckaid_map) {
	map_free(priv->virtual_fs_to_card_ckaid_map);
	priv->virtual_fs_to_card_ckaid_map = NULL;
      }

      if(priv->cdf_card_ckaid_to_card_der_map) {
	map_free(priv->cdf_card_ckaid_to_card_der_map);
	priv->cdf_card_ckaid_to_card_der_map = NULL;
      }

      if(priv->prkdf_card_ckaid_to_card_der_map) {
	map_free(priv->prkdf_card_ckaid_to_card_der_map);
	priv->prkdf_card_ckaid_to_card_der_map = NULL;
      }

      if(priv->pukdf_card_ckaid_to_card_der_map) {
	map_free(priv->pukdf_card_ckaid_to_card_der_map);
	priv->pukdf_card_ckaid_to_card_der_map = NULL;
      }

      if(priv->virtual_fs) {
        virtual_fs_free(priv->virtual_fs);
        priv->virtual_fs = NULL;
      }
      free(priv);
      priv = NULL;
    }
  }
  SC_FUNC_RETURN(card->ctx, 1, r);
}


static int card_finish(struct sc_card *card)
{ 
  SC_FUNC_CALLED(card->ctx, 1);

  if (DRVDATA(card)) {
    if(DRVDATA(card)->virtual_fs) {
      virtual_fs_free(DRVDATA(card)->virtual_fs);
      DRVDATA(card)->virtual_fs = NULL;
    }
    if(DRVDATA(card)->virtual_fs_to_card_path_map) {
      map_free(DRVDATA(card)->virtual_fs_to_card_path_map);
      DRVDATA(card)->virtual_fs_to_card_path_map = NULL;
    }
    if(DRVDATA(card)->virtual_fs_to_card_ckaid_map) {
      map_free(DRVDATA(card)->virtual_fs_to_card_ckaid_map);
      DRVDATA(card)->virtual_fs_to_card_ckaid_map = NULL;
    }
    if(DRVDATA(card)->cdf_card_ckaid_to_card_der_map) {
      map_free(DRVDATA(card)->cdf_card_ckaid_to_card_der_map);
      DRVDATA(card)->cdf_card_ckaid_to_card_der_map = NULL;
    }
    if(DRVDATA(card)->prkdf_card_ckaid_to_card_der_map) {
      map_free(DRVDATA(card)->prkdf_card_ckaid_to_card_der_map);
      DRVDATA(card)->prkdf_card_ckaid_to_card_der_map = NULL;
    }
    if(DRVDATA(card)->pukdf_card_ckaid_to_card_der_map) {
      map_free(DRVDATA(card)->pukdf_card_ckaid_to_card_der_map);
      DRVDATA(card)->pukdf_card_ckaid_to_card_der_map = NULL;
    }
    if(DRVDATA(card)->card_path_to_card_ckaid_map) {
      map_free(DRVDATA(card)->card_path_to_card_ckaid_map);
      DRVDATA(card)->card_path_to_card_ckaid_map = NULL;
    }    

    /* Wipe out private card struct memory */
    memset( card->drv_data, 0, sizeof(struct card_priv_data) );
    free(card->drv_data);
  }
  card->drv_data = NULL;
  SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);
}

static int card_check_sw(sc_card_t *card, unsigned int sw1, unsigned int sw2)
{
  sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Entering function card_check_sw\n"); 

  if((sw1==0x66)&&(sw2==0x88)) {
    sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "The securized message value is incorrect\n");
    return SC_ERROR_UNKNOWN;
  }
  if(sw1==0x6A && (sw2==0x88 || sw2==0x80 || sw2==0x89)){
    sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "File/Key already exists!\n");
    return SC_ERROR_OBJECT_ALREADY_EXISTS;
  }  
  if(sw1==0x62 && sw2==0x83) {
    sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Invalid file!\n");   
    return SC_ERROR_INVALID_FILE;
  }
  if(sw1==0x6A && sw2==0x84) {
    sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Not enough memory!\n");
    return SC_ERROR_NOT_ENOUGH_MEMORY;
  }

  sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Leaving function card_check_sw\n"); 
  
  return iso_ops->check_sw(card,sw1,sw2);
}

/* virtual fs functions */
int card_is_virtual_fs_active(struct sc_card *card)
{
  return DRVDATA(card)->use_virtual_fs;
}

void card_set_virtual_fs_state(struct sc_card *card, int active)
{
  if(active) {
    DRVDATA(card)->use_virtual_fs = 1;
    card->max_send_size = 0xffff;
    card->max_recv_size = 0xffff;
    sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "virtual_fs mode activated\n");
  } else {
    DRVDATA(card)->use_virtual_fs = 0;
    card->max_send_size = 0xf0;
    card->max_recv_size = 0xf0;
    sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "virtual_fs mode deactivated\n");
  }
}

static int card_set_security_env(struct sc_card *card,
				 const struct sc_security_env *env,
				 int se_num)
{
  SC_FUNC_CALLED(card->ctx, 1);

  if (env->flags & SC_SEC_ENV_ALG_PRESENT) {
		
    if (env->algorithm != SC_ALGORITHM_RSA) {
      sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "La tarjeta DNIe solo soporta el algoritmo RSA.\n");
      return SC_ERROR_NOT_SUPPORTED;
    }		
    if (((env->algorithm_flags & SC_ALGORITHM_RSA_HASHES) != 0) && !(env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1))
      {
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "La tarjeta DNIe solo soporta algoritmo RSA con SHA1.\n");
	return SC_ERROR_NOT_SUPPORTED;
      }
  }
  
  if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
    if(env->key_ref_len>1)
      {
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Identificador de clave erroneo.\n");
	return SC_ERROR_NOT_SUPPORTED;
      }
    
    DRVDATA(card)->rsa_key_ref = env->key_ref[0];		
  }
  
  if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
    if(env->key_ref_len>1)
      {
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Identificador de clave erróneo.\n");
	return SC_ERROR_NOT_SUPPORTED;
      }
    
    DRVDATA(card)->rsa_key_ref = env->key_ref[0];
  }
  
  sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Key_ref= 0x%X", env->key_ref[0]);

  SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);
}

static int card_compute_signature(struct sc_card *card,
				  const u8 * data, size_t datalen,
				  u8 * out, size_t outlen)
{ 
  struct sc_apdu apdu;		
  int r = SC_SUCCESS;	

  SC_FUNC_CALLED(card->ctx, 1);

  assert(card != NULL && data != NULL && out != NULL);

  memset(&apdu, 0, sizeof(struct sc_apdu));

  /* Check if we are using FIRMA private key */
  if (DRVDATA(card)->rsa_key_ref == 0x02) {
	/* FIXME: verify user consent */	    
  }

  /* check if serial channel has been created and create it if not */
  if((r = card_assure_secure_channel(card)) != SC_SUCCESS)
    goto end;

  /* Load Data */
  memset(&apdu, 0, sizeof(apdu));
  sc_format_apdu(card, &apdu, 
		 SC_APDU_CASE_3_SHORT,
		 0x58,   
		 0x00,   
		 0x00 );
  
  apdu.cla = 0x90;
  apdu.lc = datalen;
  apdu.data = data;
  apdu.datalen = datalen;	

  r = card_transmit_apdu(card, &apdu);
  if (r!=SC_SUCCESS)
    goto end;

  /* Sign Data */
  sc_format_apdu(card, &apdu, 
		 SC_APDU_CASE_3_SHORT,
		 0x5A,   
		 0x80,   
		 DRVDATA(card)->rsa_key_ref );
  
  apdu.cla = 0x90;
  apdu.le = outlen;
  apdu.resp = out;
  apdu.resplen = outlen;

  r = card_transmit_apdu(card, &apdu);
  SC_TEST_RET(card->ctx,  SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

  if (apdu.resplen == 0)
    return sc_check_sw(card, apdu.sw1, apdu.sw2);

 end:
  if (r!=SC_SUCCESS) {
    SC_FUNC_RETURN(card->ctx, 1, r);
  }
  else if (apdu.resplen==0) {
    SC_FUNC_RETURN(card->ctx, 1, sc_check_sw(card, apdu.sw1, apdu.sw2));
  }
  else {
    SC_FUNC_RETURN(card->ctx, 1, apdu.resplen);
  }
}

static int card_decipher(struct sc_card *card, const u8 *data, size_t datalen,
			 u8 *out, size_t outlen)
{ 
  int r = SC_SUCCESS;
  struct sc_apdu apdu;
  u8 rbuf[4096];		
  size_t len=0;
  
  SC_FUNC_CALLED(card->ctx, 1);

  assert(card != NULL && data != NULL && out != NULL);

  /* check if trusted channel has been created and create it if not */
  if((r = card_assure_secure_channel(card)) != SC_SUCCESS)
    SC_FUNC_RETURN(card->ctx, 1, r);

  /*! format apdu */
  sc_format_apdu(card, &apdu, 
		 SC_APDU_CASE_4_SHORT,
		 0x74,   
		 0x40,   
		 DRVDATA(card)->rsa_key_ref );
   
  memset(rbuf, 0, sizeof(rbuf));
  apdu.cla = 0x90;
  apdu.lc = datalen;
  apdu.data = data;
  apdu.datalen = apdu.lc;
  apdu.le      = sizeof(rbuf); 
  apdu.resp    = rbuf;
  apdu.resplen = sizeof(rbuf);

  /* transmit data to card */
  r = card_transmit_apdu(card, &apdu);
  if (r || apdu.resplen==0)
    r = card_check_sw(card, apdu.sw1, apdu.sw2);

  /* copies data to returned buffer */
  len = apdu.resplen > outlen ? outlen : apdu.resplen;
  memcpy(out, apdu.resp, len);
  
  SC_FUNC_RETURN(card->ctx, 1, len);
}

static int card_get_challenge(struct sc_card *card, u8 *rnd, size_t len)
{ 
  int r = SC_SUCCESS;
  struct sc_apdu apdu;
  u8 buf[22];

  SC_FUNC_CALLED(card->ctx, 1);

  /* check if serial channel has been created and create it if not */
  if((r = card_assure_secure_channel(card)) != SC_SUCCESS)
    SC_FUNC_RETURN(card->ctx, 1, r);
  
  sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT,
		 0x84, 0x00, 0x00);
  apdu.le = 20;
  apdu.resp = buf;
  apdu.resplen = 20;	/* include SW's */

  while (len > 0) {
    int n = len > 20 ? 20 : len;
		
    r = card_transmit_apdu(card, &apdu);
    SC_TEST_RET(card->ctx,  SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
    if (apdu.resplen != 20)
      return card_check_sw(card, apdu.sw1, apdu.sw2);
    memcpy(rnd, apdu.resp, n);
    len -= n;
    rnd += n;
  }	

  SC_FUNC_RETURN(card->ctx, 1, r);
}

static int iso_build_pin_apdu(sc_card_t *card, sc_apdu_t *apdu,
		struct sc_pin_cmd_data *data, u8 *buf, size_t buf_len)
{
	int r, len = 0, pad = 0, use_pin_pad = 0, ins, p1 = 0;
	
	switch (data->pin_type) {
	case SC_AC_CHV:
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (data->flags & SC_PIN_CMD_NEED_PADDING)
		pad = 1;
	if (data->flags & SC_PIN_CMD_USE_PINPAD)
		use_pin_pad = 1;

	data->pin1.offset = 5;

	switch (data->cmd) {
	case SC_PIN_CMD_VERIFY:
		ins = 0x20;
		if ((r = sc_build_pin(buf, buf_len, &data->pin1, pad)) < 0)
			return r;
		len = r;
		break;
	case SC_PIN_CMD_CHANGE:
		ins = 0x24;
		if (data->pin1.len != 0 || use_pin_pad) {
			if ((r = sc_build_pin(buf, buf_len, &data->pin1, pad)) < 0)
				return r;
			len += r;
		} else {
			/* implicit test */
			p1 = 1;
		}

		data->pin2.offset = data->pin1.offset + len;
		if ((r = sc_build_pin(buf+len, buf_len-len, &data->pin2, pad)) < 0)
			return r;
		len += r;
		break;
	case SC_PIN_CMD_UNBLOCK:
		ins = 0x2C;
		if (data->pin1.len != 0 || use_pin_pad) {
			if ((r = sc_build_pin(buf, buf_len, &data->pin1, pad)) < 0)
				return r;
			len += r;
		} else {
			p1 |= 0x02;
		}

		if (data->pin2.len != 0 || use_pin_pad) {
			data->pin2.offset = data->pin1.offset + len;
			if ((r = sc_build_pin(buf+len, buf_len-len, &data->pin2, pad)) < 0)
				return r;
			len += r;
		} else {
			p1 |= 0x01;
		}
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	sc_format_apdu(card, apdu, SC_APDU_CASE_3_SHORT,
				ins, p1, data->pin_reference);

	apdu->lc = len;
	apdu->datalen = len;
	apdu->data = buf;
	apdu->resplen = 0;

	return 0;
}

static int iso_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data,
		       int *tries_left)
{
  sc_apdu_t local_apdu, *apdu;
  int r;
  u8  sbuf[SC_MAX_APDU_BUFFER_SIZE];
  
  if (tries_left)
    *tries_left = -1;
   

  card_card_create_secure_channel(card); /*Uncomment this on MAC OS X systems*/
  /* See if we've been called from another card driver, which is
   * passing an APDU to us (this allows to write card drivers
   * whose PIN functions behave "mostly like ISO" except in some
   * special circumstances.
   */
  if (data->apdu == NULL) {
    r = iso_build_pin_apdu(card, &local_apdu, data, sbuf, sizeof(sbuf));
    if (r < 0)
      return r;
    data->apdu = &local_apdu;
  }
  apdu = data->apdu;

  /* Transmit the APDU to the card */
  r = card_transmit_apdu(card, apdu);
  
  /* Clear the buffer - it may contain pins */
  sc_mem_clear(sbuf, sizeof(sbuf));

  /* Don't pass references to local variables up to the caller. */
  if (data->apdu == &local_apdu)
    data->apdu = NULL;

  SC_TEST_RET(card->ctx,  SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
  if (apdu->sw1 == 0x63) {
    if ((apdu->sw2 & 0xF0) == 0xC0 && tries_left != NULL)
      *tries_left = apdu->sw2 & 0x0F;
    return SC_ERROR_PIN_CODE_INCORRECT;
  }
  return card_check_sw(card, apdu->sw1, apdu->sw2);
}

static int card_build_pin_apdu(struct sc_card *card,
			       struct sc_apdu *apdu,
			       struct sc_pin_cmd_data *data)
{ 
  u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
  int r = SC_SUCCESS, len=0, pad = 0, cla=0, ins, p1 = 0, p2 = 0;	

  SC_FUNC_CALLED(card->ctx, 1);

  switch (data->pin_type) {
  case SC_AC_CHV:
    break;
  default:
    return SC_ERROR_INVALID_ARGUMENTS;
  }

  if (data->flags & SC_PIN_CMD_NEED_PADDING)
    pad = 1;

  switch (data->cmd) {
  case SC_PIN_CMD_VERIFY:

    data->pin1.offset = 0;
    if ((r = sc_build_pin(sbuf, sizeof(sbuf), &data->pin1, pad)) < 0)
      return r;
    len = r;

    cla = 0x00;
    ins = 0x20;
    p1 = 0;
    /* ignore pin_reference */
    p2 = 0x00;
    break;
  case SC_PIN_CMD_CHANGE:
    /* not supported in user driver */
    return SC_ERROR_NOT_SUPPORTED;
  case SC_PIN_CMD_UNBLOCK:
    /* not supported in user driver */
    return SC_ERROR_NOT_SUPPORTED;
  default:
    return SC_ERROR_NOT_SUPPORTED;
  }

  memset(apdu, 0, sizeof(*apdu));
  apdu->cla = cla;
  apdu->cse = SC_APDU_CASE_3_SHORT;
  apdu->ins = (u8) ins;
  apdu->p1 = (u8) p1;
  apdu->p2 = (u8) p2;

  apdu->lc = len;
  apdu->datalen = len;
  apdu->data = sbuf;
  apdu->resplen = 0;
  apdu->le = 0;

  SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);
}

static int card_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, int *tries_left)
{ 
  int r = SC_SUCCESS;
  sc_apdu_t local_apdu;

  SC_FUNC_CALLED(card->ctx, 1);

  /* check if serial channel has been created and create it if not */
  if((r = card_assure_secure_channel(card)) != SC_SUCCESS)
    SC_FUNC_RETURN(card->ctx, 1, r);

  data->flags &= ~SC_PIN_CMD_NEED_PADDING;  
  data->apdu = &local_apdu;
  r = card_build_pin_apdu(card, data->apdu, data);
  if (r!=SC_SUCCESS)
    SC_FUNC_RETURN(card->ctx, 1, r);

  r = iso_pin_cmd(card, data, tries_left);
  if (r!=SC_SUCCESS)
    SC_FUNC_RETURN(card->ctx, 1, r);

  /* remove reference to stack variable apdu */
  memset(&local_apdu, 0, sizeof(local_apdu));
  data->apdu = NULL;

  SC_FUNC_RETURN(card->ctx, 1, r);
}

int iso_select_file(sc_card_t *card,
		    const sc_path_t *in_path,
		    sc_file_t **file_out)
{
  sc_context_t *ctx = NULL;
  sc_apdu_t apdu;
  u8 buf[SC_MAX_APDU_BUFFER_SIZE];
  u8 pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
  int r = SC_SUCCESS, pathlen;
  sc_file_t *file = NULL;

  SC_FUNC_CALLED(card->ctx, 1);
 
  assert(card != NULL && in_path != NULL);

  ctx = card->ctx;
  memcpy(path, in_path->value, in_path->len);
  pathlen = in_path->len;

  sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0);       
  
  switch (in_path->type) {
  case SC_PATH_TYPE_FILE_ID:
    apdu.p1 = 0;
    if (pathlen != 2) {
      sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "ERROR: Invalid arguments! pathlen != 2\n");
      SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
    }
    break;
  case SC_PATH_TYPE_DF_NAME:
    apdu.p1 = 4;
    break;
  case SC_PATH_TYPE_PATH:
    /* transform to file id */
    if(pathlen%2) {
      sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "ERROR: Invalid arguments! pathlen not multiple of 2\n");
      SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
    }
    
    while(pathlen>0) {
      sc_path_t temp_path;
      if(path[0] == 0x3f && path[1] == 0x00) {
	temp_path.type = SC_PATH_TYPE_DF_NAME;
	strcpy((char *)temp_path.value, CARD_MF_NAME);
	temp_path.len = sizeof(CARD_MF_NAME) - 1;
      } else {
	temp_path.type = SC_PATH_TYPE_FILE_ID;
	temp_path.value[0] = path[0];
	temp_path.value[1] = path[1];
	temp_path.len = 2;
      }
      r = iso_select_file(card, &temp_path, file_out);
      if(r != SC_SUCCESS) {
	goto end;
      }
      pathlen-=2;
      path+=2;
    }
    goto end;
    break;
  default:
    sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "ERROR: Invalid arguments! default case %d\n", in_path->type);
    SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_INVALID_ARGUMENTS);
  }
  apdu.p2 = 0;		/* first record, return FCI */
  apdu.lc = pathlen;
  apdu.data = path;
  apdu.datalen = pathlen;

  if (file_out != NULL) {
    apdu.resp = buf;
    apdu.resplen = sizeof(buf);
    apdu.le = 256;
  } else {
    apdu.resplen = 0;
    apdu.le = 0;
    apdu.cse = SC_APDU_CASE_3_SHORT;
  }
  r = card_transmit_apdu(card, &apdu);
  SC_TEST_RET(card->ctx,  SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
  if (file_out == NULL) {
    if (apdu.sw1 == 0x61)
      SC_FUNC_RETURN(card->ctx, 2, 0);
    SC_FUNC_RETURN(card->ctx, 2, card_check_sw(card, apdu.sw1, apdu.sw2));
  }

  r = card_check_sw(card, apdu.sw1, apdu.sw2);
  if (r!=SC_SUCCESS)
    SC_FUNC_RETURN(card->ctx, 2, r);

  switch (apdu.resp[0]) {
  case 0x6F:
    file = sc_file_new();
    if (file == NULL)
      SC_FUNC_RETURN(card->ctx, 0, SC_ERROR_OUT_OF_MEMORY);
    file->path = *in_path;
    if (card->ops->process_fci == NULL) {
      sc_file_free(file);
      SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NOT_SUPPORTED);
    }
    if (apdu.resp[1] <= apdu.resplen)
      card->ops->process_fci(card, file, apdu.resp+2, apdu.resp[1]);
    *file_out = file;
    break;
  case 0x00:	/* proprietary coding */
    SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_UNKNOWN_DATA_RECEIVED);
    break;
  default:
    SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_UNKNOWN_DATA_RECEIVED);
  }

 end:
  SC_FUNC_RETURN(card->ctx, 1, r);
}

int card_select_file(struct sc_card *card, const struct sc_path *in_path,
		     struct sc_file **file)
{   
  int r = SC_SUCCESS;
  unsigned int ii=0;
  sc_path_t temp_path;
  sc_path_t next_path;
  virtual_file_t *virtual_file = NULL;

  SC_FUNC_CALLED(card->ctx, 1);

  if(card_is_virtual_fs_active(card)) {
    /* virtual fs usage */
    if(!in_path || in_path->len < 2 || (in_path->len%2) == 1) {
      /* non-existant or bad in_path */
      r = SC_ERROR_INVALID_ARGUMENTS;
      goto csf_end;
    }

    if((in_path->type != SC_PATH_TYPE_FILE_ID) &&
       (in_path->type != SC_PATH_TYPE_PATH)) {
      /* we don't support string names in path for now */
      r = SC_ERROR_INVALID_ARGUMENTS;
      goto csf_end;
    }

    /* set current path to next_path */
    memcpy(&next_path, &DRVDATA(card)->current_path, sizeof(next_path));
  
    /* iterate through path */
    for(ii=0; ii<in_path->len; ii+=2) {
      if((in_path->value[ii]==0x3f) && (in_path->value[ii+1]==0x00)) {
	/* we go to root again */
	sc_format_path("3F00", &next_path);
      } else {
	/* build a temporal path with current file */
	/* the casting is needed tp remove warning. sc_path_set should const param id because it remains unmodified */
	r = sc_path_set_dnie(&temp_path, in_path->type, (unsigned char *)in_path->value+ii, 2, 0, 0);
	if(r!=SC_SUCCESS) 
	  goto csf_end;
	
	/* append to current file */
	r = sc_append_path(&next_path, &temp_path);
	if(r!=SC_SUCCESS) 
	  goto csf_end;
      }

      /* we have a path we should select */
      sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Selecting %s\n", sc_print_path(&next_path));
      virtual_file = virtual_fs_find_by_path(DRVDATA(card)->virtual_fs, &next_path);
      if(virtual_file) {
	/* file exists! */
	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "File selected successfully\n");

	/* set current path to this new path */
	memcpy(&DRVDATA(card)->current_path, &next_path, sizeof(next_path));
      } else {
	/* file doesn't exist! */
	r = SC_ERROR_FILE_NOT_FOUND;
	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "File selection failed\n");
	goto csf_end;
      }
      
    }

    if(!virtual_file) {
      /* this should be impossible.
	 we should really have a virtual_file here.
	 if not something happened with the internal logic */
      r = SC_ERROR_INTERNAL;
      goto csf_end;
    }

    /* we now synchronize file because this gets a correct size for it */
    r = virtual_file_data_synchronize(virtual_file, card, virtual_file_sync_type_card_to_virtual_fs, DRVDATA(card)->virtual_fs);
    if (r != SC_SUCCESS) {
      sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Synchronization failed\n");
      goto csf_end;
    }
  
    if(file) {
      /* we have to create a file structure */
      *file = sc_file_new();
      if(!*file) {
	r=SC_ERROR_OUT_OF_MEMORY;
	goto csf_end;
      }

      /* fill file */
      r = virtual_file_export_file(virtual_file, *file);
      if(r != SC_SUCCESS) {
	sc_file_free(*file);
	*file = NULL;
      }
    }
  } else {
    /* check if serial channel has been created and create it if not */
    if((r = card_assure_secure_channel(card)) != SC_SUCCESS)
      goto csf_end;
  
    /* not virtual fs select file */
    r = iso_select_file(card, in_path, file);
    if (r!=SC_SUCCESS)
      goto csf_end;
  }  
  
 csf_end:
  SC_FUNC_RETURN(card->ctx, 1, r); 
}

static void card_add_acl_entry(sc_card_t *card, sc_file_t *file, int op, u8 byte)
{
  unsigned int method, key_ref = SC_AC_KEY_REF_NONE;

  assert(card!=NULL);

  SC_FUNC_CALLED(card->ctx, 1);

  switch (byte >> 4) {
  case 0:
    method = SC_AC_NONE;
    break;
  case 1:
    method = SC_AC_CHV;
    key_ref = byte & 0x0F;	       
    break;
  case 3:
    method = SC_AC_CHV;
    key_ref = byte & 0x0F;	       
    break;
  case 4:
    method = SC_AC_TERM;
    key_ref = byte & 0x0F;
    break;
  case 15:
    method = SC_AC_NEVER;
    break;
  default:
    method = SC_AC_UNKNOWN;
    break;
  }
  sc_file_add_acl_entry(file, op, method, key_ref);

  sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Leaving function card_add_acl_entry\n"); 
}

static void card_parse_sec_attr(sc_card_t *card, sc_file_t *file, const u8 * buf, size_t len)
{
  int i;
  int idx[4];

  assert(card!=NULL);

  SC_FUNC_CALLED(card->ctx, 1);

  if (len < 4)
    return;
  if (file->type == SC_FILE_TYPE_DF) {
    const int df_idx[4] = {
      SC_AC_OP_CREATE, SC_AC_OP_DELETE ,
      SC_AC_OP_REHABILITATE, SC_AC_OP_INVALIDATE
    };
    for (i = 0; i <4; i++)
      idx[i] = df_idx[i];
  } else {
    const int ef_idx[4] = {
      SC_AC_OP_READ, SC_AC_OP_UPDATE,
      SC_AC_OP_REHABILITATE, SC_AC_OP_INVALIDATE
    };
    for (i = 0; i < 4; i++)
      idx[i] = ef_idx[i];
  }
  for (i = 0; i < 4; i++)
    card_add_acl_entry(card, file, idx[i], buf[i]);

  sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Leaving function card_parse_sec_attr\n"); 
}

static int card_process_fci(sc_card_t *card, sc_file_t *file,
			    const u8 *buf, size_t buflen)
{
  int r = SC_SUCCESS;

  SC_FUNC_CALLED(card->ctx, 1);

  r = iso_ops->process_fci(card, file, buf, buflen);
  if (r!=SC_SUCCESS)
    goto cpf_err;

  if (file->prop_attr_len >= 10) {

    /* Examine file type */
    switch (file->prop_attr[0]) {
    case 0x01:
      file->type = SC_FILE_TYPE_WORKING_EF;
      file->ef_structure = SC_FILE_EF_TRANSPARENT;
      break;
    case 0x15:
      file->type = SC_FILE_TYPE_WORKING_EF;
      break;
    case 0x38: /* 0x38 is DF */
      file->type = SC_FILE_TYPE_DF;
      break;
    }
    /* File identifier */
    file->id = (file->prop_attr[1] << 8) | file->prop_attr[2];

    /* File size */
    file->size = (file->prop_attr[3] << 8) | file->prop_attr[4];

    /* Parse acces conditions bytes (4) from propietary information */
    card_parse_sec_attr(card, file, (file->prop_attr)+5, 4);
  }

 cpf_err:
  SC_FUNC_RETURN(card->ctx, 1, r);
}

static int card_ctl(struct sc_card *card, unsigned long cmd, void *ptr)
{ 
  assert(card!=NULL);

  SC_FUNC_CALLED(card->ctx, 1);
  
  switch (cmd) {
  case SC_CARDCTL_GET_SERIALNR:
    sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Calling function card_get_serialnr\n"); 
    return card_get_serialnr(card, (sc_serial_number_t *) ptr);
  default:
    return SC_ERROR_NOT_SUPPORTED;
  }	
  
}

static int card_read_binary(sc_card_t *card,
			    unsigned int idx, u8 *buf, size_t count,
			    unsigned long flags)
{
  int r = SC_SUCCESS;
  virtual_file_t *virtual_file = NULL;
  sc_apdu_t apdu;
  u8 recvbuf[SC_MAX_APDU_BUFFER_SIZE];
 
  SC_FUNC_CALLED(card->ctx, 1);
  
  if(card_is_virtual_fs_active(card)) {
    /* we get file from our virtual_fs */
    virtual_file = virtual_fs_find_by_path(DRVDATA(card)->virtual_fs, &DRVDATA(card)->current_path);
    if(!virtual_file) {
      /* this should be impossible.
	 we should really have a virtual_file here.
	 if not something happened with the internal logic */
      r = SC_ERROR_INTERNAL;
      goto crb_end;
    }

    if(!virtual_file->is_ef) {
      r = SC_ERROR_NOT_ALLOWED;
      goto crb_end;
    }
    
    /* synchronizes if needed from the card to the virtual fs */
    r = virtual_file_data_synchronize(virtual_file, card, virtual_file_sync_type_card_to_virtual_fs, DRVDATA(card)->virtual_fs);
    if (r != SC_SUCCESS) {
      sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Synchronization failed\n");
      goto crb_end;
    }

    r = virtual_file_data_read(virtual_file, idx, buf, count);
  } else {
    /* we get file as usual from the card */
    assert(count <= card->max_recv_size);
    sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0,
                   (idx >> 8) & 0x7F, idx & 0xFF);
    apdu.le = count;
    apdu.resplen = count;
    apdu.resp = recvbuf;
    
    r = card_transmit_apdu(card, &apdu);
    SC_TEST_RET(card->ctx,  SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
    if (apdu.resplen == 0)
      SC_FUNC_RETURN(card->ctx, 2, card_check_sw(card, apdu.sw1, apdu.sw2));    
    memcpy(buf, recvbuf, apdu.resplen);
  }

 crb_end:
  if (r == SC_SUCCESS)
    r = count;

  SC_FUNC_RETURN(card->ctx, 1, r);
}


static int card_logout(struct sc_card *card)
{ 
  /* reset flag secure channel as not created */
  ((struct card_priv_data *) card->drv_data)->secure_channel_state = secure_channel_not_created;
  sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Leaving function card_logout");
  return 0;
}

int card_get_serialnr(sc_card_t *card, sc_serial_number_t *serial)
{
  int r = SC_SUCCESS;
  u8  rbuf[17];
  sc_apdu_t apdu;

  SC_FUNC_CALLED(card->ctx, 1);

  if (card->type != SC_CARD_TYPE_DNIE_USER)
    return SC_ERROR_NOT_SUPPORTED;

  if (!serial)
    return SC_ERROR_INVALID_ARGUMENTS;
  /* see if we have cached serial number */
  if (card->serialnr.len) {
    memcpy(serial, &card->serialnr, sizeof(*serial));
    return SC_SUCCESS;
  }

  /* check if serial channel has been created and create it if not */
  if((r = card_assure_secure_channel(card)) != SC_SUCCESS)
    return r;
    
  /* get serial number via APDU */
  sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xb8, 0x00, 0x00);
  apdu.cla = 0x90;
  apdu.resp = rbuf;
  apdu.resplen = sizeof(rbuf);
  apdu.le   = 0x11;
  apdu.lc   = 0;
  apdu.datalen = 0;
  r = card_transmit_apdu(card, &apdu);
  SC_TEST_RET(card->ctx,  SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
  if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00) {
    sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "ERROR: SW1:0x%x, SW2:0x%x\n", apdu.sw1, apdu.sw2); 
    return SC_ERROR_INTERNAL;
  }
  /* cache serial number */
  memcpy(card->serialnr.value, apdu.resp, 7*sizeof(u8)); /*apdu.resplen);*/
  card->serialnr.len = 7*sizeof(u8); /* apdu.resplen; */
  /* copy and return serial number */
  memcpy(serial, &card->serialnr, sizeof(*serial));

  SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);
}  

int card_envelope_transmit (sc_card_t *card, sc_apdu_t *tx)
{
  sc_apdu_t envelope_apdu;
  u8 corrected_tx[1024], envelope_data[1024];
  unsigned int len = 0, temp = 0, length = 0, total = 0;
  int r=0;

  memset(corrected_tx, 0, 1024);
  memset(envelope_data, 0, 1024);

  assert(card!=NULL);

  SC_FUNC_CALLED(card->ctx, 1);

  /* set correct p3 and slice commands if necessary */
  if (tx->lc > 255) {       
    corrected_tx[len++] = tx->cla;     /* CLA */
    corrected_tx[len++] = tx->ins;     /* INS */
    corrected_tx[len++] = tx->p1;      /* P1 */
    corrected_tx[len++] = tx->p2;      /* P2 */
    /* code data length */
    corrected_tx[len++] = 0x00;        /* 1st byte */
    corrected_tx[len++] = tx->lc>>8;   /* 2nd byte */
    corrected_tx[len++] = tx->lc&0xff; /* 3rd byte */

    /* add data */
    memcpy(corrected_tx+len,tx->data, tx->lc);

    /* total bytes */
    total = 7+tx->lc;

    /* next block length */
    length = 0;

    /* process all blocks */
    for (temp=0; temp<total; temp+=length) {
      length = ((total-temp)>255) ? 255 : total-temp;      

      /* prepare envelope apdu header */
      sc_format_apdu(card, &envelope_apdu, tx->cse, 0xC2, 0x00, 0x00);

      envelope_apdu.cla = 0x90;
      envelope_apdu.data = envelope_data;

      envelope_apdu.resp = tx->resp;
      envelope_apdu.resplen = tx->resplen;
      envelope_apdu.le = tx->le;
      
      /* P3 */
      envelope_apdu.lc = length;
      envelope_apdu.datalen = length;      

      /* copy next block */
      memcpy(envelope_data, corrected_tx+temp, length);            
      
      /* if secure channel is created, a get_response ALWAYS must be sent */
      if((((struct card_priv_data *) card->drv_data)->secure_channel_state == secure_channel_created) &&
	 (envelope_apdu.cse==SC_APDU_CASE_3_SHORT) &&
	 (envelope_apdu.resplen>0)) {
	envelope_apdu.cse = SC_APDU_CASE_4_SHORT;
	envelope_apdu.le = envelope_apdu.resplen > 255 ? 255 : envelope_apdu.resplen;
      }

      r = sc_transmit_apdu(card, &envelope_apdu);
      if (r != SC_SUCCESS)
	goto dea_err;
    }

    tx->resplen = envelope_apdu.resplen;
  } else {
    /* no envelope needed */
    int tmp_cse = tx->cse;

    /* if secure channel is created, a get_response ALWAYS must be sent */
    if((((struct card_priv_data *) card->drv_data)->secure_channel_state == secure_channel_created) &&
       (tmp_cse==SC_APDU_CASE_3_SHORT) &&
       (tx->resplen>0)) {
      tx->cse = SC_APDU_CASE_4_SHORT;
      tx->le = tx->resplen > 255 ? 255 : tx->resplen;
    }
    
    r = sc_transmit_apdu(card, tx);

    tx->cse=tmp_cse;        
  }
  
 dea_err:
  SC_FUNC_RETURN(card->ctx, 1, r);
}

int card_transmit_apdu(sc_card_t *card, sc_apdu_t *tx)
{
  int r=0;
  int retries=3;

  SC_FUNC_CALLED(card->ctx, 1);

  if (((struct card_priv_data *) card->drv_data)->secure_channel_state == secure_channel_created){
    r = card_secure_transmit(card, tx);

    while((((tx->sw1==0x66) && (tx->sw2==0x88)) ||  /* The value of the securized message is incorrect*/
           ((tx->sw1==0x69) && ((tx->sw2==0x87) || (tx->sw2==0x88)))) && /* The value of the securized message is incorrect*/
          (retries != 0)){
        
      r = card_secure_transmit(card, tx);
      retries--;
    }
  } 
  else
    r = card_envelope_transmit(card, tx);
  
  SC_FUNC_RETURN(card->ctx, 1, r);
}

static struct sc_card_driver * sc_get_driver(void)
{ 
  struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

  card_ops = *iso_drv->ops;
  card_ops.match_card = card_match_card;
  card_ops.init = card_init;
  card_ops.finish = card_finish;
  if (iso_ops == NULL)
    iso_ops = iso_drv->ops;
  card_ops.create_file = NULL;
  card_ops.set_security_env = card_set_security_env; 
  card_ops.delete_file= NULL;
  card_ops.compute_signature = card_compute_signature;
  card_ops.decipher = card_decipher;
  card_ops.get_challenge = card_get_challenge;
  card_ops.pin_cmd = card_pin_cmd;
  card_ops.select_file = card_select_file;
  card_ops.check_sw=card_check_sw;
  card_ops.process_fci = card_process_fci;
  card_ops.card_ctl = card_ctl;	
  card_ops.read_binary=card_read_binary;
  card_ops.logout=card_logout;
  
  return &card_drv;
}

struct sc_card_driver *sc_get_dnie_driver(void)
{
	return sc_get_driver();
}
    
   
int card_create_cert_file( sc_card_t *card, sc_path_t *path, size_t size ) {
  sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Function not implemented!");
  return SC_ERROR_NOT_IMPLEMENTED;
      
}
