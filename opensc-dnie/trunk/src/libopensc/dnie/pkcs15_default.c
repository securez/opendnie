/*
 * pkcs15_default.c: PKCS #15 general functions
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

#include "pkcs15_default.h"


/* DEFAULT ONE */
static const struct sc_asn1_entry c_asn1_toki[] = {
	{ "version",        SC_ASN1_INTEGER,      SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
	{ "serialNumber",   SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL },
	{ "manufacturerID", SC_ASN1_UTF8STRING,   SC_ASN1_TAG_UTF8STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "label",	    SC_ASN1_UTF8STRING,   SC_ASN1_CTX | 0, SC_ASN1_OPTIONAL, NULL, NULL },
        /* XXX the Taiwanese ID card erroneously uses explicit tagging */
        { "label-tw",       SC_ASN1_STRUCT,       SC_ASN1_CTX | 0 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "tokenflags",	    SC_ASN1_BIT_FIELD,   SC_ASN1_TAG_BIT_STRING, 0, NULL, NULL },
	{ "seInfo",	    SC_ASN1_SEQUENCE,	  SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "recordInfo",	    SC_ASN1_STRUCT,       SC_ASN1_CONS | SC_ASN1_CTX | 1, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "supportedAlgorithms", SC_ASN1_STRUCT,  SC_ASN1_CONS | SC_ASN1_CTX | 2, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "issuerId",       SC_ASN1_UTF8STRING,   SC_ASN1_CTX | 3, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "holderId",       SC_ASN1_UTF8STRING,   SC_ASN1_CTX | 4, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "lastUpdate",     SC_ASN1_GENERALIZEDTIME, SC_ASN1_CTX | 5, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "preferredLanguage", SC_ASN1_PRINTABLESTRING, SC_ASN1_TAG_PRINTABLESTRING, SC_ASN1_OPTIONAL, NULL, NULL }, 
	{ NULL, 0, 0, 0, NULL, NULL }
};
		     
/* MODIFIED ONE */ 
const struct sc_asn1_entry c_asn1_toki_dnie[] = {
  { "version",        SC_ASN1_INTEGER,      SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
  { "serialNumber",   SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL },
  { "manufacturerID", SC_ASN1_UTF8STRING,   SC_ASN1_TAG_UTF8STRING, SC_ASN1_OPTIONAL, NULL, NULL },
  { "label",	    SC_ASN1_UTF8STRING,   SC_ASN1_TAG_UTF8STRING, SC_ASN1_OPTIONAL, NULL, NULL },
  /* XXX the Taiwanese ID card erroneously uses explicit tagging */
  { "label-tw",       SC_ASN1_STRUCT,       SC_ASN1_CTX | 0 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
  { "tokenflags",	    SC_ASN1_BIT_FIELD,   SC_ASN1_TAG_BIT_STRING, 0, NULL, NULL },
  { "seInfo",	    SC_ASN1_SEQUENCE,	  SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, SC_ASN1_OPTIONAL, NULL, NULL },
  { "recordInfo",	    SC_ASN1_STRUCT,       SC_ASN1_CONS | SC_ASN1_CTX | 1, SC_ASN1_OPTIONAL, NULL, NULL },
  { "supportedAlgorithms", SC_ASN1_STRUCT,  SC_ASN1_CONS | SC_ASN1_CTX | 2, SC_ASN1_OPTIONAL, NULL, NULL },
  { "issuerId",       SC_ASN1_UTF8STRING,   SC_ASN1_CTX | 3, SC_ASN1_OPTIONAL, NULL, NULL },
  { "holderId",       SC_ASN1_UTF8STRING,   SC_ASN1_CTX | 4, SC_ASN1_OPTIONAL, NULL, NULL },
  { "lastUpdate",     SC_ASN1_GENERALIZEDTIME, SC_ASN1_CTX | 5, SC_ASN1_OPTIONAL, NULL, NULL },
  { "preferredLanguage", SC_ASN1_PRINTABLESTRING, SC_ASN1_TAG_PRINTABLESTRING, SC_ASN1_OPTIONAL, NULL, NULL }, 
  { NULL, 0, 0, 0, NULL, NULL }
};

const struct sc_asn1_entry c_asn1_tokeninfo[] = {
  { "TokenInfo", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, 0, NULL, NULL },
  { NULL, 0, 0, 0, NULL, NULL }
};


int parse_card_tokeninfo(struct sc_pkcs15_card *card, const u8 * buf, size_t buflen)
{
  int r, bug=0;
  u8 serial[128];
  size_t i;
  size_t serial_len = sizeof(serial);
  u8 mnfid[SC_PKCS15_MAX_LABEL_SIZE];
  size_t mnfid_len = sizeof(mnfid);
  u8 label[SC_PKCS15_MAX_LABEL_SIZE];
  size_t label_len = sizeof(label);
  u8 last_update[32];
  size_t lupdate_len = sizeof(last_update) - 1;
  size_t flags_len = sizeof(card->tokeninfo->flags);
  struct sc_asn1_entry asn1_toki[13], asn1_toki_dnie[13], asn1_tokeninfo[3], asn1_tokeninfo_dnie[3];
  u8 preferred_language[3];
  u8 tmp_buff[300];
  size_t lang_length = sizeof(preferred_language);

  memset(last_update, 0, sizeof(last_update));
  sc_copy_asn1_entry(c_asn1_toki, asn1_toki);
  sc_copy_asn1_entry(c_asn1_tokeninfo, asn1_tokeninfo);
  sc_format_asn1_entry(asn1_toki + 0, &card->tokeninfo->version, NULL, 0);
  sc_format_asn1_entry(asn1_toki + 1, serial, &serial_len, 0);
  sc_format_asn1_entry(asn1_toki + 2, mnfid, &mnfid_len, 0);
  sc_format_asn1_entry(asn1_toki + 3, label, &label_len, 0);
  /* skip "label-tw" */
  sc_format_asn1_entry(asn1_toki + 5, &card->tokeninfo->flags, &flags_len, 0);
  sc_format_asn1_entry(asn1_toki + 6, NULL, NULL, 0);
  sc_format_asn1_entry(asn1_toki + 7, NULL, NULL, 0);
  sc_format_asn1_entry(asn1_toki + 8, NULL, NULL, 0);
  sc_format_asn1_entry(asn1_toki + 9, NULL, NULL, 0);
  sc_format_asn1_entry(asn1_toki + 10, NULL, NULL, 0);
  sc_format_asn1_entry(asn1_toki + 11, last_update, &lupdate_len, 0);
  sc_format_asn1_entry(asn1_toki + 12, preferred_language, &lang_length, 0);
  sc_format_asn1_entry(asn1_tokeninfo, asn1_toki, NULL, 0);

  if (buf[1] == 0x2B) {    
    /* patch to adapt the correct size to TokenInfo*/
    memset(&tmp_buff, 0, sizeof(tmp_buff));
    memcpy(&tmp_buff, buf, buflen);
    tmp_buff[1] = 0x2C;
    
    r = sc_asn1_decode(card->card->ctx, asn1_tokeninfo, tmp_buff, buflen, NULL, NULL);
  } else	
    r = sc_asn1_decode(card->card->ctx, asn1_tokeninfo, buf, buflen, NULL, NULL);
 
  if (r) {

    bug = 1;
        
    sc_copy_asn1_entry(c_asn1_toki_dnie, asn1_toki_dnie);
    sc_copy_asn1_entry(c_asn1_tokeninfo, asn1_tokeninfo_dnie);
    sc_format_asn1_entry(asn1_toki_dnie + 0, &card->tokeninfo->version, NULL, 0);
    sc_format_asn1_entry(asn1_toki_dnie + 1, serial, &serial_len, 0);
    sc_format_asn1_entry(asn1_toki_dnie + 2, mnfid, &mnfid_len, 0);
    sc_format_asn1_entry(asn1_toki_dnie + 3, label, &label_len, 0);
    /* skip "label-tw" */
    sc_format_asn1_entry(asn1_toki_dnie + 5, &card->tokeninfo->flags, &flags_len, 0);
    sc_format_asn1_entry(asn1_toki_dnie + 6, NULL, NULL, 0);
    sc_format_asn1_entry(asn1_toki_dnie + 7, NULL, NULL, 0);
    sc_format_asn1_entry(asn1_toki_dnie + 8, NULL, NULL, 0);
    sc_format_asn1_entry(asn1_toki_dnie + 9, NULL, NULL, 0);
    sc_format_asn1_entry(asn1_toki_dnie + 10, NULL, NULL, 0);
    sc_format_asn1_entry(asn1_toki_dnie + 11, last_update, &lupdate_len, 0);
    sc_format_asn1_entry(asn1_toki_dnie + 12, preferred_language, &lang_length, 0);
    sc_format_asn1_entry(asn1_tokeninfo_dnie, asn1_toki_dnie, NULL, 0);
    
    if (buf[1] == 0x2B)
      r = sc_asn1_decode(card->card->ctx, asn1_tokeninfo_dnie, tmp_buff, buflen, NULL, NULL);
    else
      r = sc_asn1_decode(card->card->ctx, asn1_tokeninfo_dnie, buf, buflen, NULL, NULL);
    if (r) {
      sc_debug(card->card->ctx,
		SC_LOG_DEBUG_NORMAL, 
	       "ASN.1 parsing of EF(TokenInfo) failed: %s\n",
	       sc_strerror(r));
      goto err;
    }
  }

  card->tokeninfo->version += 1;
  card->tokeninfo->serial_number = (char *) malloc(serial_len * 2 + 1);
  if (!card->tokeninfo->serial_number) {
    sc_debug(card->card->ctx, SC_LOG_DEBUG_NORMAL, "Memory allocation failed\n");
    goto err;
  }
  card->tokeninfo->serial_number[0] = 0;
  for (i = 0; i < serial_len; i++) {
    char byte[3];

    sprintf(byte, "%02X", serial[i]);
    strcat(card->tokeninfo->serial_number, byte);
  }
  if (card->tokeninfo->manufacturer_id == NULL) {
    if (!bug) {
      if (asn1_toki[2].flags & SC_ASN1_PRESENT)
	card->tokeninfo->manufacturer_id = strdup((char *) mnfid);
      else
	card->tokeninfo->manufacturer_id = strdup("(unknown)");
    } else {
      if (asn1_toki_dnie[2].flags & SC_ASN1_PRESENT)
	card->tokeninfo->manufacturer_id = strdup((char *) mnfid);
      else
	card->tokeninfo->manufacturer_id = strdup("(unknown)");
    }
  }
  if (card->tokeninfo->label == NULL) {
    if (!bug) {
      if (asn1_toki[3].flags & SC_ASN1_PRESENT)
	card->tokeninfo->label = strdup((char *) label);
      else
	card->tokeninfo->label = strdup("(unknown)");
    } else {
      if (asn1_toki_dnie[3].flags & SC_ASN1_PRESENT)
	card->tokeninfo->label = strdup((char *) label);
      else
	card->tokeninfo->label = strdup("(unknown)");
    }
  }
  if (!bug) {
    if (asn1_toki[11].flags & SC_ASN1_PRESENT)
      card->tokeninfo->last_update = strdup((char *)last_update);
    if (asn1_toki[12].flags & SC_ASN1_PRESENT) {
      preferred_language[2] = 0;
      card->tokeninfo->preferred_language = strdup((char *)preferred_language);
    }
  } else {
    if (asn1_toki_dnie[11].flags & SC_ASN1_PRESENT)
      card->tokeninfo->last_update = strdup((char *)last_update);
    if (asn1_toki_dnie[12].flags & SC_ASN1_PRESENT) {
      preferred_language[2] = 0;
      card->tokeninfo->preferred_language = strdup((char *)preferred_language);
    }
  }
  return SC_SUCCESS;
 err:
  if (card->tokeninfo->serial_number == NULL)
    card->tokeninfo->serial_number = strdup("(unknown)");
  if (card->tokeninfo->manufacturer_id == NULL)
    card->tokeninfo->manufacturer_id = strdup("(unknown)");
  return SC_SUCCESS;
}


static const struct sc_asn1_entry c_asn1_odf[] = {
	{ "privateKeys",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 0 | SC_ASN1_CONS, 0, NULL, NULL },
	{ "publicKeys",		 SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, 0, NULL, NULL },
	{ "trustedPublicKeys",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 2 | SC_ASN1_CONS, 0, NULL, NULL },
	{ "certificates",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 4 | SC_ASN1_CONS, 0, NULL, NULL },
	{ "trustedCertificates", SC_ASN1_STRUCT, SC_ASN1_CTX | 5 | SC_ASN1_CONS, 0, NULL, NULL },
	{ "usefulCertificates",  SC_ASN1_STRUCT, SC_ASN1_CTX | 6 | SC_ASN1_CONS, 0, NULL, NULL },
	{ "dataObjects",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 7 | SC_ASN1_CONS, 0, NULL, NULL },
	{ "authObjects",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 8 | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const unsigned int odf_indexes[] = {
	SC_PKCS15_PRKDF,
	SC_PKCS15_PUKDF,
	SC_PKCS15_PUKDF_TRUSTED,
	SC_PKCS15_CDF,
	SC_PKCS15_CDF_TRUSTED,
	SC_PKCS15_CDF_USEFUL,
	SC_PKCS15_DODF,
	SC_PKCS15_AODF,
};

static int parse_card_odf(struct sc_pkcs15_card *card, const u8 * buf, size_t buflen)
{
	const u8 *p = buf;
	size_t left = buflen;
	int r, i;
	sc_path_t path;
	struct sc_asn1_entry asn1_obj_or_path[] = {
		{ "path", SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_SEQUENCE, 0, &path, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry asn1_odf[9];
	
	sc_copy_asn1_entry(c_asn1_odf, asn1_odf);
	for (i = 0; asn1_odf[i].name != NULL; i++)
		sc_format_asn1_entry(asn1_odf + i, asn1_obj_or_path, NULL, 0);
	while (left > 0) {
		r = sc_asn1_decode_choice(card->card->ctx, asn1_odf, p, left, &p, &left);
		if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
			break;
		if (r < 0)
			return r;
		r = sc_pkcs15_add_df(card, odf_indexes[r], &path, NULL);
		if (r)
			return r;
	}
	return 0;
}

int parse_card_unusedspace( sc_pkcs15_card_t *p15card, const u8 * buf, size_t buflen )
{
  return sc_pkcs15_parse_unusedspace( buf, buflen, p15card );
}

int sc_pkcs15_get_card_objects(struct sc_pkcs15_card *p15card, unsigned int type,
			       struct sc_pkcs15_object **ret, size_t ret_size)
{
  SC_FUNC_RETURN(p15card->card->ctx, 1, sc_pkcs15_get_card_objects_cond(p15card, type, NULL, NULL, ret, ret_size));
}

int sc_pkcs15_get_card_objects_cond(struct sc_pkcs15_card *p15card, unsigned int type,
                               int (* func)(struct sc_pkcs15_object *, void *),
                               void *func_arg,
                               struct sc_pkcs15_object **ret, size_t ret_size)
{
  SC_FUNC_RETURN (p15card->card->ctx, 1, __sc_pkcs15_search_card_objects(p15card, 0, type,
					 func, func_arg, ret, ret_size));
}

int __sc_pkcs15_search_card_objects(sc_pkcs15_card_t *p15card,
			       unsigned int class_mask, unsigned int type,
			       int (*func)(sc_pkcs15_object_t *, void *),
			       void *func_arg,
			       sc_pkcs15_object_t **ret, size_t ret_size)
{
  sc_debug(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE, "Entering function __sc_pkcs15_search_card_objects\n");
  sc_pkcs15_object_t *obj;
        sc_pkcs15_df_t  *df;
        unsigned int    df_mask = 0;
        size_t          match_count = 0;
        int             r = 0;

        if (type)
                class_mask |= SC_PKCS15_TYPE_TO_CLASS(type);

        /* Make sure the class mask we have makes sense */
        if (class_mask == 0
         || (class_mask & ~(SC_PKCS15_SEARCH_CLASS_PRKEY |
                            SC_PKCS15_SEARCH_CLASS_PUBKEY |
                            SC_PKCS15_SEARCH_CLASS_CERT |
                            SC_PKCS15_SEARCH_CLASS_DATA |
                            SC_PKCS15_SEARCH_CLASS_AUTH))) {
                return SC_ERROR_INVALID_ARGUMENTS;
        }

        if (class_mask & SC_PKCS15_SEARCH_CLASS_PRKEY)
                df_mask |= (1 << SC_PKCS15_PRKDF);
        if (class_mask & SC_PKCS15_SEARCH_CLASS_PUBKEY)
                df_mask |= (1 << SC_PKCS15_PUKDF)
                         | (1 << SC_PKCS15_PUKDF_TRUSTED);
        if (class_mask & SC_PKCS15_SEARCH_CLASS_CERT)
                df_mask |= (1 << SC_PKCS15_CDF)
                         | (1 << SC_PKCS15_CDF_TRUSTED)
                         | (1 << SC_PKCS15_CDF_USEFUL);
        if (class_mask & SC_PKCS15_SEARCH_CLASS_DATA)
                df_mask |= (1 << SC_PKCS15_DODF);
        if (class_mask & SC_PKCS15_SEARCH_CLASS_AUTH)
                df_mask |= (1 << SC_PKCS15_AODF);

        /* Make sure all the DFs we want to search have been
         * enumerated. */
        for (df = p15card->df_list; df != NULL; df = df->next) {
                if (!(df_mask & (1 << df->type)))
                        continue;
                if (df->enumerated)
                        continue;
                /* Enumerate the DF's, so p15card->obj_list is
                 * populated. */
                SC_TEST_RET(p15card->card->ctx,  SC_LOG_DEBUG_NORMAL, r, "DF parsing failed");
                df->enumerated = 1;
        }

        /* And now loop over all objects */
        for (obj = p15card->obj_list; obj != NULL; obj = obj->next) {
                /* Check object type */
                if (!(class_mask & SC_PKCS15_TYPE_TO_CLASS(obj->type)))
                        continue;
                if (type != 0
                 && obj->type != type
                 && (obj->type & SC_PKCS15_TYPE_CLASS_MASK) != type)
                        continue;

                /* Potential candidate, apply search function */
                if (func != NULL && func(obj, func_arg) <= 0)
                        continue;
                /* Okay, we have a match. */
                match_count++;
                if (ret_size <= 0)
                        continue;
                ret[match_count-1] = obj;
                if (ret_size <= match_count)
                        break;
        }
	sc_debug(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE, "Leaving function __sc_pkcs15_search_card_objects\n");
        return match_count;
}

int sc_pkcs15_parse_card_df(struct sc_pkcs15_card *p15card,
			    const unsigned int df_type,
			    const u8 *buf,
			    const size_t in_bufsize)
{
  sc_context_t            *ctx     = p15card->card->ctx;
  int                      r       = SC_SUCCESS;
  size_t                   bufsize = in_bufsize;
  struct sc_pkcs15_object *obj     = NULL;

  int (* func)(struct sc_pkcs15_card *, struct sc_pkcs15_object *,
	       const u8 **nbuf, size_t *nbufsize) = NULL;
  int (* func2)(struct sc_pkcs15_card *p15card, const u8 * buf, size_t buflen) = NULL;

  if ( ctx->debug ) sc_debug( ctx, SC_LOG_DEBUG_VERBOSE, "Entering function sc_pkcs15_parse_card_df\n" );
 
  switch (df_type) {
  case SC_PKCS15_PRKDF:
    func = sc_pkcs15_decode_prkdf_entry;
    break;
  case SC_PKCS15_PUKDF:
    func = sc_pkcs15_decode_pukdf_entry;
    break;
  case SC_PKCS15_CDF:
  case SC_PKCS15_CDF_TRUSTED:
  case SC_PKCS15_CDF_USEFUL:
    func = sc_pkcs15_decode_cdf_entry;
    break;
  case SC_PKCS15_DODF:
    func = sc_pkcs15_decode_dodf_entry;
    break;
  case SC_PKCS15_AODF:
    func = sc_pkcs15_decode_aodf_entry;
    break;
  }
  if (func == NULL) {
    switch (df_type) {
    case SC_PKCS15_ODF:
      func2 = parse_card_odf;
      break;
    case SC_PKCS15_TOKENINFO:
      func2 = parse_card_tokeninfo;
      break;
    case SC_PKCS15_UNUSED:
      func2 = parse_card_unusedspace;
      break;
    }
    if (func2 == NULL) {
      sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "unknown DF type: %d\n", df_type);
      r = SC_ERROR_INVALID_ARGUMENTS;
      goto ret;
    }
    r = func2(p15card, buf, bufsize);
    if (r!=SC_SUCCESS) {
      sc_debug(ctx,SC_LOG_DEBUG_NORMAL, "Error decoding DF entry %d", r);
    }
    goto ret;
  }

  do {
    const u8 *oldp;
    size_t obj_len;

    obj = (struct sc_pkcs15_object *) calloc(1, sizeof(struct sc_pkcs15_object));
    if (obj == NULL) {
      r = SC_ERROR_OUT_OF_MEMORY;
      goto ret;
    }
    oldp = buf;
		
    r = func(p15card, obj, &buf, &bufsize);
    if (r) {
      free(obj);
      if (r == SC_ERROR_ASN1_END_OF_CONTENTS) {
	r = 0;
	break;
      }
      sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Error decoding DF entry %d", r);
      goto ret;
    }

    obj_len = buf - oldp;

    obj->content.value = (u8 *) malloc(obj_len);
    if (obj->content.value == NULL) {
      r = SC_ERROR_OUT_OF_MEMORY;
      goto ret;
    }
    memcpy(obj->content.value, oldp, obj_len);
    obj->content.len = obj_len;

    /* These objects are independent one another*/
    obj->df = NULL;
    r = sc_pkcs15_add_object(p15card, obj);
    if (r) {
      if (obj->data)
	free(obj->data);
      free(obj);
      sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Error adding object %d", r);
      goto ret;
    }
  } while (bufsize && *buf != 0x00);

 ret:
  if (ctx->debug) sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Leaving function sc_pkcs15_parse_card_df\n");
  return r;
}

int sc_pkcs15_card_encode_df(sc_context_t *ctx,
                             struct sc_pkcs15_card *p15card,
                             struct sc_pkcs15_df *df,
                             u8 **buf_out, size_t *bufsize_out)
{
  u8 *buf = NULL, *tmp = NULL;
  size_t bufsize = 0, tmpsize;
  const struct sc_pkcs15_object *obj;
  int (* func)(sc_context_t *, const struct sc_pkcs15_object *nobj,
               u8 **nbuf, size_t *nbufsize) = NULL;
  int r = SC_SUCCESS;

  if (p15card->card->ctx->debug) sc_debug(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE, "Entering function sc_pkcs15_card_encode_df\n");

  assert(p15card != NULL && p15card->magic == SC_PKCS15_CARD_MAGIC);
  switch (df->type) {
  case SC_PKCS15_PRKDF:
    func = sc_pkcs15_encode_prkdf_entry;
    break;
  case SC_PKCS15_PUKDF:
  case SC_PKCS15_PUKDF_TRUSTED:
    func = sc_pkcs15_encode_pukdf_entry;
    break;
  case SC_PKCS15_CDF:
  case SC_PKCS15_CDF_TRUSTED:
  case SC_PKCS15_CDF_USEFUL:
    func = sc_pkcs15_encode_cdf_entry;
    break;
  case SC_PKCS15_DODF:
    func = sc_pkcs15_encode_dodf_entry;
    break;
  case SC_PKCS15_AODF:
    func = sc_pkcs15_encode_aodf_entry;
    break;
  }
  if (func == NULL) {
    sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "unknown DF type: %d\n", df->type);
    *buf_out = NULL;
    *bufsize_out = 0;
    return 0;
  }
  for (obj = p15card->obj_list; obj != NULL; obj = obj->next) {
    if (obj->df != df)
      continue;
    /* if we have a asn.1 codification, just use it! */
    if(obj->content.len > 0) {
      if (p15card->card->ctx->debug) sc_debug(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE, "Reusing existing DER encoding\n");
      
      tmp = malloc(sizeof(u8)*obj->content.len);
      if(!tmp) {
	r = SC_ERROR_OUT_OF_MEMORY;
	goto end;
      }
      memcpy(tmp, obj->content.value, obj->content.len);
      tmpsize = obj->content.len;
    } else {
      r = func(ctx, obj, &tmp, &tmpsize);
      if (r) {
	goto end;
      }
    }
    buf = (u8 *) realloc(buf, bufsize + tmpsize);
    memcpy(buf + bufsize, tmp, tmpsize);
    free(tmp);
    tmp = NULL;
    bufsize += tmpsize;
  }
  *buf_out = buf;
  buf = NULL;
  *bufsize_out = bufsize;
    
end:
  if(tmp) {
    free(tmp);
    tmp = NULL;
  }

  if(buf) {
    free(buf);
    buf = NULL;
  }

  if (p15card->card->ctx->debug) sc_debug(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE, "Leaving function sc_pkcs15_card_encode_df\n");

  return r;
}

int sc_find_free_unusedspace( sc_pkcs15_card_t *p15card, const size_t size, 
			      sc_pkcs15_unusedspace_t **out_unusedspace )
{
  int found=0, r = SC_SUCCESS;
  sc_path_t us_df;
  sc_pkcs15_unusedspace_t *temp_us=NULL;

  assert(p15card != NULL && out_unusedspace!=NULL);

  sc_debug(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE, "Entering function sc_find_free_unusedspace\n");
  
  if (out_unusedspace && *out_unusedspace) {
    free(out_unusedspace);
    out_unusedspace=NULL;
  }

  sc_format_path("3F0050155033", &us_df);
  /* This select file executes a parse unused space structure */
  r = sc_select_file( p15card->card, &us_df, NULL);
  if (r!=SC_SUCCESS)
    goto sffu_err;
  
  for(temp_us=p15card->unusedspace_list; temp_us!=NULL && found==0; temp_us=temp_us->next) {
    if(size<temp_us->path.count) {
      if (found && temp_us->path.count>=(*out_unusedspace)->path.count) {
	/* file is suitable but previously found was best */
	continue;
      }
      /* we found it */
      *out_unusedspace = temp_us;
      found=1;
    }
  }

 sffu_err:
  sc_debug(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE, "Leaving function sc_find_free_unusedspace\n");  
  return r;
}

int get_ckaid_from_certificate( sc_card_t *card, const u8 *data, const size_t data_size, sc_pkcs15_id_t *card_ckaid ) {
	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Function not implemented!");
	return SC_ERROR_NOT_IMPLEMENTED;
}
