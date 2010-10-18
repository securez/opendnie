/*
 * pkcs15_standard.c: Functions dealing with standard PKCS#15 
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
#include "pkcs15_standard.h"
#include <opensc/log.h>
#include <assert.h>

/**
   This function is almost identical to sc_pkcs15_parse_df, but
   it gets the data from a buffer, instead than from a file
   
   @param p15_df PKCS#15 df file
   @param p15card Structure where objects are stored (also contains card and ctx)
*/
int sc_standard_pkcs15_parse_df(struct sc_pkcs15_card *p15card, 
				sc_pkcs15_df_t *df,
				u8 *buf,
				size_t bufsize)
				
{
  sc_context_t *ctx = p15card->card->ctx;
  const u8 *p;
  int r = SC_SUCCESS;
  struct sc_pkcs15_object *obj = NULL;
  int (* func)(struct sc_pkcs15_card *, struct sc_pkcs15_object *,
	       const u8 **nbuf, size_t *nbufsize) = NULL;

  switch (df->type) {
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
    sc_error(ctx, "unknown DF type: %d\n", df->type);
    return SC_ERROR_INVALID_ARGUMENTS;
  }

  p = buf;
  while (bufsize && *p != 0x00) {
    const u8 *oldp;
    size_t obj_len;
                
    obj = (struct sc_pkcs15_object *) calloc(1, sizeof(struct sc_pkcs15_object));
    if (obj == NULL) {
      r = SC_ERROR_OUT_OF_MEMORY;
      goto ret;
    }
    oldp = p;
    r = func(p15card, obj, &p, &bufsize);
    if (r) {
      free(obj);
      if (r == SC_ERROR_ASN1_END_OF_CONTENTS) {
	r = 0;
	break;
      }
      sc_perror(ctx, r, "Error decoding DF entry");
      goto ret;
    }
    obj_len = p - oldp;
    
    obj->der.value = (u8 *) malloc(obj_len);
    if (obj->der.value == NULL) {
      r = SC_ERROR_OUT_OF_MEMORY;
      goto ret;
    }
    memcpy(obj->der.value, oldp, obj_len);
    obj->der.len = obj_len;
    
    obj->df = df;
    r = sc_pkcs15_add_object(p15card, obj);
    if (r) {
      if (obj->data)
	free(obj->data);
      free(obj);
      sc_perror(ctx, r, "Error adding object");
      goto ret;
    }
  };
ret:
  return r;
}

/**
   This function is similar to sc_pkcs15_encode_df, but
   it encodes a list of PKCS#15 DF's objects of the same type
   to an output buffer.
   This function encodes any type of DF: ODF, TokenInfo, UnusedSpace 
   and the default ones, DODF, AODF, CDF, PrKDF and PuKDF.
   
   @param ctx context
   @param p15card structure where objects are stored
   @param type of df objects stores on p15card
   @param buf_out output buffer where encoded data is stored
   @param bufsize_out output buffer length
*/
int sc_standard_pkcs15_encode_any_df(sc_context_t *ctx,
				     struct sc_pkcs15_card *p15card,
				     const unsigned int df_type,
				     u8 **buf_out, size_t *bufsize_out)
{
  int (*func)(sc_context_t *ctx,
	      struct sc_pkcs15_card *p15card,
	      u8 **buf, size_t *buflen) = NULL;
  int (* func2)(sc_context_t *ctx,
		sc_pkcs15_tokeninfo_t *ti,
		u8 **buf, size_t *buflen) = NULL;
  int r = SC_SUCCESS;
  
  if (ctx->debug) sc_debug(ctx, "Entering function sc_standard_pkcs15_encode_df\n");
 
  assert(p15card != NULL && p15card->magic == SC_PKCS15_CARD_MAGIC);

  /* check buffers and free them if needed */
  if(buf_out && *buf_out) {
    free(*buf_out);
    *buf_out = NULL;
  }
  
  if(bufsize_out)
    *bufsize_out = 0;

  switch (df_type) {
  case SC_PKCS15_ODF:
    func = sc_pkcs15_encode_odf;
    break;
  case SC_PKCS15_UNUSED:
    func = sc_pkcs15_encode_unusedspace;
    break;
  case SC_PKCS15_TOKENINFO:
    func2 = sc_pkcs15_encode_tokeninfo;
  }
  if (func == NULL && func2 == NULL) {
    if (ctx->debug) sc_debug(ctx, "Going to encode the other PKCS#15 DF\n");
    /* decode the other PKCS#15 DF as usual */
    r = sc_standard_pkcs15_encode_other_df( ctx, p15card, df_type, buf_out, bufsize_out );
    goto sspead_out;
  }

  if (func2){
    sc_pkcs15_tokeninfo_t tokeninfo;

    /* create a temporary tokeninfo structure */
    tokeninfo.version = p15card->version;
    tokeninfo.flags = p15card->flags;
    tokeninfo.label = p15card->label;
    tokeninfo.serial_number = p15card->serial_number;
    tokeninfo.manufacturer_id = p15card->manufacturer_id;
    tokeninfo.last_update = p15card->last_update;
    tokeninfo.preferred_language = p15card->preferred_language;

    if (ctx->debug) sc_debug(ctx, "Going to encode TokenInfo PKCS#15 DF\n");
    r = sc_pkcs15_encode_tokeninfo( ctx, &tokeninfo, buf_out, bufsize_out );
    goto sspead_out;

  }
  /* decode ODF or UNUSED_SPACE PKCS#15 DF */
  if (ctx->debug) sc_debug(ctx, "Going to encode ODF or UNUSED_SPACE PKCS#15 DF\n");
  r = func( ctx, p15card, buf_out, bufsize_out );
  
 sspead_out:
  if (ctx->debug) sc_debug(ctx, "Leaving function sc_standard_pkcs15_encode_df\n");
  return r;
}


/**
   This function is almost identical to sc_pkcs15_encode_df, but
   it gets as a parameter a DF type instead of a df struct. 

   That is because we do not have a real sc_pkcs15_df struct 
   when calling this function and we only want to decode a list
   of PKCS#15 DF objects of the same type to a buffer.

   Another difference from the original function is that we
   allocate memory directly to the output buffer instead of
   creating a temporal one.
   
   @param ctx context
   @param p15card structure where objects are stored
   @param type of df objects stores on p15card
   @param buf_out output buffer where encoded data is stored
   @param bufsize_out output buffer length
*/
int sc_standard_pkcs15_encode_other_df(sc_context_t *ctx,
				       struct sc_pkcs15_card *p15card,
				       const unsigned int df_type,
				       u8 **buf_out, size_t *bufsize_out)
{
  u8 *tmp = NULL;
  size_t bufsize = 0, tmpsize;
  const struct sc_pkcs15_object *obj;
  int (* func)(sc_context_t *, const struct sc_pkcs15_object *nobj,
	       u8 **nbuf, size_t *nbufsize) = NULL;
  int r = SC_SUCCESS;

  if (ctx->debug) sc_debug(ctx, "Entering function sc_standard_pkcs15_encode_other_df\n");

  assert(p15card != NULL && p15card->magic == SC_PKCS15_CARD_MAGIC);

  /* check buffers and free them if needed */
  if(buf_out && *buf_out) {
    free(*buf_out);
    *buf_out = NULL;
  }
  
  if(bufsize_out)
    *bufsize_out = 0;

  switch (df_type) {
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
    sc_error(ctx, "unknown DF type: %d\n", df_type);
    *buf_out = NULL;
    *bufsize_out = 0;
    r = SC_ERROR_INVALID_ARGUMENTS;
    goto sspeod_out;
  }
  for (obj = p15card->obj_list; obj != NULL; obj = obj->next) {
    /* 
       As each df object is independent one another and
       struct p15card has only objects of the only one DF, 
       we can comment the following instructions.
       We do not have a correct df struct.

    */
    r = func(ctx, obj, &tmp, &tmpsize);
    if (r) {
      free(tmp);
      free(*buf_out);
      *buf_out = NULL;
      goto sspeod_out;
    }
    *buf_out = (u8 *) realloc( *buf_out, bufsize + tmpsize);
    memcpy((*buf_out) + bufsize, tmp, tmpsize);
    free(tmp);
    bufsize += tmpsize;
  }
  *bufsize_out = bufsize;
 
 sspeod_out:
  if (ctx->debug) sc_debug(ctx, "Leaving function sc_standard_pkcs15_encode_other_df\n");
  return r;
}


/**
   Parses standard PKCS#15 and returns the parsed objects
   
   @param card Card Context
   @param p15_df structure with file to parse
   @param df Unitialized df file used to parse structure
   @param temp_p15card Pointer to a NULLified pointer to sc_pkcs15_card_t. A new sc_pkcs15_card will be malloced into this pointer
*/
int card_parse_standard_pkcs15( sc_card_t *card,
				card_pkcs15_df_t *p15_df,
				sc_pkcs15_df_t *df, 
				sc_pkcs15_card_t **temp_p15card )
{
  int r = SC_SUCCESS;
  
  /* we init df type */
  memset(df, 0, sizeof(*df));
  df->type = p15_df->type;

  /* we create a fake p15card structure */
  *temp_p15card = sc_pkcs15_card_new();
  if(!(*temp_p15card)) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto cpsp_end;
  }

  /*
    All paths are hardcoded because we don't have access to
    real sc_pkcs15_card_t structure to copy data.
  */
  if(((*temp_p15card)->file_app = sc_file_new()))
    sc_format_path("3F005015", &(*temp_p15card)->file_app->path);
  if(((*temp_p15card)->file_tokeninfo = sc_file_new()))
    sc_format_path("3F0050155032", &(*temp_p15card)->file_tokeninfo->path);
  if(((*temp_p15card)->file_odf = sc_file_new()))
    sc_format_path("3F0050155031", &(*temp_p15card)->file_odf->path);

  (*temp_p15card)->card = card;
  
  /* parse df */
  r = sc_standard_pkcs15_parse_df((*temp_p15card), df, p15_df->data, p15_df->filled_len);

  cpsp_end:
  if(r != SC_SUCCESS) {
    if(temp_p15card && *temp_p15card) {
      sc_pkcs15_card_free(*temp_p15card);
      *temp_p15card = NULL;
    }
  }

  SC_FUNC_RETURN(card->ctx, 1, r);
}
