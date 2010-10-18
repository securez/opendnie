/*
 * pkcs15_default.h: PKCS#15 default header file
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


#ifndef _PKCS15_DEFAULT_H
#define _PKCS15_DEFAULT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <assert.h>
#include <ltdl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "libopensc/log.h"
#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/pkcs15.h"
#include "pkcs15init/pkcs15-init.h"
#include "libopensc/asn1.h"
#include "libopensc/internal.h"
#include "pkcs15_standard.h"

#define SC_ASN1_BIT_FIELD_3              132

int get_ckaid_from_certificate( sc_card_t *card, const u8 *data, const size_t data_size, sc_pkcs15_id_t *card_ckaid );

/* new functions from new pkcs15 cache structure */
int sc_pkcs15_parse_card_df(struct sc_pkcs15_card *p15card,
			    const unsigned int df_type,
			    const u8 *buf,
			    const size_t in_bufsize);

int sc_find_free_unusedspace( sc_pkcs15_card_t *p15card, const size_t size, 
			      sc_pkcs15_unusedspace_t **unused_space );

  /* internal declaration */
  int sc_pkcs15_get_card_objects_cond(struct sc_pkcs15_card *p15card, unsigned int type,
				      int (* func)(struct sc_pkcs15_object *, void *),
				      void *func_arg,
				      struct sc_pkcs15_object **ret, size_t ret_size);
  int __sc_pkcs15_search_card_objects(sc_pkcs15_card_t *p15card,
				      unsigned int class_mask, unsigned int type,
				      int (*func)(sc_pkcs15_object_t *, void *),
				      void *func_arg,
				      sc_pkcs15_object_t **ret, size_t ret_size);
  
  int sc_pkcs15_decode_aodf_entry(struct sc_pkcs15_card *p15card,
					struct sc_pkcs15_object *obj,
					const u8 ** buf, size_t *buflen);

  int sc_pkcs15_decode_cdf_entry(struct sc_pkcs15_card *p15card,
				       struct sc_pkcs15_object *obj,
				       const u8 ** buf, size_t *buflen);

  int sc_pkcs15_encode_cdf_entry(sc_context_t *ctx,
				       const struct sc_pkcs15_object *obj,
				       u8 **buf, size_t *bufsize);

  int sc_pkcs15_decode_prkdf_entry(struct sc_pkcs15_card *p15card,
					 struct sc_pkcs15_object *obj,
					 const u8 ** buf, size_t *buflen);

  int sc_pkcs15_encode_prkdf_entry(sc_context_t *ctx,
					 const struct sc_pkcs15_object *obj,
					 u8 **buf, size_t *buflen);

  int sc_pkcs15_decode_pukdf_entry(struct sc_pkcs15_card *p15card,
					 struct sc_pkcs15_object *obj,
					 const u8 ** buf, size_t *buflen);

  int sc_pkcs15_encode_pukdf_entry(sc_context_t *ctx,
					 const struct sc_pkcs15_object *obj,
					 u8 **buf, size_t *buflen);

  int sc_asn1_decode(sc_context_t *ctx, struct sc_asn1_entry *asn1,
			   const u8 *in, size_t len, const u8 **newp, size_t *len_left);

  int sc_asn1_encode(sc_context_t *ctx, const struct sc_asn1_entry *asn1,
			   u8 **ptr, size_t *size);

  int sc_asn1_decode_choice(sc_context_t *ctx, struct sc_asn1_entry *asn1,
				  const u8 *in, size_t len, const u8 **newp, size_t *len_left);

  int sc_pkcs1_strip_02_padding(const u8 *data, size_t len, u8 *out,
				size_t *out_len);

  int sc_pkcs1_add_digest_info_prefix(unsigned int algorithm, const u8 *in,
				      size_t in_len, u8 *out, size_t *out_len);

  int sc_pkcs1_encode(sc_context_t *ctx, unsigned long flags,
		      const u8 *in, size_t in_len, u8 *out, size_t *out_len, size_t mod_len);

  int get_real_certificate_length( struct sc_pkcs15_card *p15card,
				   struct sc_pkcs15_cert_info *cert_info );

  int asn1_decode_path(sc_context_t *ctx, const u8 *in, size_t len,
			     sc_path_t *path, int depth);

  int sc_pkcs15_card_encode_df(sc_context_t *ctx,
			       struct sc_pkcs15_card *p15card,
			       struct sc_pkcs15_df *df,
			       u8 **buf_out, size_t *bufsize_out);
  int sc_pkcs15_encode_pubkey(sc_context_t *ctx,
				    struct sc_pkcs15_pubkey *key,
				    u8 **buf, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* _PKCS15_DEFAULT_H */
