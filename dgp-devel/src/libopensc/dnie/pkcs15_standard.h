/*
 * pkcs15_standard.h: Header for definitions related to parsing of
 *                    standard PKCS#15 structures.
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


#ifndef _PKCS15_STANDARD_H
#define _PKCS15_STANDARD_H

#ifdef __cplusplus
extern "C" {
#endif

#include "base_card.h"

int card_parse_standard_pkcs15( sc_card_t *card,
				card_pkcs15_df_t *p15_df,
				sc_pkcs15_df_t *df, 
				sc_pkcs15_card_t **temp_p15card );

int sc_standard_pkcs15_parse_df(struct sc_pkcs15_card *p15card, 
				sc_pkcs15_df_t *df,
				u8 *buf,
				size_t bufsize);
  
int sc_standard_pkcs15_encode_any_df(sc_context_t *ctx,
				     struct sc_pkcs15_card *p15card,
				       const unsigned int df_type,
				     u8 **buf_out, size_t *bufsize_out);

int sc_standard_pkcs15_encode_other_df(sc_context_t *ctx,
				       struct sc_pkcs15_card *p15card,
				       const unsigned int df_type,
				       u8 **buf_out, size_t *bufsize_out);  
#ifdef __cplusplus
}
#endif

#endif /* _PKCS15_STANDARD_H */
