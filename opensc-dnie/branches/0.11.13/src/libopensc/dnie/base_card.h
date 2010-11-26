/*
 * base_card.h: Support for DNI-e card 
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

#ifndef BASE_CARD_H
#define BASE_CARD_H

#include <stdlib.h>
#include <opensc/pkcs15.h>
#include "base_cardctl.h"
#include "card_structures.h"
#include "virtual_fs.h"
#include "map.h"
#include "map_helper.h"

/* definitions */
#define MODULE_DESC "DNIe card driver"
#define MODULE_NAME "dnie"

#define CARD_CHIP_NAME		"dnie"

#define CARD_MF_TYPE		0x00
#define CARD_DF_TYPE		0x01
#define CARD_EF_TYPE		0x02
#define CARD_SEL_ID		0x00
#define CARD_SEL_AID		0x04
#define CARD_FID_MF		0x3F00
#define CARD_MF_NAME		"Master.File"

#define CARD_SCHANNEL_KEYLEN_IN_BYTES 128

#define SC_PKCS15_ODF           0xC0
#define SC_PKCS15_TOKENINFO     0xC1
#define SC_PKCS15_UNUSED        0xC2

struct card_priv_data {
  /* this variable holds secure channel state */
  enum {
    secure_channel_not_created = 0, /* set when secure channel hasn't been created yet */
    secure_channel_creating, /* set by card_create_secure_channel when it has begun creating
				the secure channel but it hasn't succeeded yet */
    secure_channel_created /* set by card_create_secure_channel when it has succeeded
			      creating the secure channel */
  } secure_channel_state;
  u8 kenc[16];
  u8 kmac[16];
  u8 ssc[8];
  int card_type;
  int rsa_key_ref;		
  int trusted_channel_err;
  /* virtual fs variables */
  sc_path_t current_path; /*!< current path */
  virtual_fs_t *virtual_fs; /*!< virtual fs */
  int use_virtual_fs; /*!< use virtual fs in operations */

  /* mapped variables */
  map_path_to_path_t *virtual_fs_to_card_path_map; /*!< maps virtual_fs sc_path_t * to card sc_path_t * */
  map_id_to_id_t *virtual_fs_to_card_ckaid_map; /*< maps CKA_ID virtual_fs sc_pkcs15_id * to card sc_pkcs15_id * */
  map_id_to_der_t *cdf_card_ckaid_to_card_der_map; /*< maps CDF card CKA_ID to card der encoded asn1 */
  map_id_to_der_t *prkdf_card_ckaid_to_card_der_map; /*< maps PrKDF card CKA_ID to card der encoded asn1 */
  map_id_to_der_t *pukdf_card_ckaid_to_card_der_map; /*< maps PuKDF card CKA_ID to card der encoded asn1 */
  map_path_to_id_t *card_path_to_card_ckaid_map; /*< maps card certificate file path to card certificate ckaid */
};

/* useful macros */
#define DRVDATA(card) ((struct card_priv_data *) ((card)->drv_data))

/* function declarations */
int card_get_serialnr(sc_card_t *card, sc_serial_number_t *serial);
int card_assure_secure_channel(struct sc_card *card);
int card_card_create_secure_channel(struct sc_card *card);
int card_secure_transmit(sc_card_t *card, sc_apdu_t *tx);
int card_envelope_transmit (sc_card_t *card, sc_apdu_t *tx);
int card_transmit_apdu(sc_card_t *card, sc_apdu_t *tx);
int card_select_file(struct sc_card *card, const struct sc_path *in_path, struct sc_file **file);
int card_create_cert_file( sc_card_t *card, sc_path_t *path, size_t size );
int ask_user_auth();
int card_is_virtual_fs_active(struct sc_card *card);
void card_set_virtual_fs_state(struct sc_card *card, int active);

#endif /* BASE_CARD_H */
