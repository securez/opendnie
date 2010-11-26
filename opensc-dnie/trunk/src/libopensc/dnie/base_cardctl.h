/*
 * base_cardctl.h: cardctl definitions for custom driver
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

#ifndef _SC_DNIE_CARDCTL_H
#define _SC_DNIE_CARDCTL_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "libopensc/cardctl.h"

/* key usage for card keys */
#define SC_CARD_KEY_USAGE_SIG 0x80
#define SC_CARD_KEY_USAGE_CIF 0x40

/* ERRORS */
#define SC_ERROR_INVALID_FILE -3001
/*
#ifndef SC_ERROR_NOT_ENOUGH_MEMORY
#define SC_ERROR_NOT_ENOUGH_MEMORY -3002
#endif
*/
#define SC_ERROR_OBJECT_ALREADY_EXISTS -3003


enum {
  SC_CARDCTL_DNIE_BASE = _CTL_PREFIX('D', 'N', 'I'),
  SC_CARDCTL_DNIE_GENERATE_KEY,
  SC_CARDCTL_DNIE_STORE_KEY_COMPONENT,
  SC_CARDCTL_DNIE_GET_NEW_KEY_REFERENCE,
  SC_CARDCTL_DNIE_CREATE_FILE,
  SC_CARDCTL_DNIE_DELETE_FILE
};
  
struct sc_cardctl_card_genkey_info {
  unsigned char   *pubkey;
  unsigned int    pubkey_len;
  unsigned char   *exponent;
  unsigned int    exponent_len;
  unsigned int    key_usage;
  unsigned char   key_reference;

};

struct tlv {
  u8 tag;
  u8 *length;
  size_t nlen;
  u8 *value;
};
typedef struct tlv tlv_t;

struct sc_cardctl_card_store_key_component_info {
  int private_component;
  u8 key_usage;
  u8 key_id; 
  tlv_t component;
};

#ifdef __cplusplus
}
#endif

#endif
