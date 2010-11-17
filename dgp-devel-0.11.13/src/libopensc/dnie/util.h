/*
 * util.h: Auxiliary functions
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

#ifndef _UTIL_H
#define _UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <opensc/types.h>
#include "base_cardctl.h"

  void ulong2lebytes(u8 *buf, unsigned long x);
  void ushort2lebytes(u8 *buf, unsigned short x);
  unsigned long lebytes2ulong(const u8 *buf);
  unsigned short lebytes2ushort(const u8 *buf);
  int push_front_data2buf(u8 **buf, size_t *buflen, const u8 *data, const size_t datalen);
  int push_back_data2buf(u8 **buf, size_t *buflen, const u8 *data, const size_t datalen);
  void free_struct( void *ptr, size_t length );
  int sc_path_set_dnie(sc_path_t *path, int type, unsigned char *id, size_t id_len,
		  int idx, int count);
  /*
    Parse a tlv and gets a buffer from all its components
    computing the tlv value length.

    \param[in] tlv structure containing all tlv data
    \param[out] buf buffer containing all tlv data parsed

    \return number of all tlv bytes if success, or error otherwise
   */
  int tlv2buf(const tlv_t *tlv, u8 **buf);

  /*
    Builds a tlv computing a tlv correct length (dnie mode) and filling its parameters.
    Allocates necessary internal tlv buffers. Need to be freed on external function.

    \param[in] tag byte corresponding to a tag of tlv struct
    \param[in] data data to be copied to tlv
    \param[in] len length of data buffer
    \param[out] tlv structure to be filled

    returns SC_SUCCESS on succes, error otherwise
  */
  int buf2tlv(const u8 tag, const u8 *data, const size_t len, tlv_t *tlv);

  /*
    Frees memory from tlv length and tlv value buffers

    \param[in] tlv structure tlv to be freed
   */
  void free_tlv( tlv_t *tlv );

#ifdef __cplusplus
}
#endif

#endif /* _UTIL_H */
