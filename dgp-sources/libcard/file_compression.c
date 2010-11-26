/*!
 * \file file_compression.h
 * \brief File compression functions
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


#include "file_compression.h"
#include <opensc/opensc.h>
#include <opensc/log.h>
#include <zlib.h>
#include <string.h>
#include "../common/util.h"
#include <stdlib.h>
#include <assert.h>

int file_uncompress_data(struct sc_card *card, u8 * data, size_t length, u8 **uncompressed_data, size_t *uncompressed_data_length )
{
  size_t compressed_data_length;
  int r = SC_SUCCESS, pos=0;

  SC_FUNC_CALLED(card->ctx, 1);

  /* zlib header; uncompressed length + compressed length: always will be 8 bytes */
  pos = 8;	
  *uncompressed_data_length = lebytes2ulong(data);
  compressed_data_length = lebytes2ulong(data+4);

  *uncompressed_data = (u8 *) calloc(*uncompressed_data_length, sizeof(u8));		
  if (!*uncompressed_data)		
    return SC_ERROR_OUT_OF_MEMORY;

  if(compressed_data_length < *uncompressed_data_length) {
    r = uncompress(*uncompressed_data, (unsigned long *)uncompressed_data_length, data+pos, length-pos);			
    if(r!=Z_OK) {
      free(*uncompressed_data);		
      return r;
    }
    r = SC_SUCCESS;
  }  else {
    memcpy(*uncompressed_data, data+pos, *uncompressed_data_length);
    r = SC_SUCCESS;
  }

  SC_FUNC_RETURN(card->ctx, 1, r);
}

int file_compress_data(struct sc_card *card, 
		       u8 * uncompressed_data, size_t uncompressed_data_length, 
		       u8 **compressed_data, size_t *compressed_data_length )
{
  int r = SC_SUCCESS;
  u8 *tmp_compressed_data=NULL, header[8];
  unsigned long tmp_compressed_data_len=0;
  size_t complen=0, unclen=0;

  assert(card!=NULL && uncompressed_data!=NULL && compressed_data!=NULL && 
	 compressed_data_length!=NULL);

  SC_FUNC_CALLED(card->ctx, 1);

  if(*compressed_data) {
    free(*compressed_data);
    *compressed_data = NULL;
  }
  *compressed_data_length = 0;

  /* Compress certificate and get compressed length */
  /* make room for a new one */
  /* compress function says to make room for at least 0.1% more plus 8. 
     We make sure everything is ok by using a little bit more   */

  tmp_compressed_data_len = (unsigned long) uncompressed_data_length*1.002+8+1;
  tmp_compressed_data = (u8 *) calloc(1, tmp_compressed_data_len);
  if (!tmp_compressed_data) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto fcd_end;
  }
    
  r = compress( tmp_compressed_data, 
		&tmp_compressed_data_len, 
		uncompressed_data, 
		uncompressed_data_length );
  if(r)
    goto fcd_end;

  unclen = uncompressed_data_length;
  complen = tmp_compressed_data_len;
   
  if ( complen > unclen ) {
    /* we keep the uncompressed certificate */
    if (*compressed_data)
      *compressed_data_length = unclen;

    r = push_back_data2buf( compressed_data, 
			    compressed_data_length,
			    uncompressed_data,
			    uncompressed_data_length );
    if(r!=SC_SUCCESS)
      goto fcd_end;

  } else {
    /* we keep the compressed certificate */
    if (*compressed_data)
      *compressed_data_length = complen;

    r = push_back_data2buf( compressed_data, 
			    compressed_data_length,
			    tmp_compressed_data, 
			    tmp_compressed_data_len );
    if(r!=SC_SUCCESS)
      goto fcd_end;

  }

  /* Add 8 header compress info bytes to certificate data */
  memset(header, 0, 8);
  ulong2lebytes(header, unclen);
  ulong2lebytes(header+4, *compressed_data_length);

  r = push_front_data2buf( compressed_data, 
			   compressed_data_length,
			   header,
			   8 );
  if (r!=SC_SUCCESS)
    goto fcd_end;

 fcd_end:
  /* free buffers */
  if (tmp_compressed_data) {
    free(tmp_compressed_data);
    tmp_compressed_data=NULL;
  }

  SC_FUNC_RETURN(card->ctx, 1, r);
}
