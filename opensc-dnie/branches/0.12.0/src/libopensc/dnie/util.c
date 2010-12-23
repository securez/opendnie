/*
 * util.c: Auxiliary functions
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
#include "util.h"
#include "libopensc/opensc.h"
#include <assert.h>

#define SC_COPY_TO_FRONT 0
#define SC_COPY_TO_BACK  1

void ulong2lebytes(u8 *buf, unsigned long x)
{
    buf[0] = (u8) (x & 0xff);
    buf[1] = (u8) ((x >> 8) & 0xff);
    buf[2] = (u8) ((x >> 16) & 0xff);
    buf[3] = (u8) ((x >> 24) & 0xff);
}

void ushort2lebytes(u8 *buf, unsigned short x)
{
    buf[0] = (u8) (x & 0xff);
    buf[1] = (u8) ((x >> 8) & 0xff);
}

unsigned long lebytes2ulong(const u8 *buf)
{
  return (unsigned long) (buf[3] << 24 | buf[2] << 16 | buf[1] << 8 | buf[0]);  
}

unsigned short lebytes2ushort(const u8 *buf)
{
    return (unsigned short) (buf[0] << 24 | buf[1] << 16);
}

/*
  Function definition
  
  @param buf buffer with some data that will be increased in datalen
             with data of buffer data
  @param buflen length of buf buffer
  @param data buffer with data to copy to buf
  @param  datalen length of data buffer

  @return SC_SUCCESS on exit, SC_ERROR_OUT_OF_MEMORY whether we get an
          error allocating memory
 */
static int data2buf(u8 **buf, size_t *buflen, const u8 *data, const size_t datalen, int to_where)
{
  u8  *temp = NULL;

  if (!buf)
    return SC_ERROR_OUT_OF_MEMORY;
  
  if (*buflen>0) {
    temp = (u8 *) malloc(*buflen);
    if (!temp)
      return SC_ERROR_OUT_OF_MEMORY;
    memcpy( temp, *buf, *buflen);
  }

  *buf = realloc( *buf, *buflen+datalen );
  if (!*buf)
    return SC_ERROR_OUT_OF_MEMORY;

  switch (to_where) {
  case SC_COPY_TO_FRONT:
    memcpy( *buf, data, datalen );
    memcpy( *buf+datalen, temp, *buflen );
    break;
  case SC_COPY_TO_BACK:
    memcpy( *buf, temp, *buflen );
    memcpy( *buf+*buflen, data, datalen );
    break;
  default:
    return SC_ERROR_INVALID_ARGUMENTS;
  }
  *buflen += datalen;

  if(temp)
    free(temp);
  return SC_SUCCESS;
}

/*
  Function definition
  
  @param buf buffer with some data that will be increased in datalen
             with data of buffer data
  @param buflen length of buf buffer
  @param data buffer with data to copy to buf
  @param  datalen length of data buffer

  @return SC_SUCCESS on exit, SC_ERROR_OUT_OF_MEMORY whether we get an
          error allocating memory
 */
int push_front_data2buf(u8 **buf, size_t *buflen, const u8 *data, const size_t datalen)
{
  return data2buf(buf, buflen, data, datalen, SC_COPY_TO_FRONT);
}

/*
  Function definition
  
  @param buf buffer with some data that will be increased in datalen
             with data of buffer data
  @param buflen length of buf buffer
  @param data buffer with data to copy to buf
  @param  datalen length of data buffer

  @return SC_SUCCESS on exit, SC_ERROR_OUT_OF_MEMORY whether we get an
          error allocating memory
 */
int push_back_data2buf(u8 **buf, size_t *buflen, const u8 *data, const size_t datalen)
{
  return data2buf(buf, buflen, data, datalen, SC_COPY_TO_BACK);
}

/*
  Function definition
  
  @param void pointer to a  buffer
  @param length of buffer
 */
void free_struct( void *ptr, size_t length )
{
  if (ptr) {
    memset( ptr, 0, length );
    free( ptr );
    ptr=NULL;
  }
}

int sc_path_set_dnie(sc_path_t *path, int type, unsigned char *id, size_t id_len,
		int idx, int count)
{
  if (path == NULL || id == NULL || id_len == 0 || id_len > SC_MAX_PATH_SIZE)
    return SC_ERROR_INVALID_ARGUMENTS;
  memcpy(path->value, id, id_len);
  path->len   = id_len;
  path->type  = type;
  path->index = idx;
  path->count = count;

  return SC_SUCCESS;
}

int compute_tlv_value_len( const tlv_t *tlv )
{
  size_t valuelen=0;
  unsigned int ii=0;

  assert(tlv!=NULL && tlv->length!=NULL);
  
  valuelen = tlv->length[0];
  for(ii=1; tlv->nlen>ii; ii++)    
    valuelen = tlv->length[ii] | (valuelen << 8); 
  
  return valuelen;
}

int tlv2buf( const tlv_t *tlv, u8 **buf)
{
  size_t valuelen=0, total=0, offset=0;
  int r=SC_SUCCESS;

  assert(tlv!=NULL && buf!=NULL && tlv->value!=NULL && tlv->length!=NULL);

  if(*buf) {
    free(*buf);
    *buf=NULL;
  }
  
  valuelen = compute_tlv_value_len( tlv );    
  total = 1+tlv->nlen+valuelen;
  *buf = calloc(1, total);
  if(!*buf) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto end;
  }

  *buf[offset++] = tlv->tag;
  memcpy(*buf+offset, tlv->length, tlv->nlen);
  offset+=tlv->nlen;
  memcpy(*buf+offset, tlv->value, valuelen);

  end:
    if (r == SC_SUCCESS)
      return total;
    else
      return r;
}

int buf2tlv(const u8 tag, const u8 *data, const size_t len, tlv_t *tlv)
{
  int r = SC_SUCCESS;

  assert(data!=NULL && len>0 && tlv!=NULL);

  tlv->tag = tag;
  
  if (len<=0x00FF) {
    tlv->nlen=0x01;
    tlv->length = calloc(1, tlv->nlen);
    if (!tlv->length) {
      r = SC_ERROR_OUT_OF_MEMORY;
      goto end;
    }
    tlv->length[0] = (u8) len;
  } else if (len<=0xFFFF) {
    tlv->nlen=0x03;
    tlv->length = calloc(1, tlv->nlen);
    if (!tlv->length) {
      r = SC_ERROR_OUT_OF_MEMORY;
      goto end;
    }
    tlv->length[0] = 0x00;
    tlv->length[1] = 0x00FF & (len>>8);
    tlv->length[2] = 0x00FF & len;
  } else {
    r = SC_ERROR_INVALID_DATA;
    goto end;
  }

  tlv->value = calloc(1, len);
  if (!tlv->value) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto end;
  }
  memcpy(tlv->value, data, len);

 end:
  return r;
}

void free_tlv( tlv_t *tlv )
{
  assert(tlv!=NULL);
  
  free(tlv->length);
  tlv->length = NULL;
  free(tlv->value);
  tlv->value = NULL;
  
  memset(tlv, 0, sizeof(struct tlv));
}
