/*!
 * \file virtual_fs.c
 * \brief Card virtual filesystem
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

#include "virtual_fs.h"
#include <stdlib.h>
#include <string.h>

virtual_file_t * virtual_file_new()
{
  /* calloc already zeroes memory */
  return calloc(1, sizeof(virtual_file_t));
}

void virtual_file_free( virtual_file_t *virtual_file )
{
  if(virtual_file) {
    if(virtual_file->data) {
      memset(virtual_file->data, 0, virtual_file->data_size);
      free(virtual_file->data);
      virtual_file->data = NULL;
    }
    memset(virtual_file, 0, sizeof(virtual_file_t));
    free(virtual_file);
    virtual_file = NULL;
  }
}

int virtual_file_data_update( virtual_file_t *virtual_file, int offset, const unsigned char *data, int data_length )
{
  unsigned char *temp_data = NULL;
  int temp_data_size;

  if(!virtual_file)
    return SC_ERROR_INVALID_ARGUMENTS;

  if(data_length==0) /* do nothing */
    return SC_SUCCESS;
			
  if(!data)
    return SC_ERROR_INVALID_ARGUMENTS;

  /* correct if data_size is not ok */
  if(!virtual_file->data)
    virtual_file->data_size = 0;

  /* check if we have enough room for the data */
  if(virtual_file->data_size<(data_length+offset)) {
    /* we need more room */
    temp_data_size = data_length+offset;
    temp_data = calloc(1, temp_data_size);
    if(!temp_data)
      return SC_ERROR_OUT_OF_MEMORY;

    /* copy old data */
    if(virtual_file->data_size > 0)
      memcpy(temp_data, virtual_file->data, virtual_file->data_size);
    
    /* free old buffer */
    if(virtual_file->data)
      free(virtual_file->data);

    /* set new buffer */
    virtual_file->data = temp_data;
    virtual_file->data_size = temp_data_size;
  }

  /* we have enough room now, copy data */
  if(data_length > 0) {
    memcpy(virtual_file->data+offset, data, data_length);

    /* flag as not synchronized */
    virtual_file->virtual_fs_to_card.sync_state = virtual_file_sync_state_sync_pending;
  }

  return SC_SUCCESS;
}

int virtual_file_data_read( virtual_file_t *virtual_file, int offset, unsigned char *data, int data_length )
{
  if(!virtual_file)
    return SC_ERROR_INVALID_ARGUMENTS;

  if(data_length==0) /* do nothing */
    return SC_SUCCESS;
			
  if(!data)
    return SC_ERROR_INVALID_ARGUMENTS;

  /* correct if data_size is not ok */
  if(!virtual_file->data)
    virtual_file->data_size = 0;
  
  /* check if request is not out of bounds */
  if(virtual_file->data_size<(data_length+offset))
    return SC_ERROR_WRONG_LENGTH;

  /* copy data */
  if(data_length > 0)
    memcpy(data, virtual_file->data+offset, data_length);

  return SC_SUCCESS;
}

int virtual_file_data_zero( virtual_file_t *virtual_file, int data_size )
{
  if(!virtual_file)
    return SC_ERROR_INVALID_ARGUMENTS;

  if(data_size == 0) {
    if(virtual_file->data) {
      free(virtual_file->data);
      virtual_file->data = NULL;
    }
    virtual_file->data_size = data_size;
    return SC_SUCCESS;
  }

  if((virtual_file->data_size == data_size) && virtual_file->data) {
    /* we already have a suitable buffer */
    memset(virtual_file->data, 0, virtual_file->data_size); 
    return SC_SUCCESS;
  }

  if(virtual_file->data) {
    /* free existing buffer */
    memset(virtual_file->data, 0, virtual_file->data_size); 
    free(virtual_file->data);
    virtual_file->data = NULL;
  }

  /* set to 0 to have a coherent state if anything fails */
  virtual_file->data_size = 0;

  /* allocate new zeroed buffer */
  virtual_file->data = calloc(1, data_size);
  if(!virtual_file->data)
    return SC_ERROR_OUT_OF_MEMORY;
  
  /* set correct size */
  virtual_file->data_size = data_size;
  
  return SC_SUCCESS;
}

int virtual_file_data_synchronize( virtual_file_t *virtual_file, sc_card_t *card, virtual_file_sync_type_t sync_type, virtual_fs_t *virtual_fs )
{
  int r = SC_SUCCESS;

  if(!virtual_file)
    return SC_ERROR_INVALID_ARGUMENTS;

  virtual_file_sync_t *sync = NULL;

  if(sync_type == virtual_file_sync_type_card_to_virtual_fs)
    sync = &virtual_file->card_to_virtual_fs;
  else
    sync = &virtual_file->virtual_fs_to_card;
  
  /* we only synchronized if the same type of synchronization as the object type was request */
  if(!sync->sync_callback)
    return SC_SUCCESS;

  if(sync->sync_state == virtual_file_sync_state_sync_pending) {
    r = sync->sync_callback(card, virtual_file, virtual_fs);
    if(r == SC_SUCCESS)
      sync->sync_state = virtual_file_sync_state_synced;
    if(r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
      r = SC_SUCCESS;
  }

  /* no synchronization needed */
  return r;
}

int virtual_file_export_file( virtual_file_t *virtual_file, sc_file_t *file )
{
  if(!virtual_file || !file)
    return SC_ERROR_INVALID_ARGUMENTS;
  
  if(virtual_file->is_ef) {
    file->type = SC_FILE_TYPE_WORKING_EF;
    file->ef_structure = SC_FILE_EF_TRANSPARENT;
    file->size = virtual_file->data_size;
  } else {
    file->type = SC_FILE_TYPE_DF;
  }

  memcpy(&file->path, &virtual_file->path, sizeof(virtual_file->path));
  return SC_SUCCESS;
}
  
virtual_file_list_item_t * virtual_file_list_item_new()
{
  /* calloc already zeroes memory */
  return calloc(1, sizeof(virtual_file_list_item_t));
}

void virtual_file_list_item_free( virtual_file_list_item_t *virtual_file_list_item )
{
  if(virtual_file_list_item) {
    if(virtual_file_list_item->virtual_file) {
      virtual_file_free(virtual_file_list_item->virtual_file);
      virtual_file_list_item->virtual_file = NULL;
    }
    memset(virtual_file_list_item, 0, sizeof(virtual_file_list_item_t));
    free(virtual_file_list_item);
    virtual_file_list_item = NULL;
  }
}

virtual_fs_t * virtual_fs_new()
{
  /* calloc already zeroes memory */
  return calloc(1, sizeof(virtual_fs_t));
}

void virtual_fs_free( virtual_fs_t *virtual_fs )
{
  if(virtual_fs) {
    if(virtual_fs->list) {
      virtual_file_list_item_free(virtual_fs->list);
      virtual_fs->list = NULL;
    }
    memset(virtual_fs, 0, sizeof(virtual_fs_t));
    free(virtual_fs);
    virtual_fs = NULL;
  }
}

int virtual_fs_append( virtual_fs_t *virtual_fs, virtual_file_t *virtual_file )
{
  virtual_file_list_item_t *virtual_file_list_item = NULL;

  if(!virtual_fs || !virtual_file)
    return SC_ERROR_INVALID_ARGUMENTS;

  virtual_file_list_item = virtual_file_list_item_new();
  if(!virtual_file_list_item)
    return SC_ERROR_OUT_OF_MEMORY;

  virtual_file_list_item->virtual_file = virtual_file;
  virtual_file_list_item->next = virtual_fs->list;
  virtual_fs->list = virtual_file_list_item;

  return SC_SUCCESS;
}

virtual_file_t * virtual_fs_find_by_path( virtual_fs_t *virtual_fs, const sc_path_t *path )
{
  virtual_file_list_item_t *virtual_file_list_item = NULL;

  if(!virtual_fs || !path )
    return NULL;

  virtual_file_list_item = virtual_fs->list;
  while(virtual_file_list_item) {
    if(virtual_file_list_item->virtual_file && sc_compare_path(&virtual_file_list_item->virtual_file->path, path)) {
      /* we found it! */
      return virtual_file_list_item->virtual_file;
    }
    /* iterate through the list */
    virtual_file_list_item = virtual_file_list_item->next;
  }

  /* we didn't find the virtual_file */
  return NULL;
}

int virtual_fs_get_data_by_path( virtual_fs_t *virtual_fs, const sc_path_t *path, u8 **buffer, int *length )
{
  int r = SC_SUCCESS;
  virtual_file_t *virtual_file = NULL;

  if(!virtual_fs || !path || !buffer || *buffer || !length)
    return SC_ERROR_INVALID_ARGUMENTS;

  virtual_file = virtual_fs_find_by_path(virtual_fs, path);
  if(!virtual_file) {
    r = SC_ERROR_OBJECT_NOT_FOUND;
    goto end;
  }

  if(!virtual_file->is_ef) {
    /* file must be an ef */
    r = SC_ERROR_INVALID_ARGUMENTS;
    goto end;
  }

  *length = virtual_file->data_size;

  if(*length > 0) {
    if(!virtual_file->data) {
      r = SC_ERROR_INTERNAL;
      goto end;
    }

    *buffer = malloc(*length);
    if(!*buffer) {
      r = SC_ERROR_OUT_OF_MEMORY;
      goto end;
    }

    memcpy(*buffer, virtual_file->data, *length);
  }
  
 end:
  return r;
}

int virtual_fs_append_new_virtual_file( virtual_fs_t *virtual_fs, 
					const sc_path_t *path,
					const unsigned char *data,
					int data_length,
					int file_size,
					int is_ef,
					virtual_file_sync_state_t card_to_virtual_fs_sync_state,
					virtual_file_sync_callback *card_to_virtual_fs_sync_callback,
					virtual_file_sync_state_t virtual_fs_to_card_sync_state,
					virtual_file_sync_callback *virtual_fs_to_card_sync_callback
				      )
{
  int r = SC_SUCCESS;
  virtual_file_t *virtual_file = NULL;

  if(!virtual_fs || !path)
    return SC_ERROR_INVALID_ARGUMENTS;

  if(file_size < data_length)
    return SC_ERROR_INVALID_ARGUMENTS;

  /* create new virtual_file */
  virtual_file = virtual_file_new();
  if(!virtual_file) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto end;
  }

  /* copy data */
  if(file_size > data_length) {
    r = virtual_file_data_zero(virtual_file, file_size);
    if(r != SC_SUCCESS)
      goto end;
  }

  if(data_length>0 && data!=NULL) {
    r = virtual_file_data_update(virtual_file, 0, data, data_length);
    if(r != SC_SUCCESS)
      goto end;
  }

  /* copy all remaining fields */
  memcpy(&virtual_file->path, path, sizeof(virtual_file->path));
  virtual_file->is_ef = is_ef;
  virtual_file->card_to_virtual_fs.sync_state = card_to_virtual_fs_sync_state;
  virtual_file->card_to_virtual_fs.sync_callback = card_to_virtual_fs_sync_callback;
  virtual_file->virtual_fs_to_card.sync_state = virtual_fs_to_card_sync_state;
  virtual_file->virtual_fs_to_card.sync_callback = virtual_fs_to_card_sync_callback;

  /* append file to virtual_fs */
  r = virtual_fs_append(virtual_fs, virtual_file);
  if(r != SC_SUCCESS)
    goto end;

  /* we don't have ownership of virtual_file now,
     so we don't need to free it */
  virtual_file = NULL;
  

 end:
  if(r != SC_SUCCESS) {
    if(virtual_file) {
      virtual_file_free(virtual_file);
      virtual_file = NULL;
    }
  }
    
  return r;
}
