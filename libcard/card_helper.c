/*!
 * \file card_helper.c
 * \brief Card helper routines
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

#include "card_helper.h"
#include "base_card.h"
#include <opensc/log.h>
#include <assert.h>
#include <string.h>
#include "pkcs15_default.h"
#include "card_sync.h"
#include "../common/util.h"

int card_helper_read_file(sc_card_t *card, const sc_path_t *path, u8 **buffer, size_t *length)
{
  int r = SC_SUCCESS;
  sc_file_t *file = NULL;
  unsigned char *card_data = NULL;
  int old_use_virtual_fs; /*!< backup of use_virtual_fs */

  SC_FUNC_CALLED(card->ctx, 1);
  
  /* we backup use_virtual_fs */
  old_use_virtual_fs = card_is_virtual_fs_active(card);

  /* we want to use card without virtual fs */
  card_set_virtual_fs_state(card, 0);

  if(!buffer || !length) {
    r = SC_ERROR_INVALID_ARGUMENTS;
    goto end;
  }

  if(*buffer) {
    free(*buffer);
    *buffer = NULL;
  }

  /* get file */
  r = card_select_file(card, path, &file);
  if(r != SC_SUCCESS)
    goto end;

  if(file->size <= 0) {
    r = SC_ERROR_FILE_TOO_SMALL;
    goto end;
  }

  card_data = malloc(file->size);
  if(!card_data) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto end;
  }

  r = sc_read_binary(card, 0, card_data, file->size, 0);
  if(r < 0)
    goto end;

  *buffer = card_data;
  card_data = NULL;
  *length = r;
  r = SC_SUCCESS;

 end:
  /* we restore use_virtual_fs */
  card_set_virtual_fs_state(card, old_use_virtual_fs);

  if(file) {
    sc_file_free(file);
    file = NULL;
  }
  
  if(card_data) {
    free(card_data);
    card_data = NULL;
  }


  SC_FUNC_RETURN(card->ctx, 1, r); 
}

int card_helper_update_file(sc_card_t *card, const sc_path_t *path, u8 *buffer, size_t length)
{
  int r = SC_SUCCESS;
  sc_file_t *file = NULL;
  int old_use_virtual_fs; /*!< backup of use_virtual_fs */

  SC_FUNC_CALLED(card->ctx, 1);
  
  /* we backup use_virtual_fs */
  old_use_virtual_fs = card_is_virtual_fs_active(card);

  /* we want to use card without virtual fs */
  card_set_virtual_fs_state(card, 0);

  if(!buffer || length<=0) {
    r = SC_ERROR_INVALID_ARGUMENTS;
    goto chuf_end;
  }

  /* get file */
  r = card_select_file(card, path, &file);
  if(r != SC_SUCCESS)
    goto chuf_end;
  
  if(file->size <= 0) {
    r = SC_ERROR_FILE_TOO_SMALL;
    goto chuf_end;
  }
  
  if (file->size<length) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto chuf_end;
  }

  r = sc_update_binary(card, 0, buffer, length, 0);
  if(r < 0)
    goto chuf_end;
  if (r == length)
    r = SC_SUCCESS;

 chuf_end:
  /* we restore use_virtual_fs */
  card_set_virtual_fs_state(card, old_use_virtual_fs);

  if(file) {
    sc_file_free(file);
    file = NULL;
  }

 SC_FUNC_RETURN(card->ctx, 1, r); 
}

int card_helper_create_cert_file(sc_card_t *card, struct _virtual_file_t *virtual_file, 
				 size_t fcert_len, struct _virtual_file_t **certificate_virtual_file)
{
  int r = SC_SUCCESS;
  sc_path_t fcert_path;
  sc_pkcs15_unusedspace_t *unused_space=NULL;
  sc_pkcs15_card_t *temp_p15card = NULL;
  int old_use_virtual_fs; /*!< backup of use_virtual_fs */

  assert(card!=NULL && virtual_file!=NULL && certificate_virtual_file!=NULL);

  SC_FUNC_CALLED(card->ctx, 1);
  
  /* we backup use_virtual_fs */
  old_use_virtual_fs = card_is_virtual_fs_active(card);

  /* we want to use card without virtual fs */
  card_set_virtual_fs_state(card, 0);

  if(*certificate_virtual_file) {
    virtual_file_free(*certificate_virtual_file);
    *certificate_virtual_file = NULL;
  }

  memset(&fcert_path, 0, sizeof(struct sc_path));

  /* 2. Look for a suitable file on UnusedSpace struct
     which fits the final certificate file size.
     2.1 If found, take file's path to reuse it.
     2.2 If not, create a file on Certificate Directory
     with final certificate len as its size
  */
    
  /* we create a fake p15card structure */
  temp_p15card = sc_pkcs15_card_new();
  temp_p15card->card = card;
    
  r = sc_find_free_unusedspace( temp_p15card, fcert_len, &unused_space );
  if (r!=SC_SUCCESS)
    goto chccf_end;

  if(unused_space) {
    /* we got a path */
    r = sc_path_set_dnie ( &fcert_path, 
		      unused_space->path.type, 
		      unused_space->path.value,
		      unused_space->path.len,
		      unused_space->path.index,
		      unused_space->path.count );
    if (r!=SC_SUCCESS)
      goto chccf_end;
  } else {            
    sc_path_t temp_path;
    /* move to certificate DF */
    sc_format_path("3F006061", &temp_path);
    r = card_select_file(card, &temp_path, NULL);
    if(r != SC_SUCCESS)
      goto chccf_end;

    /* we start at 0x7001 file ID */
    sc_format_path("7001", &fcert_path);

    do {
      r = card_create_cert_file( card, &fcert_path, fcert_len );
      if (r == SC_ERROR_OBJECT_ALREADY_EXISTS) {
	fcert_path.value[1]++;	
      }
      if(r!=SC_SUCCESS && r!=SC_ERROR_OBJECT_ALREADY_EXISTS)
	goto chccf_end;
    } while (r!=SC_SUCCESS);
    r = SC_SUCCESS;
  }    

  /* create certificate file into vfs */
  r = virtual_fs_append_new_virtual_file( DRVDATA(card)->virtual_fs, 
					  &fcert_path, 
					  virtual_file->data, 
					  virtual_file->data_size, 
					  virtual_file->data_size, 
					  1, 
					  virtual_file_sync_state_synced, 
					  card_sync_card_to_virtual_fs_certificate_file_callback, 
					  virtual_file_sync_state_sync_pending, 
					  card_sync_virtual_fs_to_card_certificate_file_callback );
  if(r != SC_SUCCESS)
    goto chccf_end;

  /* retrieve just created virtual file */
  *certificate_virtual_file = virtual_fs_find_by_path( DRVDATA(card)->virtual_fs, &fcert_path );

 chccf_end:
/* we restore use_virtual_fs */
  card_set_virtual_fs_state(card, old_use_virtual_fs);

  if (unused_space) {
    /* Delete UnusedSpace object if reused 
       and also frees reserved memory
    */
    sc_pkcs15_remove_unusedspace(temp_p15card, unused_space);
  }
  if (temp_p15card) { 
    /* set to NULL without freeing because we reused structure */
    temp_p15card->card = NULL;
    
    /* now free temp structure */
    sc_pkcs15_card_free(temp_p15card);
    temp_p15card = NULL;
  }
  SC_FUNC_RETURN(card->ctx, 1, r); 
}

int card_helper_read_certificate_file(sc_card_t *card, const sc_path_t *path, u8 **buffer, size_t *length)
{
  int r = SC_SUCCESS;
  sc_file_t *file = NULL;
  unsigned char *card_data = NULL;
  u8 header[8];
  int old_use_virtual_fs; /*!< backup of use_virtual_fs */
  size_t compressed_data_length=0;

  SC_FUNC_CALLED(card->ctx, 1);
  
  /* we backup use_virtual_fs */
  old_use_virtual_fs = card_is_virtual_fs_active(card);

  /* we want to use card without virtual fs */
  card_set_virtual_fs_state(card, 0);

  if(!buffer || !length) {
    r = SC_ERROR_INVALID_ARGUMENTS;
    goto end;
  }

  if(*buffer) {
    free(*buffer);
    *buffer = NULL;
  }

  /* get file */
  r = card_select_file(card, path, &file);
  if(r != SC_SUCCESS)
    goto end;

  if(file->size <= 0) {
    r = SC_ERROR_FILE_TOO_SMALL;
    goto end;
  }

  memset(header, 0, sizeof(header));
  /* read certificate header information */
  r = sc_read_binary(card, 0, header, sizeof(header), 0);
  if(r<0 || r!=sizeof(header))
    goto end;
  /* get certificate compressed length */
  compressed_data_length = lebytes2ulong(header+4);

  /* update file size */
  file->size = (file->size>(compressed_data_length+8)) ? compressed_data_length+8 : file->size;

  card_data = malloc(file->size);
  if(!card_data) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto end;
  }

  r = sc_read_binary(card, 0, card_data, file->size, 0);
  if(r < 0)
    goto end;

  *buffer = card_data;
  card_data = NULL;
  *length = r;
  r = SC_SUCCESS;

 end:
  /* we restore use_virtual_fs */
  card_set_virtual_fs_state(card, old_use_virtual_fs);

  if(file) {
    sc_file_free(file);
    file = NULL;
  }
  
  if(card_data) {
    free(card_data);
    card_data = NULL;
  }

  SC_FUNC_RETURN(card->ctx, 1, r); 
}
