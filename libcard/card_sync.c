/*!
 * \file card_sync.c
 * \brief Card synchronization functions
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

#include "card_sync.h"
#include <opensc/opensc.h>
#include <opensc/pkcs15.h>
#include "base_card.h"
#include "pkcs15_standard.h"
#include "pkcs15_default.h"
#include "card_helper.h"
#include "file_compression.h"
#include <string.h> /*!< to call memory functions */


int card_sync_card_to_virtual_fs_filter_cert( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs, sc_pkcs15_object_t *obj )
{
  int r = SC_SUCCESS;
  struct sc_pkcs15_cert_info *cert = NULL;
  unsigned char *card_data = NULL;
  virtual_file_t  *certificate_virtual_file = NULL;
  virtual_file_t  *certificate_virtual_file_weak_link = NULL; 
  sc_path_t abs_cert_path, cert_card_path;

  SC_FUNC_CALLED(card->ctx, 1);

  /* we need to correct certificate length in path */
  cert = (struct sc_pkcs15_cert_info *) obj->data;
  if(cert) {
    /* set asn1 to map */
    r = map_id_to_der_set_item(DRVDATA(card)->cdf_card_ckaid_to_card_der_map, &cert->id, &obj->der);
    if(r != SC_SUCCESS)
      goto end;
    
    if(cert->path.len > 0) {
      certificate_virtual_file = virtual_file_new();
      if(!certificate_virtual_file) {
	r = SC_ERROR_OUT_OF_MEMORY;
	goto end;
      }
      
      memset(&abs_cert_path, 0, sizeof(struct sc_path));
      memset(&cert_card_path, 0, sizeof(struct sc_path));

      if(cert->path.len==2) {
	sc_format_path("3F005015", &abs_cert_path);
	r = sc_append_path(&abs_cert_path, &cert->path);
	if(r!=SC_SUCCESS)
	  goto end;
	sc_format_path("3F006061", &cert_card_path);
	r = sc_append_path(&cert_card_path, &cert->path);
	if(r!=SC_SUCCESS)
	  goto end;
      } else if(cert->path.len==4) {
	sc_format_path("3F00", &abs_cert_path);
	r = sc_append_path(&abs_cert_path, &cert->path);
	if(r!=SC_SUCCESS)
	  goto end;
	sc_format_path("3F00", &cert_card_path);
	r = sc_append_path(&cert_card_path, &cert->path);
	if(r!=SC_SUCCESS)
	  goto end;
        memcpy(cert->path.value, cert_card_path.value, cert_card_path.len);
        cert->path.len = 6;
      } else { 
	r = sc_append_path(&abs_cert_path, &cert->path);
	if(r!=SC_SUCCESS)
	  goto end;
	if(abs_cert_path.len==6) {
	  r = sc_append_path(&cert_card_path, &cert->path);
	  if(r!=SC_SUCCESS)
	    goto end;
	}
      }

      memcpy(&certificate_virtual_file->path, &abs_cert_path, sizeof(certificate_virtual_file->path));
      r = map_path_to_path_set_item(DRVDATA(card)->virtual_fs_to_card_path_map, &certificate_virtual_file->path, &cert_card_path);
      if(r != SC_SUCCESS)
	goto end;
      certificate_virtual_file->is_ef = 1;

      certificate_virtual_file->card_to_virtual_fs.sync_state = virtual_file_sync_state_sync_pending;
      certificate_virtual_file->card_to_virtual_fs.sync_callback = card_sync_card_to_virtual_fs_certificate_file_callback;
      certificate_virtual_file->virtual_fs_to_card.sync_state = virtual_file_sync_state_unknown;
      certificate_virtual_file->virtual_fs_to_card.sync_callback = NULL;
      
      /* append file to virtual_fs */
      r = virtual_fs_append(virtual_fs, certificate_virtual_file);
      if(r != SC_SUCCESS)
	goto end;

      /* we don't have ownership of virtual_file now,
	 so we don't need to free it */
      certificate_virtual_file_weak_link = certificate_virtual_file;
      certificate_virtual_file = NULL;
        
      /* we now synchronize file because this gets a correct size for it */
      r = virtual_file_data_synchronize(certificate_virtual_file_weak_link, card, virtual_file_sync_type_card_to_virtual_fs, DRVDATA(card)->virtual_fs);
      if (r != SC_SUCCESS) {
	sc_error(card->ctx, "Synchronization failed\n");
	goto end;
      }
      
      /* correct length in PKCS#15 */
      cert->path.count = certificate_virtual_file_weak_link->data_size;
    } else {
      sc_debug(card->ctx, "Path length is 0");
    }
  } else {
    sc_debug(card->ctx, "Pointer to cert info was empty");
  }

 end:
  if(card_data) {
    free(card_data);
    card_data = NULL;
  }

  if(certificate_virtual_file) {
    virtual_file_free(certificate_virtual_file);
    certificate_virtual_file = NULL;
  }

  SC_FUNC_RETURN(card->ctx, 1, r);
}

int card_sync_card_to_virtual_fs_filter_prkey( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs, sc_pkcs15_object_t *obj )
{
  int r = SC_SUCCESS;
  struct sc_pkcs15_prkey_info *prkey = NULL;
  sc_path_t def_path;

  /* This flag identifies the FIRMA private key */
  u8 flag_id[1] = "F";
  
  memset(&def_path, 0, sizeof(struct sc_path));

  SC_FUNC_CALLED(card->ctx, 1);

  if(!card || !virtual_file)
    return SC_ERROR_INVALID_ARGUMENTS;

  prkey = (struct sc_pkcs15_prkey_info *) obj->data;
  if(prkey) {
    /* set asn1 to map */
    r = map_id_to_der_set_item(DRVDATA(card)->prkdf_card_ckaid_to_card_der_map, &prkey->id, &obj->der);
    if(r != SC_SUCCESS)
      goto end;

    if(prkey->modulus_length < 512)
      prkey->modulus_length = prkey->modulus_length * 8;
    if(prkey->modulus_length != 2048)
      prkey->modulus_length = 1024;

    if(prkey->path.len > 0) {
      /* append empty file */

      if(prkey->path.len == 4) {
        sc_format_path("3F00", &def_path);
   	r = sc_append_path(&def_path, &prkey->path);

	if(r!=SC_SUCCESS)
	  goto end;

        memcpy(prkey->path.value, def_path.value, def_path.len);
        prkey->path.len = 6;

      } else {
        memcpy(&def_path, &prkey->path, sizeof(prkey->path));      
      }

      r = virtual_fs_append_new_virtual_file(virtual_fs, &def_path, NULL, 1, 1, 1, virtual_file_sync_state_unknown, NULL, virtual_file_sync_state_unknown, NULL);
      if(r != SC_SUCCESS)
	goto end;

      /* correct length in PKCS#15 */
      prkey->path.count = 0;

      /* Fixed key usage for FIRMA private key */
      if(memcmp(prkey->id.value, flag_id, 1)==0)
	prkey->usage |= SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;

      obj->auth_id.value[0]=0x01;
      obj->auth_id.len=0x01;
    } else {
      sc_debug(card->ctx, "Path length is 0");
    }
  } else {
    sc_debug(card->ctx, "Pointer to prkey info was empty");
  }

 end:
  SC_FUNC_RETURN(card->ctx, 1, r);
}

int card_sync_card_to_virtual_fs_filter_pukey( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs, sc_pkcs15_object_t *obj )
{
  int r = SC_SUCCESS;
  struct sc_pkcs15_pubkey_info *pukey = NULL;
  sc_path_t def_path;
  /* This flag identifies the FIRMA public key */
  u8 flag_id[1] = "F";

  SC_FUNC_CALLED(card->ctx, 1);

  memset(&def_path, 0, sizeof(struct sc_path));

  if(!card || !virtual_file)
    return SC_ERROR_INVALID_ARGUMENTS;

  pukey = (struct sc_pkcs15_pubkey_info *) obj->data;
  if(pukey) {
    /* set asn1 to map */
    r = map_id_to_der_set_item(DRVDATA(card)->pukdf_card_ckaid_to_card_der_map, &pukey->id, &obj->der);
    if(r != SC_SUCCESS)
      goto end;


    if(pukey->path.len > 0) {

      if(pukey->path.len == 4) {
        sc_format_path("3F00", &def_path);
   	r = sc_append_path(&def_path, &pukey->path);

	if(r!=SC_SUCCESS)
	  goto end;

        memcpy(pukey->path.value, def_path.value, def_path.len);
        pukey->path.len = 6;

      } else {
        memcpy(&def_path, &pukey->path, sizeof(pukey->path));      
      }

      /* append empty file */
      r = virtual_fs_append_new_virtual_file(virtual_fs, 
					     &def_path, 
					     obj->der.value, 
					     obj->der.len, 
					     obj->der.len, 
					     1, 
					     virtual_file_sync_state_unknown, 
					     NULL, 
					     virtual_file_sync_state_unknown, 
					     NULL);
      if(r != SC_SUCCESS)
	goto end;

      /* correct length in PKCS#15 */
      pukey->path.count = 0;

      /* Fixed key usage for FIRMA public key */
      if(memcmp(pukey->id.value, flag_id, 1)==0)
	pukey->usage |= SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;

    } else {
      sc_debug(card->ctx, "Path length is 0");
    }
  } else {
    sc_debug(card->ctx, "Pointer to pukey info was empty");
  }

 end:
  SC_FUNC_RETURN(card->ctx, 1, r);
}


int card_sync_card_to_virtual_fs_filter_data_object( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs, sc_pkcs15_object_t *obj )
{
  int r = SC_SUCCESS;
  struct sc_pkcs15_data_info *data = NULL;
  unsigned char *card_data = NULL;
  virtual_file_t  *data_virtual_file = NULL;
  virtual_file_t  *data_virtual_file_weak_link = NULL; 
  sc_path_t abs_data_path, data_card_path, def_path;

  SC_FUNC_CALLED(card->ctx, 1);

  /* we need to correct certificate length in path */
  data = (struct sc_pkcs15_data_info *) obj->data;
  if(data) {    
    if(data->path.len > 0) {
      data_virtual_file = virtual_file_new();
      if(!data_virtual_file) {
	r = SC_ERROR_OUT_OF_MEMORY;
	goto end;
      }

      memset(&abs_data_path, 0, sizeof(struct sc_path));
      memset(&data_card_path, 0, sizeof(struct sc_path));      	
      memset(&def_path, 0, sizeof(struct sc_path));

      
      if(data->path.len == 4) {
        sc_format_path("3F00", &def_path);
   	r = sc_append_path(&def_path, &data->path);

	if(r!=SC_SUCCESS)
	  goto end;

        memcpy(data->path.value, def_path.value, def_path.len);
        data->path.len = 6;

      } else {
        memcpy(&def_path, &data->path, sizeof(data->path));
      }

      r = sc_append_path(&abs_data_path, &def_path);
      if(r!=SC_SUCCESS)
	goto end;

      if(abs_data_path.len==6) {
	r = sc_append_path(&data_card_path, &def_path);
	if(r!=SC_SUCCESS)
	  goto end;
      }      

      memcpy(&data_virtual_file->path, &abs_data_path, sizeof(data_virtual_file->path));
      r = map_path_to_path_set_item(DRVDATA(card)->virtual_fs_to_card_path_map, &data_virtual_file->path, &data_card_path);
      if(r != SC_SUCCESS)
	goto end;
      data_virtual_file->is_ef = 1;

      data_virtual_file->card_to_virtual_fs.sync_state = virtual_file_sync_state_sync_pending;
      data_virtual_file->card_to_virtual_fs.sync_callback = card_sync_card_to_virtual_fs_data_file_callback;
      data_virtual_file->virtual_fs_to_card.sync_state = virtual_file_sync_state_unknown;
      data_virtual_file->virtual_fs_to_card.sync_callback = NULL;
      
      /* append file to virtual_fs */
      r = virtual_fs_append(virtual_fs, data_virtual_file);
      if(r != SC_SUCCESS)
	goto end;

      /* we don't have ownership of virtual_file now,
	 so we don't need to free it */
      data_virtual_file_weak_link = data_virtual_file;
      data_virtual_file = NULL;
        
      /* we now synchronize file because this gets a correct size for it */
      r = virtual_file_data_synchronize(data_virtual_file_weak_link, card, virtual_file_sync_type_card_to_virtual_fs, DRVDATA(card)->virtual_fs);
      if (r != SC_SUCCESS) {
	sc_error(card->ctx, "Synchronization failed\n");
	goto end;
      }
      
      /* correct length in PKCS#15 */
      data->path.count = data_virtual_file_weak_link->data_size;
      obj->auth_id.value[0]=0x01;
      obj->auth_id.len=0x01;
    } else {
      sc_debug(card->ctx, "Path length is 0");
    }
  } else {
    sc_debug(card->ctx, "Pointer to data info was empty");
  }

 end:
  if(card_data) {
    free(card_data);
    card_data = NULL;
  }

  if(data_virtual_file) {
    virtual_file_free(data_virtual_file);
    data_virtual_file = NULL;
  }

  SC_FUNC_RETURN(card->ctx, 1, r);
}

int card_sync_card_to_virtual_fs_any_df( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs, int type )
{
  int r = SC_SUCCESS;
  unsigned char *encoded_pkcs15 = NULL;
  size_t encoded_pkcs15_size = 0;
  sc_pkcs15_card_t *temp_pkcs15_card  = NULL;
  sc_pkcs15_object_t *obj = NULL;
  unsigned char *card_data = NULL;
  size_t card_data_length = 0;  
  
  SC_FUNC_CALLED(card->ctx, 1);

  if(!card || !virtual_file)
    return SC_ERROR_INVALID_ARGUMENTS;

  /* get file */
  r = card_helper_read_file(card, &virtual_file->path, &card_data, &card_data_length);
  if(r < 0)
    goto end;

  /* create a new pkcs15_card structure */
  temp_pkcs15_card = sc_pkcs15_card_new();
  if(!temp_pkcs15_card) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto end;
  }

  /* we set some important fields */
  temp_pkcs15_card->card = card;
  temp_pkcs15_card->file_app = sc_file_new();
  if (!temp_pkcs15_card->file_app) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto end;
  }
  sc_format_path("3F00", &temp_pkcs15_card->file_app->path);

  /* Convert card df read to a list of same type of pkcs15 objects. 
     This function uses our internal card decoding parser.
  */
  r = sc_pkcs15_parse_card_df( temp_pkcs15_card, 
			       type, 
			       card_data, 
			       card_data_length
                               );
  if(r != SC_SUCCESS) {
    sc_error(card->ctx, "Card parsing failed\n"); 
    goto end;
  }

  /* we need to correct some PKCS#15 data */
  for(obj = temp_pkcs15_card->obj_list; obj != NULL; obj = obj->next) {
    switch(obj->type & SC_PKCS15_TYPE_CLASS_MASK) {
    case SC_PKCS15_TYPE_CERT:
      r = card_sync_card_to_virtual_fs_filter_cert(card, virtual_file, virtual_fs, obj);
      break;

    case SC_PKCS15_TYPE_PRKEY:
      r = card_sync_card_to_virtual_fs_filter_prkey(card, virtual_file, virtual_fs, obj);
      break;
      
    case SC_PKCS15_TYPE_PUBKEY:
      r = card_sync_card_to_virtual_fs_filter_pukey(card, virtual_file, virtual_fs, obj);
      break;

    case SC_PKCS15_TYPE_AUTH:
      if(obj->data) {
	sc_pkcs15_pin_info_t * pin=obj->data;
	/* remove security officer pin */
	pin->flags &= (~SC_PKCS15_PIN_FLAG_SO_PIN);
	sc_format_path("3F00", &pin->path);		
	pin->stored_length= (pin->max_length>pin->stored_length) ? pin->max_length : pin->stored_length;
      }
      break;

    case SC_PKCS15_TYPE_DATA_OBJECT:
      r = card_sync_card_to_virtual_fs_filter_data_object(card, virtual_file, virtual_fs, obj);
      break;

    default:
      /* ignore this object */
      break;
    }
  }
  if(r != SC_SUCCESS) {
    sc_error(card->ctx, "Object filtering failed\n");
    goto end;
  }
 

  /* generate pkcs#15 stream for the appropiate object type */
  r = sc_standard_pkcs15_encode_any_df( card->ctx, 
					temp_pkcs15_card, 
					type, /* encode only specific objects type */
					&encoded_pkcs15,
					&encoded_pkcs15_size
                                        );
  if(r != SC_SUCCESS) {
    sc_error(card->ctx, "Standard PKCS#15 encoding failed\n"); 
    goto end;
  }
    
  r = virtual_file_data_update(virtual_file, 0, encoded_pkcs15, encoded_pkcs15_size);
  if(r == SC_SUCCESS) {
    /* add a trailing 0 */
    r = virtual_file_data_update(virtual_file, encoded_pkcs15_size, (const unsigned char *)"\0", 1);
  }

 end:
  if(card_data) {
    free(card_data);
    card_data = NULL;
  }

  if(temp_pkcs15_card) { 
    /* set to NULL without freeing because we reused structure */
    temp_pkcs15_card->card = NULL;
    
    /* now free temp structure */
    sc_pkcs15_card_free(temp_pkcs15_card);
    temp_pkcs15_card = NULL;
  }  

  if(encoded_pkcs15) {
    free(encoded_pkcs15);
    encoded_pkcs15 = NULL;
  }
  SC_FUNC_RETURN(card->ctx, 1, r);
}

int card_sync_card_to_virtual_fs_odf_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs )
{
  return card_sync_card_to_virtual_fs_any_df(card, virtual_file, virtual_fs, SC_PKCS15_ODF);
}

int card_sync_card_to_virtual_fs_tokeninfo_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs )
{
  return card_sync_card_to_virtual_fs_any_df(card, virtual_file, virtual_fs, SC_PKCS15_TOKENINFO);
}

int card_sync_card_to_virtual_fs_aodf_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs )
{
  return card_sync_card_to_virtual_fs_any_df(card, virtual_file, virtual_fs, SC_PKCS15_AODF);
}

int card_sync_card_to_virtual_fs_prkdf_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs )
{
  /* use generic synchronization with PrKDF param */
  return card_sync_card_to_virtual_fs_any_df(card, virtual_file, virtual_fs, SC_PKCS15_PRKDF);
}

int card_sync_card_to_virtual_fs_pukdf_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs )
{
  /* use generic synchronization with PuKDF param */
  return card_sync_card_to_virtual_fs_any_df(card, virtual_file, virtual_fs, SC_PKCS15_PUKDF);
}

int card_sync_card_to_virtual_fs_cdf_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs )
{
  return card_sync_card_to_virtual_fs_any_df(card, virtual_file, virtual_fs, SC_PKCS15_CDF);
}

int card_sync_card_to_virtual_fs_dodf_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs )
{
  return card_sync_card_to_virtual_fs_any_df(card, virtual_file, virtual_fs, SC_PKCS15_DODF);
}

int card_sync_virtual_fs_to_card_filter_cert( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs, sc_pkcs15_object_t *obj )
{
  int r = SC_SUCCESS;
  struct sc_pkcs15_cert_info *cert = NULL;
  sc_pkcs15_der_t *der = NULL;
  sc_path_t *path = NULL;
  sc_pkcs15_id_t *ckaid = NULL;
  struct _virtual_file_t *tmp_vf=NULL;
  unsigned char *compressed_data = NULL;
  size_t compressed_data_length = 0;

  SC_FUNC_CALLED(card->ctx, 1);

  if(!card || !virtual_file)
    return SC_ERROR_INVALID_ARGUMENTS;

  cert = (struct sc_pkcs15_cert_info *) obj->data;
  if(cert) {
    sc_der_clear(&obj->der);

    /* try to find an old der if present */
    der = map_id_to_der_find(DRVDATA(card)->cdf_card_ckaid_to_card_der_map, &cert->id);
    if(der) {
      sc_der_copy(&obj->der, der);
    }

    path = map_path_to_path_find(DRVDATA(card)->virtual_fs_to_card_path_map, &cert->path);
    if(path) {
      /* replace path data */
      memcpy(&cert->path, path, sizeof(sc_path_t));
      
      tmp_vf=virtual_fs_find_by_path(virtual_fs, &cert->path);
      if(!tmp_vf) {
	r = SC_ERROR_INVALID_DATA;
	goto end;
      }
      
      r = file_compress_data(card, tmp_vf->data, tmp_vf->data_size, &compressed_data, &compressed_data_length); 
      if(r!=SC_SUCCESS)
	goto end;

      /* certificate file has an info header */
      cert->path.count = compressed_data_length+8;
    }

    ckaid = map_opensc_id_to_id_find(DRVDATA(card)->virtual_fs_to_card_ckaid_map, &cert->id);
    if(ckaid) {
      /* replace ckaid */
      memcpy(&cert->id, ckaid, sizeof(struct sc_pkcs15_id));
    } else {
      ckaid = map_path_to_id_find(DRVDATA(card)->card_path_to_card_ckaid_map, &cert->path);
      if (ckaid) {
	/* replace ckaid */
	memcpy(&cert->id, ckaid, sizeof(struct sc_pkcs15_id));
      }
    }
  }

 end:
  if(compressed_data) {
    free(compressed_data);
    compressed_data = NULL;
  }
  SC_FUNC_RETURN(card->ctx, 1, r);
}

int card_sync_virtual_fs_to_card_filter_prkey( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs, sc_pkcs15_object_t *obj )
{
  int r = SC_SUCCESS;
  struct sc_pkcs15_prkey_info *prkey = NULL;
  sc_pkcs15_der_t *der = NULL;
  sc_path_t *path = NULL;
  sc_pkcs15_id_t *ckaid = NULL;

  SC_FUNC_CALLED(card->ctx, 1);

  if(!card || !virtual_file)
    return SC_ERROR_INVALID_ARGUMENTS;
  
  prkey = (struct sc_pkcs15_prkey_info *) obj->data;
  if(prkey) {
    sc_der_clear(&obj->der);

    /* try to find an old der if present */
    der = map_id_to_der_find(DRVDATA(card)->prkdf_card_ckaid_to_card_der_map, &prkey->id);
    if(der) {
      sc_der_copy(&obj->der, der);
    }

    path = map_path_to_path_find(DRVDATA(card)->virtual_fs_to_card_path_map, &prkey->path);
    if(path) {
      /* replace path data */
      memcpy(&prkey->path, path, sizeof(sc_path_t));
    }

    ckaid = map_opensc_id_to_id_find(DRVDATA(card)->virtual_fs_to_card_ckaid_map, &prkey->id);
    if(ckaid) {
      /* replace ckaid */
      memcpy(&prkey->id, ckaid, sizeof(struct sc_pkcs15_id));
    }

    /* add manual flags */
    prkey->native = 0x01;
  } else {
    sc_debug(card->ctx, "Pointer to prkey info was empty");
  }

  SC_FUNC_RETURN(card->ctx, 1, r);
}

int card_sync_virtual_fs_to_card_filter_pukey( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs, sc_pkcs15_object_t *obj )
{
  int r = SC_SUCCESS;
  struct sc_pkcs15_pubkey_info *pukey = NULL;
  sc_pkcs15_der_t *der = NULL;
  sc_path_t *path = NULL;
  sc_pkcs15_id_t *ckaid = NULL;

  SC_FUNC_CALLED(card->ctx, 1);

  if(!card || !virtual_file)
    return SC_ERROR_INVALID_ARGUMENTS;
  
  pukey = (struct sc_pkcs15_pubkey_info *) obj->data;
  if(pukey) {
    sc_der_clear(&obj->der);

    /* try to find an old der if present */
    der = map_id_to_der_find(DRVDATA(card)->pukdf_card_ckaid_to_card_der_map, &pukey->id);
    if(der) {
      sc_der_copy(&obj->der, der);
    }

    path = map_path_to_path_find(DRVDATA(card)->virtual_fs_to_card_path_map, &pukey->path);
    if(path) {
      /* replace path data */
      memcpy(&pukey->path, path, sizeof(sc_path_t));
    }

    ckaid = map_opensc_id_to_id_find(DRVDATA(card)->virtual_fs_to_card_ckaid_map, &pukey->id);
    if(ckaid) {
      /* replace ckaid */
      memcpy(&pukey->id, ckaid, sizeof(struct sc_pkcs15_id));
    }
        /* add manual flags */
    pukey->native = 0x01;
    pukey->access_flags |= SC_PKCS15_PRKEY_ACCESS_LOCAL;
    pukey->access_flags |= SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE;
    pukey->key_reference = pukey->path.value[pukey->path.len-1];
  } else {
    sc_debug(card->ctx, "Pointer to pukey info was empty");
  }

  SC_FUNC_RETURN(card->ctx, 1, r);
}

int card_sync_virtual_fs_to_card_any_df( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs, int type )
{
  int r = SC_SUCCESS;
  sc_pkcs15_card_t *temp_pkcs15_card  = NULL;
  sc_pkcs15_object_t *obj = NULL;
  card_pkcs15_df_t p15_df;
  sc_pkcs15_df_t df;
  u8 *translated_buf = NULL;
  size_t translated_bufsize = 0;
  u8 *card_buf = NULL;
  size_t card_bufsize = 0;


  SC_FUNC_CALLED(card->ctx, 1);

  if(!card || !virtual_file)
    return SC_ERROR_INVALID_ARGUMENTS;

  /* init p15_df structure */
  memset(&p15_df, 0, sizeof(p15_df));
  p15_df.type = type;

  /* virtualfs keeps buffer ownership */
  p15_df.data = virtual_file->data;
  p15_df.data_len = virtual_file->data_size;
  p15_df.file_len = virtual_file->data_size;
  p15_df.filled_len = virtual_file->data_size;

  /* We parse PKCS#15 using a standard parser */
  r = card_parse_standard_pkcs15(card, &p15_df, &df, &temp_pkcs15_card);
  if(r != SC_SUCCESS) {
    if (card->ctx->debug) sc_debug(card->ctx, "Parsing of standard PKCS#15 failed\n");
    goto end;
  }

  /* we need to correct some PKCS#15 data */
  for(obj = temp_pkcs15_card->obj_list; obj != NULL; obj = obj->next) {
    switch(obj->type & SC_PKCS15_TYPE_CLASS_MASK) {
    case SC_PKCS15_TYPE_CERT:
      {
	r = card_sync_virtual_fs_to_card_filter_cert(card, virtual_file, virtual_fs, obj);
      }
      break;

    case SC_PKCS15_TYPE_PRKEY:
      {
	r = card_sync_virtual_fs_to_card_filter_prkey(card, virtual_file, virtual_fs, obj);
      }
      break;

    case SC_PKCS15_TYPE_PUBKEY:
      {
	r = card_sync_virtual_fs_to_card_filter_pukey(card, virtual_file, virtual_fs, obj);
      }
      break;
      
    default:
      /* ignore this object */
      break;
    }
  }
  if(r != SC_SUCCESS) {
    sc_error(card->ctx, "Object filtering failed\n");
    goto end;
  }

  /* We encode PKCS#15 using DNIe PKCS#15 */
  r = sc_pkcs15_card_encode_df(card->ctx,
                               temp_pkcs15_card,
                               &df,
                               &translated_buf,
                               &translated_bufsize);
 
  if(r != SC_SUCCESS) {
    sc_error(card->ctx, "DNIe PKCS#15 encoding failed\n"); 
    goto end;
  }

  card_bufsize = translated_bufsize+1;
  card_buf = (u8 *) malloc(card_bufsize);
  if(!card_buf) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto end;
  }
      
  memcpy(card_buf, translated_buf, translated_bufsize);
  card_buf[translated_bufsize] = 0x00;

  r = card_helper_update_file( card, &virtual_file->path, card_buf, card_bufsize);
  if(r != SC_SUCCESS) {
    sc_error(card->ctx, "DNIe PKCS#15 encoding failed\n"); 
    goto end;
  } 
 end:
  if(translated_buf) {
    memset(translated_buf, 0, translated_bufsize);
    free(translated_buf);
    translated_buf = NULL;
    translated_bufsize = 0;
  }

  if(card_buf) {
    memset(card_buf, 0, card_bufsize);
    free(card_buf);
    card_buf = NULL;
    card_bufsize = 0;
  }

  if(temp_pkcs15_card) { 
    /* set to NULL without freeing because we reused structure */
    temp_pkcs15_card->card = NULL;
    
    /* now free temp structure */
    sc_pkcs15_card_free(temp_pkcs15_card);
    temp_pkcs15_card = NULL;
  }  

  SC_FUNC_RETURN(card->ctx, 1, r);
}

int card_sync_virtual_fs_to_card_cdf_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs )
{
  /* use generic synchronization with CDF param */
  return card_sync_virtual_fs_to_card_any_df(card, virtual_file, virtual_fs, SC_PKCS15_CDF);
}

int card_sync_virtual_fs_to_card_prkdf_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs )
{
  /* use generic synchronization with PrKDF param */
  return card_sync_virtual_fs_to_card_any_df(card, virtual_file, virtual_fs, SC_PKCS15_PRKDF);
}

int card_sync_virtual_fs_to_card_pukdf_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs )
{
  /* use generic synchronization with PrKDF param */
  return card_sync_virtual_fs_to_card_any_df(card, virtual_file, virtual_fs, SC_PKCS15_PUKDF);
}

int card_sync_card_to_virtual_fs_certificate_file_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs )
{
  int r = SC_SUCCESS;
  unsigned char *card_data = NULL;
  unsigned char *uncompressed_data = NULL;
  size_t card_data_length = 0;
  size_t uncompressed_data_length = 0;
  sc_path_t *path=NULL;

  SC_FUNC_CALLED(card->ctx, 1);

  if(!card || !virtual_file)
    return SC_ERROR_INVALID_ARGUMENTS;

  path=NULL;
  path = map_path_to_path_find(DRVDATA(card)->virtual_fs_to_card_path_map, &virtual_file->path);
  if(!path) {
    r = SC_ERROR_OBJECT_NOT_FOUND;
    goto end;
  }

  /* get file */
  r = card_helper_read_certificate_file(card, path, &card_data, &card_data_length);
  if (r!=SC_SUCCESS)
    goto end;
  if (card_data_length>0) {     
    r = file_uncompress_data(card, card_data, card_data_length, &uncompressed_data, &uncompressed_data_length); 
    if(r < 0)
      goto end;
    
    r = virtual_file_data_update(virtual_file, 0, uncompressed_data, uncompressed_data_length);
    if(r != SC_SUCCESS)
      goto end;
  }
 end:
  if(card_data) {
    free(card_data);
    card_data = NULL;
  }

  if(uncompressed_data) {
    free(uncompressed_data);
    uncompressed_data = NULL;
  }
  SC_FUNC_RETURN(card->ctx, 1, r);
}


int card_sync_virtual_fs_to_card_certificate_file_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs )
{
  int r = SC_SUCCESS;
  unsigned char *compressed_data = NULL;
  size_t compressed_data_length = 0;
  struct _virtual_file_t *certificate_virtual_file=NULL;
  sc_pkcs15_id_t *card_ckaid=NULL;
  sc_path_t *cert_path=NULL;

  SC_FUNC_CALLED(card->ctx, 1);

  if(!card || !virtual_file)
    return SC_ERROR_INVALID_ARGUMENTS;
  
  r = file_compress_data(card, virtual_file->data, virtual_file->data_size, &compressed_data, &compressed_data_length); 
  if(r!=SC_SUCCESS)
    goto cert_vfs2c_end;

  /* create certificate file into card */
  r = card_helper_create_cert_file(card, virtual_file, compressed_data_length, &certificate_virtual_file);
  if(r!=SC_SUCCESS)
    goto cert_vfs2c_end;

  /* set file data to card */
  r = card_helper_update_file(card, &certificate_virtual_file->path, compressed_data, compressed_data_length);
  if(r!=SC_SUCCESS)
    goto cert_vfs2c_end;

  /* add path_to_path */
  r = map_path_to_path_set_item(DRVDATA(card)->virtual_fs_to_card_path_map, &virtual_file->path, &certificate_virtual_file->path);
  if(r != SC_SUCCESS)
    goto cert_vfs2c_end;

  /* get ckaid from certificate (computeing a sha1 form public key modulus) */
  card_ckaid = calloc(1, sizeof(struct sc_pkcs15_id));
  if (!card_ckaid) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto cert_vfs2c_end;
  }
  r = get_ckaid_from_certificate( card, virtual_file->data, virtual_file->data_size, card_ckaid );
  if(r!=SC_SUCCESS)
    goto cert_vfs2c_end;

  cert_path = calloc(1, sizeof(struct sc_path));
  if(!cert_path) {
    r = SC_ERROR_OUT_OF_MEMORY;
    goto cert_vfs2c_end;
  }
  memcpy(cert_path, &certificate_virtual_file->path, sizeof(struct sc_path));
  r = map_path_to_id_set_item(DRVDATA(card)->card_path_to_card_ckaid_map, cert_path, card_ckaid);
  if(r!=SC_SUCCESS)
    goto cert_vfs2c_end;

  /* ownership regards to vfs */
  certificate_virtual_file=NULL;
  card_ckaid=NULL;
  cert_path=NULL;
    
 cert_vfs2c_end:
  if(compressed_data) {
    free(compressed_data);
    compressed_data = NULL;
  }
  if(certificate_virtual_file) {
    free(certificate_virtual_file);
    certificate_virtual_file=NULL;
  }
  if(card_ckaid) {
    free(card_ckaid);
    card_ckaid=NULL;
  }
  if(cert_path) {
    free(cert_path);
    cert_path=NULL;
  }
  SC_FUNC_RETURN(card->ctx, 1, r);
}

int card_sync_card_to_virtual_fs_data_file_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs )
{
  int r = SC_SUCCESS;
  unsigned char *card_data = NULL;
  size_t card_data_length = 0;
  sc_path_t *path=NULL;

  SC_FUNC_CALLED(card->ctx, 1);

  if(!card || !virtual_file)
    return SC_ERROR_INVALID_ARGUMENTS;

  path = map_path_to_path_find(DRVDATA(card)->virtual_fs_to_card_path_map, &virtual_file->path);
  if(!path) {
    r = SC_ERROR_OBJECT_NOT_FOUND;
    goto end;
  }

  /* get file */
  r = card_helper_read_file(card, path, &card_data, &card_data_length);
  if (r!=SC_SUCCESS)
    goto end;
  if (card_data_length>0) {
    r = virtual_file_data_update(virtual_file, 0, card_data, card_data_length);
    if(r != SC_SUCCESS)
      goto end;
  }
 end:
  if(card_data) {
    free(card_data);
    card_data = NULL;
  }

  SC_FUNC_RETURN(card->ctx, 1, r);
}
