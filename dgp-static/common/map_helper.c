/*!
 * \file map.c
 * \brief A map data type
 *
 * Copyright (C) 2006-2010 Dirección General de la Policía y de la Guardia Civil
 *
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
*/

#include "map_helper.h"
#include <opensc/opensc.h>
#include <opensc/pkcs15.h>
#include <stdlib.h>
#include <string.h>


map_two_t * map_two_new( column_operation_free *index_free,
			 column_operation_is_equal *index_is_equal,
			 column_operation_free *mapped_free,
			 column_operation_is_equal *mapped_is_equal)
{
  column_operations_t column_operations[2];

  column_operations[0].free = index_free;
  column_operations[0].is_equal = index_is_equal;
  column_operations[1].free = mapped_free;
  column_operations[1].is_equal = mapped_is_equal;

  return map_new(2, column_operations);
}

void * map_two_find_mapped( map_two_t *map, const void *index )
{
  void **map_item = NULL;

  map_item = map_find_by_column_data(map, index, 0);
  if(map_item && map_item[1]) {
    return map_item[1];
  }
  return NULL;
}

int map_two_set_item( map_two_t *map, const void *index, copy_constructor *index_copy_constructor, const void *mapped, copy_constructor *mapped_copy_constructor )
{
  int r = SC_SUCCESS;
  void **map_item = NULL;
  void *map_item_array[2] = {NULL, NULL};
  void *temp_mapped = NULL;
  void *temp = NULL;

  if(mapped_copy_constructor) {
    temp_mapped = mapped_copy_constructor(mapped);
  } else {
    temp_mapped = (void *)mapped;
  }

  map_item = map_find_by_column_data(map, index, 0);
  if(map_item) {
    /* replace mapped */
    /* modifying map_item is modifying object */
    temp = map_item[1];
    map_item[1] = temp_mapped;
    
    /* we leave old data in temp_mapped_path so that it gets freed */
    temp_mapped = temp;
    temp = NULL;
  } else {
    /* we introduce a new item */
    if(index_copy_constructor) {
      temp = index_copy_constructor(index);
    } else {
      temp = (void *)index;
    }

    map_item_array[0] = temp;
    map_item_array[1] = temp_mapped;
    r = map_append_item(map, map_item_array);
    if(r != SC_SUCCESS)
      goto end;

    /* avoid data being freed.. we transfered ownership to map */
    temp = NULL;
    temp_mapped = NULL;
  }

 end:
  if(temp_mapped && map->column_operations && map->column_operations[1].free) {
    map->column_operations[1].free(temp_mapped);
    temp_mapped = NULL;
  }
  
  if(temp && map->column_operations && map->column_operations[0].free) {
    map->column_operations[0].free(temp);
    temp_mapped = NULL;
  }

  return r;
}




map_path_to_path_t * map_path_to_path_new()
{
  return map_two_new(free,
		     (int(*)(const void *, const void *))sc_compare_path,
		     free,
		     (int(*)(const void *, const void *))sc_compare_path);
}

int map_path_to_path_set_item( map_path_to_path_t *map, const sc_path_t *index_path, const sc_path_t *mapped_path )
{
  return map_two_set_item(map, index_path, (copy_constructor *)path_copy_constructor, mapped_path, (copy_constructor *)path_copy_constructor);
}

sc_path_t * map_path_to_path_find( map_path_to_path_t *map, const sc_path_t *path )
{
  return map_two_find_mapped(map, path);
}


int map_path_to_path_set_all_keys_paths( map_path_to_path_t *map, int opensc_key_reference, int card_key_reference, int is_st )
{
  int r = SC_SUCCESS;
  sc_path_t opensc_path;
  sc_path_t card_path;
  
  /* clear path */
  memset(&opensc_path, 0, sizeof(opensc_path));
  opensc_path.type = SC_PATH_TYPE_PATH;

  memset(&card_path, 0, sizeof(card_path));
  card_path.type = SC_PATH_TYPE_PATH;

  
  /*
    Store card paths

    card paths:
    * INFINEON:
     - 3F11//3F77 (Prk)
     - 3F11//3F78 (Pbk)
    
    * ST:
     - 3F11//01id (Prk & Pbk)
  */
  if(is_st) {
    /* card path */
    memcpy(&card_path.value, "\x3f\x00\x3f\x11\x01", 5);
    card_path.value[5] = card_key_reference;
    card_path.len = 6;

    /* private key */
    memcpy(&opensc_path.value, "\x3f\x00\x50\x15\x20", 5);
    opensc_path.value[5] = opensc_key_reference;
    opensc_path.len = 6;
    r = map_path_to_path_set_item(map, &opensc_path, &card_path);
    if(r != SC_SUCCESS)
      goto end;

    /* second private key version */
    memcpy(&opensc_path.value, "\x3f\x00\x20", 3);
    opensc_path.value[3] = opensc_key_reference;
    opensc_path.len = 4;
    r = map_path_to_path_set_item(map, &opensc_path, &card_path);
    if(r != SC_SUCCESS)
      goto end;

    /* public key */
    memcpy(&opensc_path.value, "\x3f\x00\x50\x15\x21", 5);
    opensc_path.value[5] = opensc_key_reference;
    opensc_path.len = 6;
    r = map_path_to_path_set_item(map, &opensc_path, &card_path);
    if(r != SC_SUCCESS)
      goto end;

    /* second public key version */
    memcpy(&opensc_path.value, "\x3f\x00\x21", 3);
    opensc_path.value[3] = opensc_key_reference;
    opensc_path.len = 4;
    r = map_path_to_path_set_item(map, &opensc_path, &card_path);
    if(r != SC_SUCCESS)
      goto end;
  } else {
    /* private key card path */
    memcpy(&card_path.value, "\x3f\x00\x3f\x11\x3f\x77", 6);
    card_path.len = 6;

    /* private key */
    memcpy(&opensc_path.value, "\x3f\x00\x50\x15\x20", 5);
    opensc_path.value[5] = opensc_key_reference;
    opensc_path.len = 6;
    r = map_path_to_path_set_item(map, &opensc_path, &card_path);
    if(r != SC_SUCCESS)
      goto end;

    /* second private key version */
    memcpy(&opensc_path.value, "\x3f\x00\x20", 3);
    opensc_path.value[3] = opensc_key_reference;
    opensc_path.len = 4;
    r = map_path_to_path_set_item(map, &opensc_path, &card_path);
    if(r != SC_SUCCESS)
      goto end;

    /* public key card path */
    memcpy(&card_path.value, "\x3f\x00\x3f\x11\x3f\x78", 6);
    card_path.len = 6;

    /* public key */
    memcpy(&opensc_path.value, "\x3f\x00\x50\x15\x21", 5);
    opensc_path.value[5] = opensc_key_reference;
    opensc_path.len = 6;
    r = map_path_to_path_set_item(map, &opensc_path, &card_path);
    if(r != SC_SUCCESS)
      goto end;

    /* second public key version */
    memcpy(&opensc_path.value, "\x3f\x00\x21", 3);
    opensc_path.value[3] = opensc_key_reference;
    opensc_path.len = 4;
    r = map_path_to_path_set_item(map, &opensc_path, &card_path);
    if(r != SC_SUCCESS)
      goto end;
  }

 end:
  return r;
}

map_id_to_id_t * map_id_to_id_new()
{
  return map_two_new(free,
		     (int(*)(const void *, const void *))sc_pkcs15_compare_id,
		     free,
		     (int(*)(const void *, const void *))sc_pkcs15_compare_id);
}

/*!
  Append new id to map.

  \param map The map object
  \param index_id path to index item
  \param mapped_id mapped path of item
  
  \returns SC_SUCCESS on success, error code otherwise
*/
int map_id_to_id_set_item( map_path_to_path_t *map, const sc_pkcs15_id_t *index_id, const sc_pkcs15_id_t *mapped_id )
{
  return map_two_set_item(map, index_id, (copy_constructor *)id_copy_constructor, mapped_id, (copy_constructor *)id_copy_constructor);
}

map_path_to_id_t * map_path_to_id_new()
{
  return map_two_new(free,
		     (int(*)(const void *, const void *))sc_compare_path,
		     free,
		     (int(*)(const void *, const void *))sc_pkcs15_compare_id);
}

int map_path_to_id_set_item( map_path_to_id_t *map, const sc_path_t *path, const sc_pkcs15_id_t *id )
{
  return map_two_set_item(map, path, (copy_constructor *)path_copy_constructor, id, (copy_constructor *)id_copy_constructor);
}

sc_pkcs15_id_t * map_path_to_id_find( map_path_to_id_t *map, const sc_path_t *path )
{
  return map_two_find_mapped(map, path);
}

map_id_to_der_t * map_id_to_der_new()
{
  return map_two_new(free,
		     (int(*)(const void *, const void *))sc_pkcs15_compare_id,
		     (void(*)(void *))sc_der_free, /* sc_pkcs15_der_t */
		     NULL /* can't find by der */);
}

int map_id_to_der_set_item( map_id_to_der_t *map, const sc_pkcs15_id_t *id, const sc_pkcs15_der_t *der )
{
  return map_two_set_item(map, id, (copy_constructor *)id_copy_constructor, der, (copy_constructor *)der_copy_constructor);
}

sc_pkcs15_der_t * map_id_to_der_find( map_path_to_path_t *map, const sc_pkcs15_id_t *id )
{
  return map_two_find_mapped(map, id);
}

sc_pkcs15_id_t * map_opensc_id_to_id_find( map_opensc_id_to_id_t *map, const sc_pkcs15_id_t *id )
{
  return map_two_find_mapped(map, id);
}

sc_path_t *path_copy_constructor( const sc_path_t *path )
{
  sc_path_t *result = NULL;
  BINARY_COPY_CONSTRUCTOR(result,path,sizeof(sc_path_t));
  return result;
}

sc_pkcs15_id_t *id_copy_constructor( const sc_pkcs15_id_t *id )
{
  sc_pkcs15_id_t *result = NULL;
  BINARY_COPY_CONSTRUCTOR(result,id,sizeof(sc_pkcs15_id_t));
  return result;
}

sc_pkcs15_der_t *der_copy_constructor( const sc_pkcs15_der_t *der )
{
  sc_pkcs15_der_t *result = NULL;

  if(!der)
    return NULL;

  result = calloc(1, sizeof(sc_pkcs15_der_t));
  if(!result)
    return NULL;

  sc_der_copy(result, der);
  return result;
}

void sc_der_free(sc_pkcs15_der_t *der)
{
  if(der) {
    sc_der_clear(der);
    free(der);
  }
}
