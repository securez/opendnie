/*!
 * \file map_helper.h
 * \brief Map helpers
 *
 * Copyright (C) 2006-2010 Dirección General de la Policía y de la Guardia Civil
 *
 */

#ifndef MAP_HELPER_H
#define MAP_HELPER_H


#include "map.h"
#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"



typedef void * copy_constructor( const void * );

typedef map_t map_two_t;


/*!
  Creates a new map of 2 items (index, mapped)

  \param index_free free operation on index
  \param index_is_equal is_equal operation on index
  \param mapped_free free operation on mapped
  \param mapped_is_equal is_equal operation on mapped
 */
map_two_t * map_two_new( column_operation_free *index_free,
			 column_operation_is_equal *index_is_equal,
			 column_operation_free *mapped_free,
			 column_operation_is_equal *mapped_is_equal);


/*!
  Finds mapped using index

  \param map The map object
  \param index The index
 */
void * map_two_find_mapped( map_two_t *map, const void *index );

/*!
  Append new item to map.

  \param map The map object
  \param index index object... transfers ownership
  \param mapped_path mapped path of item
  
  \returns SC_SUCCESS on success, error code otherwise
*/
int map_two_set_item( map_two_t *map, const void *index, copy_constructor *index_copy_constructor, const void *mapped, copy_constructor *mapped_copy_constructor );




typedef map_t map_path_to_path_t;

/*!
  Creates a new sc_path_t to sc_path_t map.
  
  \returns pointer to newly allocated structure and initialized.
*/
map_path_to_path_t * map_path_to_path_new();

/*!
  Append new path to map.

  \param map The map object
  \param index_path path to index item
  \param mapped_path mapped path of item
  
  \returns SC_SUCCESS on success, error code otherwise
*/
int map_path_to_path_set_item( map_path_to_path_t *map, const sc_path_t *index_path, const sc_path_t *mapped_path );

/*!
  Finds mapped path and returns it.

  Note that map still holds ownership of the object. Returned data can be changed.

  \param map The map object
  \param path Path used to index

  \returns Pointer to first object found, NULL if not.
*/
sc_path_t * map_path_to_path_find( map_path_to_path_t *map, const sc_path_t *path );

/*!
  Append public and private key paths by opensc by key reference

  \param map The map object
  \param index_path path to index item
  \param mapped_path mapped path of item
  
  \returns SC_SUCCESS on success, error code otherwise
*/
int map_path_to_path_set_all_keys_paths( map_path_to_path_t *map, int opensc_key_reference, int card_key_reference, int is_st );



typedef map_t map_id_to_id_t;

/*!
  Creates a new sc_pkcs15_id_t to sc_pkcs15_id_t map
  
  \returns pointer to newly allocated structure and initialized.
*/
map_id_to_id_t * map_id_to_id_new();

/*!
  Append new id to map.

  \param map The map object
  \param index_id path to index item
  \param mapped_id mapped path of item
  
  \returns SC_SUCCESS on success, error code otherwise
*/
int map_id_to_id_set_item( map_path_to_path_t *map, const sc_pkcs15_id_t *index_id, const sc_pkcs15_id_t *mapped_id );

typedef map_t map_id_to_der_t;

/*!
  Creates a new sc_pkcs15_id_t to sc_pkcs15_der_t map
  
  \returns pointer to newly allocated structure and initialized.
*/
map_id_to_der_t * map_id_to_der_new();

/*!
  Append new id-der to map.

  \param map The map object
  \param id id of the item
  \param der der of the item
  
  \returns SC_SUCCESS on success, error code otherwise
*/
int map_id_to_der_set_item( map_id_to_der_t *map, const sc_pkcs15_id_t *id, const sc_pkcs15_der_t *der );

/*!
  Finds mapped der and returns it.

  Note that map still holds ownership of the object. Returned data can be changed.

  \param map The map object
  \param id id used to index

  \returns Pointer to first object found, NULL if not.
*/
sc_pkcs15_der_t * map_id_to_der_find( map_path_to_path_t *map, const sc_pkcs15_id_t *id );

typedef map_t map_opensc_id_to_id_t;

/*!
  Finds mapped id and returns it.

  Note that map still holds ownership of the object. Returned data can be changed.

  \param map The map object
  \param id id used to index

  \returns Pointer to first object found, NULL if not.
*/
sc_pkcs15_id_t * map_opensc_id_to_id_find( map_opensc_id_to_id_t *map, const sc_pkcs15_id_t *id );

typedef map_t map_path_to_id_t;

/*!
  Creates a new sc_path_t to sc_pkcs15_id_t map
  
  \returns pointer to newly allocated structure and initialized.
*/
map_path_to_id_t * map_path_to_id_new();

/*!
  Append new path-id to map.

  \param map The map object
  \param path path of the item
  \param id id of the item
  
  \returns SC_SUCCESS on success, error code otherwise
*/
int map_path_to_id_set_item( map_path_to_id_t *map, const sc_path_t *path, const sc_pkcs15_id_t *id );

/*!
  Finds mapped path and returns mapped id.

  Note that map still holds ownership of the object. Returned data can be changed.

  \param map The map object
  \param path path used to index

  \returns Pointer to first object found, NULL if not.
*/
sc_pkcs15_id_t * map_path_to_id_find( map_path_to_id_t *map, const sc_path_t *path );

/* 
   Helper copy constructors
*/

#define BINARY_COPY_CONSTRUCTOR(result,original,size)	\
  if(original) {					\
    (result) = malloc(size);				\
    if(result) {					\
      memcpy(result, original, size);			\
    }							\
  } else {						\
    (result) = NULL;					\
  }

/*!
  Path copy constructor
*/
sc_path_t *path_copy_constructor( const sc_path_t *path );

/*!
  id copy constructor
*/
sc_pkcs15_id_t *id_copy_constructor( const sc_pkcs15_id_t *id );

/*!
  Der copy constructor
*/
sc_pkcs15_der_t *der_copy_constructor( const sc_pkcs15_der_t *der );


/*!
  Free structures
*/
void sc_der_free( sc_pkcs15_der_t *der );



#endif /* MAP_HELPER_H */
