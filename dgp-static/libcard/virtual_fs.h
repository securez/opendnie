/*!
 * \file virtual_fs.h
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

#ifndef VIRTUAL_FS_H
#define VIRTUAL_FS_H


/* include for sc_card_t and sc_path_t definitions */
#include <opensc/opensc.h>

/*!
  Kind of synchronization for the file.
*/
typedef enum _virtual_file_sync_type_t {
  virtual_file_sync_type_card_to_virtual_fs = 0,   /*!< this file will be synchronized from the card to the virtual fs */
  virtual_file_sync_type_virtual_fs_to_card    /*!< this file will be synchronized from the virtual fs to the card */
} virtual_file_sync_type_t;



/*!
  File synchronization state
*/
typedef enum _virtual_file_sync_state_t {
  virtual_file_sync_state_unknown = 0,    /*!< unknown synchronization state (also possible if file doesn't admit synchronization) */
  virtual_file_sync_state_synced,         /*!< file is in sync */
  virtual_file_sync_state_sync_pending    /*!< file synchronization pending */
} virtual_file_sync_state_t;

/*
  Forward declaration of struct _virtual_file_t because
  we need it in virtual_file_sync_callback.
*/
struct _virtual_file_t;
  
/*
  Forward declaration of struct _virtual_fs_t because
  we need it in virtual_file_sync_callback.
*/
struct _virtual_fs_t;

/*!
  Synchronization callback
*/
typedef int virtual_file_sync_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, struct _virtual_fs_t *virtual_fs );

/*!
  This structure holds synchronization info in one direction
*/
typedef struct _virtual_file_sync_t
{
  virtual_file_sync_state_t sync_state;      /*!< synchronization state */
  virtual_file_sync_callback *sync_callback; /*!< synchronization callback */
} virtual_file_sync_t;

/*!
  This structure holds a virtual file.
*/
typedef struct _virtual_file_t {
  sc_path_t path;      /*!< Absolute path of the file */
  unsigned char *data; /*!< Data of the file */
  int data_size;       /*!< Size of the data in the file */
  int is_ef;           /*!< 1 if file is an ef, 0 if a df */

  /* synchronization fields */
  virtual_file_sync_t card_to_virtual_fs; /*!< card to virtual_fs (read) synchronization */
  virtual_file_sync_t virtual_fs_to_card; /*!< virtual_fs to card (write) synchronization */
} virtual_file_t;

/*!
  Single-linked list of virtual_file
 */
typedef struct _virtual_file_list_item_t {
  virtual_file_t *virtual_file;              /*!< virtual_file pointer (data) */
  struct _virtual_file_list_item_t *next;    /*!< pointer to next item in list */
} virtual_file_list_item_t;

/*!
  Virtual filesystem
*/
typedef struct _virtual_fs_t {
  virtual_file_list_item_t *list;            /*!< list of virtual_file */
} virtual_fs_t;


/*!
  Returns a new virtual_file_t structure

  \returns pointer to newly allocated (and zeroed) structure.
 */
virtual_file_t * virtual_file_new();

/*!
  Frees structure and members.
  
  \param virtual_file pointer to the structure to be freed.
*/
void virtual_file_free( virtual_file_t *virtual_file );

/*!
  Update data in file. It handles automatic reallocation of internal
  buffer if running out of space.

  \param virtual_file virtual_file
  \param offset offset in virtual_file data buffer where to copy data
  \param data data buffer to copy
  \param data_length length of data to copy

  \returns SC_SUCCESS on success, error code otherwise
 */
int virtual_file_data_update( virtual_file_t *virtual_file, int offset, const unsigned char *data, int data_length );

/*!
  Read data from virtual file. 

  \param virtual_file virtual_file
  \param offset offset in virtual_file data buffer where to copy data from
  \param data data buffer to copy
  \param data_length length of data to copy

  \returns SC_SUCCESS on succes, error code otherwise
 */
int virtual_file_data_read( virtual_file_t *virtual_file, int offset, unsigned char *data, int data_length );

/*!
  Create a data buffer with specified number of zeroes

  \param virtual_file virtual_file
  \param data_size length of newly allocated buffer
*/
int virtual_file_data_zero( virtual_file_t *virtual_file, int data_size );
 
/*!
  Synchronize data in file if needed. This function checks if
  synchronization is needed and calls function to perform it.

  Synchronization might need inclusion of new files into
  virtual_fs as a side effect (for instance: new certificate data
  files).

  \param virtual_file virtual_file
  \param card sc_card_t pointer that will be passed to synchronization function.
  \param sync_type sync type we need... the function will only synchronizate if the virtual_file has the same sync_type
  \param virtual_fs virtual_fs pointer where to add new virtual_file objects if needed

  \returns SC_SUCCESS on succes, error code otherwise
 */
int virtual_file_data_synchronize( virtual_file_t *virtual_file, sc_card_t *card, virtual_file_sync_type_t sync_type, virtual_fs_t *virtual_fs );

/*!
  Create a sc_file_t structure from a virtual_file
  
  \param virtual_file a virtual file structure
  \param file output struct where to generate file data
 */
int virtual_file_export_file( virtual_file_t *virtual_file, sc_file_t *file );

/*!
  Returns a new virtual_file_list_item_t structure

  \returns pointer to newly allocated (and zeroed) structure.
*/
virtual_file_list_item_t * virtual_file_list_item_new();

/*!
  Frees structure and members.
  
  \param virtual_file_list_item pointer to the structure to be freed.
*/
void virtual_file_list_item_free( virtual_file_list_item_t *virtual_file_list_item );

/*!
  Creates a new virtual filesystem

  \returns pointer to newly allocated (and zeroed) structure.
*/
virtual_fs_t * virtual_fs_new();

/*!
  Frees structure and members.
  
  \param virtual_fs pointer to the structure to be freed.
*/
void virtual_fs_free( virtual_fs_t *virtual_fs );

/*!
  Appends virtual_file to virtual_fs and transfers ownership
  of the virtual_file system structure to the virtual_fs.

  virtual_fs will deallocate memory on its destruction in
  virtual_fs_free(), so virtual_file must be created on the
  heap using a call to virtual_file_new().
  
  This operation is a O(1) since we append from the beginning
  in a single-linked list.

  \param virtual_fs virtual_fs where virtual_file will be appended.
  \param virtual_file virtual_file_t pointer to append.

  \returns SC_SUCCESS on succes, error code otherwise
*/
int virtual_fs_append( virtual_fs_t *virtual_fs, virtual_file_t *virtual_file );


/*!
  Finds a file using a path and returns a pointer to the virtual_file.

  This is a O(n) operation since virtual_fs uses a single-linked list
  internally.
  
  Note: Ownership of virtual_file still belongs to virtual_fs. Users
  can't free the object.
  
  \param virtual_fs filesystem
  \param path path to search in virtual_file

  \returns pointer to the virtual_file if found, NULL otherwise.
*/
virtual_file_t * virtual_fs_find_by_path( virtual_fs_t *virtual_fs, const sc_path_t *path );


/*!
  Finds a ef file using a path and returns its data (allocating memory).

  It uses virtual_fs_find_by_path() to find file
  
  \param virtual_fs filesystem
  \param path path to search in virtual_file
  \param buffer Pointer to a malloced memory with the data. User is responsible of freeing it.
  \param length Output length of buffer data.

  \returns pointer to the virtual_file if found, NULL otherwise.
*/
int virtual_fs_get_data_by_path( virtual_fs_t *virtual_fs, const sc_path_t *path, u8 **buffer, int *length );

/*!
  Helper routine that creates a new virtual file, fills it and appends it to
  the virtual_fs.

  \param path Absolute path of the file. Can't be NULL.
  \param data Initial data of the file.
  \param data_length Length of data
  \param file_size Size of the file. If it doesn't match data_size it fills the file with zeroes till it reaches file_size
  \param is_ef 1 if file is ef, 0 if df.
  \param sync_type type of synchronization
  \param sync_state state of synchronization
  \param sync_callback callback to synchronize file

  \returns SC_SUCCESS on succes, error code otherwise
*/
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
					);



#endif /* VIRTUAL_FS_H */

