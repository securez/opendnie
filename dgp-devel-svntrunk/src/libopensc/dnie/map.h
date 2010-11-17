/*!
 * \file map.h
 * \brief A map data type
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

#ifndef MAP_H
#define MAP_H

/*! frees object... If object can't be freed just set to null */
typedef void column_operation_free(void *);

/*! operation that tests for equality two objects */
typedef int column_operation_is_equal(const void *, const void *);


/*!
  Operations on each item column
*/
typedef struct _column_operations_t {
  void (*free)(void *); /*!< frees object... If object can't be freed just set to null */
  int (*is_equal)(const void *, const void *); /*< operation that tests for equality two objects */
} column_operations_t;

/*!
  This is an item
*/
typedef struct _map_item_t {
  void **data; /*! Array of num_columns elements which hold data */
  struct _map_item_t *next; /*! Pointer to next item */
} map_item_t;

/*!
  This is a map type
*/
typedef struct _map_t {
  map_item_t *first; /*!< Pointer to first element in map */
  column_operations_t *column_operations; /*!< pointer to array of column_operations_t. There are num_columns elements in this array */
  int num_columns; /*!< number of columns */
} map_t;

/*!
  Creates a new map_item.
  
  \param num_columns Number of columns in this map
  \param item_data num_columns array of void * holding each column of a data item
  
  \returns pointer to newly allocated structure and initialized.
*/
map_item_t * map_item_new( int num_columns, void **item_data );

/*!
  Frees a map_item. It freed all objects it holds if column_operations_t.free operation
  is defined.

  It doesn't free linked (in next) map_item. But it returns it in next_map_item.
  
  \param map_item The map_item to be freed.
  \param num_columns Number of columns in this map
  \param column_operations Operations to free each column. It uses free function. If NULL it doesn't free anything.
  \param next_map_item Returns linked next map item.
*/
void map_item_free( map_item_t *map_item, int num_columns, const column_operations_t *column_operations, map_item_t **next_map_item );


/*!
  Creates a new map.
  
  \param num_columns Number of columns in this map
  \param column_operations num_columns long array of operations for each column.
  
  \returns pointer to newly allocated structure and initialized.
*/
map_t * map_new( int num_columns, const column_operations_t *column_operations );

/*!
  Frees a map. It freed all objects it holds if column_operations_t.free operation
  is defined.
  
  \param map The map to be freed.
*/
void map_free( map_t *map );


/*!
  Append object to map.

  \param map The map object
  \param item_data num_columns array of void * holding each column of a data item
  
  \returns SC_SUCCESS on success, error code otherwise
*/
int map_append_item( map_t *map, void **item_data );

/*!
  Finds object and returns it.

  Note that map still holds ownership of the object. Returned data can be changed.

  \param map The map object
  \param column_data column data to compare to using is_equal operation
  \param index_column 0-based column number we are using as index

  \returns Pointer to first object found, NULL if not.
*/
void ** map_find_by_column_data( map_t *map, const void *column_data, int index_column );

#endif /* MAP_H */
