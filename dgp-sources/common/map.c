/*!
 * \file map.c
 * \brief A map data type
 *
 * Copyright (C) 2006-2010 Dirección General de la Policía y de la Guardia Civil
 * oficinatecnica@dnielectronico.es
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

#include "map.h"
#include <opensc/opensc.h>
#include <stdlib.h>
#include <string.h>

map_item_t * map_item_new( int num_columns, void **item_data )
{
  map_item_t *map_item = NULL;
  void **data = NULL;

  if(!num_columns || !item_data)
    return NULL;

  data = malloc(sizeof(void *) * num_columns);
  if(!data)
    goto end;

  memcpy(data, item_data, sizeof(void *) * num_columns);

  map_item = calloc(1, sizeof(map_item_t));
  if(!map_item)
    goto end;
  
  /* transfer ownership of allocated data */
  map_item->data = data;
  data = NULL;
 
 end:
  if(data) {
    free(data);
    data = NULL;
  }

  return map_item;
}

void map_item_free( map_item_t *map_item, int num_columns, const column_operations_t *column_operations, map_item_t **next_map_item )
{
  int ii;

  if(next_map_item)
    *next_map_item = NULL;

  if(!map_item)
    return;

  if(map_item->data) {
    for(ii=0; ii<num_columns; ii++) {
      if(map_item->data[ii] && column_operations && column_operations[ii].free) {
	/* we have data and a pointer to a function to free it! */
	column_operations[ii].free(map_item->data[ii]);
	map_item->data[ii] = NULL;
      }
    }
    
    /* free data array */
    free(map_item->data);
    map_item->data = NULL;
  }

  *next_map_item = map_item->next;

  free(map_item);
  map_item = NULL;
}

map_t * map_new( int num_columns, const column_operations_t *column_operations )
{
  map_t *map = NULL;
  column_operations_t *map_column_operations;

  if(!num_columns || !column_operations)
    return NULL;

  map_column_operations = malloc(sizeof(column_operations_t) * num_columns);
  if(!map_column_operations)
    return NULL;

  memcpy(map_column_operations, column_operations, sizeof(column_operations_t) * num_columns);
  
  map = calloc(1, sizeof(map_t));
  if(!map)
    goto end;
  
  /* transfer ownership of allocated map_column_operations */
  map->column_operations = map_column_operations;
  map_column_operations = NULL;

  map->num_columns = num_columns;
  
 end:
  if(map_column_operations) {
    free(map_column_operations);
    map_column_operations = NULL;
  }
  
  return map;
}

void map_free( map_t *map )
{
  map_item_t *map_item = NULL;

  if(!map)
    return;

  /* free all map_items */
  for(map_item = map->first;
      map_item;
      map_item_free(map_item, map->num_columns, map->column_operations, &map_item)
      );

  map->first = NULL;

  /* free operations */
  if(map->column_operations) {
    free(map->column_operations);
    map->column_operations = NULL;
  }

  free(map);
}

int map_append_item( map_t *map, void **item_data )
{
  map_item_t *map_item = NULL;

  if(!map || !item_data)
    return SC_ERROR_INVALID_ARGUMENTS;

  map_item = map_item_new(map->num_columns, item_data);
  if(!map_item)
    return SC_ERROR_OUT_OF_MEMORY;

  map_item->next = map->first;
  map->first = map_item;

  return SC_SUCCESS;
}

void ** map_find_by_column_data( map_t *map, const void *column_data, int index_column )
{
  map_item_t *map_item = NULL;

  if(!map || index_column<0 || index_column>=map->num_columns)
    return NULL;

  for(map_item = map->first; map_item; map_item = map_item->next) {
    if(map_item->data) {
      if(map->column_operations && map->column_operations[index_column].is_equal) {
	if(map->column_operations[index_column].is_equal(map_item->data[index_column], column_data)) {
	  /* we found it! */
	  return map_item->data;
	}
      }
    }
  }
  
  /* we didn't find it! */
  return NULL;
}

