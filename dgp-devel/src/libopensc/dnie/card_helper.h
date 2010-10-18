/*!
 * \file card_helper.h
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

#ifndef CARD_HELPER_H
#define CARD_HELPER_H


#include "libopensc/opensc.h"
#include "virtual_fs.h"

/*!
  Selects path and reads a file. It returns an allocated
  buffer (which must be freed by the user) with the data.
  
  \param card Struct to access the card
  \param path Path to the file to be read.
  \param buffer Output buffer with data allocated using malloc
  \param length Output length of data

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_helper_read_file(sc_card_t *card, const sc_path_t *path, u8 **buffer, size_t *length); 

/*!
  Selects path and updates new data to file. 
  
  \param[in] card Struct to access the card
  \param[in] path Path to the file to be updated.
  \param[in] buffer Buffer with data
  \param[in] length Length of data buffer

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_helper_update_file(sc_card_t *card, const sc_path_t *path, u8 *buffer, size_t length); 

/*!
  Creates a certificate file to card and also a new certificate file
  into virtual fs. This last file is returned as a parameter.
  
  \param[in] card Struct to access the card
  \param[in] virtual_file File containing certificate data but with an OpenSC path
  \param[in] fcert_len Length of certificate file
  \param[out] certificate_virtual_file New certificate file created into virtual fs

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_helper_create_cert_file(sc_card_t *card, struct _virtual_file_t *virtual_file, 
				 size_t fcert_len, struct _virtual_file_t **certificate_virtual_file);

/*!
  Selects path and reads a certificate file checking header compressed information.
  It returns an allocated buffer (which must be freed by the user) with the data.
  
  \param card Struct to access the card
  \param path Path to the file to be read.
  \param buffer Output buffer with data allocated using malloc
  \param length Output length of data

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_helper_read_certificate_file(sc_card_t *card, const sc_path_t *path, u8 **buffer, size_t *length);

#endif /* CARD_HELPER_H */
	    
