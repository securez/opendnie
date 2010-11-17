/*!
 * \file file_compression.h
 * \brief File compression functions
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

#ifndef FILE_COMPRESSION_H
#define FILE_COMPRESSION_H

#include "libopensc/opensc.h"

int file_uncompress_data(struct sc_card *card, u8 * data, size_t length, u8 **uncompressed_data, size_t *uncompressed_data_length );

int file_compress_data(struct sc_card *card, 
		       u8 * uncompressed_data, size_t uncompressed_data_length, 
		       u8 **compressed_data, size_t *compressed_data_length );

#endif /* FILE_COMPRESSION_H */

