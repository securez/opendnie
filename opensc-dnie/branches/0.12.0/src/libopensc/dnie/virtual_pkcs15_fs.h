/*!
 * \file virtual_pkcs15_fs.h
 * \brief Card virtual PKCS#15 filesystem
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

#ifndef VIRTUAL_PKCS15_FS_H
#define VIRTUAL_PKCS15_FS_H


/* include for all virtual_* definitions */
#include "virtual_fs.h"


/*!
  Creates all files needed in PKCS#15 operation
  
  \param virtual_fs Virtual filesystem where the files will be created.

  \returns SC_SUCCESS on succes, error code otherwise
*/
int virtual_pkcs15_fs_init( virtual_fs_t *virtual_fs );


#endif /* VIRTUAL_PKCS15_FS_H */

