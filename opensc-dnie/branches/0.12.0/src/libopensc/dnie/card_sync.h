/*!
 * \file card_sync.h
 * \brief Card synchronization functions
 *
 * Copyright (C) 2006-2010 Dirección General de la Policía y de la Guardía Civil
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

#ifndef CARD_SYNC_H
#define CARD_SYNC_H

/* include for all virtual_* definitions */
#include "virtual_fs.h"
#include "libopensc/pkcs15.h"

/*!
  Function to filter object fields from certificate PKCS#15
  objects called when loading objects from the card

  It also loads certificates from the card and adds it to
  the virtual_fs
  
  \param card Struct to access the card
  \param virtual_file this is CDF virtual file
  \param virtual_fs Virtual fs pointer.
  \param obj PKCS#15 object

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_card_to_virtual_fs_filter_cert( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs, sc_pkcs15_object_t *obj );

/*!
  Function to filter object fields from prkey PKCS#15
  objects called when loading objects from the card

  \param card Struct to access the card
  \param virtual_file this is PrKDF virtual file
  \param virtual_fs Virtual fs pointer.
  \param obj PKCS#15 object

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_card_to_virtual_fs_filter_prkey( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs, sc_pkcs15_object_t *obj );

/*!
  Function to filter object fields from pukey PKCS#15
  objects called when loading objects from the card

  \param card Struct to access the card
  \param virtual_file this is PuKDF virtual file
  \param virtual_fs Virtual fs pointer.
  \param obj PKCS#15 object

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_card_to_virtual_fs_filter_pukey( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs, sc_pkcs15_object_t *obj );

/*!
  Function to filter object fields from data object PKCS#15
  objects called when loading objects from the card

  \param card Struct to access the card
  \param virtual_file this is DODF virtual file
  \param virtual_fs Virtual fs pointer.
  \param obj PKCS#15 object

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_card_to_virtual_fs_filter_data_object( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs, sc_pkcs15_object_t *obj );

/*!
  Function to synchronize any PKCS#15 file from the card. It
  follows the virtual_file_sync_callback definition except for
  an extra file_type parameter.

  This synchronization might need inclusion of new files into
  virtual_fs as a side effect (for instance: new certificate data
  files).
  
  \param card Struct to access the card
  \param virtual_file this is virtual file to sync
  \param virtual_fs Virtual fs pointer.
  \param type PKCS#15 object type in encoding

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_card_to_virtual_fs_any_df( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs, int type );


/*!
  Callback to synchronize a ODF PKCS#15 file from the card. It
  follows the virtual_file_sync_callback definition.

  This synchronization might need inclusion of new files into
  virtual_fs as a side effect (for instance: new certificate data
  files).
  
  \param card Struct to access the card
  \param virtual_file this is ODF virtual file
  \param virtual_fs Virtual fs pointer.

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_card_to_virtual_fs_odf_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs );

/*!
  Callback to synchronize a TokenInfo PKCS#15 file from the card. It
  follows the virtual_file_sync_callback definition.

  This synchronization might need inclusion of new files into
  virtual_fs as a side effect (for instance: new certificate data
  files).
  
  \param card Struct to access the card
  \param virtual_file this is TokenInfo virtual file
  \param virtual_fs Virtual fs pointer.

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_card_to_virtual_fs_tokeninfo_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs );

/*!
  Callback to synchronize a AODF PKCS#15 file from the card. It
  follows the virtual_file_sync_callback definition.

  This synchronization might need inclusion of new files into
  virtual_fs as a side effect (for instance: new certificate data
  files).
  
  \param card Struct to access the card
  \param virtual_file this is AODF virtual file
  \param virtual_fs Virtual fs pointer.

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_card_to_virtual_fs_aodf_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs );

/*!
  Callback to synchronize PRKDF from the card. It
  follows the virtual_file_sync_callback definition.

  It internally uses card_sync_card_to_virtual_fs_any_df() with SC_PKCS15_PRKDF in type param.

  This synchronization might need inclusion of new files into
  virtual_fs as a side effect (for instance: new certificate data
  files).
  
  \param card Struct to access the card
  \param virtual_file this is PrKDF virtual file
  \param virtual_fs Virtual fs pointer.

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_card_to_virtual_fs_prkdf_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs );

/*!
  Callback to synchronize PUKDF from the card. It
  follows the virtual_file_sync_callback definition.

  It internally uses card_sync_card_to_virtual_fs_any_df() with SC_PKCS15_PUKDF in type param.

  This synchronization might need inclusion of new files into
  virtual_fs as a side effect (for instance: new certificate data
  files).
  
  \param card Struct to access the card
  \param virtual_file this is PuKDF virtual file
  \param virtual_fs Virtual fs pointer.

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_card_to_virtual_fs_pukdf_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs );

/*!
  Callback to synchronize CDF from the card. It
  follows the virtual_file_sync_callback definition.

  It internally uses card_sync_card_to_virtual_fs_any_df() with SC_PKCS15_CDF in type param.

  This synchronization might need inclusion of new files into
  virtual_fs as a side effect (for instance: new certificate data
  files).
  
  \param card Struct to access the card
  \param virtual_file this is CDF virtual file
  \param virtual_fs Virtual fs pointer.

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_card_to_virtual_fs_cdf_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs );

/*!
  Callback to synchronize DODF from the card. It
  follows the virtual_file_sync_callback definition.

  It internally uses card_sync_card_to_virtual_fs_any_df() with SC_PKCS15_DODF in type param.

  This synchronization might need inclusion of new files into
  virtual_fs as a side effect (for instance: new certificate data
  files).
  
  \param card Struct to access the card
  \param virtual_file this is DODF virtual file
  \param virtual_fs Virtual fs pointer.

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_card_to_virtual_fs_dodf_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs );

/*!
  Function to filter object fields from certificate PKCS#15
  objects called when loading objects from the card

  It also loads certificates from the card and adds it to
  the virtual_fs
  
  \param card Struct to access the card
  \param virtual_file this is CDF virtual file
  \param virtual_fs Virtual fs pointer.
  \param obj PKCS#15 object

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_virtual_fs_to_card_filter_cert( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs, sc_pkcs15_object_t *obj );

/*!
  Function to filter object fields from prkey PKCS#15
  objects called when loading objects from the card

  \param card Struct to access the card
  \param virtual_file this is PrKDF virtual file
  \param virtual_fs Virtual fs pointer.
  \param obj PKCS#15 object

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_virtual_fs_to_card_filter_prkey( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs, sc_pkcs15_object_t *obj );

/*!
  Function to filter object fields from pukey PKCS#15
  objects called when loading objects from the card

  \param card Struct to access the card
  \param virtual_file this is PuKDF virtual file
  \param virtual_fs Virtual fs pointer.
  \param obj PKCS#15 object

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_virtual_fs_to_card_filter_pukey( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs, sc_pkcs15_object_t *obj );

/*!
  Function to synchronize any PKCS#15 file to the card. It
  follows the virtual_file_sync_callback definition except for
  an extra file_type parameter.

  \param card Struct to access the card
  \param virtual_file this is PuKDF virtual file
  \param virtual_fs Virtual fs pointer.
  \param type PKCS#15 object type in encoding

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_virtual_fs_to_card_any_df( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs, int type );

/*!
  Callback to synchronize CDF to the card. It
  follows the virtual_file_sync_callback definition.

  It internally uses card_sync_virtual_fs_to_card_any_df()
  with SC_PKCS15_CDF in type param.

  \param card Struct to access the card
  \param virtual_file this is CDF virtual file
  \param virtual_fs Virtual fs pointer.

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_virtual_fs_to_card_cdf_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs );

/*!
  Callback to synchronize PRKDF to the card. It
  follows the virtual_file_sync_callback definition.

  It internally uses card_sync_virtual_fs_to_card_any_df()
  with SC_PKCS15_PRKDF in type param.

  \param card Struct to access the card
  \param virtual_file this is PrKDF virtual file
  \param virtual_fs Virtual fs pointer.

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_virtual_fs_to_card_prkdf_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs );

/*!
  Callback to synchronize PUKDF to the card. It
  follows the virtual_file_sync_callback definition.

  It internally uses card_sync_virtual_fs_to_card_any_df()
  with SC_PKCS15_PUKDF in type param.

  \param card Struct to access the card
  \param virtual_file this is PuKDF virtual file
  \param virtual_fs Virtual fs pointer.

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_virtual_fs_to_card_pukdf_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs );

/*!
  Callback to synchronize a certificate file from the card. It
  follows the virtual_file_sync_callback definition.

  \param card Struct to access the card
  \param virtual_file this is CDF virtual file
  \param virtual_fs Virtual fs pointer.

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_card_to_virtual_fs_certificate_file_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs );

/*!
  Callback to synchronize a certificate file from virtual fs to the card. It
  follows the virtual_file_sync_callback definition.

  \param card Struct to access the card
  \param virtual_file this is certificate virtual file
  \param virtual_fs Virtual fs pointer.

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_virtual_fs_to_card_certificate_file_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs );

/*!
  Callback to synchronize a data object file from virtual fs to the card. It
  follows the virtual_file_sync_callback definition.

  \param card Struct to access the card
  \param virtual_file this is data object virtual file
  \param virtual_fs Virtual fs pointer.

  \returns SC_SUCCESS on success, error code otherwise
*/
int card_sync_card_to_virtual_fs_data_file_callback( sc_card_t *card, struct _virtual_file_t *virtual_file, virtual_fs_t *virtual_fs );

#endif /* CARD_SYNC_H */
