/*!
 * \file virtual_pkcs15_fs.c
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

#include "virtual_pkcs15_fs.h"
#include "card_sync.h"

/* type definitions */
/* struct to initialize virtual files in virtual_pkcs15_fs_init */
struct _virtual_file_initializer {
  const char *path_string;
  const unsigned char *data;
  int data_length;
  int file_size;
  int is_ef;
  virtual_file_sync_state_t card_to_virtual_fs_sync_state;
  virtual_file_sync_callback *card_to_virtual_fs_sync_callback;
  virtual_file_sync_state_t virtual_fs_to_card_sync_state;
  virtual_file_sync_callback *virtual_fs_to_card_sync_callback;
};

/* PKCS#15 filesystem */
int virtual_pkcs15_fs_init( virtual_fs_t *virtual_fs )
{
  int ii;
  int r = SC_SUCCESS;
  sc_path_t path;
  
  static const struct _virtual_file_initializer files[] = {
    {"3F00", NULL, 0, 0, 0, virtual_file_sync_state_unknown, NULL, virtual_file_sync_state_unknown, NULL}, /* df mf */
    {"3F003F11", NULL, 0, 0, 0 /* df */, virtual_file_sync_state_unknown, NULL, virtual_file_sync_state_unknown, NULL}, /* df ICC.Crypto */
    {"3F006061", NULL, 0, 0, 0 /* df */, virtual_file_sync_state_unknown, NULL, virtual_file_sync_state_unknown, NULL}, /* df certs */
    {"3F006081", NULL, 0, 0, 0 /* df */, virtual_file_sync_state_unknown, NULL, virtual_file_sync_state_unknown, NULL}, /* df certs */
    {"3F005015", NULL, 0, 0, 0 /* df */, virtual_file_sync_state_unknown, NULL, virtual_file_sync_state_unknown, NULL},
    {"3F0050155031", NULL, 0, 0x1000, 1, virtual_file_sync_state_sync_pending, card_sync_card_to_virtual_fs_odf_callback, virtual_file_sync_state_unknown, NULL}, /* ef odf */
    {"3F0050155032", NULL, 0, 0x1000, 1, virtual_file_sync_state_sync_pending, card_sync_card_to_virtual_fs_tokeninfo_callback, virtual_file_sync_state_unknown, NULL}, /* ef tokeninfo */
    {"3F0050156000", NULL, 0, 0x1000, 1, virtual_file_sync_state_sync_pending, card_sync_card_to_virtual_fs_aodf_callback, virtual_file_sync_state_unknown, NULL}, /* ef aodf */
    {"3F0050156001", NULL, 0, 0x4000, 1, virtual_file_sync_state_sync_pending, card_sync_card_to_virtual_fs_prkdf_callback, virtual_file_sync_state_unknown, NULL}, /* ef prkdf */
    {"3F0050156002", NULL, 0, 0x4000, 1, virtual_file_sync_state_sync_pending, card_sync_card_to_virtual_fs_pukdf_callback, virtual_file_sync_state_unknown, NULL}, /* ef pukdf */
    {"3F0050156004", NULL, 0, 0x4000, 1, virtual_file_sync_state_sync_pending, card_sync_card_to_virtual_fs_cdf_callback, virtual_file_sync_state_unknown, NULL}, /* ef cdf */
    {"3F0050156005", NULL, 0, 0x4000, 1, virtual_file_sync_state_sync_pending, card_sync_card_to_virtual_fs_dodf_callback, virtual_file_sync_state_unknown, NULL}, /* ef dodf */
    {"3F006031", NULL, 0, 0, 0 /* df */, virtual_file_sync_state_unknown, NULL, virtual_file_sync_state_unknown, NULL},
    {NULL, NULL, 0, 0, 0, virtual_file_sync_state_unknown, NULL, virtual_file_sync_state_unknown, NULL} /* terminal item. first null flags end */
  };

  if(!virtual_fs)
    return SC_ERROR_INVALID_ARGUMENTS;

  for(ii=0; files[ii].path_string != NULL ; ii++) {
    sc_format_path(files[ii].path_string, &path);
    r = virtual_fs_append_new_virtual_file(virtual_fs, 
					   &path,
					   files[ii].data,
					   files[ii].data_length,
					   files[ii].file_size,
					   files[ii].is_ef,
					   files[ii].card_to_virtual_fs_sync_state,
					   files[ii].card_to_virtual_fs_sync_callback,
					   files[ii].virtual_fs_to_card_sync_state,
					   files[ii].virtual_fs_to_card_sync_callback
					   );
    if(r != SC_SUCCESS)
      break;
  }

  return r;
}
