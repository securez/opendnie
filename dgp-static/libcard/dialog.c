/*
 *  dialog.c: dialog functions
 *  
 *  Copyright (C) 2006-2010 Dirección General de la Policía y de la Guardia Civil
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



#include <assuan.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include <locale.h>
#include "../../config.h"
#include "../common/i18n.h"

int ask_user_auth()
{
  int r;
  const char *argv[3];
  const char *pgmname = PIN_ENTRY; 
  ASSUAN_CONTEXT ctx;
  gchar buf[500];
  gsize buflen = sizeof(buf);
  gchar *buf_conv_ptr = NULL;
  const char *local_charset, *default_charset;
  gsize bytes_read=0, bytes_written=0;  
  gboolean is_utf8;

  memset(buf, 0, buflen);
  default_charset = setlocale(LC_CTYPE, "");

  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, "/usr/share/locale");
  textdomain(PACKAGE);

  argv[0] = pgmname;
  argv[1] = NULL;
	
  r = assuan_pipe_connect(&ctx, pgmname, (char **) argv, 0);
  if (r) {
    printf(i18n("Can't connect to the PIN entry module: %s\n"),
	   assuan_strerror((AssuanError) r));
    goto err;
  }
	
  sprintf(buf, i18n("SETDESC Está a punto de realizar una firma electrónica con su clave de FIRMA del DNI electrónico. ¿Desea permitir esta operación?"));
  
  is_utf8 = g_get_charset(&local_charset);  
  buf_conv_ptr = g_convert_with_fallback(buf, buflen, local_charset, "UTF-8", 
					 NULL, &bytes_read, &bytes_written, NULL);
  if(!buf_conv_ptr) {
    printf(i18n("Error converting string to locale charset.\n"));
    goto err;
  }

  r = assuan_transact(ctx, buf_conv_ptr, NULL, NULL, NULL, NULL, NULL, NULL);
  if (r) {
    printf("SETDESC: %s\n", assuan_strerror((AssuanError) r));
    goto err;
  }
  while (1) {
    r = assuan_transact(ctx, "CONFIRM", NULL, NULL, NULL, NULL, NULL, NULL);
    if (r == ASSUAN_Canceled) {
      assuan_disconnect(ctx);
      return -2;
    }
    if (r) {
      printf("SETERROR: %s\n", assuan_strerror((AssuanError) r));
      goto err;
    }
    if (r == 0)
      break;
  }

  assuan_disconnect(ctx);	
  return 0;
 err:	
  assuan_disconnect(ctx);
  return -1;
}
