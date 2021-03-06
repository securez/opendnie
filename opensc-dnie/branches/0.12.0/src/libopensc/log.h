/*
 * log.h: Logging functions header file
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2003  Antti Tapaninen <aet@cc.hut.fi>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _OPENSC_LOG_H
#define _OPENSC_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include "libopensc/opensc.h"

enum {
	SC_LOG_DEBUG_VERBOSE_TOOL = 1,	/* tools only: verbose */
	SC_LOG_DEBUG_VERBOSE,		/* helps users */
	SC_LOG_DEBUG_NORMAL,		/* helps developers */
	SC_LOG_DEBUG_RFU1,		/* RFU */
	SC_LOG_DEBUG_RFU2,		/* RFU */
	SC_LOG_DEBUG_ASN1,		/* asn1.c only */
	SC_LOG_DEBUG_MATCH,		/* card matching only */
};

/* You can't do #ifndef __FUNCTION__ */
#if !defined(__GNUC__) && !defined(__IBMC__) && !(defined(_MSC_VER) && (_MSC_VER >= 1300))
#define __FUNCTION__ NULL
#endif

#if defined(__GNUC__)
#define sc_debug(ctx, level, format, args...)	sc_do_log(ctx, level, __FILE__, __LINE__, __FUNCTION__, format , ## args)
#else
#define sc_debug _sc_debug
#endif

void sc_do_log(struct sc_context *ctx, int level, const char *file, int line, const char *func, 
		const char *format, ...);
void sc_do_log_va(struct sc_context *ctx, int level, const char *file, int line, const char *func, 
		const char *format, va_list args);
void _sc_debug(struct sc_context *ctx, int level, const char *format, ...);

void sc_hex_dump(struct sc_context *ctx, int level, const u8 * buf, size_t len, char *out, size_t outlen);
char * sc_dump_hex(const u8 * in, size_t count);

#define SC_FUNC_CALLED(ctx, level) do { \
	 sc_do_log(ctx, level, __FILE__, __LINE__, __FUNCTION__, "called\n"); \
} while (0)

#define SC_FUNC_RETURN(ctx, level, r) do { \
	int _ret = r; \
	if (_ret <= 0) { \
		sc_do_log(ctx, level, __FILE__, __LINE__, __FUNCTION__, \
			"returning with: %d (%s)\n", _ret, sc_strerror(_ret)); \
	} else { \
		sc_do_log(ctx, level, __FILE__, __LINE__, __FUNCTION__, \
			"returning with: %d\n", _ret); \
	} \
	return _ret; \
} while(0)

#define SC_TEST_RET(ctx, level, r, text) do { \
	int _ret = (r); \
	if (_ret < 0) { \
		sc_do_log(ctx, level, __FILE__, __LINE__, __FUNCTION__, \
			"%s: %d (%s)\n", (text), _ret, sc_strerror(_ret)); \
		return _ret; \
	} \
} while(0)

#ifdef __cplusplus
}
#endif

#endif
