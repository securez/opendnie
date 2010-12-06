/*
 * dnie.h: Defines, Typedefs and prototype functions 
 * for Spanish DNI electronico (DNIe card)
 *
 * Copyright (C) 2010 Juan Antonio Martinez <jonsito@terra.es>
 *
 * This work is derived from many sources at OpenSC Project site,
 * (see references) and the information made public for Spanish 
 * Direccion General de la Policia y de la Guardia Civil
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

#ifndef __CARD_DNIE_H__
#define __CARD_DNIE_H__

/* Secure Messaging state indicator */
#define DNIE_SM_NONE            0x00 /* no channel defined */
#define DNIE_SM_INPROGRESS      0x01 /* chanel is being created: dont use */
#define DNIE_SM_INTERNAL        0x02 /* using local keys */
#define DNIE_SM_EXTERNAL        0x03 /* using SSL connection to handle keys */

/************************** data structures for DNIe **********************/
typedef struct dnie_file_cache {
    sc_file_t *file;
    u8 *data;
    size_t datalen;
    struct dnie_file_cache *next;
} dnie_file_cache_t;

typedef struct dnie_sm_handler {
    int state;
    int (*deinit)(struct sc_card *card);
    int (*encode)(sc_card_t *card,sc_apdu_t *from, sc_apdu_t *to);
    int (*decode)(sc_card_t *card,sc_apdu_t *from, sc_apdu_t *to);
} dnie_sm_handler_t;

typedef struct dnie_private_data {
    char *user_consent_app;
    int user_consent_enabled;
    sc_serial_number_t *serialnumber;
    dnie_sm_handler_t *sm_handler;
    dnie_file_cache_t *cache_top;
    dnie_file_cache_t *cache_pt;
    int rsa_key_ref;   /* key id being used in sec operation */
} dnie_private_data_t;

/************************** external function prototypes ******************/

extern int dnie_sm_init(
        struct sc_card *card,           /* card data */
        dnie_sm_handler_t **sm_handler, /* pointer to dnie_priv.sm_handler */
        int state);                     /* requested SM state */

extern int dnie_sm_wrap_apdu(
        struct sc_card *card,           /* card data */
        dnie_sm_handler_t *sm_handler,  /* pointer to dnie_priv.sm_handler */
        struct sc_apdu *from,           /* apdu to be parsed */
        struct sc_apdu *to,             /* apdu to store result */
        int flag                        /* 0:SM encode 1:SM decode */
);

extern int dnie_read_file(
        sc_card_t *card,      /* card data */
        const sc_path_t *path,/* path file to search for */
        sc_file_t **file,     /* path file to search for */
        u8 **buffer,          /* where to store data */
        size_t *length        /* data length */
);

/* used to handle raw apdu data in set_security_env() on SM stblishment */
extern int dnie_sm_set_security_env(
        sc_card_t *card,      /* card data */
        u8 p1,
        u8 p2,                /* P1 and P2 apdu parameters */
        u8 *buffer,           /* apdu data */
        size_t length         /* apdu length */
);
#endif

