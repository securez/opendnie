#include <stdlib.h>
#include <string.h>
#include "../config.h"
#include "libopensc/internal.h"
#include "libopensc/log.h"
#include "libopensc/asn1.h"
#include "libopensc/pkcs15.h"

#define DNIE_CHIP_SHORTNAME "dnie"

#if 0
/* Card driver related */
static struct sc_atr_table dnie_atrs[] = {
    /* TODO: get ATR for uninitalized DNIe */
    {   /* card activated; normal operation state */
        "3B:7F:00:00:00:00:6A:44:4E:49:65:00:00:00:00:00:00:03:90:00",
        "FF:FF:00:FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:FF:FF:FF",
        DNIE_CHIP_SHORTNAME,
        SC_CARD_TYPE_DNIE_USER,
        0,
        NULL
    },
    { /* card finalized, unusable */
        "3B:7F:00:00:00:00:6A:44:4E:49:65:00:00:00:00:00:00:0F:65:81",
        "FF:FF:00:FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:FF:FF:FF",
        DNIE_CHIP_SHORTNAME,
        SC_CARD_TYPE_DNIE_TERMINATED,
        0,
        NULL
    },
    { NULL, NULL, NULL, 0, 0, NULL }
};
#endif
static
int match_card(struct sc_card *card)
{
    // int matched=_sc_match_atr(card,dnie_atrs,&card->type);
    // return (matched>=0)? 1:0;
    return 1;
}


/* Helper functions to get the pkcs15 stuff bound. */

static
int dump_ef(sc_card_t *card, const char *path, u8 *buf, size_t *buf_len) {
	int rv;
	sc_file_t *file = sc_file_new();
	sc_format_path(path, &file->path);
	sc_select_file(card, &file->path, &file);
	if (file->size > *buf_len)
		return SC_ERROR_BUFFER_TOO_SMALL;
	rv = sc_read_binary(card, 0, buf, file->size, 0);
	if (rv < 0)
		return rv;
	*buf_len = rv;

	return SC_SUCCESS;
}

static const struct sc_asn1_entry c_asn1_odf[] = {
        { "privateKeys",         SC_ASN1_STRUCT, SC_ASN1_CTX | 0 | SC_ASN1_CONS, 0, NULL, NULL },
        { "publicKeys",          SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, 0, NULL, NULL },
        { "trustedPublicKeys",   SC_ASN1_STRUCT, SC_ASN1_CTX | 2 | SC_ASN1_CONS, 0, NULL, NULL },
        { "secretKeys",          SC_ASN1_STRUCT, SC_ASN1_CTX | 3 | SC_ASN1_CONS, 0, NULL, NULL },
        { "certificates",        SC_ASN1_STRUCT, SC_ASN1_CTX | 4 | SC_ASN1_CONS, 0, NULL, NULL },
        { "trustedCertificates", SC_ASN1_STRUCT, SC_ASN1_CTX | 5 | SC_ASN1_CONS, 0, NULL, NULL },
        { "usefulCertificates",  SC_ASN1_STRUCT, SC_ASN1_CTX | 6 | SC_ASN1_CONS, 0, NULL, NULL },
        { "dataObjects",         SC_ASN1_STRUCT, SC_ASN1_CTX | 7 | SC_ASN1_CONS, 0, NULL, NULL },
        { "authObjects",         SC_ASN1_STRUCT, SC_ASN1_CTX | 8 | SC_ASN1_CONS, 0, NULL, NULL },
        { NULL, 0, 0, 0, NULL, NULL }
};

static const unsigned int odf_indexes[] = {
        SC_PKCS15_PRKDF,
        SC_PKCS15_PUKDF,
        SC_PKCS15_PUKDF_TRUSTED,
        SC_PKCS15_SKDF,
        SC_PKCS15_CDF,
        SC_PKCS15_CDF_TRUSTED,
        SC_PKCS15_CDF_USEFUL,
        SC_PKCS15_DODF,
        SC_PKCS15_AODF,
};


static
int parse_odf(const u8 * buf, size_t buflen, struct sc_pkcs15_card *p15card)
{
        const u8 *p = buf;
        size_t left = buflen;
        int r, i, type;
        sc_path_t path;
        struct sc_asn1_entry asn1_obj_or_path[] = {
                { "path", SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_SEQUENCE, 0, &path, NULL },
                { NULL, 0, 0, 0, NULL, NULL }
        };
        struct sc_asn1_entry asn1_odf[10];
        
        sc_copy_asn1_entry(c_asn1_odf, asn1_odf);
        for (i = 0; asn1_odf[i].name != NULL; i++)
                sc_format_asn1_entry(asn1_odf + i, asn1_obj_or_path, NULL, 0);
        while (left > 0) {
                r = sc_asn1_decode_choice(p15card->card->ctx, asn1_odf, p, left, &p, &left);
                if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
                        break;
                if (r < 0)
                        return r;
                type = r;
                r = sc_pkcs15_make_absolute_path(&p15card->file_app->path, &path);
                if (r < 0)
                        return r;
                r = sc_pkcs15_add_df(p15card, odf_indexes[type], &path, NULL);
                if (r)
                        return r;
        }
        return 0;
}


/***************************/
/* Public Module Functions */
/***************************/

const char *sc_driver_version() {
        return "0.12.1-svn";		/* defined in config.h of OpenSC */
}


int bind(sc_pkcs15_card_t *p15card, sc_pkcs15emu_opt_t *options)
{
	u8 buf[1024];
	sc_pkcs15_df_t *df;
	sc_pkcs15_object_t *p15_obj;
	size_t len = sizeof(buf);
	int rv;

	/* Check for correct card driver (i.e. iso7816) */
	if (strcmp(p15card->card->driver->short_name, DNIE_CHIP_SHORTNAME) != 0)
		return SC_ERROR_WRONG_CARD;

	/* Check for correct card */
	if (match_card(p15card->card) != 1)
		return SC_ERROR_WRONG_CARD;

	/* Set root path of this application */
	p15card->file_app = sc_file_new();
	sc_format_path("3F00", &p15card->file_app->path);

	/* Load TokenInfo */
	rv = dump_ef(p15card->card, "3F0050155032", buf, &len);
	if (rv != SC_SUCCESS) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "Reading of EF.TOKENINFO failed: %d", rv);
		return rv;
	}
	rv = sc_pkcs15_parse_tokeninfo(p15card->card->ctx, p15card->tokeninfo, buf, len);
	if (rv != SC_SUCCESS) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "Decoding of EF.TOKENINFO failed: %d", rv);
		return rv;
	}

	/* Only accept the original stuff */
	if (strcmp(p15card->tokeninfo->manufacturer_id, "DGP-FNMT") != 0)
		return SC_ERROR_WRONG_CARD;

	/* Load ODF */
	rv = dump_ef(p15card->card, "3F0050155031", buf, &len);
	if (rv != SC_SUCCESS) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "Reading of ODF failed: %d", rv);
		return rv;
	}
	rv = parse_odf(buf, len, p15card);
	if (rv != SC_SUCCESS) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "Decoding of ODF failed: %d", rv);
		return rv;
	}

	/* Decode EF.PrKDF, EF.PuKDF and EF.CDF */
	for (df = p15card->df_list; df != NULL; df = df->next) {
		if (df->type == SC_PKCS15_PRKDF) {
			rv = sc_pkcs15_parse_df(p15card, df);
			if (rv != SC_SUCCESS) {
				sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL,
					"Decoding of EF.PrKDF (%s) failed: %d", sc_print_path(&df->path), rv);
				// return rv;
			}
		}
		if (df->type == SC_PKCS15_PUKDF) {
			rv = sc_pkcs15_parse_df(p15card, df);
			if (rv != SC_SUCCESS) {
				sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL,
					"Decoding of EF.PuKDF (%s) failed: %d", sc_print_path(&df->path), rv);
				// return rv;
			}
		}
		if (df->type == SC_PKCS15_CDF) {
			rv = sc_pkcs15_parse_df(p15card, df);
			if (rv != SC_SUCCESS) {
				sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL,
					"Decoding of EF.CDF (%s) failed: %d", sc_print_path(&df->path), rv);
				// return rv;
			}
		}
	}

	/* Perform required fixes */
	p15_obj = p15card->obj_list;
	while (p15_obj != NULL) {
		/* Add 'auth_id' to private keys */
		if ((p15_obj->type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_PRKEY) {
			p15_obj->auth_id.value[0] = 0x01;
			p15_obj->auth_id.len = 1;
		}

		/* Unset flags 'private, modifiable' on public keys */
		if ((p15_obj->type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_PUBKEY) {
			p15_obj->flags &= ~(SC_PKCS15_CO_FLAG_PRIVATE | SC_PKCS15_CO_FLAG_MODIFIABLE);
		}

		/* Unset flags 'private, modifiable' on certificates */
		if ((p15_obj->type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_CERT) {
			p15_obj->flags &= ~(SC_PKCS15_CO_FLAG_PRIVATE | SC_PKCS15_CO_FLAG_MODIFIABLE);
		}

		p15_obj = p15_obj->next;
	}

	return SC_SUCCESS;
}

