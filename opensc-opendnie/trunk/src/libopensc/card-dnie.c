/*
 * card-dnie.c: Support for Spanish DNI electronico (DNIe card)
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

#define __CARD_DNIE_C__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ENABLE_OPENSSL   /* empty file without openssl */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>

#ifdef HAVE_LIBASSUAN
# include <assuan.h>
/* check for libassuan version */
# ifndef ASSUAN_No_Error
#  define HAVE_LIBASSUAN_2
#  define _gpg_error(t) gpg_strerror((t))
# else
#  define HAVE_LIBASSUAN_1
#  define _gpg_error(t) assuan_strerror( (AssuanError) (t) )
# endif
#endif

#include "opensc.h"
#include "cardctl.h"
#include "internal.h"

#include "cwa14890.h"

typedef struct dnie_private_data_st {
    char *user_consent_app;
    int user_consent_enabled;
    sc_serial_number_t *serialnumber;
    cwa_provider_t *provider;
    int rsa_key_ref;   /* key id being used in sec operation */
} dnie_private_data_t;

extern cwa_provider_t *dnie_get_cwa_provider(sc_card_t *card);

#define DNIE_CHIP_NAME "DNIe: Spanish eID card"
#define DNIE_CHIP_SHORTNAME "dnie"
#define DNIE_MF_NAME "Master.File"

/* default user consent program (if required) */
#define USER_CONSENT_CMD "/usr/bin/pinentry"

/* Undeclared dnie APDU responses in iso7816.c */
static struct sc_card_error dnie_errors[] = {
    { 0x6688, SC_ERROR_UNKNOWN, "Secure Message value is incorrect" },
    { 0x6A89, SC_ERROR_FILE_ALREADY_EXISTS, "File/Key already exists" },
    { 0,0,NULL }
};

/* 
 * DNIe ATR info from DGP web page
 *
Tag Value Meaning
TS  0x3B  Direct Convention
T0  0x7F  Y1=0x07=0111; TA1,TB1 y TC1 present.
          K=0x0F=1111; 15 historical bytes
TA1 0x38  FI (Factor de conversión de la tasa de reloj) = 744
          DI (Factor de ajuste de la tasa de bits) = 12
          Máximo 8 Mhz.
TB1 0x00  Vpp (voltaje de programación) no requerido.
TC1 0x00  No se requiere tiempo de espera adicional.
H1  0x00  No usado
H2  0x6A  Datos de preexpedición. Diez bytes con identificación del expedidor.
H3  0x44  'D'
H4  0x4E  'N'
H5  0x49  'I'
H6  0x65  'e'
H7  Fabricante de la tecnología Match-on-Card incorporada.
    0x10  SAGEM
    0x20  SIEMENS
H8  0x02  Fabricante del CI: STMicroelectronics.
H9  0x4C
H10 0x34  Tipo de CI: 19WL34
H11 0x01  MSB de la version del SO: 1
H12 0x1v  LSB de la version del SO: 1v
H13 Fase del ciclo de vida .
    0x00  prepersonalización.
    0x01  personalización.
    0x03  usuario.
    0x0F  final.
H14 0xss
H15 0xss  Bytes de estado

H13-H15: 0x03 0x90 0x00 user phase: tarjeta operativa
H13-H15: 0x0F 0x65 0x81 final phase: tarjeta no operativa
*/

/* ATR Table list */
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

static dnie_private_data_t dnie_priv;
static struct sc_card_operations dnie_ops;
static struct sc_card_operations *iso_ops=NULL; 

static sc_card_driver_t dnie_driver  = {
    DNIE_CHIP_NAME,
    DNIE_CHIP_SHORTNAME,
    &dnie_ops,
    dnie_atrs,
    0, /* nattrs */
    NULL /* dll */
};

/************************** card-dnie.c internal functions ****************/

/**
 * Parse configuration file for dnie parameters
 * See opensc.conf for details
 *@param ctx card context
 *@param priv pointer to dnie private data
 *@return SC_SUCCESS (should return no errors)
 */
static int dnie_get_environment(sc_context_t *ctx,dnie_private_data_t *priv) {
    int i;
    scconf_block **blocks, *blk;
    for (i = 0; ctx->conf_blocks[i]; i++) {
        blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],"card_driver","dnie");
        if (!blocks) continue;
        blk=blocks[0];
        free(blocks);
        if (blk==NULL) continue;
        /* fill private data with configuration parameters */
        priv->user_consent_app = /* def user consent app is "pinentry" */
            (char *) scconf_get_str(blk,"user_consent_app",USER_CONSENT_CMD); 
        priv->user_consent_enabled = /* user consent is enabled by default */
            scconf_get_bool(blk,"user_consent_enabled",1);
    }
    return SC_SUCCESS;
}

#ifndef HAVE_LIBASSUAN

/**
 * Stripped down function for user consent
 * Will be called instead of real if opensc is compiled without libassuan
 *@param card pointer to sc_card structure
 *@return SC_SUCCESS if ok, error code if bad parameters
 */
static int ask_user_consent(sc_card_t *card) {
   if ( (card==NULL) || (card->ctx==NULL)) return SC_ERROR_INVALID_ARGUMENTS;
   sc_log(card->ctx,,"Libassuan support is off. User Consent disabled");
   return SC_SUCCESS;
}

#else

/**
 * Ask for user consent on signature operation
 * Requires libassuan to compile
 *@param card pointer to sc_card structure
 *@return SC_SUCCESS if ok, else error code
 */
static int ask_user_consent(sc_card_t *card) {
    int res;
    struct stat buf;
    const char *argv[3];
    assuan_fd_t noclosefds[2];
    assuan_context_t ctx; 
    if ( (card==NULL) || (card->ctx==NULL)) return SC_ERROR_INVALID_ARGUMENTS;
    LOG_FUNC_CALLED(card->ctx);
    
    dnie_get_environment(card->ctx,&dnie_priv);
    if (dnie_priv.user_consent_enabled==0) {
        sc_log(card->ctx,"User Consent is disabled in configuration file");
        return SC_SUCCESS;
    }
    res=stat(dnie_priv.user_consent_app,&buf);
    if (res!=0) {
      /* TODO: check that pinentry file is executable */
      sc_log(card->ctx,"Invalid pinentry application: %s\n",dnie_priv.user_consent_app);
       LOG_FUNC_RETURN(card->ctx,SC_ERROR_INVALID_ARGUMENTS);
    }
    argv[0]=dnie_priv.user_consent_app;
    argv[1]=NULL;
    argv[2]=NULL;
    noclosefds[0]= fileno(stderr);
    noclosefds[1]= ASSUAN_INVALID_FD;
#ifdef HAVE_LIBASSUAN_2
    res = assuan_new(&ctx);
    if (res!=0) {
      sc_log(card->ctx,"Can't create the User Consent environment: %s\n",_gpg_error(res));
      LOG_FUNC_RETURN(card->ctx,SC_ERROR_INTERNAL);
    }
    res = assuan_pipe_connect(ctx,dnie_priv.user_consent_app,argv,noclosefds,NULL,NULL,0);
#else 
    res = assuan_pipe_connect(&ctx,dnie_priv.user_consent_app,argv,0);
#endif
    if (res!=0) {
        sc_log(card->ctx,"Can't connect to the User Consent module: %s\n",_gpg_error(res));
        res=SC_ERROR_INVALID_ARGUMENTS; /* invalid or not available pinentry */
        goto exit;
    }
    res = assuan_transact(
       ctx, 
       "SETDESC Está a punto de realizar una firma electrónica con su clave de FIRMA del DNI electrónico. ¿Desea permitir esta operación?", 
       NULL, NULL, NULL, NULL, NULL, NULL);
    if (res!=0) {
       sc_log(card->ctx,"SETDESC: %s\n", _gpg_error(res));
       res=SC_ERROR_CARD_CMD_FAILED; /* perhaps should use a better errcode */
       goto exit;
    }
    res = assuan_transact(ctx,"CONFIRM",NULL,NULL,NULL,NULL,NULL,NULL);
#ifdef HAVE_LIBASSUAN_1
    if (res == ASSUAN_Canceled) {
       sc_log(card->ctx,"CONFIRM: signature cancelled by user");
       res= SC_ERROR_NOT_ALLOWED;
       goto exit;
    }
#endif
    if (res) {
       sc_log(card->ctx,"SETERROR: %s\n",_gpg_error(res));
       res=SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
     } else {
       res=SC_SUCCESS;
     }
exit:
#ifdef HAVE_LIBASSUAN_2
    assuan_release(ctx);
#else
    assuan_disconnect(ctx);
#endif
    LOG_FUNC_RETURN(card->ctx,res);
}
#endif

/************************** cardctl defined operations *******************/

/* 
 * Manual says that generate_keys() is a reserved operation; that is: 
 * only can be done at DGP offices. But several authors talks about 
 * this operation is available also outside. So need to test :-)
 * Notice that write operations are not supported, so we can't use 
 * created keys to generate and store new certificates into the card.
 * TODO: copy code from card-jcop.c::jcop_generate_keys()
 */
static int dnie_generate_key(sc_card_t *card, void *data) {
    if ( (card==NULL) || (data==NULL) ) return SC_ERROR_INVALID_ARGUMENTS;
    int result=SC_ERROR_NOT_SUPPORTED;
    LOG_FUNC_CALLED(card->ctx);
    /* TODO: write dnie_generate_key() */
    LOG_FUNC_RETURN(card->ctx,result);
}

/**
 * Retrieve serial number (7 bytes) from card
 *@param card pointer to card description
 *@param serial where to store data retrieved
 *@return SC_SUCCESS if ok; else error code
 */
static int dnie_get_serialnr(sc_card_t *card, sc_serial_number_t *serial) {
    int result;
    sc_apdu_t apdu;
    u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
    if ( (card==NULL) || (card->ctx==NULL) || (serial==NULL) ) 
        return SC_ERROR_INVALID_ARGUMENTS;

    LOG_FUNC_CALLED(card->ctx);
    if (card->type!=SC_CARD_TYPE_DNIE_USER) return SC_ERROR_NOT_SUPPORTED;
    /* if serial number is cached, use it */
    if (card->serialnr.len) {
        memcpy(serial, &card->serialnr, sizeof(*serial));
        sc_log(card->ctx,"Serial Number (cached): '%s'",sc_dump_hex(serial->value,serial->len));
        LOG_FUNC_RETURN(card->ctx,SC_SUCCESS);
    }
    /* not cached, retrieve it by mean of an APDU */
    sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xb8, 0x00, 0x00);
    apdu.cla = 0x90; /* propietary cmd */
    apdu.resp = rbuf;
    apdu.resplen = sizeof(rbuf);
    /* official driver read 0x11 bytes, but only uses 7. Manual says just 7 */
    apdu.le   = 0x07;
    apdu.lc   = 0;
    apdu.datalen = 0;
    /* send apdu */
    result=sc_transmit_apdu(card,&apdu);
    LOG_TEST_RET(card->ctx,result,"APDU transmit failed");
    if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00) return SC_ERROR_INTERNAL;
    /* cache serial number */
    memcpy(card->serialnr.value, apdu.resp, 7*sizeof(u8));
    card->serialnr.len = 7*sizeof(u8);
    /* TODO: fill Issuer Identification Number data with proper (ATR?) info */
    /*
    card->serialnr.iin.mii=;
    card->serialnr.iin.country=;
    card->serialnr.iin.issuer_id=;
    */
    /* copy and return serial number */
    memcpy(serial, &card->serialnr, sizeof(*serial));
    sc_log(card->ctx,"Serial Number (apdu): '%s'",sc_dump_hex(serial->value,serial->len));
    LOG_FUNC_RETURN(card->ctx,SC_SUCCESS);
}

/**************************** sc_card_operations **********************/

/* Generic operations */

/* Called in sc_connect_card().  Must return 1, if the current
 * card can be handled with this driver, or 0 otherwise.  ATR
 * field of the sc_card struct is filled in before calling
 * this function. */
static int dnie_match_card(struct sc_card *card){
    int result=0;
    LOG_FUNC_CALLED(card->ctx);
    int matched=_sc_match_atr(card,dnie_atrs,&card->type);
    result=(matched>=0)? 1:0;
    LOG_FUNC_RETURN(card->ctx,result);
}

/* Called when ATR of the inserted card matches an entry in ATR
 * table.  May return SC_ERROR_INVALID_CARD to indicate that
 * the card cannot be handled with this driver. */
static int dnie_init(struct sc_card *card){
    int result=SC_SUCCESS;
    if ( (card==NULL) || (card->ctx==NULL)) return SC_ERROR_INVALID_ARGUMENTS;
    LOG_FUNC_CALLED(card->ctx);

    /* if recognized as terminated DNIe card, return error */
    if (card->type==SC_CARD_TYPE_DNIE_TERMINATED) {
       card->drv_data = NULL;
       result = SC_ERROR_MEMORY_FAILURE;
       goto dnie_init_error;
    }

    /* initialize private data */
    memset(&dnie_priv,0,sizeof(dnie_private_data_t));

    /* read environment from configuration file */
    result=dnie_get_environment(card->ctx,&dnie_priv);
    if (result!=SC_SUCCESS) goto dnie_init_error;

    /* initialize cwa-dnie provider */
    cwa_provider_t *p=dnie_get_cwa_provider(card);
    if(!p) {
        sc_log(card->ctx,"Error in initialize cwa-dnie provider");
        result=SC_ERROR_OUT_OF_MEMORY;
        goto dnie_init_error;
    }
    dnie_priv.provider=p;

    /* store private data into card driver structure */
    card->drv_data=&dnie_priv;
     
    /* set up flags according documentation */
    card->name = DNIE_CHIP_SHORTNAME;
    card->cla  = 0x00; // card uses default APDU class (interindustry)
    card->caps |=SC_CARD_CAP_RNG; /* we have a random number generator */
    card->max_send_size=0xf0; /* manual says 255, but to be safe... */
    card->max_recv_size=0xf0;

    unsigned long algoflags = SC_ALGORITHM_RSA_RAW; /* RSA support */
    algoflags    |= SC_ALGORITHM_RSA_HASH_NONE;
    _sc_card_add_rsa_alg(card,1024,algoflags,0);
    _sc_card_add_rsa_alg(card,2048,algoflags,0);
    
    /* initialize SM state to NONE */
    /* TODO: change to CWA_SM_OFF when SM testing get done */
    result=cwa_create_secure_channel(card,p,CWA_SM_COLD);

dnie_init_error:
    LOG_FUNC_RETURN(card->ctx,result);
}

/* Called when the card object is being freed.  finish() has to
 * deallocate all possible private data. */
static int dnie_finish(struct sc_card *card) {
    int result=SC_SUCCESS;
    LOG_FUNC_CALLED(card->ctx);

    /* disable sm channel if stablished */
    cwa_create_secure_channel(card, dnie_priv.provider,CWA_SM_OFF);

    LOG_FUNC_RETURN(card->ctx,result);
}

/* Called before sc_transmit_apdu() to allowing APDU wrapping
 * If set to NULL no wrapping process will be done
 * Usefull on Secure Messaging APDU encode/decode
 * If returned value is greater than zero, sc_transmit_apdu() 
 * will be called, else means either SC_SUCCESS or error code */
static int dnie_wrap_apdu(sc_card_t *card, sc_apdu_t *apdu) {
    int res=SC_SUCCESS;
    if( (card==NULL) || (card->ctx==NULL) || (apdu==NULL) )
        return SC_ERROR_INVALID_ARGUMENTS;
    LOG_FUNC_CALLED(card->ctx);
    cwa_provider_t *provider=dnie_priv.provider;
    /* TODO: if state is "in progress", should lock... */
    if (provider->status.state!=CWA_SM_ACTIVE) return 1;
    /* encode/send/receivedecode apdu process*/

    /* TODO: write */ 

    LOG_FUNC_RETURN(card->ctx,res);
}

/* ISO 7816-4 functions */

/* select_file: Does the equivalent of SELECT FILE command specified
 *   in ISO7816-4. Stores information about the selected file to
 *   <file>, if not NULL. */
static int dnie_select_file(struct sc_card *card,
                       const struct sc_path *in_path,
                       struct sc_file **file_out){

    u8 buf[SC_MAX_APDU_BUFFER_SIZE];
    u8 pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
    int pathlen;

    sc_file_t *file = NULL;
    int res=SC_SUCCESS;
    sc_apdu_t apdu;

    if ( !card || !card->ctx || !in_path) return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;

    LOG_FUNC_CALLED(ctx);

    memcpy(path, in_path->value, in_path->len);
    pathlen = in_path->len;
    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0);

    /* SELECT file in DNIe is a bit tricky: 
     * - only handles file types 
     * SC_PATH_TYPE_FILE_ID and SC_PATH_TYPE_DF_NAME
     * - Also MF must be addressed by their Name, not their ID
     * So some magic is needed:
     * - split SC_PATH_TYPE_PATH into several calls to each 2-byte data
     * (take care on initial 3F00 to be named as 'Master.File')
     * - other file types are marked as unssupported
     *
     * Also, Response always handle a proprietary FCI info, so
     * need to handle it manually via dnie_process_fci()
     *
     * (Again manual is so obscure: only talks about APDUs
     * 00 A4 00 00 xx / 00 A4 04 00 xx works. I've discovered that
     * the other P1 values fails by mean of trial and error )
     */
    switch (in_path->type) {
        case SC_PATH_TYPE_FILE_ID:
            /* pathlen must be of len=2 */
            if (pathlen != 2) LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
            sc_log(ctx,"select_file(ID): %s",sc_dump_hex(path,pathlen));
            apdu.p1 = 0;
            break;
        case SC_PATH_TYPE_DF_NAME:
            sc_log(ctx,"select_file(NAME): %s",sc_dump_hex(path,pathlen));
            apdu.p1 = 4;
            break;
        case SC_PATH_TYPE_PATH:
            if ((pathlen%2)!=0) LOG_FUNC_RETURN(ctx,SC_ERROR_INVALID_ARGUMENTS);
            sc_log(ctx,"select_file(PATH): %s",sc_dump_hex(path,pathlen));
            /* convert to SC_PATH_TYPE_FILE_ID */
	    while(pathlen>0) {
                sc_path_t tmpp;
                if (pathlen >= 2 && memcmp(path, "\x3F\x00", 2) == 0) {
                    /* if MF, use their name as path */
                    tmpp.type = SC_PATH_TYPE_DF_NAME;
                    strcpy((char *)tmpp.value, DNIE_MF_NAME);
                    tmpp.len = sizeof(DNIE_MF_NAME) - 1;
                } else {
                    /* else use 2-byte file id */
                    tmpp.type = SC_PATH_TYPE_FILE_ID;
                    tmpp.value[0] = path[0];
                    tmpp.value[1] = path[1];
                    tmpp.len = 2;
                }
                /* recursively call to select_file */
                res=card->ops->select_file(card,&tmpp,file_out);
                LOG_TEST_RET(ctx,res,"select_file(PATH) failed");
                pathlen-=2;
                path+=2;
            }
            LOG_FUNC_RETURN(ctx,SC_SUCCESS);
            break;
        case SC_PATH_TYPE_FROM_CURRENT:
        case SC_PATH_TYPE_PARENT:
            LOG_FUNC_RETURN(ctx, SC_ERROR_NO_CARD_SUPPORT);
        default:
            LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
            break;
    }
    /* Arriving here means need to compose and send apdu */
    apdu.p2 = 0;            /* first record, return FCI */
    apdu.lc = pathlen;
    apdu.data = path;
    apdu.datalen = pathlen;

    if (file_out != NULL) {
        apdu.resp = buf;
        apdu.resplen = sizeof(buf);
        apdu.le = card->max_recv_size > 0 ? card->max_recv_size : 256;
    } else {
        apdu.cse = (apdu.lc == 0) ? SC_APDU_CASE_1 : SC_APDU_CASE_3_SHORT;
    }
    res = sc_transmit_apdu(card, &apdu);
    LOG_TEST_RET(ctx,res, "SelectFile() APDU transmit failed");
    if (file_out == NULL) {
        if (apdu.sw1 == 0x61) SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, 0);
        SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
    }

    /* analyze response. if FCI, try to parse */
    res = sc_check_sw(card, apdu.sw1, apdu.sw2);
    LOG_TEST_RET(ctx,res,"SelectFile() check_sw failed");
    if (apdu.resplen < 2) LOG_FUNC_RETURN(ctx,SC_ERROR_UNKNOWN_DATA_RECEIVED);
    if (apdu.resp[0]==0x00) /* proprietary coding */
       LOG_FUNC_RETURN(ctx,SC_ERROR_UNKNOWN_DATA_RECEIVED);

    /* finally process FCI response */
    file = sc_file_new();
    if (file == NULL) LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
    if (!card->ops->process_fci) { /* hey! DNIe MUST have process_fci */
        if (file) sc_file_free(file);
        LOG_FUNC_RETURN(ctx,SC_ERROR_INTERNAL);
    }
    res=card->ops->process_fci(card, file, apdu.resp+2, apdu.resp[1]);
    *file_out=file;
    LOG_FUNC_RETURN(ctx,res);
}

/* Get challenge: retrieve 8 random bytes for any further use
 * (eg perform an external authenticate command)
 * NOTEs
 * Official driver redundantly sets SM before execute this command
 * No reason to do it, as is needed to do SM handshake...
 * Also: official driver reads in blocks of 20 bytes. 
 * Why? Manual and iso-7816-4 states that only 8 bytes 
 * are required... so we will obbey Manual
 */
static int dnie_get_challenge(struct sc_card *card, u8 * rnd, size_t len) {
	sc_apdu_t apdu;
    u8 buf[10];
    int result=SC_SUCCESS;
    if ( (card==NULL) || (card->ctx==NULL)) return SC_ERROR_INVALID_ARGUMENTS;
    LOG_FUNC_CALLED(card->ctx);
    /* just a copy of iso7816::get_challenge() but call dnie_check_sw to
     * look for extra error codes */
    if ((rnd==NULL) || (len<=0)) {
        /* no valid buffer provided */ 
        result=SC_ERROR_INVALID_ARGUMENTS;
        goto dnie_get_challenge_error;
    }
    sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x84, 0x00, 0x00);
    apdu.le      = 8;
    apdu.resp    = buf;
    apdu.resplen = 8;       /* include SW's */

    /* perform consecutive reads until retrieve "len" bytes */
    while (len > 0) {
        size_t n = len > 8 ? 8 : len;
        result = sc_transmit_apdu(card, &apdu);
        LOG_TEST_RET(card->ctx,result,"APDU transmit failed");
        if (apdu.resplen != 8) {
            result=sc_check_sw(card, apdu.sw1, apdu.sw2);
            goto dnie_get_challenge_error;
        }
        memcpy(rnd, apdu.resp, n);
        len -= n;
        rnd += n;
    }
    result=SC_SUCCESS;
dnie_get_challenge_error:
    LOG_FUNC_RETURN(card->ctx,result);
}

/*
 * ISO 7816-8 functions
 */

/* logout: Resets all access rights that were gained. */
static int dnie_logout(struct sc_card *card){
    if ( (card==NULL) || (card->ctx==NULL) ) return SC_ERROR_INVALID_ARGUMENTS;
    LOG_FUNC_CALLED(card->ctx);
    /* disable and free any sm channel related data */
    int result=cwa_create_secure_channel(card,dnie_priv.provider,CWA_SM_OFF);
    /* TODO: _logout() see comments.txt on what to do here */
    LOG_FUNC_RETURN(card->ctx, result);
}

/* set_security_env:  Initializes the security environment on card
 *   according to <env>, and stores the environment as <se_num> on the
 *   card. If se_num <= 0, the environment will not be stored. */
static int dnie_set_security_env(struct sc_card *card,
                                const struct sc_security_env *env, 
                                int se_num){
    sc_apdu_t apdu;
    u8 sbuf[SC_MAX_APDU_BUFFER_SIZE]; /* buffer to compose apdu data */
    u8 *p=sbuf;
    int result=SC_SUCCESS;
    if ( (card==NULL) || (card->ctx==NULL) || (env==NULL) ) 
      return SC_ERROR_INVALID_ARGUMENTS;
    LOG_FUNC_CALLED(card->ctx);

    /* check for algorithms */
    if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT) {
      switch (env->algorithm) {
        case SC_ALGORITHM_RSA: result=SC_SUCCESS; break;
        case SC_ALGORITHM_DSA: 
        case SC_ALGORITHM_EC: 
        case SC_ALGORITHM_GOSTR3410: 
        default: result=SC_ERROR_NOT_SUPPORTED; break;
      }
      LOG_TEST_RET(card->ctx,result,"Unsupported algorithm");
      if ( (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1 )==0) {
        result=SC_ERROR_NOT_SUPPORTED;
        /* TODO: 
         * Manual says that only RSA with SHA1 is supported, but found
         * some docs where states that SHA256 is also handled
         */
      }
      LOG_TEST_RET(card->ctx,result,"Only RSA with SHA1 is supported");
      /* ok: insert algorithm reference into buffer */
      *p++=0x80; /* algorithm reference tag */
      *p++=0x01; /* len */
      *p++=env->algorithm_ref & 0xff; /* val */ 
    }

    /* check for key references */
    if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
      if (env->key_ref_len!=1) result=SC_ERROR_NOT_SUPPORTED;
      LOG_TEST_RET(card->ctx,result,"Invalid key id");
      /* ok: insert key reference into buffer */
      if (env->flags & SC_SEC_ENV_KEY_REF_ASYMMETRIC) 
           *p++ = 0x83;
      else *p++ = 0x84;
      *p++ = env->key_ref_len;
      memcpy(p, env->key_ref, env->key_ref_len);
      p += env->key_ref_len;
    }

    /* check for file references */
    if (env->flags & SC_SEC_ENV_FILE_REF_PRESENT) {
      /* insert file reference into buffer */
      *p++ = 0x81;
      *p++ = env->file_ref.len;
      memcpy(p, env->file_ref.value, env->file_ref.len);
      p += env->file_ref.len;
    }

    /* create and format apdu */
    sc_format_apdu(card,&apdu,SC_APDU_CASE_3_SHORT,0x22,0x00,0x00);

    /* check and perform operation */
    switch (env->operation) {
      case SC_SEC_OPERATION_DECIPHER:
        /* TODO: Manual is unsure about if decipher() is supported */
        apdu.p1=0xC1;
        apdu.p2=0xB8;
        break;
      case SC_SEC_OPERATION_SIGN:
        apdu.p1=0x81;
        apdu.p2=0xB6;
        break;
      case SC_SEC_OPERATION_AUTHENTICATE:
        /* TODO: _set_security_env() study diffs on internal/external auth */
        apdu.p1=0xC1;
        apdu.p2=0xA4;
        break;
      default:
        LOG_FUNC_RETURN(card->ctx,SC_ERROR_INVALID_ARGUMENTS);
    }

    /* complete apdu contents with buffer data */
    apdu.data=sbuf;
    apdu.datalen=p-sbuf;
    apdu.lc=p-sbuf;
    apdu.resplen=0;
    
    /* Notice that Manual states that DNIE only allows handle of 
     * current security environment, so se_num is ignored, and
     * store sec env apdu (00 22 F2 se_num) command will not be issued */

    /* send composed apdu and parse result */
    result=sc_transmit_apdu(card,&apdu);
    LOG_TEST_RET(card->ctx,result,"Set Security Environment failed");
    result=sc_check_sw(card,apdu.sw1,apdu.sw2); 

    LOG_FUNC_RETURN(card->ctx,result);
}

/* decipher:  Engages the deciphering operation.  Card will use the
 *   security environment set in a call to set_security_env or
 *   restore_security_env. */
static int dnie_decipher(struct sc_card *card, 
                         const u8 * crgram, size_t crgram_len, 
                         u8 * out, size_t outlen){
    struct sc_apdu apdu;
    u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
    u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
    size_t len;
    int result=SC_SUCCESS;
    if ( (card==NULL) || (card->ctx==NULL) )return SC_ERROR_INVALID_ARGUMENTS;
    LOG_FUNC_CALLED(card->ctx);
    if ( (crgram==NULL) || (out==NULL) || (crgram_len>255) ) {
      LOG_FUNC_RETURN(card->ctx,SC_ERROR_INVALID_ARGUMENTS);
    }
    /* make sure that Secure Channel is on */
    result=cwa_create_secure_channel(card,dnie_priv.provider,CWA_SM_WARM);
    LOG_TEST_RET(card->ctx,result,"decipher(); Cannot establish SM");

    /* Official driver uses an undocumented proprietary APDU
     * (90 74 40 keyID). This code uses standard 00 2A 80 8x one)
     * as shown in card-atrust-acos.c and card-jcop.c
     */
    sc_format_apdu(card, &apdu, 
        SC_APDU_CASE_4_SHORT, 
        0x2A, /* INS: 0x2A  perform security operation */ 
        0x80, /* P1: Response is plain value */
        0x86  /* P2: 8x: Padding indicator byte followed by cryptogram */
    );
    apdu.resp = rbuf;
    apdu.resplen = sizeof(rbuf);

    sbuf[0] = 0; /* padding indicator byte, 0x00 = No further indication */
    memcpy(sbuf + 1, crgram, crgram_len);
    apdu.data = sbuf;
    apdu.lc = crgram_len + 1;
    apdu.datalen = crgram_len + 1;
    apdu.le = 256;
    /* send apdu */
    result = sc_transmit_apdu(card, &apdu);
    LOG_TEST_RET(card->ctx,result,"APDU transmit failed");
    /* check response */
    result=sc_check_sw(card,apdu.sw1,apdu.sw2);
    LOG_TEST_RET(card->ctx,result,"decipher returned error");
    /* responde ok: fill result data and return */
    len = apdu.resplen > outlen ? outlen : apdu.resplen;
    memcpy(out, apdu.resp, len);
    LOG_FUNC_RETURN(card->ctx, len);
}

/* compute_signature:  Generates a digital signature on the card.  Similiar
 *   to the function decipher. */
static int dnie_compute_signature(struct sc_card *card,
                                   const u8 * data, size_t datalen,
                                   u8 * out, size_t outlen){
    int result=SC_SUCCESS;
    struct sc_apdu apdu;
    u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
    u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
 
    /* some preliminar checks */
    if ((card==NULL) || (card->ctx==NULL)) return SC_ERROR_INVALID_ARGUMENTS;
    /* OK: start working */
    LOG_FUNC_CALLED(card->ctx);
    /* more checks */
    if ( (data==NULL) || (out==NULL))
      LOG_FUNC_RETURN(card->ctx,SC_ERROR_INVALID_ARGUMENTS);
    if (datalen > SC_MAX_APDU_BUFFER_SIZE || outlen > SC_MAX_APDU_BUFFER_SIZE)
      LOG_FUNC_RETURN(card->ctx,SC_ERROR_BUFFER_TOO_SMALL);

    /* ensure that secure channel is stablished */
    result=cwa_create_secure_channel(card,dnie_priv.provider,CWA_SM_WARM);
    LOG_TEST_RET(card->ctx,result,"decipher(); Cannot establish SM");
    /* (Requested by DGP): on signature operation, ask user consent */
    if (dnie_priv.rsa_key_ref==0x02) { /* TODO: revise key ID handling */
        result=ask_user_consent(card);
        LOG_TEST_RET(card->ctx,result,"User consent denied");
    }
    /* TODO _compute_signature(): handle separate hash process
       Manual says that dnie card can do hashing operations
       Some cards take care on this and compute hash before signing
       So in a further dev stage, we should take check data
       content type (plain, partial, hash) and process it
     */

    memset(&apdu,0,sizeof(struct sc_apdu)); /* clear data */
    memcpy(sbuf,data,datalen); /* copy data to buffer */
    /* compose apdu */
    /* INS: 0x2A  PERFORM SECURITY OPERATION
     * P1:  0x9E  Resp: Digital Signature
     * P2:  0x9A  Cmd: Input for Digital Signature */
    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, 0x9A);
    apdu.resp = rbuf;
    apdu.resplen = sizeof(rbuf);
    apdu.le = outlen;
    
    apdu.data = sbuf;
    apdu.lc = datalen;
    apdu.datalen = datalen;
    /* tell card to compute signature */
    result = sc_transmit_apdu(card, &apdu);
    LOG_TEST_RET(card->ctx,result,"APDU transmit failed");
    /* check response */
    result=sc_check_sw(card,apdu.sw1,apdu.sw2);
    LOG_TEST_RET(card->ctx,result,"APDU response error");
    /* ok: copy result from buffer */
    memcpy(out,rbuf,outlen);
    /* and return response length */
    LOG_FUNC_RETURN(card->ctx,apdu.resplen);
}

/*
 * ISO 7816-9 functions
 */

/**
 * parse APDU results
 */
static int dnie_check_sw(struct sc_card *card,
                         unsigned int sw1,
                         unsigned int sw2){
    int res=SC_SUCCESS;
    int n=0;
    LOG_FUNC_CALLED(card->ctx);
    /* check specific dnie errors */
    for( n=0; dnie_errors[n].SWs!=0; n++) {
      if (dnie_errors[n].SWs == ((sw1 << 8) | sw2)) {
        sc_log(card->ctx,"%s",dnie_errors[n].errorstr);
        return dnie_errors[n].errorno;
      }
    }
    /* arriving here means check for supported iso error codes */
    res=iso_ops->check_sw(card,sw1,sw2);
    LOG_FUNC_RETURN(card->ctx,res);
}

static int dnie_card_ctl(struct sc_card *card,
                         unsigned long request,
                         void *data){
    int result=SC_SUCCESS;
    if ( (card==NULL) || (card->ctx==NULL))  return SC_ERROR_INVALID_ARGUMENTS;
    LOG_FUNC_CALLED(card->ctx);
    if ( data==NULL) {
        LOG_FUNC_RETURN(card->ctx,SC_ERROR_INVALID_ARGUMENTS); 
    }
    switch(request) {
        /* obtain lifecycle status by reading card->type */
        case SC_CARDCTL_LIFECYCLE_GET:
           switch (card->type) {
               case SC_CARD_TYPE_DNIE_ADMIN: 
                    result = SC_CARDCTRL_LIFECYCLE_ADMIN; break;
               case SC_CARD_TYPE_DNIE_USER :
                    result = SC_CARDCTRL_LIFECYCLE_USER; break;
               case SC_CARD_TYPE_DNIE_BLANK:
               case SC_CARD_TYPE_DNIE_TERMINATED:
                    result = SC_CARDCTRL_LIFECYCLE_OTHER; break;
           }
           *(int*)data=result;
           LOG_FUNC_RETURN(card->ctx,SC_SUCCESS);
        /* call card to obtain serial number */
        case SC_CARDCTL_GET_SERIALNR:
           result=dnie_get_serialnr(card, (sc_serial_number_t *) data);
           LOG_FUNC_RETURN(card->ctx,result);
        case SC_CARDCTL_DNIE_GENERATE_KEY:
           /* some reports says that this card supports genkey */
           result=dnie_generate_key(card,data);
           LOG_FUNC_RETURN(card->ctx,result);
        default:
           /* default: unsupported function */
           LOG_FUNC_RETURN(card->ctx,SC_ERROR_NOT_SUPPORTED);
    }
}

static int df_acl[]= {
      SC_AC_OP_CREATE, SC_AC_OP_DELETE ,
      SC_AC_OP_REHABILITATE, SC_AC_OP_INVALIDATE,
      -1 /* !hey!, what about 5th byte of FCI info? */
    };
static int ef_acl[]= {
      SC_AC_OP_READ, SC_AC_OP_UPDATE,
      SC_AC_OP_REHABILITATE, SC_AC_OP_INVALIDATE,
      -1 /* !hey!, what about 5th byte of FCI info? */
    };

static int dnie_process_fci(struct sc_card *card,
                            struct sc_file *file,
                            const u8 *buf,
                            size_t buflen){
    int res=SC_SUCCESS;
    int *acl=df_acl;
    int n=0;
    if ((card==NULL) || (card->ctx==NULL) || (file==NULL)) return SC_ERROR_INVALID_ARGUMENTS;
    sc_context_t *ctx=card->ctx;
    LOG_FUNC_CALLED(ctx);
    /* first of all, let iso do the hard work */
    res = iso_ops -> process_fci(card,file,buf,buflen);
    LOG_TEST_RET(ctx,res,"iso7816_process_fci() failed");
    /* if tag 0x85 is received, then file->prop_attr_len should be filled
     * by sc_file_set_prop_attr() code. So check and set data according manual 
     * Note errata at pg 35 of Manual  about DF identifier (should be 0x38) */
    if(file->prop_attr_len==0) { /* no proprietary tag (0x85) received */
        res=SC_SUCCESS;
        goto dnie_process_fci_end;
    }
    /* at least 10 bytes should be received */
    if (file->prop_attr_len<10) {
        res=SC_ERROR_WRONG_LENGTH;
        goto dnie_process_fci_end;
    }
    /* byte 0 denotes file type */
    switch(file->prop_attr[0]) {
        case 0x01:
            file->type = SC_FILE_TYPE_WORKING_EF;
            file->ef_structure = SC_FILE_EF_TRANSPARENT;
            break;
        case 0x15: /* EF for keys: linear variable simple TLV */
            file->type = SC_FILE_TYPE_WORKING_EF;
            break;
        case 0x38: /* Errata: manual page 35 says wrong 0x34 */
            file->type = SC_FILE_TYPE_DF;
            break;
        default: 
            res=SC_ERROR_UNKNOWN_DATA_RECEIVED;
            goto dnie_process_fci_end;
    }
    /* bytes 1 and 2 stores file ID */
    file->id = (file->prop_attr[1] << 8) | file->prop_attr[2];
    /* bytes 3 and 4 states file length */
    file->size = (file->prop_attr[3] << 8) | file->prop_attr[4];
    /* bytes 5 to 9 states security attributes */
    /* NOTE: 
     * seems that these 5 bytes are handled according iso7816-9 sect 8.
     * but sadly that each card uses their own bits :-(
     * Moreover: Manual talks on 5 bytes, but official driver only uses 4
     * No info available (yet), so copy code from card-jcos.c and card-flex.c
     * card drivers and pray... */
    acl=(file->type==SC_FILE_TYPE_DF)? df_acl:ef_acl; 
    for(n=0;n<5;n++,acl++) {
        if (*acl==-1) continue; /* unused entry: skip */
        int key_ref=file->prop_attr[5+n] & 0x0F;
        switch(0xF0 & file->prop_attr[5+n]) {
          case 0x00: 
            sc_file_add_acl_entry(file,*acl,SC_AC_NONE,SC_AC_KEY_REF_NONE); 
            break;
          case 0x10:
          /* this tag is omitted in official code 
          case 0x20: 
          */
          case 0x30:
            sc_file_add_acl_entry(file,*acl,SC_AC_CHV,key_ref); 
            break;
          case 0x40:
            sc_file_add_acl_entry(file,*acl,SC_AC_TERM,key_ref); 
            break;
           /* these tags are omitted in official code 
          case 0x50:
            sc_file_add_acl_entry(file,*acl,SC_AC_AUT,SC_AC_KEY_REF_NONE); 
            break;
          case 0x60: 
            sc_file_add_acl_entry(file,*acl,SC_AC_CHV,key_ref); 
            sc_file_add_acl_entry(file,*acl,SC_AC_PRO,SC_AC_KEY_REF_NONE); 
            break;
          case 0x70: 
            sc_file_add_acl_entry(file,*acl,SC_AC_CHV,key_ref); 
            sc_file_add_acl_entry(file,*acl,SC_AC_PRO,SC_AC_KEY_REF_NONE); 
            break;
          case 0x80: 
            sc_file_add_acl_entry(file,*acl,SC_AC_CHV,key_ref); 
            sc_file_add_acl_entry(file,*acl,SC_AC_AUT,key_ref
            break;
          case 0x90: 
            sc_file_add_acl_entry(file,*acl,SC_AC_CHV,key_ref); 
            sc_file_add_acl_entry(file,*acl,SC_AC_AUT,key_ref); 
            break;
          */
          case 0xF0:
            sc_file_add_acl_entry(file,*acl,SC_AC_NEVER,SC_AC_KEY_REF_NONE); 
            break;
          default:
            sc_file_add_acl_entry(file,*acl,SC_AC_UNKNOWN,SC_AC_KEY_REF_NONE); 
            break;
        }
    }
    /* NOTE: Following bytes are described at DNIe manual pg 36, but No 
    documentation about what to do with following data is provided... 
    logs suggest that they are neither generated nor handled 
    so we blindy ignore....
    */
    /* byte 10 (if present) shows Control Flags for security files */
    /* bytes 11 and 12 (if present) states Control bytes for RSA crypto files */
    res=SC_SUCCESS; /* arriving here means success */
dnie_process_fci_end:
    LOG_FUNC_RETURN(card->ctx,res);
}

/* pin_cmd: verify/change/unblock command; optionally using the
 * card's pin pad if supported.
 */
static int dnie_pin_cmd(struct sc_card * card,
                        struct sc_pin_cmd_data * data,
                        int *tries_left){
    int res=SC_SUCCESS;
    int lc=SC_CARDCTRL_LIFECYCLE_USER;
    sc_apdu_t apdu;

    u8 pinbuffer[SC_MAX_APDU_BUFFER_SIZE];
    int pinlen=0;
    int padding=0;

    if ( (card==NULL) || (card->ctx==NULL) || (data==NULL) ) 
       return SC_ERROR_INVALID_ARGUMENTS;
    LOG_FUNC_CALLED(card->ctx);

    /* some flags and settings from documentation */
    data->flags &= ~SC_PIN_CMD_NEED_PADDING; /* no pin padding */
    data->apdu = &apdu; /* prepare apdu struct */

    /* ensure that card is in USER Lifecycle */
    res=dnie_card_ctl(card,SC_CARDCTL_LIFECYCLE_GET,&lc);
    LOG_TEST_RET(card->ctx,res,"Cannot get card LC status");
    if (lc!=SC_CARDCTRL_LIFECYCLE_USER) {
        LOG_FUNC_RETURN(card->ctx,SC_ERROR_INVALID_CARD);
    }

    /* ensure that secure channel is established from reset */
    res=cwa_create_secure_channel(card,dnie_priv.provider,CWA_SM_COLD);
    LOG_TEST_RET(card->ctx,res,"Establish SM failed");

    /* what about pinpad support? */
    /* NOTE: 
     * don't know how to handle pinpad throught SM channel.
     * as a temporary solution, mark use pinpad as an error 
     */
    if (data->flags & SC_PIN_CMD_USE_PINPAD ) {
        LOG_FUNC_RETURN(card->ctx,SC_ERROR_NOT_SUPPORTED);
    }

    /* only allow changes on CHV pin ) */
    switch (data->pin_type) {
      case SC_AC_CHV:  /* Card Holder Verifier */ break;
      case SC_AC_TERM: /* Terminal auth */
      case SC_AC_PRO:  /* SM auth */
      case SC_AC_AUT:  /* Key auth */
        LOG_FUNC_RETURN(card->ctx,SC_ERROR_NOT_SUPPORTED);
      default: 
        LOG_FUNC_RETURN(card->ctx,SC_ERROR_INVALID_ARGUMENTS);
    }
    /* This DNIe driver only supports VERIFY operation */
    switch (data->cmd) {
      case SC_PIN_CMD_VERIFY: break;
      case SC_PIN_CMD_CHANGE:
      case SC_PIN_CMD_UNBLOCK:
      case SC_PIN_CMD_GET_INFO:
        LOG_FUNC_RETURN(card->ctx,SC_ERROR_NOT_SUPPORTED);
      default: 
        LOG_FUNC_RETURN(card->ctx,SC_ERROR_INVALID_ARGUMENTS);
    }
    /* Arriving here means that's all checks are OK. So do task */

    /* compose pin data to be inserted in apdu*/
    if (data->flags & SC_PIN_CMD_NEED_PADDING) padding=1;
    data->pin1.offset=0;
    res=sc_build_pin(pinbuffer,sizeof(pinbuffer),&data->pin1,padding);
    if (res<0) LOG_FUNC_RETURN(card->ctx,res);
    pinlen=res;

    /* compose apdu */
    memset(&apdu, 0, sizeof(apdu)); /* clear buffer */
    apdu.cla = 0x00;
    apdu.cse = SC_APDU_CASE_3_SHORT;
    apdu.ins = (u8) 0x20; /* Verify cmd */
    apdu.p1 = (u8) 0x00;
    apdu.p2 = (u8) 0x00;
    apdu.lc = pinlen;
    apdu.datalen = pinlen;
    apdu.data = pinbuffer;
    apdu.resplen = 0;
    apdu.le = 0;

    /* and send to card throught virtual channel */
    res=sc_transmit_apdu(card,&apdu);
    LOG_TEST_RET(card->ctx,res,"VERIFY APDU Transmit fail");
    
    /* check response and if requested setup tries_left */
    if (tries_left!=NULL) { /* returning tries_left count is requested */
      if ( (apdu.sw1==0x63) && ((apdu.sw2 & 0xF0)==0xC0) ) {
        *tries_left=apdu.sw2&0x0F;
        LOG_FUNC_RETURN(card->ctx,SC_ERROR_PIN_CODE_INCORRECT);
      }
    }
    res=dnie_check_sw(card,apdu.sw1,apdu.sw2); /* not a pinerr: parse result */
 
    /* the end: a bit of Mister Proper and return */
    memset(&apdu, 0, sizeof(apdu)); /* clear buffer */
    data->apdu = NULL;
    LOG_FUNC_RETURN(card->ctx,res);
}

/**********************************************************************/

static sc_card_driver_t *get_dnie_driver(void) {
    sc_card_driver_t *iso_drv = sc_get_iso7816_driver();

    /* memcpy() from standard iso7816 declared operations */
    if (iso_ops == NULL) iso_ops   = iso_drv->ops;
    dnie_ops                       = *iso_drv->ops;

    /* fill card specific function pointers */
    /* if pointer is omitted, default ISO7816 function will be used */

    /* initialization */
    dnie_ops.match_card            = dnie_match_card;
    dnie_ops.init                  = dnie_init;
    dnie_ops.finish                = dnie_finish;
    dnie_ops.wrap_apdu             = dnie_wrap_apdu;

    /* iso7816-4 functions */
    /* dnie_ops.read_binary */
    /* dnie_ops.write_binary */
    /* dnie_ops.update_binary */
    /* dnie_ops.erase_binary */
    /* dnie_ops.read_record */
    /* dnie_ops.write_record */
    /* dnie_ops.append_record */
    /* dnie_ops.update_record */
    dnie_ops.select_file           = dnie_select_file;
    /* dnie_ops.get_response */
    dnie_ops.get_challenge         = dnie_get_challenge;

    /* iso7816-8 functions */
    /* dnie_ops.verify */
    dnie_ops.logout                = dnie_logout;
    /* dnie_ops.restore_security_env */
    dnie_ops.set_security_env      = dnie_set_security_env; 
    dnie_ops.decipher              = dnie_decipher;
    dnie_ops.compute_signature     = dnie_compute_signature;
    /* dnie_ops.change_reference_data */
    /* dnie_ops.reset_retry_counter */

    /* iso7816-9 functions */
    dnie_ops.create_file           = NULL; /* not allowed on DNIe user mode*/
    dnie_ops.delete_file           = NULL;
    /* dnie_ops.list_files */
    dnie_ops.check_sw              = dnie_check_sw;
    dnie_ops.card_ctl              = dnie_card_ctl; 
    dnie_ops.process_fci           = dnie_process_fci;
    /* dnie_ops.construct_fci */
    dnie_ops.pin_cmd               = dnie_pin_cmd;
    /* dnie_ops.get_data */
    /* dnie_ops.put_data */
    /* dnie_ops.delete_record */

    return &dnie_driver;
}

sc_card_driver_t * sc_get_dnie_driver(void) {
    return get_dnie_driver();
}

#undef __CARD_DNIE_C__

#endif /* ENABLE_OPENSSL */
