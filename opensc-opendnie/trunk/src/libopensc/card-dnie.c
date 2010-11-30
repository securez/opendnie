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

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>

#include "opensc.h"
#include "cardctl.h"
#include "internal.h"
#include "config.h"
#include "dnie.h"

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

#define DNIE_CHIP_NAME "DNIe: Spanish eID card"
#define DNIE_CHIP_SHORTNAME "dnie"

/* default user consent program (if required) */
#define USER_CONSENT_CMD "/usr/bin/pinentry"

/* Undeclared dnie APDU responses in iso7816.c */
static struct sc_card_error dnie_errors[] = {
    { 0x6688, SC_ERROR_UNKNOWN, "Secure Message value is incorrect" },
    { 0x6A89, SC_ERROR_FILE_ALREADY_EXISTS, "File/Key already exists" },
    { 0,0,NULL }
};

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

static struct dnie_private_data dnie_priv;
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
   sc_debug(card->ctx,SC_LOG_DEBUG_NORMAL,"Libassuan support is off. User Consent disabled");
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
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    dnie_get_environment(card->ctx,&dnie_priv);
    if (dnie_priv.user_consent_enabled==0) {
        sc_debug(card->ctx,SC_LOG_DEBUG_NORMAL,"User Consent is disabled in configuration file");
        return SC_SUCCESS;
    }
    res=stat(dnie_priv.user_consent_app,&buf);
    if (res!=0) {
      /* TODO: check that pinentry file is executable */
      sc_debug(card->ctx,SC_LOG_DEBUG_NORMAL,"Invalid pinentry application: %s\n",dnie_priv.user_consent_app);
       SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_NORMAL,SC_ERROR_INVALID_ARGUMENTS);
    }
    argv[0]=dnie_priv.user_consent_app;
    argv[1]=NULL;
    argv[2]=NULL;
    noclosefds[0]= fileno(stderr);
    noclosefds[1]= ASSUAN_INVALID_FD;
#ifdef HAVE_LIBASSUAN_2
    res = assuan_new(&ctx);
    if (res!=0) {
      sc_debug(card->ctx,SC_LOG_DEBUG_NORMAL,"Can't create the User Consent environment: %s\n",_gpg_error(res));
      SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_NORMAL,SC_ERROR_INTERNAL);
    }
    res = assuan_pipe_connect(ctx,dnie_priv.user_consent_app,argv,noclosefds,NULL,NULL,0);
#else 
    res = assuan_pipe_connect(&ctx,dnie_priv.user_consent_app,argv,0);
#endif
    if (res!=0) {
        sc_debug(card->ctx,SC_LOG_DEBUG_NORMAL,"Can't connect to the User Consent module: %s\n",_gpg_error(res));
        res=SC_ERROR_INVALID_ARGUMENTS; /* invalid or not available pinentry */
        goto exit;
    }
    res = assuan_transact(
       ctx, 
       "SETDESC Está a punto de realizar una firma electrónica con su clave de FIRMA del DNI electrónico. ¿Desea permitir esta operación?", 
       NULL, NULL, NULL, NULL, NULL, NULL);
    if (res!=0) {
       sc_debug(card->ctx,SC_LOG_DEBUG_NORMAL,"SETDESC: %s\n", _gpg_error(res));
       res=SC_ERROR_CARD_CMD_FAILED; /* perhaps should use a better errcode */
       goto exit;
    }
    res = assuan_transact(ctx,"CONFIRM",NULL,NULL,NULL,NULL,NULL,NULL);
#ifdef HAVE_LIBASSUAN_1
    if (res == ASSUAN_Canceled) {
       sc_debug(card->ctx,SC_LOG_DEBUG_VERBOSE,"CONFIRM: signature cancelled by user");
       res= SC_ERROR_NOT_ALLOWED;
       goto exit;
    }
#endif
    if (res) {
       sc_debug(card->ctx,SC_LOG_DEBUG_NORMAL,"SETERROR: %s\n",_gpg_error(res));
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
    SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_NORMAL,res);
}
#endif

/**
 * Select a file from card, process fci and if path is not A DF
 * read data and store into cache
 * This is done by mean of iso_select_file() and iso_read_binary()
 * If path stands for a DNIe certificate, test for uncompress data
 *@param card pointer to sc_card data
 *@param path pathfile
 *@param file pointer to resulting file descriptor
 *@param buffer pointer to buffer where to store file contents
 *@param length length of buffer data
 *@return SC_SUCCESS if ok; else error code
 */
int dnie_read_file(
        sc_card_t *card,
        const sc_path_t *path,
        sc_file_t **file,
        u8 **buffer,
        size_t *length
        ) {
    u8 *data;
    int res = SC_SUCCESS;
    assert( (card!=NULL) && (card->ctx!=NULL) && (path!=NULL) );
    sc_context_t *ctx= card->ctx;
    SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
    if (!buffer && !length) /* check received arguments */
        SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_VERBOSE,SC_ERROR_INVALID_ARGUMENTS);
    /* try to adquire lock on card */
    res=sc_lock(card);
    SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, res, "sc_lock() failed");
    /* select file by mean of iso7816 ops */
    res=iso_ops->select_file(card,path,file);
    if (res!=SC_SUCCESS) goto dnie_read_file_err;
    /* iso's select file calls if needed process_fci, so arriving here
     * we have file structure filled.
     */
    if ((*file)->type==SC_FILE_TYPE_DF) {
        /* just a DF, no need to read_binary() */
        *buffer=NULL;
        *length=0;
        res=SC_SUCCESS;
        goto dnie_read_file_end;
    }
    /* reserve enought space to read data from card*/
    if((*file)->size <= 0) {
        res = SC_ERROR_FILE_TOO_SMALL;
        goto dnie_read_file_err;
    }
    data=calloc((*file)->size,sizeof(u8));
    if (data==NULL) {
        res = SC_ERROR_OUT_OF_MEMORY;
        goto dnie_read_file_err;
    }
    /* call iso7816 read_binary() to retrieve data */
    res=iso_ops->read_binary(card,0,data,(*file)->size,0L);
    if (res<0) { /* read_binary returns number of bytes readed */
        res = SC_ERROR_CARD_CMD_FAILED;
        goto dnie_read_file_err;
    }
    *buffer=data;
    *length=res;
    /* now check if needed to uncompress data */
    /* TODO: dnie_read_file() check if uncompress data is required */
    /* arriving here means success */
    res=SC_SUCCESS;
    goto dnie_read_file_end;
dnie_read_file_err:
    if (*file) sc_file_free(*file);
dnie_read_file_end:
    sc_unlock(card);
    SC_FUNC_RETURN(ctx,SC_LOG_DEBUG_NORMAL,res);
}

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
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    /* TODO: write dnie_generate_key() */
    SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_VERBOSE,result);
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
    u8        rbuf[SC_MAX_APDU_BUFFER_SIZE];
    /* 
     * TODO: get_serialnr() this function seems to be duplicated 
     * on many cards, just variyng sent APDU. Look for integration
     */
    if ( (card==NULL) || (serial==NULL) ) return SC_ERROR_INVALID_ARGUMENTS;
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    if (card->type!=SC_CARD_TYPE_DNIE_USER) return SC_ERROR_NOT_SUPPORTED;
    /* if serial number is cached, use it */
    if (card->serialnr.len) {
        memcpy(serial, &card->serialnr, sizeof(*serial));
        return SC_SUCCESS;
    }
    /* not cached, retrieve it by mean of an APDU */
    sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xb8, 0x00, 0x00);
    apdu.cla = 0x90;
    apdu.resp = rbuf;
    apdu.resplen = sizeof(rbuf);
    apdu.le   = 0x11;
    apdu.lc   = 0;
    apdu.datalen = 0;
    /* send apdu */
    result=sc_transmit_apdu(card,&apdu);
    SC_TEST_RET(card->ctx,SC_LOG_DEBUG_NORMAL,result,"APDU transmit failed");
    if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00) return SC_ERROR_INTERNAL;
    /* cache serial number */
    /* According to doc only first seven bytes from response are meaningfull */
    memcpy(card->serialnr.value, apdu.resp, 7*sizeof(u8));
    card->serialnr.len = 7*sizeof(u8);
    /* copy and return serial number */
    memcpy(serial, &card->serialnr, sizeof(*serial));
    return SC_SUCCESS;
}

/**************************** sc_card_operations **********************/

/* Generic operations */

/* Called in sc_connect_card().  Must return 1, if the current
 * card can be handled with this driver, or 0 otherwise.  ATR
 * field of the sc_card struct is filled in before calling
 * this function. */
static int dnie_match_card(struct sc_card *card){
    int result=0;
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    int matched=_sc_match_atr(card,dnie_atrs,&card->type);
    result=(matched>=0)? SC_SUCCESS:SC_ERROR_NO_CARD_SUPPORT;
    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,result);
}

/* Called when ATR of the inserted card matches an entry in ATR
 * table.  May return SC_ERROR_INVALID_CARD to indicate that
 * the card cannot be handled with this driver. */
static int dnie_init(struct sc_card *card){
    int result=SC_SUCCESS;
    assert(card!=NULL);
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

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

    /* initialize SM to none */
    result=dnie_sm_init(card,&dnie_priv.sm_handler,DNIE_SM_NONE);
    if (result!=SC_SUCCESS) goto dnie_init_error;
    card->drv_data=&dnie_priv;
     
    /* set up flags according documentation */
    card->name = DNIE_CHIP_SHORTNAME;
    card->cla  = 0x00; // card uses default APDU class (interindustry)
    card->caps |=SC_CARD_CAP_RNG; /* we have a random number generator */
    card->max_send_size=256;
    card->max_recv_size=256;

    unsigned long algoflags = SC_ALGORITHM_RSA_RAW; /* RSA support */
    algoflags    |= SC_ALGORITHM_RSA_HASH_NONE;
    _sc_card_add_rsa_alg(card,1024,algoflags,0);
    _sc_card_add_rsa_alg(card,2048,algoflags,0);
    
    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
dnie_init_error:
    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL,result);
}

/* Called when the card object is being freed.  finish() has to
 * deallocate all possible private data. */
static int dnie_finish(struct sc_card *card) {
    int result=SC_SUCCESS;
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    /* disable sm channel if stablished */
    dnie_sm_init(card, &dnie_priv.sm_handler, DNIE_SM_NONE);
    /* free any cached data */
    dnie_file_cache_t *pt=dnie_priv.cache_top;
    while(pt!=NULL) {
        dnie_file_cache_t *next=pt->next;
	if (!pt->file) sc_file_free(pt->file);
        if (!pt->data) free(pt->data);
        free(pt);
        pt=next;
    }
    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,result);
}

/* Called before invoke card_driver->ops->transmit.
 * for performing APDU wrap(flag=0) or unwrap(flag=1)
 * If set to NULL no wrapping process will be done
 * Usefull on Secure Messaging APDU encode/decode
 * Returns SC_SUCCESS or error code */
static int dnie_wrap_apdu(sc_card_t *card, sc_apdu_t *from,sc_apdu_t *to,int flag) {
    int res=SC_SUCCESS;
    assert( (card!=NULL) && (from!=NULL) && (to!=NULL) );
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    if (dnie_priv.sm_handler==NULL) { /* not initialized yet: time to do */
        res=dnie_sm_init(card,&dnie_priv.sm_handler,DNIE_SM_NONE);
        if (res!=SC_SUCCESS) SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_NORMAL,res);
    }
    /* encode/decode apdu */
    res=dnie_sm_wrap_apdu(card,dnie_priv.sm_handler,from,to,flag);
    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,res);
}

/* ISO 7816-4 functions */

static int dnie_read_binary(struct sc_card *card, 
                       unsigned int idx,
                       u8 * buf,
                       size_t count,
                       unsigned long flags){
    int result=SC_SUCCESS;
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    /* TODO: dnie_read_binary: detect and use cache */
    /* data is not cached: use std iso function */
    result=iso_ops->read_binary(card,idx,buf,count, flags);
    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,result);
}

/* select_file: Does the equivalent of SELECT FILE command specified
 *   in ISO7816-4. Stores information about the selected file to
 *   <file>, if not NULL. */
static int dnie_select_file(struct sc_card *card,
                       const struct sc_path *path,
                       struct sc_file **file_out){
    int result=SC_SUCCESS;
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    /* Manual says that some special paths store data in compressed
     * format. So trap those paths, and perform file_read() & uncompress.
     * in that way next read_binary call will use catched data */
    /* find file in cache */
    dnie_file_cache_t *pt=dnie_priv.cache_top;
    for (; pt!=NULL; pt=pt->next) {
        if (!sc_compare_path(path,&(pt->file->path))) continue;
        /* file found in cache */
        dnie_priv.cache_pt=pt;
        *file_out=pt->file;
        SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
    }
    /* arriving here means file is not in cache: read and store */
    /* create a new cache entry */
    dnie_file_cache_t *cache=
        (dnie_file_cache_t *)calloc(1,sizeof(dnie_file_cache_t));
    if (cache==NULL) {
        result=SC_ERROR_OUT_OF_MEMORY;
        goto select_file_error;
    }
    /* allocate a new file entry */
    cache->file=sc_file_new();
    if (cache->file==NULL) {
        result=SC_ERROR_OUT_OF_MEMORY;
        goto select_file_error;
    } 
    /* do file read */
    result=dnie_read_file(card,path,&cache->file,&cache->data,&cache->datalen);
    if (result!=SC_SUCCESS) goto select_file_error;
    /* add entry at the begining of cache list */
    cache->next=dnie_priv.cache_top;
    dnie_priv.cache_top=cache;
    dnie_priv.cache_pt=cache;
    /* and set up return values */
    *file_out=cache->file;
    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL,SC_SUCCESS);
select_file_error:
    if (cache && cache->file) sc_file_free(cache->file);
    if (cache) free(cache);
    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL,result);
}

static int dnie_get_challenge(struct sc_card *card,
                         u8 * buf,
                         size_t count){
    int result=SC_SUCCESS;
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    /* TODO: _get_challenge() write */
    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,result);
}

/*
 * ISO 7816-8 functions
 */

/* logout: Resets all access rights that were gained. */
static int dnie_logout(struct sc_card *card){
    assert(card && card->ctx);
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    /* disable and free any sm channel related data */
    int result=dnie_sm_init(card,&dnie_priv.sm_handler,DNIE_SM_NONE);
    /* TODO: _logout() see comments.txt on what to do here */
    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,result);
}

/* set_security_env:  Initializes the security environment on card
 *   according to <env>, and stores the environment as <se_num> on the
 *   card. If se_num <= 0, the environment will not be stored. */
static int dnie_set_security_env(struct sc_card *card,
                                const struct sc_security_env *env, 
                                int se_num){
    sc_apdu_t apdu;
    int result=SC_SUCCESS;
    if ( (card==NULL) || (env==NULL) ) 
      SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_VERBOSE,SC_ERROR_INVALID_ARGUMENTS);
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    /* check algorithms and keys */
    if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT) {
      /* TODO: _set_security_env() revise algoritms. 
       * Manual says that only RSA with SHA1 is supported, but found
       * some docs where states that SHA256 is also handled
       */
    }
    if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
      /* TODO: _set_security_env() check key id reference */
    }
    /* check and perform operation */
    switch (env->operation) {
      case SC_SEC_OPERATION_DECIPHER:
        /* TODO: _set_security_env() revise if decipher() is supported
        * not sure if supported: DGP's driver implements nonstandard
        * decipher() function. Assumed here standard is supported too
        */
        sc_format_apdu(card,&apdu,SC_APDU_CASE_3_SHORT,0x22,0xC1,0xB8);
        /* TODO: _set_security_env() fill decipher() apdu data */
        break;
      case SC_SEC_OPERATION_SIGN:
        sc_format_apdu(card,&apdu,SC_APDU_CASE_3_SHORT,0x22,0x81,0xB6);
        /* TODO: _set_security_env() fill signature() apdu data */
        break;
      case SC_SEC_OPERATION_AUTHENTICATE:
        /* TODO: _set_security_env() study diffs on internal/external auth */
        sc_format_apdu(card,&apdu,SC_APDU_CASE_3_SHORT,0x22,0xC1,0xA4);
        /* TODO: _set_security_env() fill authenticate() apdu data */
        break;
      default:
        SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_VERBOSE,SC_ERROR_INVALID_ARGUMENTS);
    }
    /* send composed apdu and retrieve result */
    result=sc_transmit_apdu(card,&apdu);
    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,result);
}

/* decipher:  Engages the deciphering operation.  Card will use the
 *   security environment set in a call to set_security_env or
 *   restore_security_env. */
static int dnie_decipher(struct sc_card *card, 
                         const u8 * crgram,
                         size_t crgram_len, 
                         u8 * out,
                         size_t outlen){
    int result=SC_SUCCESS;
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    /* TODO: _decipher() write */
    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,result);
}

/* compute_signature:  Generates a digital signature on the card.  Similiar
 *   to the function decipher. */
static int dnie_compute_signature(struct sc_card *card,
                                   const u8 * data,
                                   size_t datalen,
                                   u8 * out,
                                   size_t outlen){
    int result=SC_SUCCESS;
    struct sc_apdu apdu;
    u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
    u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
 
    /* some preliminar checks */
    if ((card==NULL) || (data==NULL) || (out==NULL))
      SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL,SC_ERROR_INVALID_ARGUMENTS);
    if (datalen > SC_MAX_APDU_BUFFER_SIZE || outlen > SC_MAX_APDU_BUFFER_SIZE)
      SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL,SC_ERROR_BUFFER_TOO_SMALL);

    /* OK: start working */
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    /* ensure that secure channel is stablished */
    result=dnie_sm_init(card,&dnie_priv.sm_handler,DNIE_SM_INTERNAL);
    if (result!=SC_SUCCESS) goto signature_error;
    /* (Requested by DGP): on signature operation, ask user consent */
    if (dnie_priv.rsa_key_ref==0x02) { /* TODO: revise key ID handling */
        result=ask_user_consent(card);
        if (result!=SC_SUCCESS) goto signature_error;
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
    SC_TEST_RET(card->ctx,SC_LOG_DEBUG_NORMAL,result,"APDU transmit failed");
    /* check response */
    result=sc_check_sw(card,apdu.sw1,apdu.sw2);
    if (result!=SC_NO_ERROR) goto signature_error;
    memcpy(out,rbuf,outlen); /* copy result from buffer */
    /* and return response length */
    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL,apdu.resplen);
signature_error:
    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,result);
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
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    /* check specific dnie errors */
    for( n=0; dnie_errors[n].SWs!=0; n++) {
      if (dnie_errors[n].SWs == ((sw1 << 8) | sw2)) {
        sc_debug(card->ctx,SC_LOG_DEBUG_NORMAL,"%s",dnie_errors[n].errorstr);
        return dnie_errors[n].errorno;
      }
    }
    /* arriving here means check for supported iso error codes */
    res=iso_ops->check_sw(card,sw1,sw2);
    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,res);
}

static int dnie_card_ctl(struct sc_card *card,
                         unsigned long request,
                         void *data){
    int result=SC_SUCCESS;
    if ( card==NULL) return SC_ERROR_INVALID_ARGUMENTS;
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
    if ( data==NULL) {
        SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL,SC_ERROR_INVALID_ARGUMENTS); 
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
           SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
        /* call card to obtain serial number */
        case SC_CARDCTL_GET_SERIALNR:
           result=dnie_get_serialnr(card, (sc_serial_number_t *) data);
           SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_VERBOSE,result);
        case SC_CARDCTL_DNIE_GENERATE_KEY:
           /* some reports says that this card supports genkey */
           result=dnie_generate_key(card,data);
           SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_VERBOSE,result);
        default:
           /* default: unsupported function */
           SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_NORMAL,SC_ERROR_NOT_SUPPORTED);
    }
}

static int df_acl[]= {
      SC_AC_OP_CREATE, SC_AC_OP_DELETE ,
      SC_AC_OP_REHABILITATE, SC_AC_OP_INVALIDATE
      /* !hey!, what about 5th byte of FCI info? */
    };
static int ef_acl[]= {
      SC_AC_OP_READ, SC_AC_OP_UPDATE,
      SC_AC_OP_REHABILITATE, SC_AC_OP_INVALIDATE
      /* !hey!, what about 5th byte of FCI info? */
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
    SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
    /* first of all, let iso do the hard work */
    res = iso_ops -> process_fci(card,file,buf,buflen);
    SC_TEST_RET(ctx,SC_LOG_DEBUG_NORMAL,res,"iso7816_process_fci() failed");
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
    for(n=0;n<4;n++,acl++) {
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
    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,res);
}

/* pin_cmd: verify/change/unblock command; optionally using the
 * card's pin pad if supported.
 */
static int dnie_pin_cmd(struct sc_card * card,
                        struct sc_pin_cmd_data * data,
                        int *tries_left){
    int res=SC_SUCCESS;
    sc_apdu_t apdu;

    u8 pinbuffer[SC_MAX_APDU_BUFFER_SIZE];
    int pinlen=0;
    int padding=0;

    if ( (card==NULL) || (data==NULL) ) 
       SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_NORMAL,SC_ERROR_INVALID_ARGUMENTS);
    SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

    /* some flags and settings from documentation */
    data->flags &= ~SC_PIN_CMD_NEED_PADDING; /* no pin padding */
    data->apdu = &apdu; /* prepare apdu struct */

    /* ensure that secure channel is established */
    res=dnie_sm_init(card,&dnie_priv.sm_handler,DNIE_SM_INTERNAL);
    if (res!=SC_SUCCESS) SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_NORMAL,res);

    /* TODO: _pin_cmd() ensure that card is in USER Lifecycle */
    /* TODO: _pin_cmd() what about pinpad support? */

    /* only allow changes on CHV pin ) */
    switch (data->pin_type) {
      case SC_AC_CHV:  /* Card Holder Verifier */ break;
      case SC_AC_TERM: /* Terminal auth */
      case SC_AC_PRO:  /* SM auth */
      case SC_AC_AUT:  /* Key auth */
        SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_NORMAL,SC_ERROR_NOT_SUPPORTED);
      default: 
        SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_NORMAL,SC_ERROR_INVALID_ARGUMENTS);
    }
    /* This DNIe driver only supports VERIFY operation */
    switch (data->cmd) {
      case SC_PIN_CMD_VERIFY: break;
      case SC_PIN_CMD_CHANGE:
      case SC_PIN_CMD_UNBLOCK:
      case SC_PIN_CMD_GET_INFO:
        SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_NORMAL,SC_ERROR_NOT_SUPPORTED);
      default: 
        SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_NORMAL,SC_ERROR_INVALID_ARGUMENTS);
    }
    /* Arriving here means that's all checks are OK. So do task */

    /* compose pin data to be inserted in apdu*/
    if (data->flags & SC_PIN_CMD_NEED_PADDING) padding=1;
    data->pin1.offset=0;
    res=sc_build_pin(pinbuffer,sizeof(pinbuffer),&data->pin1,padding);
    if (res<0) SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_NORMAL,res);
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
    SC_TEST_RET(card->ctx,SC_LOG_DEBUG_NORMAL,res,"VERIFY APDU Transmit fail");
    
    /* check response and if requested setup tries_left */
    if (tries_left!=NULL) { /* returning tries_left count is requested */
      if ( (apdu.sw1==0x63) && ((apdu.sw2 & 0xF0)==0xC0) ) {
        *tries_left=apdu.sw2&0x0F;
        SC_FUNC_RETURN(card->ctx,SC_LOG_DEBUG_VERBOSE,SC_ERROR_PIN_CODE_INCORRECT);
      }
    }
    res=dnie_check_sw(card,apdu.sw1,apdu.sw2); /* not a pinerr: parse result */
 
    /* the end: a bit of Mister Proper and return */
    memset(&apdu, 0, sizeof(apdu)); /* clear buffer */
    data->apdu = NULL;
    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,res);
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
    dnie_ops.read_binary           = dnie_read_binary;
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
