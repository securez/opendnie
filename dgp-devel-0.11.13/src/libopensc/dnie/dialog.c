/*
 * User consent function
 * Based on dialog.c from opensc-0.11.14
 * And original code from DGP's DNIe module
 */

/* 
 * IMPORTANT NOTICE:
 * This code may don't work on:
 * - Headless systems
 * - Sites without pinentry / libassuan properly installed
 * So to handle this, we provide several flags at /etc/opensc.conf:
 * ....
 *     card_driver dnie {
 *          # Enable/Disable user consent on signing (default: enable)
 *          user_consent_enabled = true;
 *          # Program to be used for ask confirmation (default: pinentry)
 *          user_consent_app = /usr/bin/pinentry;
 *     }
 * .....
 * NOTICE that disable User Consent may result on unnoticed signing if 
 * used on unsecure environments and/or with bad designed/uncertified apps
 *
 */

#include <stdio.h>
#include <assuan.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <opensc/opensc.h>
#include <opensc/errors.h>
#include <opensc/log.h>

#ifndef PIN_ENTRY
#define PIN_ENTRY "/usr/bin/pinentry"
#endif

static char *user_consent_app=PIN_ENTRY;
static int  user_consent_enabled=1; /* default true */

/* check for libassuan version */
#ifndef ASSUAN_No_Error
#define HAVE_ASSUAN_2
#define _gpg_error(t) gpg_strerror((t))
#else
#define HAVE_ASSUAN_1
#define _gpg_error(t) assuan_strerror( (AssuanError) (t) )
#endif


/**
 * Parse configuration file to extract user consent flags
 */
static int get_user_consent_env(sc_context_t *ctx) {
    int i;
    scconf_block **blocks, *blk;
    for (i = 0; ctx->conf_blocks[i]; i++) {
        blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],"card_driver","dnie");
        if (!blocks) continue;
        blk=blocks[0];
        free(blocks);
        if (blk==NULL) continue;
        user_consent_app = scconf_get_str(blk,"user_consent_app",PIN_ENTRY); 
        user_consent_enabled = scconf_get_bool(blk,"user_consent_enabled",1);
    }
    return SC_SUCCESS;
}

int ask_user_consent(sc_card_t *card) {
    int res;
    struct stat buf;
    const char *argv[3];
    assuan_fd_t noclosefds[2];
    assuan_context_t ctx; 
    if ( (card==NULL) || (card->ctx==NULL)) return SC_ERROR_INVALID_ARGUMENTS;
    get_user_consent_env(card->ctx);
    res=stat(user_consent_app,&buf);
    if (res!=0) {
      /* TODO: check that pinentry file is executable */
      sc_debug(card->ctx,"Invalid pinentry application: %s\n",user_consent_app);
      SC_FUNC_RETURN(card->ctx,1,SC_ERROR_INVALID_ARGUMENTS);
    }
    argv[0]=user_consent_app;
    argv[1]=NULL;
    argv[2]=NULL;
    noclosefds[0]= fileno(stderr);
    noclosefds[1]= ASSUAN_INVALID_FD;
#ifdef HAVE_ASSUAN_2
    res = assuan_new(&ctx);
    if (res!=0) {
      sc_debug(card->ctx,"Can't create the User Consent environment: %s\n",_gpg_error(res));
      SC_FUNC_RETURN(card->ctx,1,SC_ERROR_INVALID_ARGUMENTS);
    }
    res = assuan_pipe_connect(ctx,user_consent_app,argv,noclosefds,NULL,NULL,0);
#else 
    res = assuan_pipe_connect(&ctx,user_consent_app,argv,0);
#endif
    if (res!=0) {
        sc_debug(card->ctx,"Can't connect to the User Consent module: %s\n",_gpg_error(res));
        res=SC_ERROR_INVALID_ARGUMENTS; /* invalid or not available pinentry */
        goto exit;
    }
    res = assuan_transact(
       ctx, 
       "SETDESC Está a punto de realizar una firma electrónica con su clave de FIRMA del DNI electrónico.¿Desea permitir esta operación?", 
       NULL, NULL, NULL, NULL, NULL, NULL);
    if (res!=0) {
       sc_debug(card->ctx,"SETDESC: %s\n", _gpg_error(res));
       res=SC_ERROR_CARD_CMD_FAILED; /* perhaps should use a better errcode */
       goto exit;
    }
    res = assuan_transact(ctx,"CONFIRM",NULL,NULL,NULL,NULL,NULL,NULL);
#ifdef HAVE_ASSUAN_1
    if (res == ASSUAN_Canceled) {
       sc_debug(card->ctx,"Sign cancelled by user");
       res= SC_ERROR_NOT_ALLOWED;
       goto exit;
    }
#endif
    if (res) {
       sc_debug(card->ctx,"SETERROR: %s\n",_gpg_error(res));
       res=SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
     } else {
       res=SC_SUCCESS;
     }
exit:
#ifdef HAVE_ASSUAN_2
    assuan_release(ctx);
#else
    assuan_disconnect(ctx);
#endif
    SC_FUNC_RETURN(card->ctx,1,res);
}
