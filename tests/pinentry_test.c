
#include <stdio.h>
#include <assuan.h>
#include <stdarg.h>
#include <stdlib.h>

#ifndef PIN_ENTRY
#define PIN_ENTRY "/usr/bin/pinentry"
#endif

static char *user_consent_app=PIN_ENTRY;

/* check for libassuan version */
#ifndef ASSUAN_No_Error
# define HAVE_ASSUAN_2
# define _gpg_error(t) gpg_error((t))
#else
# define HAVE_ASSUAN_1
# define _gpg_error(t) assuan_strerror( (AssuanError) (t) )
#endif


int ask_user_consent() {
    int res;
    const char *argv[3];
    assuan_fd_t noclosefds[2];
    assuan_context_t ctx; 
    argv[0]=user_consent_app;
    argv[1]=NULL;
    argv[2]=NULL;
    noclosefds[0]= fileno(stderr);
    noclosefds[1]= ASSUAN_INVALID_FD;
#ifdef HAVE_ASSUAN_2
    res = assuan_new(&ctx);
    if (res!=0) {
      fprintf(stderr,"Can't create the User Consent environment: %s\n",_gpg_error(res));
      return -1;
    }
    res = assuan_pipe_connect(ctx,user_consent_app,argv,noclosefds,NULL,NULL,0);
#else 
    res = assuan_pipe_connect(&ctx,user_consent_app,argv,0);
#endif
    if (res!=0) {
        fprintf(stderr,"Can't connect to the User Consent module: %s\n",_gpg_error(res));
        goto exit;
    }
    res = assuan_transact(
       ctx, 
       "SETDESC Está a punto de realizar una firma electrónica con su certificado de FIRMA del DNI electrónico.¿Desea permitir esta operación?", 
       NULL, NULL, NULL, NULL, NULL, NULL);
    if (res!=0) {
       fprintf(stderr,"SETDESC: %s\n", _gpg_error(res));
       goto exit;
    }
    res = assuan_transact(ctx,"CONFIRM",NULL,NULL,NULL,NULL,NULL,NULL);
#ifdef HAVE_ASSUAN_1
    if (res == ASSUAN_Canceled) {
       fprintf(stderr,"Sign cancelled by user");
       goto exit;
    }
#endif
    if (res) {
       fprintf(stderr,"SETERROR: %s\n",_gpg_error(res));
     } else {
       res=0;
     }
exit:
#ifdef HAVE_ASSUAN_2
    assuan_release(ctx);
#else
    assuan_disconnect(ctx);
#endif
    return res;
}

int main(int argc,char *argv[]) {
	return ask_user_consent();
}
