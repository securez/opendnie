#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#ifndef PIN_ENTRY
#define PIN_ENTRY "/usr/bin/pinentry"
#endif

char *messages[] = {
    "SETTITLE Signature requested\n",
    "SETDESC A signature operation is to be done. ok or cancel?\n",
    "CONFIRM\n",
    "BYE\n",
    NULL
};

int do_task(char *prog) {
  int srv_send[2]; /* to send data from server to client */
  int srv_recv[2]; /* to receive data from client to server */
  pid_t pid;       /* child process id */
  char buf[1024];  /* to store client responses */
  char *msg=NULL;  /* to makr errors */
  int res=0;       /* read/write results */
  int n=0;         /* to iterate on to-be-sent messages */
  FILE *fin,*fout; /* to handle pipes as streams */

  /* In a pipe, xx[0] is for reading, xx[1] is for writing */
  if (pipe(srv_send) < 0) { msg="pipe(srv_send)"; goto do_error; }
  if (pipe(srv_recv) < 0) { msg="pipe(srv_recv)"; goto do_error; }
  pid=fork();
  switch(pid) {
     case -1: /* error  */
        msg="fork()";
        goto do_error;
     case 0:  /* child  */
        /* make our pipes, our new stdin & stderr, closing older ones */
        dup2(srv_send[0],STDIN_FILENO); /* client: map srv send for input */
        dup2(srv_recv[1],STDOUT_FILENO); /* client: map srv_recv for output */
        /* once dup2'd pipes are no longer needed on client; so close */
        close(srv_send[0]);
        close(srv_send[1]);
        close(srv_recv[0]);
        close(srv_recv[1]);
        /* Over-write the child process with the requested binary */
        execlp(prog, prog,(char *)NULL); /* if ok should never return */
        msg="execlp() error";
        goto do_error;
     default: /* parent */
        /* Close the pipe ends that the child uses to read from / write to so
         * the when we close the others, an EOF will be transmitted properly.
        */
        close(srv_send[0]);
        close(srv_recv[1]);
        fin=fdopen(srv_recv[0],"r");
        if (fin==NULL) { msg="fdopen(in)"; goto do_error; }
        fout=fdopen(srv_send[1],"w");
        if (fout==NULL) { msg="fdopen(out)"; goto do_error; }
        /* read and ignore first line */
        fflush(stdin);
        for (n=0; messages[n] != NULL ; n++) {
            /* send message */
            fprintf(stderr,"SENT: %s",messages[n]);
            fputs(messages[n],fout);
            fflush(fout);
            /* get response */
            memset(buf,0,sizeof(buf));
            fgets(buf,sizeof(buf)-1,fin);
            fprintf(stderr,"RECV: %s",buf);
            if (strstr(buf,"OK")==NULL) { msg="fail"; goto do_error; }
         }
         /* close out channel to force client receive EOF and also die */
         fclose(fout);
         fclose(fin);
  } /* switch */

do_error:
  if (msg==NULL) return 0;
  fprintf(stderr,"%s\n",msg);
  return 1;
}

int main(int c, char *argv[]) {
    return do_task(PIN_ENTRY);
}

