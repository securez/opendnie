/**
 * Programa para convertir un fichero de volcado de datos
 * hexadecimales a su correspondiente binario
 *
 * Uso: hex2bin <file.hex >file.bin
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>

int main(int argc,char *argv[]) {
    int c;
    int count=0;
    int a=0;
    while ( (c=getchar())!=EOF ) {
        a<<=4;
        switch(c) {
            case '0':a|=0x00; break;
            case '1':a|=0x01; break;
            case '2':a|=0x02; break;
            case '3':a|=0x03; break;
            case '4':a|=0x04; break;
            case '5':a|=0x05; break;
            case '6':a|=0x06; break;
            case '7':a|=0x07; break;
            case '8':a|=0x08; break;
            case '9':a|=0x09; break;
            case 'a':a|=0x0A; break;
            case 'b':a|=0x0B; break;
            case 'c':a|=0x0C; break;
            case 'd':a|=0x0D; break;
            case 'e':a|=0x0E; break;
            case 'f':a|=0x0F; break;
            case 'A':a|=0x0A; break;
            case 'B':a|=0x0B; break;
            case 'C':a|=0x0C; break;
            case 'D':a|=0x0D; break;
            case 'E':a|=0x0E; break;
            case 'F':a|=0x0F; break;
            default: continue;
        }
        if ((count&0x01)!=0) { 
            putchar(a); 
            a=0x00;
        };
        count++;
    }
    fprintf(stderr,"Leidos %d bytes\n",count);
    return 0;
}
