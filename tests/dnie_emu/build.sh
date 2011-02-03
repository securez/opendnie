#!/bin/sh
cd $(dirname $0)

OPENSC_TRUNK=/home/jantonio/work/dnie/opendnie/opensc-opendnie/trunk

gcc -g -Wall -Wextra -Wno-unused-parameter -Werror -I$OPENSC_TRUNK/src -L$OPENSC_TRUNK/src/libopensc/.libs -shared -o dnie.so *.c -lopensc
