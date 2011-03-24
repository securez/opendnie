/*
 * dnie-tool.c: DNIe tool
 *
 * Copyright (C) 2011  Juan Antonio Martinez <jonsito@terra.es>
 *
 * Based on file rutoken-tool.c from  Pavel Mironchik <rutoken@rutoken.ru>
 * and Eugene Hermann <rutoken@rutoken.ru>
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/pkcs15.h"
#include "util.h"

/* win32 needs this in open(2) */
#ifndef O_BINARY
#define O_BINARY 0
#endif

#define IV_SIZE 4

static const char *app_name = "dnie-tool";

enum {
	OP_NONE,
	OP_GET_SERIALNR,  /* Get SerialNumber */
	OP_GET_INFO, /* retrieve DNIe number, apellidos, nombre */
	OP_GEN_KEY,  /* generate keypair. Not supported yet */
	OP_ENCRYPT,  /* encrypt. Not supported yet */
	OP_DECRYPT   /* decrypt. Not supported yet */
};

static const struct option options[] = {
	{"reader",      1, NULL, 'r'},
	{"wait",	0, NULL, 'w'},
	{"pin",	 1, NULL, 'p'},
	{"input",       1, NULL, 'i'},
	{"output",      1, NULL, 'o'},
	{"info",	0, NULL, 'n'},
	{"genkey",      0, NULL, 'g'},
	{"encrypt",     0, NULL, 'e'},
	{"decrypt",     0, NULL, 'd'},
	{"serial",      0, NULL, 's'},
	{"verbose",     0, NULL, 'v'},
	{NULL,	  0, NULL,  0 }
};

static const char *option_help[] = {
	"Uses reader number <arg> [0]",
	"Wait for a card to be inserted",
	"Specify PIN",
	"Selects the input file to cipher",
	"Selects the output file to cipher",
	"Show DNIe number, Name, and GivenName",
	"Generate new keypair",
	"Performs encryption operation",
	"Performs decryption operation",
	"Show DNIe serial number",
	"Verbose operation. Use several times to enable debug output."
};

/*  Get DNIe device information  */

static int dnie_info(sc_card_t *card)
{	
	u8 *data[] = { NULL, NULL, NULL };
	int r;
	
	r = sc_card_ctl(card, SC_CARDCTL_DNIE_GET_INFO, data);
	if (r) {
		fprintf(stderr, "Error: Get info failed: %s\n", sc_strerror(r));
		return -1;
	}
	printf("Num. DNIe: %s\n", data[0]);
	printf("Apellidos: %s\n", data[1]);
	printf("Nombre:    %s\n", data[2]);
	return 0;
}

static int dnie_serialnumber(sc_card_t *card)
{
	sc_serial_number_t serial;
	int r;	
	r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serial);
	if (r) {
		fprintf(stderr, "Error: Get serial failed: %s\n", sc_strerror(r));
		return -1;
	}
	printf("Serial number: ");
	util_hex_dump(stdout, serial.value, serial.len, NULL);
	putchar('\n');
	return 0;
}
	
/*  Cipher/Decipher a buffer on token */
	
static int dnie_cipher(sc_card_t *card, u8 keyid,
		const u8 *in, size_t inlen,
		u8 *out, size_t outlen, int oper)
{
	int r=SC_SUCCESS;
	sc_security_env_t env;
	memset(&env, 0, sizeof(env));

	env.key_ref[0] = keyid;
	env.key_ref_len = 1;
	env.algorithm = SC_ALGORITHM_RSA;
	env.operation = SC_SEC_OPERATION_DECIPHER;

	/*  set security env  */
	r = sc_set_security_env(card, &env, 0);
	if (r) {
		fprintf(stderr, "Error: Cipher failed (set security environment): %s\n",
			sc_strerror(r));
		return -1;
	}
	/*  (de)cipher  */
	/* r = sc_card_ctl(card, cmd, &inf); */
	if (r) {
		fprintf(stderr, "Error: Cipher failed: %s\n", sc_strerror(r));
		return -1;
	}
	return 0;
}

/*  Encrypt/Decrypt infile to outfile  */

static int do_crypt(sc_card_t *card, u8 keyid,
		const char *path_infile, const char *path_outfile,
		const u8 IV[IV_SIZE], int oper)
{
	int err;
	int fd_in, fd_out;
	struct stat st;
	size_t insize, outsize, readsize;
	u8 *inbuf = NULL, *outbuf = NULL, *p;

	fd_in = open(path_infile, O_RDONLY | O_BINARY);
	if (fd_in < 0) {
		fprintf(stderr, "Error: Cannot open file '%s'\n", path_infile);
		return -1;
				}
	err = fstat(fd_in, &st);
	if (err || (oper == OP_DECRYPT && st.st_size < IV_SIZE)) {
		fprintf(stderr, "Error: File '%s' is invalid\n", path_infile);
		close(fd_in);
		return -1;
	}
	insize = st.st_size;
	if (oper == OP_ENCRYPT)
		insize += IV_SIZE;
	outsize = insize;
	if (oper == OP_DECRYPT)  /*  !(stat.st_size < IV_SIZE)  already true  */
		outsize -= IV_SIZE;

	inbuf = malloc(insize);
	outbuf = malloc(outsize);
	if (!inbuf || !outbuf) {
		fprintf(stderr, "Error: File '%s' is too big (allocate memory)\n",
				path_infile);
		err = -1;
	}
	if (err == 0) {
		p = inbuf;
		readsize = insize;
		if (oper == OP_ENCRYPT) {
			memcpy(inbuf, IV, IV_SIZE);  /*  Set IV in first bytes buf  */
			/*  insize >= IV_SIZE  already true  */
			p += IV_SIZE;
			readsize -= IV_SIZE;
		}
		err = read(fd_in, p, readsize);
		if (err < 0  ||  (size_t)err != readsize) {
			fprintf(stderr, "Error: Read file '%s' failed\n", path_infile);
			err = -1;
			}
			else
			err = 0;
		}
	close(fd_in);

	if (err == 0) {
		fd_out = open(path_outfile, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY,
				S_IRUSR | S_IWUSR);
		if (fd_out < 0) {
			fprintf(stderr, "Error: Cannot create file '%s'\n",path_outfile);
			err = -1;
		}
		else {
			err = dnie_cipher(card, keyid, inbuf, insize,
					outbuf, outsize, oper);
			if (err == 0) {
				err = write(fd_out, outbuf, outsize);
				if (err < 0  ||  (size_t)err != outsize) {
					fprintf(stderr,"Error: Write file '%s' failed\n",
							path_outfile);
					err = -1;
	}
	else
					err = 0;
			}
			close(fd_out);
	}
	}
	if (outbuf)
		free(outbuf);
	if (inbuf)
		free(inbuf);
	return err;
}

static int generate_key(sc_card_t *card, u8 keyid, u8 keyoptions)
{
	int r = SC_SUCCESS;
        u8 paramkey[2];
	paramkey[0]=keyid;
	paramkey[1]=keyoptions;

	r = sc_card_ctl(card, SC_CARDCTL_DNIE_GENERATE_KEY, &paramkey);
	if (r) {
		fprintf(stderr, "Error: Generate keypair failed: %s\n", sc_strerror(r));
		return -1;
	}
	return 0;
}

int main(int argc, char* argv[])
{
	int	     opt_wait = 0;
	const char  *opt_pin = NULL;
	const char  *opt_reader = NULL;
	int	     opt_key = 0;
	int	     opt_keytype = 0;
	const char  *opt_input = NULL;
	const char  *opt_output = NULL;
	int	     opt_operation = OP_NONE;
	int	     opt_debug = 0;
	char IV[IV_SIZE];
	
	int err = 0;
	sc_context_t *ctx = NULL;
	sc_context_param_t ctx_param;
	sc_card_t *card = NULL;
	int c, long_optind, r, tries_left;
	
	while (1) {
		c = getopt_long(argc, argv, "r:wp:i:o:ngdesv",
				options, &long_optind);
		if (c == -1)
			break;
		switch (c) {
		case '?':
			util_print_usage_and_die(app_name, options, option_help);
		case 'r':
			opt_reader = optarg;
			break;
		case 'w':
			opt_wait = 1;
			break;
		case 'p':
			opt_pin = optarg;
			break;
		case 'i':
			opt_input = optarg;
			break;
		case 'o':
			opt_output = optarg;
			break;
		case 'n':
			opt_operation = OP_GET_INFO;
			break;
		case 'g':
			opt_operation = OP_GEN_KEY;
			break;
		case 'e':
			opt_operation = OP_ENCRYPT;
			break;
		case 'd':
			opt_operation = OP_DECRYPT;
			break;
		case 's':
			opt_operation = OP_GET_SERIALNR;
			break;
		case 'v':
			opt_debug++;
			break;
		}
	}

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.app_name = app_name;
	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
		fprintf(stderr, "Error: Failed to establish context: %s\n",
			sc_strerror(r));
		return -1;
	}

	if (opt_debug > 1) {
		ctx->debug = opt_debug;
		ctx->debug_file = stderr;
	}

	if (util_connect_card(ctx, &card, opt_reader, opt_wait, opt_debug) != 0)
		err = -1;
		
	if (err == 0  &&  opt_pin) {
		/*  verify  */
		r = sc_verify(card, SC_AC_CHV, 0,
				(u8*)opt_pin, strlen(opt_pin), &tries_left);
		if (r) {
			fprintf(stderr, "Error: PIN verification failed: %s",
					sc_strerror(r));
			if (r == SC_ERROR_PIN_CODE_INCORRECT)
				fprintf(stderr, " (tries left %d)\n", tries_left);
			else
				putc('\n', stderr);
			err = 1;
		}
	}
	if (err == 0) {
		err = -1;
		switch (opt_operation) {
			case OP_GET_SERIALNR:
				err = dnie_serialnumber(card);
				break;
			case OP_GET_INFO:
				err = dnie_info(card);
				break;
			case OP_DECRYPT:
			case OP_ENCRYPT:
				if (!opt_input) {
					fprintf(stderr, "Error: No input file specified\n");
				break;
				}
				if (!opt_output) {
					fprintf(stderr, "Error: No output file specified\n");
					break;
				}
			case OP_GEN_KEY:
				if (opt_key == 0) {
					fprintf(stderr, "Error: You must set key ID\n");
					break;
				}
				err = generate_keypair(card, (u8)opt_key, opt_keytype);
				break;
			default:
				fprintf(stderr, "Error: No operation specified\n");
				break;
		}
	}
	if (card) {
		/*  sc_lock  and  sc_connect_card  in  util_connect_card  */
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	if (ctx)
		sc_release_context(ctx);
	return err;
}

