﻿/*
 * Copyright (c) 2020 - 2021 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/sm3.h>
#include <gmssl/hex.h>
#include <gmssl/error.h>


int sm3hmac_main(int argc, char **argv)
{
	int ret = -1;
	char *prog = argv[0];
	char *keyhex = NULL;
	char *infile = NULL;
	uint8_t key[32];
	size_t keylen;
	FILE *in = stdin;
	SM3_HMAC_CTX ctx;
	uint8_t dgst[32];
	uint8_t buf[4096];
	size_t len;
	size_t i;

	argc--;
	argv++;

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
help:
			fprintf(stderr, "usage: %s -keyhex hex [-in file]\n", prog);
			return -1;

		} else if (!strcmp(*argv, "-keyhex")) {
			if (--argc < 1) goto bad;
			keyhex = *(++argv);

		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);

		} else {
			fprintf(stderr, "%s: illegal option '%s'\n", prog, *argv);
			goto help;
		}

		argc--;
		argv++;
	}

	if (!keyhex) {
		fprintf(stderr, "%s: option '-keyhex' required\n", prog);
		goto help;
	}
	if (strlen(keyhex) > sizeof(key) * 2) {
		error_print();
		return -1;
	}
	if (hex_to_bytes(keyhex, strlen(keyhex), key, &keylen) != 1) {
		error_print();
		return -1;
	}

	sm3_hmac_init(&ctx, key, keylen);

	while ((len = fread(buf, 1, sizeof(buf), stdin)) > 0) {
		sm3_hmac_update(&ctx, buf, len);
	}
	sm3_hmac_finish(&ctx, dgst);

	for (i = 0; i < sizeof(dgst); i++) {
		printf("%02x", dgst[i]);
	}
	if (infile) {
		printf(" : %s", infile);
	}
	printf("\n");

	memset(&ctx, 0, sizeof(ctx));
	memset(key, 0, sizeof(key));
	return 0;

bad:
	fprintf(stderr, "%s: '%s' option value required\n", prog, *argv);
	return -1;
}
