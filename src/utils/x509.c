/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mbedtls/bignum.h>
#include <mbedtls/md.h>
#include <mbedtls/rsa.h>

#include "asinine/dsl.h"
#include "asinine/x509.h"
#include "internal/utils.h"

#define OPTPARSE_IMPLEMENTATION
#include "internal/optparse.h"

static void
dump_name(FILE *fd, const x509_name_t *name) {
	char buf[256];

	for (size_t i = 0; i < name->num; i++) {
		const x509_rdn_t *rdn = &name->rdns[i];

		if (asn1_oid_to_string(buf, sizeof(buf), &rdn->oid) >= sizeof(buf)) {
			fprintf(fd, "  %s...: ", buf);
		} else {
			fprintf(fd, "  %s: ", buf);
		}

		asinine_err_t err;
		if ((err = asn1_string(&rdn->value, buf, sizeof(buf))) != ASININE_OK) {
			fprintf(fd, "%s\n", asinine_strerror(err));
		} else {
			fprintf(fd, "%s\n", buf);
		}
	}
}

static void
dump_certificate(const x509_cert_t *cert) {
	char buf[256];

	printf("---\n");
	printf("Version: %d, Algo: %d\n", cert->version, cert->signature.algorithm);

	assert(
	    asn1_time_to_string(buf, sizeof(buf), &cert->valid_from) < sizeof(buf));
	printf("Valid from: %s", buf);

	assert(
	    asn1_time_to_string(buf, sizeof(buf), &cert->valid_to) < sizeof(buf));
	printf(", to: %s\n", buf);

	printf("Issuer:\n");
	dump_name(stdout, &cert->issuer);

	printf("Subject:\n");
	dump_name(stdout, &cert->subject);

	printf("Public key: %d\n", cert->pubkey.algorithm);
	switch (cert->pubkey.algorithm) {
	case X509_PUBKEY_RSA:
		printf("  Public exponent:\n");
		hexdump(cert->pubkey.key.rsa.e, cert->pubkey.key.rsa.e_num, 1);
		printf("  Modulus:\n");
		hexdump(cert->pubkey.key.rsa.n, cert->pubkey.key.rsa.n_num, 1);
		break;
	case X509_PUBKEY_ECDSA:
		printf("Point:\n");
		hexdump(
		    cert->pubkey.key.ecdsa.point, cert->pubkey.key.ecdsa.point_num, 1);
		break;
	default:
		printf("NOT IMPLEMENTED\n");
	}
}

static void
get_current_time(asn1_time_t *now) {
	time_t t = time(NULL);
	assert(t != (time_t)(-1));
	struct tm *utc = gmtime(&t);
	assert(utc != NULL);

	now->year   = (int32_t)utc->tm_year + 1900;
	now->month  = (uint8_t)utc->tm_mon + 1;
	now->day    = (uint8_t)utc->tm_mday;
	now->hour   = (uint8_t)utc->tm_hour;
	now->minute = (uint8_t)utc->tm_min;
	now->second = (uint8_t)utc->tm_sec;
}

asinine_err_t
validate_signature(const x509_pubkey_t *pubkey, x509_pubkey_params_t params,
    const x509_signature_t *sig, const uint8_t *raw, size_t raw_num,
    void *ctx) {
	(void)params;
	(void)ctx;

	mbedtls_md_type_t digest;
	switch (sig->algorithm) {
	case X509_SIGNATURE_SHA256_RSA:
		digest = MBEDTLS_MD_SHA256;
		break;
	case X509_SIGNATURE_SHA384_RSA:
		digest = MBEDTLS_MD_SHA384;
		break;
	case X509_SIGNATURE_SHA512_RSA:
		digest = MBEDTLS_MD_SHA512;
		break;
	default:
		return ASININE_ERR_UNSUPPORTED;
	}

	mbedtls_rsa_context rsa;
	mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
	rsa.len = pubkey->key.rsa.n_num;

	asinine_err_t res = ASININE_ERR_MALFORMED;
	if (mbedtls_mpi_read_binary(
	        &rsa.N, pubkey->key.rsa.n, pubkey->key.rsa.n_num) != 0) {
		goto error;
	}

	if (mbedtls_mpi_read_binary(
	        &rsa.E, pubkey->key.rsa.e, pubkey->key.rsa.e_num) != 0) {
		goto error;
	}

	if (mbedtls_rsa_check_pubkey(&rsa) != 0) {
		goto error;
	}

	uint8_t hash[64]                 = {0};
	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(digest);
	if (mbedtls_md(md_info, raw, raw_num, hash) != 0) {
		goto error;
	}

	if (mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, digest,
	        0, hash, sig->data) != 0) {
		res = ASININE_ERR_INVALID;
		goto error;
	}

	res = ASININE_OK;
error:
	mbedtls_rsa_free(&rsa);
	return res;
}

static asinine_err_t
dump_certificates(const uint8_t *contents, size_t length) {
	x509_cert_t cert;

	asn1_parser_t parser;
	asn1_init(&parser, contents, length);

	while (!asn1_end(&parser)) {
		asinine_err_t err = x509_parse(&parser, &cert);
		if (err != ASININE_OK) {
			fprintf(stderr, "Invalid certificate: %s\n", asinine_strerror(err));
			return err;
		}

		dump_certificate(&cert);
	}

	return ASININE_OK;
}

static asinine_err_t
find_issuer(const uint8_t *buf, size_t length, const x509_cert_t *cert,
    x509_cert_t *issuer) {
	asn1_parser_t parser;
	asn1_init(&parser, buf, length);
	return x509_find_issuer(&parser, cert, issuer);
}

static asinine_err_t
validate_path(const uint8_t *trust, size_t trust_length,
    const uint8_t *contents, size_t length) {
	x509_cert_t issuer, cert;
	x509_path_t path;

	asn1_time_t now;
	get_current_time(&now);

	asn1_parser_t parser;
	asn1_init(&parser, contents, length);

	asinine_err_t err = x509_parse(&parser, &cert);
	if (err != ASININE_OK) {
		fprintf(stderr, "Invalid certificate: %s\n", asinine_strerror(err));
		return false;
	}

	err = find_issuer(trust, trust_length, &cert, &issuer);
	if (err != ASININE_OK) {
		fprintf(stderr, "Can't find issuer: %s\n", asinine_strerror(err));
		dump_name(stderr, &cert.issuer);
		return false;
	}

	x509_path_init(&path, &issuer, &now, validate_signature, NULL);

	while (!asn1_end(&parser)) {
		err = x509_path_add(&path, &cert);
		if (err != ASININE_OK) {
			fprintf(stderr, "Validation failed: %s\n", asinine_strerror(err));
			fprintf(stderr, "Failing certificate:\n");
			dump_name(stderr, &cert.subject);
			return err;
		}

		err = x509_parse(&parser, &cert);
		if (err != ASININE_OK) {
			fprintf(stderr, "Invalid certificate: %s\n", asinine_strerror(err));
			return err;
		}
	}

	err = x509_path_end(&path, &cert);
	if (err != ASININE_OK) {
		fprintf(stderr, "Validation failed: %s\n", asinine_strerror(err));
		fprintf(stderr, "Failing certificate:\n");
		dump_name(stderr, &cert.subject);
		return err;
	}

	printf("Chain is valid\n");
	return ASININE_OK;
}

static void
print_help() {
	printf("x509 [--check (<trust file>|-)] (<certs file>|-)\n");
	exit(0);
}

int
main(int argc, char *argv[]) {
	(void)argc;

	struct optparse_long longopts[] = {
	    {
	        "check", 'c', OPTPARSE_REQUIRED,
	    },
	    {
	        "help", 'h', OPTPARSE_NONE,
	    },
	    {0},
	};

	const char *trust_file;

	int option;
	struct optparse options;

	optparse_init(&options, argv);
	while ((option = optparse_long(&options, longopts, NULL)) != -1) {
		switch (option) {
		case 'h':
			print_help();
			break;
		case 'c':
			trust_file = options.optarg;
			break;
		case '?':
			fprintf(stderr, "%s: %s\n", argv[0], options.errmsg);
			return 1;
		}
	}

	const char *certs_file = optparse_arg(&options);
	if (certs_file == NULL) {
		fprintf(stderr, "Need at least one argument\n");
		return 1;
	}

	if (strcmp(certs_file, "-") == 0 && strcmp(trust_file, "-") == 0) {
		fprintf(stderr, "stdin ('-') can only be specified once\n");
		return 1;
	}

	size_t certs_len;
	uint8_t *certs = load(certs_file, &certs_len);
	if (certs == NULL) {
		return 1;
	}

	if (trust_file != NULL) {
		size_t trust_len;
		uint8_t *trust;

		trust = load(trust_file, &trust_len);
		if (trust == NULL) {
			return 1;
		}

		return (int)validate_path(trust, trust_len, certs, certs_len);
	}

	return (int)dump_certificates(certs, certs_len);
}
