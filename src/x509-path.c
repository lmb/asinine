/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdint.h>
#include <string.h>

#include "asinine/dsl.h"
#include "asinine/x509.h"

#include "internal/macros.h"

static bool signature_is_compatible(
    x509_sig_algo_t sig_algo, x509_pubkey_algo_t pubkey_algo);

static bool
cert_is_self_issued(const x509_cert_t *cert) {
	return x509_name_eq(&cert->issuer, &cert->subject, NULL);
}

asinine_err_t
x509_find_issuer(
    asn1_parser_t *parser, const x509_cert_t *cert, x509_cert_t *issuer) {
	while (!asn1_end(parser)) {
		asinine_err_t err = x509_parse_cert(parser, issuer);
		if (err.errno != ASININE_OK) {
			// We can't parse this certificate. Rather than giving up
			// parse the next one, in the hopes that we don't need
			// this one.
			RETURN_ON_ERROR(asn1_abort(parser));
			continue;
		}

		if (x509_name_eq(&issuer->subject, &cert->issuer, NULL)) {
			return ERROR(ASININE_OK, NULL);
		}
	}

	return ERROR(ASININE_ERR_NOT_FOUND, "issuer: no match in trust store");
}

void
x509_path_init(x509_path_t *path, const x509_cert_t *anchor,
    const asn1_time_t *now, x509_validation_cb_t cb, void *ctx) {
	*path                       = (x509_path_t){0};
	path->ctx                   = ctx;
	path->public_key            = anchor->pubkey;
	path->public_key_parameters = anchor->pubkey_params;
	path->issuer_name           = anchor->subject;
	path->max_length            = -1;
	path->cb                    = cb;
	path->now                   = *now;
}

static asinine_err_t
process_certificate(x509_path_t *path, const x509_cert_t *cert) {
	// 6.1.3. Basic Certificate Processing
	// 6.1.3. (a) (1)

	if (!signature_is_compatible(
	        cert->signature.algorithm, path->public_key.algorithm)) {
		return ERROR(ASININE_ERR_INVALID,
		    "signature: algorithm doesn't match public key");
	}

	RETURN_ON_ERROR(path->cb(&path->public_key, path->public_key_parameters,
	    &cert->signature, cert->raw, cert->raw_num, path->ctx));

	// 6.1.3. (a) (2)
	if (asn1_time_cmp(&cert->valid_from, &path->now) > 0 ||
	    asn1_time_cmp(&cert->valid_to, &path->now) < 0) {
		return ERROR(ASININE_ERR_EXPIRED, NULL);
	}

	// 6.1.3. (a) (3)
	// Checking certificate revocation is not supported

	// 6.1.3. (a) (4)
	if (!x509_name_eq(&cert->issuer, &path->issuer_name, NULL)) {
		return ERROR(ASININE_ERR_INVALID, "issuer: no match");
	}

	// 6.1.3. (b)
	// permitted_subtrees is not supported

	// 6.1.3. (c)
	// excluded_subtrees is not supported

	// 6.1.3. (d)
	// 6.1.3. (e)
	// 6.1.3. (f)
	// Certificate policy extension is not supported

	// 6.1.4. Preparation for Certificate i+1

	// 6.1.4. (a)
	// 6.1.4. (b)
	// Policy mappings extension is not supported
	return ERROR(ASININE_OK, NULL);
}

asinine_err_t
x509_path_add(x509_path_t *path, const x509_cert_t *cert) {
	RETURN_ON_ERROR(process_certificate(path, cert));

	// 6.1.4. (c)
	path->issuer_name = cert->subject;

	// 6.1.4. (e)
	if (cert->has_pubkey_params) {
		path->public_key_parameters = cert->pubkey_params;
	} else if (cert->pubkey.algorithm != path->public_key.algorithm) {
		path->public_key_parameters = (x509_pubkey_params_t){0};
	}

	// 6.1.4. (d) + (f)
	// Re-ordered to avoid influencing 6.1.4 (e)
	path->public_key = cert->pubkey;

	// 6.1.4. (g)
	// Name constraints extension is not supported

	// 6.1.4. (h)
	// Certificate policy extension is not supported

	// 6.1.4. (i)
	// 6.1.4. (j)
	// Certificate policy constraints extension is not supported

	// 6.1.4. (k)
	if (cert->version != X509_V3) {
		return ERROR(ASININE_ERR_INVALID, "certficiate: not X509v3");
	}

	// We don't enforce the presence of basic constraints, but
	// is_ca can never be true without one present, so this works, too.
	if (!cert->is_ca) {
		return ERROR(ASININE_ERR_INVALID, "certificate: not a CA");
	}

	// 6.1.4. (l)
	if (!cert_is_self_issued(cert) && path->max_length != -1) {
		if (path->max_length < 1) {
			return ERROR(ASININE_ERR_INVALID, "path: too long");
		}
		path->max_length--;
	}

	// 6.1.4. (m)
	if (cert->path_len_constraint != -1 &&
	    (path->max_length == -1 ||
	        cert->path_len_constraint < path->max_length)) {
		path->max_length = cert->path_len_constraint;
	}

	// 6.1.4. (m)
	if (cert->key_usage != 0 &&
	    (cert->key_usage & X509_KEYUSE_KEY_CERT_SIGN) == 0) {
		return ERROR(
		    ASININE_ERR_INVALID, "certificate: missing signing key usage");
	}

	// 6.1.4. (o)
	// TODO: Process any other critical extensions
	// TODO: Process any other non-critical extensions

	return ERROR(ASININE_OK, NULL);
}

asinine_err_t
x509_path_end(x509_path_t *path, const x509_cert_t *cert) {
	RETURN_ON_ERROR(process_certificate(path, cert));

	// 6.1.5. Wrap-Up Procedure

	// 6.1.5. (a)
	// explicit_policy not supported

	// 6.1.5. (b)
	// Policy constraints extension not supported

	// 6.1.5. (d)
	// if (cert->pubkey.has_params) {
	// 	working_public_key_parameters = cert->pubkey.params;
	// } else if (cert->pubkey.algorithm != working_public_key.algorithm) {
	// 	working_public_key_parameters = (x509_pubkey_params_t){0};
	// }

	// 6.1.5. (c) + (e)
	// Reordered to avoid influencing 6.1.5 (d)
	// working_public_key = &cert->pubkey;

	// 6.1.5. (f)
	// TODO: Process any other critical extensions
	// TODO: Process any other non-critical extensions

	// 6.1.5. (g)
	// valid_policy_tree is not supported

	return ERROR(ASININE_OK, NULL);
}

static bool
signature_is_compatible(
    x509_sig_algo_t sig_algo, x509_pubkey_algo_t pubkey_algo) {
	switch (pubkey_algo) {
	case X509_PUBKEY_RSA:
		switch (sig_algo) {
		case X509_SIGNATURE_MD2_RSA:
		case X509_SIGNATURE_MD5_RSA:
		case X509_SIGNATURE_SHA1_RSA:
		case X509_SIGNATURE_SHA256_RSA:
		case X509_SIGNATURE_SHA384_RSA:
		case X509_SIGNATURE_SHA512_RSA:
			return true;
		default:
			return false;
		}
	case X509_PUBKEY_ECDSA:
		switch (sig_algo) {
		case X509_SIGNATURE_SHA256_ECDSA:
		case X509_SIGNATURE_SHA384_ECDSA:
		case X509_SIGNATURE_SHA512_ECDSA:
			return true;
		default:
			return false;
		}
	default:
		return false;
	}
}
