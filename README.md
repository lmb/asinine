libasinine
==========

`libasinine` provides decoding facilities of DER encoded ASN.1 data, as well as
X.509v3 (and earlier) certificates. The focus is on small size and static memory allocation,
making it suitable for use in an embedded environment. In general, you are
encouraged to ship `libasinine` with your code, and link to it statically.

Status
======

The library is still alpha quality, but correctly parses and validates 98% of the
certificates used by the Alexa Top 10k sites.

Be warned: `libasinine` will shoot you in the foot and then run away with the
savings you hid under your mattress.

### ASN.1

The implementation follows ITU-T X.680 (11/2008) and ITU-T X.690 (11/2008), and has the functionality required to parse X.509 certificates. The only supported character set is UTF-8 (and by extension ASCII).

### X.509

The implementation largely follows [RFC 5280](https://tools.ietf.org/html/rfc5280). Only a limited set of extensions is supported:

* Basic Constraints
* Key Usage
* Extended Key Usage
* Subject Alternative Name (only common ones)

This is enough to parse most certificates used for HTTP traffic. There is a small utility which excercises this part of the library.

```
> brew install mbedtls # on macOS
> make x509
> ./bin/Debug/x509 -h
x509 <options> (<certs file>|-)
  --check[=trust store|-]    Validate certificates against trust store

  Use '-' to read from stdin. Only a single argument can be read from stdin.
```

Requirements
============

* GCC / Clang (C99)
* libc
* Optional: mbedtls (for utilities)

Compiling
=========

```bash
> make tests
> ./bin/Debug/tests
```

Usage
=====

The current API is subject to change. Have a look at `x509.c` for a
more complex / convoluted example.

```C
#include <stdint.h>
#include <asinine/dsl.h>

/* ... */

asinine_err_t
parse_asn1(const uint8_t *data, size_t length) {
	asn1_parser_t parser;
	asn1_init(&parser, data, length);

	NEXT_TOKEN(&parser);

	// "token" now contains the next token
	if (!asn1_is_seq(parser.token)) {
		return ERROR(ASININE_ERR_INVALID, "expected sequence");
	}

	// Iterate over unknown number of children
	RETURN_ON_ERROR(asn1_push_seq(&parser));

	while (!asn1_eof(&parser)) {
		// Call NEXT_TOKEN and process it
	}

	// Undo the push from before
	RETURN_ON_ERROR(asn1_pop(&parser));

	// Do some more parsing

	// Make sure there the buffer has been fully parsed
	if (!asn1_end(&parser)) {
		return ERROR(ASININE_ERR_MALFORMED, "trailing data");
	}

	// Yay!
	return ERROR(ASININE_OK, NULL);
}
```

License
=======

`libasinine` is licensed unter the Mozilla Public License 2.0, please see
LICENSE for details.

The implications are: you can link statically to `libasinine`, without having to
release your own code. Modifications to `libasinine` have to be made public
though.
