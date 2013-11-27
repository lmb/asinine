`libasinine` provides decoding facilities of DER encoded ASN.1 data. Specifically,
the library is intended to parse X.509 certificates. The focus is on small size 
and static memory allocation, making it suitable for use in an embedded
environment. In general, you are encouraged to ship `libasinine` with your code,
and link to it statically.

Status
======

The library is still alpha quality. It (should) parse X.509v1 certificates, v3
is work-in-progress. There are some type conversion routines in `asn1-types.c`,
which allow basic interpretation of the different types.
Be warned: `libasinine` will shoot you in the foot and then run away with the
savings you had under your mattress.

Requirements
============

Right now, the library itself is quite lightweight. To properly handle ASN.1
time types it requires 64bit unsigned integers. Even slow emulation will do the
trick though, and smallish "bignum" support could be added if need be.
Also, a compiler like GCC or Clang (on which development happens) is
recommended, and the only platform expressly supported. Compiling from git also
requires premake4.

Compiling
=========

```bash
> premake4 gmake # or other targets, see premake4 --help
> make
> ./tests
```

Usage
=====

The current API is, of course, subject to change. Have a look at `x509.c` for a
more complex / convoluted example.

```C
#include <asinine/asn1.h>

/* ... */

bool parse_asn1(const uint8_t *data, size_t length)
{
	asn1_parser_t parser;
	asn1_token_t token;

	if (asn1_parser_init(&parser, &token, data, length) < ASN1_OK) {
		// The return code will shed some light on what went wrong
		return false;
	}

	if (asn1_parser_next(&parser) < ASN1_OK) {
		return false;
	}

	// "token" now contains the next token
	if (asn1_is_sequence(&token)) {
		// Do something
	}

	// Iterate over unknown number of children
	asn1_token_t parent = token;

	while (asn1_parser_is_within(&parser, &parent)) {
		// Call asn1_parser_next and then handle the token
	}

	// Yay!
	return true;
}
```

License
=======

`libasinine` is licensed unter the Mozilla Public License 2.0, please see
LICENSE for details.

The implications are: you can link statically to `libasinine`, without having to
release your own code. Modifications to libasinine have to be made public
though.
