#<cldoc:ASN.1>

Parse DER encoded ASN.1

Use the parser to decode DER encoded ASN.1 buffers into tokens, which you can then decode using various helpers.

Traversing ASN.1 structures
---

The parser uses a stack to keep track which parts of an ASN.1 structure it has parsed. Push makes the parser descend into the current token. Pop ascends from the current token, while making sure that it has been fully parsed.

The implementation is according to ITU-T X.680 (11/2008) and ITU-T X.690 (11/2008).