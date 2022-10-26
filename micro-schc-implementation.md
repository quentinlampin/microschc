# MicroSCHC implementation

**brief**: This document keeps track of choices made during the implementation of microSCHC.

## 1. Parser

Instead of relying on an external parser, e.g. Scapy [1], microSCHC includes its own parser.
This choice is motivated by constraints on the memory footprint, code size and library availability
of the targeted run environment, i.e. microPython. This is further motivated by design choices made
in [section 1.2](#parsing-and-not-interpretation), in particular the decision to **not** interpret
fields of headers.

### 1.1. Types Support: `bytes` and `int`

Discussed extensively in issue [#2](https://github.com/quentinlampin/microschc/issues/2), microSCHC only support basic types, i.e. `bytes` and `int`.

The rationale is that supporting types other than bytes requires keeping track of the encoding/decoding of the type, i.e. how to translate from/to bytes, during the compression of the headers. This obviously yields an increased complexity of the parser code, with no obvious benefit (none identified yet) to the compression process.

The case for supporting the `int` type is not definitive. While it seems practical to support it, e.g. for describing Matching rules such `IPv6.VERSION == 6`, it limits the Matching Operators (MOs) and Compression-Decompression Actions that can be applied to those fields. Indeed, the `MSB(x)/LSB` MO and CDA cannot be applied to such a representation unless, of course, the field is reverted to `bytes`.

### 1.2 Parsing and not interpretation

Contrary to the OpenSCHC implementation [2], the parser including in microSCHC do **not** perform any interpretation on the fields carried within a packet. To illustrate this, let's consider CoAP Option fields. In CoAP [3], Options, such as `Uri-Host`, `Uri-Port`, and their parameters are encoded into a
structure of header fields represented here-after.

```text

                                0   1   2   3   4   5   6   7
                            +---------------+---------------+
                            |               |               |
                            |  Option Delta | Option Length |   1 byte
                            |               |               |
                            +---------------+---------------+
                            |                               |
                            |         Option Delta          |   0-2 bytes
                            |          (extended)           |
                            +-------------------------------+
                            |                               |
                            |         Option Length         |   0-2 bytes
                            |          (extended)           |
                            +-------------------------------+
                            |                               |
                            |                               |
                            |                               |
                            |         Option Value          |   0 or more bytes
                            |                               |
                            |                               |
                            |                               |
                            +-------------------------------+
```

The actual option requires parsing, and interpreting the `Option Delta`, `Option Length`, etc. Similarly to the types support discussion, this requires keeping track of the encoding and decoding of those interpretations into their bytes counterparts. Furthermore, how the compression residue should be computed based on the interpretation is a mystery to me (Quentin), unless simple compression actions are performed, e.g. `not-sent`. For this reason, microSCHC parser only exposes fields and their raw content (except for the integers odd case).

- [1] "Scapy, packet crafting for Python2 and Python3"
- [2] "OpenSCHC: Open implementation, hackathon support, ... of the IETF SCHC protocol (compression for LPWANs), https://github.com/openschc"
- [3] "RFC 7252 The Constrained Application Protocol (CoAP), Z. Shelby et al."
