# MicroSCHC implementation

**brief**: This document keeps track of choices made during the implementation of microSCHC.

## 1. Parser

Instead of relying on an external parser, e.g. Scapy [1], microSCHC includes its own parser.
This choice is motivated by constraints on the memory footprint, code size and library availability
of the targeted run environment, i.e. microPython. This is further motivated by design choices made
in [section 1.2](#parsing-and-not-interpretation), in particular the decision to **not** interpret
fields of headers.

### 1.1. Types Support: `bytes`

Discussed extensively in issue [#2](https://github.com/quentinlampin/microschc/issues/2), microSCHC only support `bytes`.

The rationale is that supporting types other than bytes requires keeping track of the encoding/decoding of the type, i.e. how to translate from/to bytes, during the compression of the headers. This obviously yields an increased complexity of the parser code, with no obvious benefit (none identified yet) to the compression process.

The case for supporting the `int` type is not definitively closed. While it seems practical to support it, e.g. for describing Matching rules such `IPv6.VERSION == 6`, it limits the Matching Operators (MOs) and Compression-Decompression Actions that can be applied to those fields. Indeed, the `MSB(x)/LSB` MO and CDA cannot be applied to such a representation unless, of course, the field is reverted to `bytes`.

At first, prior to commit #47803bd96db8f5ac8d9b92cd6144aeb0223b1cc4, "integer" fields, such as lengths, versions, where decoded and exposed as integers. I later decided to resort to `bytes` only to test and see if any benefit of integer is revealed in the process of avoid them.

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

## 2. Ruler

The Ruler is in charge of the rules and their application to packets, i.e.:
    - rule storing: manages a collection of rules.
    - rule matching for packet descriptors: determine if a rule applies to a packet descriptor.
    - rule matching for SCHC packet: determine the rule descriptor corresponding to a SCHC packet.
    - packet compression: compress packets according to matching rules.
    - packet decompression: decompress packets according to rules IDs.

## 2.1 Rule ID

microSCHC expects rule IDs to be provided as right-aligned (left zero-padding) bytes. microSCHC further expects rule ID length to be strictly greater than 0, as opposed to what's defined in [4], section 5:

```text
A length of 0 is allowed to represent an implicit rule.
```

## 2.2 Rules field descriptors order matters

The Ruler makes the assumption that rules' field descriptors are provided in the same order as in the target packet structure.
For example, if the packet fields are, in order : [`field-1`, `field-2`, `field-3`, ...], it is supposed that rules field descriptors
are listed such that those that apply to `field-1` appear first, then those applying to `field-2`, `field-3`, etc.

In case multiple field descriptors apply to the same packet fields, i.e. field descriptors with different `DirectionIndicator`s (`Up`, `Dw`, `Bi`) applying to the same packet field,
it is mandated that field descriptors applying to a given packet, i.e. once the direction is resolved, are in the same order as the fields of the packet.

**This implementation choice differs from the SCHC specification where rules' field descriptors are described as ensembles, i.e. order does not matter, for matching packets.**

The rationale is that unordered field descriptors eventually yield fields residues in a different order than that of the source packet. This means that the order is potentially
lost at the reconstruction, leading to advert effects, including reconstructed packets different from the source packets.

## 2.3 Default Compression/Decompression rule, implementation details

microSCHC expects the default Compression/Decompression rule is provided last in the list of rules. The default rule list of fields descriptors is assumed empty and matches any packet not matched by any prior rule.

## 2.4 Variable field length

In microSCHC, a field of variable length is denoted with a 0 value of the FL attribute of the corresponding Field Descriptor.

- [1] "Scapy, packet crafting for Python2 and Python3"
- [2] "OpenSCHC: Open implementation, hackathon support, ... of the IETF SCHC protocol (compression for LPWANs), https://github.com/openschc"
- [3] "RFC 7252 The Constrained Application Protocol (CoAP), Z. Shelby et al."
- [4] "Draft: Data Model for Static Context Header Compression (SCHC)", A. Minaburo et al.

## 3. Compressor

The compressor is in charge of the compression of a packet, provided as a packet descriptor by the parser, using the rule identified by the **Ruler**.
The compression procedure is:
    - compress packet fields using compression actions defined in the corresponding field descriptors of the rule.
    - concatenate fields residues prepended with the rule ID, removing (left)-padding in the process.

