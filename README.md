# microSCHC

## In a nutshell

Implementation in microPython of SCHC as specified in RFC 8724 [1].

## License

MIT License, Copyright (c) 2022 Orange, by Quentin Lampin

## Installing microSCHC

Releases of microSCHC are available on PyPI. To install microSCHC, run

```bash
pip install microschc
```

Latest (pre-release) microSCHC versions can be built from source using `hatch` and installed using the wheel (.whl) file generated in the `dist/` folder.

**build**:

```bash
hatch build -t wheel
```

**installation**:

```bash
pip install dist/microschc-<version>-py3-none-any.whl
```

## microSCHC, developpement plan

microSCHC aims at implementing the SCHC Compression/Decompression (C/D) and Fragmentation/Reassembly (F/R) routines described in RFC 8724 [1].

The initial focus of this effort is on the Compression/Decompression (C/D) routines and parsers for typical IoT protocol stacks, i.e. based
on IPv6 [2], UDP [3], CoAP [4], lwM2M.

Current features:

1. Parsers
   - [x] IPv4
   - [x] IPv6
   - [x] UDP
   - [x] CoAP (partial test coverage: options missing)
   - [x] CoAP over UDP over IPv6 stack parser
   - [ ] lwM2M ( when not using CoAP options, i.e. CoAP payloads) --> postponed to after full SCHC C/D implementation
2. Matching Operators (MO)
   - [x] equal
   - [x] ignore
   - [x] MSB(x)
   - [x] match-mapping
3. Compression/Decompression Actions (CDA)
   1. Compression
      - [x] not-sent
      - [x] value-sent
      - [x] mapping-sent
      - [x] LSB
      - [x] compute-* (e.g. UDP-checksum)
      - [ ] devIID
      - [ ] AppIID
      
   2. Decompression counteparts
      - [x] not-sent
      - [x] value-sent
      - [x] mapping-sent
      - [x] LSB
      - [-] compute-* (e.g. UDP-checksum)
         - [x] UDP Checksum
         - [x] UDP Length
         - [x] IPv6 Payload Length
         - [ ] IPv4 Payload Length
      - [ ] devIID
      - [ ] AppIID
      
4. Rules
   - [x] rule data model
   - [x] rule matching algorithm
   - [ ] YANG model interpreter
5. Compression
   - [x] field (left-)packet
   - [x] field residues concatenation
   - [x] length of variable length field encoding
   - [x] packet compression
6. Context Management
   - [x] Definition & implementation of custom SCHC Context (not specified in RFCs)

- [1] "RFC 8724 SCHC: Generic Framework for Static Context Header Compression and Fragmentation" , A. Minaburo et al.
- [2] "RFC 8200 Internet Protocol, Version 6 (IPv6) Specification, S. Deering et al."
- [3] "RFC 768 User Datagram Protocol, J. Postel"
- [4] "RFC 7252 The Constrained Application Protocol (CoAP), Z. Shelby et al."
