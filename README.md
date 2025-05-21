# microSCHC

## In a nutshell

Implementation in microPython of SCHC as specified in RFC 8724 [1].

## License

MIT License, Copyright (c) 2022-2025 Orange, by Quentin Lampin

## Installing microSCHC

Releases of microSCHC are available on PyPI. To install microSCHC, run

```bash
pip install microschc[extras]
```

Note: you can also install microschc with support of PCAPng capture files in case you don't need it

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

## Quickstart Example

Here's a quick example of how to use microSCHC to compress IPv6/UDP/CoAP headers:

```python
from microschc import ContextManager, Context, Stack, RuleDescriptor, RuleNature
from microschc.protocol.ipv6 import ipv6_base_header_template
from microschc.protocol.udp import udp_header_template
from microschc.protocol.coap import coap_base_header_template, coap_option_template

# Create field descriptors for IPv6 header
ipv6_field_descriptors = ipv6_base_header_template(
    flow_label=b'\x0f\xf8\x5f',
    src_address=b'\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03',
    dst_address=b'\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20',
    next_header=17,
    hop_limit=64
)

# Create field descriptors for UDP header
udp_field_descriptors = udp_header_template(
    source_port=b'\x90\xa0',
    destination_port=b'\x16\x33'
)

# Create field descriptors for CoAP header
coap_base_header_field_descriptors = coap_base_header_template(
    type=b'\x00',
    code=0b01000101,
    token=[b'\xd1\x59', b'\x21\x50', b'\x37\x09', b'\x1f\x0a', b'\xb7\x25', b'\x8d\x43']
)

# Create field descriptors for CoAP options
coap_option_1_field_descriptors = coap_option_template(
    option_delta=b'\x06',
    option_length=[1, 2],
    option_value=None
)

coap_option_2_field_descriptors = coap_option_template(
    option_delta=6,
    option_length=[1,2],
    option_value=[b"\x2d\x16", b"\x3c"]
)

# Combine all field descriptors
field_descriptors = (
    ipv6_field_descriptors
    + udp_field_descriptors 
    + coap_base_header_field_descriptors 
    + coap_option_1_field_descriptors 
    + coap_option_2_field_descriptors 
)

# Create a rule descriptor
rule_descriptor = RuleDescriptor(
    id=b'\x00',
    nature=RuleNature.COMPRESSION,
    field_descriptors=field_descriptors,
)

# Create a context with the rule
context = Context(
    id="quickstart-context",
    description="Context for IoT device communication",
    interface_id="default",
    parser_id=Stack.IPV6_UDP_COAP,
    ruleset=[rule_descriptor],
)

# Create a context manager
context_manager = ContextManager(context=context)

# Use the context manager to compress packets
compressed_packet = context_manager.compress(packet)
```

## microSCHC, developpement plan

microSCHC aims at implementing the SCHC Compression/Decompression (C/D) routines described in RFC 8724 [1].

Currently, microSCHC provides parsers for IPv4[2] IPv6[3], UDP[4], CoAP[5] and SCTP[6].

Beyond implementing the core SCHC specification, microSCHC also aims to support the IETF WG SCHC in its ongoing work. 
For example, it implements and evaluates different approaches for CoAP parsing, including both syntactic and semantic approaches, to help inform the WG's decisions on best practices for CoAP compression in constrained networks.

Current features:

1. Parsers
   - [x] IPv4
   - [x] IPv6
   - [x] UDP
   - [x] SCTP
   - [x] CoAP (syntactic and semantic approaches)
   - [x] CoAP over UDP over IPv6 stack parser
   
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
      
   2. Decompression counterparts
      - [x] not-sent
      - [x] value-sent
      - [x] mapping-sent
      - [x] LSB
      - [-] compute-* (e.g. UDP-checksum)
         - [x] UDP Checksum
         - [x] UDP Length
         - [x] IPv6 Payload Length
         - [x] IPv4 Payload Length
      
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
- [2] "RFC 791 INTERNET PROTOCOL. J.Postel et al."
- [3] "RFC 8200 Internet Protocol, Version 6 (IPv6) Specification, S. Deering et al."
- [4] "RFC 768 User Datagram Protocol, J. Postel"
- [5] "RFC 7252 The Constrained Application Protocol (CoAP), Z. Shelby et al."
- [6] "RFC 4960 Stream Control Transmission Protocol, R. Stewart et al."