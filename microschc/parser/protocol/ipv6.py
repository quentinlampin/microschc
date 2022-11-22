"""
IPv6 header parser

Parser for the IPv6 protocol header as defined in RFC8200 [1].

Note 1: Hop by Hop Options, Routing header parsing is not implemented yet.
Note 2: Fragment header parsing is not implemented as fragmentation and reassembly
        are handled by SCHC-RF.
Note 3: Authentication and Encapsulating Security payload parsing is not implemented yet.

[1] "RFC8200: Internet Protocol, Version 6 (IPv6) Specification", S. Deering et al.
"""

from enum import Enum
from microschc.binary.buffer import Buffer
from microschc.parser import HeaderParser
from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor

IPv6_HEADER_ID = 'IPv6'

class IPv6Fields(str, Enum):
    VERSION         = f'{IPv6_HEADER_ID}:Version'
    TRAFFIC_CLASS   = f'{IPv6_HEADER_ID}:Traffic Class'
    FLOW_LABEL      = f'{IPv6_HEADER_ID}:Flow Label'
    PAYLOAD_LENGTH  = f'{IPv6_HEADER_ID}:Payload Length'
    NEXT_HEADER     = f'{IPv6_HEADER_ID}:Next Header'
    HOP_LIMIT       = f'{IPv6_HEADER_ID}:Hop Limit'
    SRC_ADDRESS     = f'{IPv6_HEADER_ID}:Source Address'
    DST_ADDRESS     = f'{IPv6_HEADER_ID}:Destination Address'


class IPv6Parser(HeaderParser):

    def __init__(self) -> None:
        super().__init__(name=IPv6_HEADER_ID)

    def parse(self, buffer:bytes) -> HeaderDescriptor:
        """
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Version| Traffic Class |           Flow Label                  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         Payload Length        |  Next Header  |   Hop Limit   |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        +                                                               +
        |                                                               |
        +                         Source Address                        +
        |                                                               |
        +                                                               +
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        +                                                               +
        |                                                               |
        +                      Destination Address                      +
        |                                                               |
        +                                                               +
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        header_bytes:bytes = buffer[0:40]

        # version: 4 bits
        version:bytes = ((header_bytes[0] & 0xf0) >> 4).to_bytes(1, 'big')
        # traffic_class: 8 bits
        traffic_class:bytes = (( (header_bytes[0] & 0x0f) << 4 ) | ( (header_bytes[1] & 0xf0) >> 4 )).to_bytes(1, 'big')
        # flow label: 20 bits
        flow_label:bytes = ((header_bytes[1] & 0xf0) >> 4).to_bytes(1, 'big') + header_bytes[2:4]
        # payload length: 16 bits
        payload_length:bytes = header_bytes[4:6]
        # next header: 8 bits
        next_header:bytes = header_bytes[6:7]
        # hop limit: 8 bits
        hop_limit:bytes = header_bytes[7:8]
        # source address: 128 bits (16 bytes)
        source_address:bytes = header_bytes[8:24]
        # destination address: 128 bits (16 bytes)
        destination_address:bytes = header_bytes[24:40]

        header_descriptor:HeaderDescriptor = HeaderDescriptor(
            id=IPv6_HEADER_ID,
            length=40*8,
            fields=[
                FieldDescriptor(id=IPv6Fields.VERSION,         position=0, value=Buffer(content=version, bit_length=4)),
                FieldDescriptor(id=IPv6Fields.TRAFFIC_CLASS,   position=0, value=Buffer(content=traffic_class, bit_length=8)),
                FieldDescriptor(id=IPv6Fields.FLOW_LABEL,      position=0, value=Buffer(content=flow_label, bit_length=20)),
                FieldDescriptor(id=IPv6Fields.PAYLOAD_LENGTH,  position=0, value=Buffer(content=payload_length, bit_length=16)),
                FieldDescriptor(id=IPv6Fields.NEXT_HEADER,     position=0, value=Buffer(content=next_header, bit_length=8)),
                FieldDescriptor(id=IPv6Fields.HOP_LIMIT,       position=0, value=Buffer(content=hop_limit, bit_length=8)),
                FieldDescriptor(id=IPv6Fields.SRC_ADDRESS,     position=0, value=Buffer(content=source_address, bit_length=128)),
                FieldDescriptor(id=IPv6Fields.DST_ADDRESS,     position=0, value=Buffer(content=destination_address, bit_length=128))
            ]
        )
        return header_descriptor
