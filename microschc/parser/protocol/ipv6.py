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
from microschc.parser import HeaderParser
from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor

IPv6_HEADER_ID = 'IPv6'

class IPv6Fields(str, Enum):
    VERSION         = 'Version'
    TRAFFIC_CLASS   = 'Traffic Class'
    FLOW_LABEL      = 'Flow Label'
    PAYLOAD_LENGTH  = 'Payload Length'
    NEXT_HEADER     = 'Next Header'
    HOP_LIMIT       = 'Hop Limit'
    SRC_ADDRESS     = 'Source Address'
    DST_ADDRESS     = 'Destination Address'


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
        payload_length:bytes = ((header_bytes[4] << 8) | (header_bytes[5])).to_bytes(2, 'big')
        # next header: 8 bits
        next_header:bytes = (header_bytes[6]).to_bytes(1, 'big')
        # hop limit: 8 bits
        hop_limit:bytes = ((header_bytes[7])).to_bytes(1, 'big')
        # source address: 128 bits (16 bytes)
        source_address:bytes = header_bytes[8:24]
        # destination address: 128 bits (16 bytes)
        destination_address:bytes = header_bytes[24:40]

        header_descriptor:HeaderDescriptor = HeaderDescriptor(
            id=IPv6_HEADER_ID,
            length=40*8,
            fields=[
                FieldDescriptor(id=IPv6Fields.VERSION,          length=4,   position=0, value=version),
                FieldDescriptor(id=IPv6Fields.TRAFFIC_CLASS,    length=8,   position=0, value=traffic_class),
                FieldDescriptor(id=IPv6Fields.FLOW_LABEL,       length=20,  position=0, value=flow_label),
                FieldDescriptor(id=IPv6Fields.PAYLOAD_LENGTH,   length=16,  position=0, value=payload_length),
                FieldDescriptor(id=IPv6Fields.NEXT_HEADER,      length=8,   position=0, value=next_header),
                FieldDescriptor(id=IPv6Fields.HOP_LIMIT,        length=8,   position=0, value=hop_limit),
                FieldDescriptor(id=IPv6Fields.SRC_ADDRESS,      length=128, position=0, value=source_address),
                FieldDescriptor(id=IPv6Fields.DST_ADDRESS,      length=128, position=0, value=destination_address)
            ]
        )
        return header_descriptor
