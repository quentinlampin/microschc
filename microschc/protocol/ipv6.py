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
from typing import Callable
from microschc.binary.buffer import Buffer, Padding
from microschc.parser import HeaderParser, ParserError
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

    def parse(self, buffer:Buffer) -> HeaderDescriptor:
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

        if buffer.length < 320:
            raise ParserError(buffer=buffer, message=f'length too short: {buffer.length} < 320')
        
        # version: 4 bits
        version:Buffer = buffer[0:4]

        if version != b'\x06':
            raise ParserError(buffer=buffer, message=f"version mismatch: {version.content} != '\x06'")
        
        # traffic_class: 8 bits
        traffic_class:Buffer = buffer[4:12]
        # flow label: 20 bits
        flow_label:Buffer = buffer[12:32]
        # payload length: 16 bits
        payload_length:Buffer = buffer[32:48]
        # next header: 8 bits
        next_header:Buffer = buffer[48:56]
        # hop limit: 8 bits
        hop_limit:Buffer = buffer[56:64]
        # source address: 128 bits (16 bytes)
        source_address:Buffer = buffer[64:192]
        # destination address: 128 bits (16 bytes)
        destination_address:Buffer = buffer[192:320]

        header_descriptor:HeaderDescriptor = HeaderDescriptor(
            id=IPv6_HEADER_ID,
            length=320,
            fields=[
                FieldDescriptor(id=IPv6Fields.VERSION,         position=0, value=version),
                FieldDescriptor(id=IPv6Fields.TRAFFIC_CLASS,   position=0, value=traffic_class),
                FieldDescriptor(id=IPv6Fields.FLOW_LABEL,      position=0, value=flow_label),
                FieldDescriptor(id=IPv6Fields.PAYLOAD_LENGTH,  position=0, value=payload_length),
                FieldDescriptor(id=IPv6Fields.NEXT_HEADER,     position=0, value=next_header),
                FieldDescriptor(id=IPv6Fields.HOP_LIMIT,       position=0, value=hop_limit),
                FieldDescriptor(id=IPv6Fields.SRC_ADDRESS,     position=0, value=source_address),
                FieldDescriptor(id=IPv6Fields.DST_ADDRESS,     position=0, value=destination_address)
            ]
        )
        return header_descriptor
    
def _compute_payload_length(packet: Buffer, field_cursor: int) -> Buffer:
    payload: Buffer = packet[field_cursor + 288:]
    payload_length: int = payload.length // 8 if payload.length%8 == 0 else payload.length // 8 + 1
    buffer: Buffer = Buffer(content=payload_length.to_bytes(2, 'big'), length=16, padding=Padding.LEFT)
    return buffer


IPv6ComputeFunctions: dict(str, Callable[[Buffer, int], Buffer]) = {
    IPv6Fields.PAYLOAD_LENGTH: _compute_payload_length
}
    
