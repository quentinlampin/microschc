"""
CoAP header parser

Parser for the CoAP protocol header as defined in RFC7252 [1].


[1] "RFC7252: The Constrained Application Protocol (CoAP)", Z. Shelby et al.
"""

from enum import Enum
from microschc.parser import HeaderParser
from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor

COAP_HEADER_ID = 'CoAP'

class CoAPFields(str, Enum):
    VERSION         = 'Version'
    TYPE            = 'Type'
    TOKEN_LENGTH    = 'Token Length'
    CODE            = 'Code'
    MESSAGE_ID      = 'Message ID'
    HOP_LIMIT       = 'Hop Limit'
    SRC_ADDRESS     = 'Source Address'
    DST_ADDRESS     = 'Destination Address'


class CoAPParser(HeaderParser):

    def __init__(self) -> None:
        super().__init__(name=COAP_HEADER_ID)

    def parse(self, buffer:bytes) -> HeaderDescriptor:
        """
         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Ver| T |  TKL  |      Code     |          Message ID           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Token (if any, TKL bytes) ...
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Options (if any) ...
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |1 1 1 1 1 1 1 1|    Payload (if any) ...
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        header_bytes:bytes = buffer[0:32]

        # version: 2 bits
        version:int = (header_bytes[0] & 0b1100_0000) >> 6
        # type: 2 bits
        type:int = (header_bytes[0] & 0x0011_0000) >> 4
        # token_length: 4 bits
        token_length:int = header_bytes[0] & 0x0f
    
        header_descriptor:HeaderDescriptor = HeaderDescriptor(
            id=COAP_HEADER_ID,
            length=40*8,
            fields=[
                FieldDescriptor(id=CoAPFields.VERSION,          length=4,   position=0, value=version),
                FieldDescriptor(id=CoAPFields.TYPE,             length=2,   position=0, value=type),
                FieldDescriptor(id=CoAPFields.TOKEN_LENGTH,       length=20,  position=0, value=token_length),
            ]
        )
        return header_descriptor
