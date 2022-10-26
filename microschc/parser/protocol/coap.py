"""
CoAP header parser

Parser for the CoAP protocol header as defined in RFC7252 [1].

Note: The case of CoAP in the context of SCHC is a odd one.
      Compressing `Option Values` requires **interpreting** CoAP fields,
      specifically option deltas to identify options types.

      By default, this implementation strays away from SCHC philosophy: instead of
      interpreting fields values, i.e. provide absolute option types and
      option values, it only exposes the `raw` fields: option deltas and
      option lengths. The rationale for this choice is that options inside
      a CoAP packet are not expected to vary too much for a device, therefore
      rendering the need to access to option semantic useless.




[1] "RFC7252: The Constrained Application Protocol (CoAP)", Z. Shelby et al.
"""


from enum import Enum
from typing import List
from microschc.parser import HeaderParser
from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor


COAP_HEADER_ID = 'CoAP'


class CoAPHeaderFields(str, Enum):
    VERSION                 = 'Version'
    TYPE                    = 'Type'
    TOKEN_LENGTH            = 'Token Length'
    CODE                    = 'Code'
    MESSAGE_ID              = 'Message ID'
    TOKEN                   = 'Token'
    PAYLOAD_MARKER          = 'Payload Marker'
    OPTION_DELTA            = 'Option Delta'
    OPTION_LENGTH           = 'Option Length'
    OPTION_DELTA_EXTENDED   = 'Option Delta Extended'
    OPTION_LENGTH_EXTENDED  = 'Option Length Extended'
    OPTION_VALUE            = 'Option Value'


    HOP_LIMIT               = 'Hop Limit'
    SRC_ADDRESS             = 'Source Address'
    DST_ADDRESS             = 'Destination Address'

    
class CoAOptionFields(str, Enum):
    CONTENT_FORMAT          = 'Content-Format'
    ENTITY_TAG              = 'ETag'
    LOCATION_PATH           = 'Location-Path'
    LOCATION_QUERY          = 'Location-Query'
    MAX_AGE                 = 'Max-Age'
    PROXY_URI               = 'Proxy-Uri'
    PROXY_SCHEME            = 'Proxy-Scheme'
    URI_HOST                = 'Uri-Host'
    URI_PATH                = 'Uri-Path'
    URI_PORT                = 'Uri-Port'


class CoAPDefinitions(int, Enum):
    OPTION_DELTA_EXTENDED_8BITS      = 13
    OPTION_DELTA_EXTENDED_16BITS     = 14
    OPTION_LENGTH_EXTENDED_8BITS     = 13
    OPTION_LENGTH_EXTENDED_16BITS    = 14


class CoAPParser(HeaderParser):

    def __init__(self, interpret_options=False) -> None:
        super().__init__(name=COAP_HEADER_ID)

    def parse(self, buffer: bytes) -> HeaderDescriptor:
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
        header_bytes: bytes = buffer[0:]

        # version: 2 bits
        version: int = (header_bytes[0] & 0b1100_0000) >> 6
        # type: 2 bits # noqa: F723 
        type: int = (header_bytes[0] & 0b0011_0000) >> 4
        # token_length: 4 bits
        token_length: int = header_bytes[0] & 0x0f
        # code: 8 bits
        code: int = header_bytes[1] & 0xff
        # message ID : 16 bits
        message_id: int = (header_bytes[2] << 8) | header_bytes[3]
        # token : token_length x 8 bits (token length is in bytes)
        token: bytes = header_bytes[4: 4+token_length]

        header_fields: List[FieldDescriptor] = [
                FieldDescriptor(id=CoAPHeaderFields.VERSION,          length=2,                 position=0,    value=version),
                FieldDescriptor(id=CoAPHeaderFields.TYPE,             length=2,                 position=0,    value=type),
                FieldDescriptor(id=CoAPHeaderFields.TOKEN_LENGTH,     length=4,                 position=0,    value=token_length),
                FieldDescriptor(id=CoAPHeaderFields.CODE,             length=8,                 position=0,    value=code),
                FieldDescriptor(id=CoAPHeaderFields.MESSAGE_ID,       length=16,                position=0,    value=message_id),
                FieldDescriptor(id=CoAPHeaderFields.TOKEN,            length=token_length*8,    position=0,    value=token),
        ]

        options_bytes: bytes = buffer[4+token_length:]
        options_fields: List[FieldDescriptor] = _parse_options(options_bytes)
    
        header_descriptor:HeaderDescriptor = HeaderDescriptor(
            id= COAP_HEADER_ID,
            length= 4*8,
            fields= header_fields + options_fields
        )
        return header_descriptor

def _parse_options(buffer: bytes) -> List[FieldDescriptor]:
    """
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
    """
    fields: List[FieldDescriptor] = []
    cursor: int = 0
    option_index: int = 0

    # parse options until reaching the payload marker byte
    while buffer[cursor] != 0xff:
        option_index += 1
        option_bytes: bytes = buffer[cursor:]
        
        # option_delta: 4 bits
        option_delta: int = (option_bytes[0] & 0xf0) >> 4
        fields.append(FieldDescriptor(id=CoAPHeaderFields.OPTION_DELTA, length=4, position=option_index, value=option_delta))

        # option_length: 4 bits
        option_length: int = option_bytes[0] & 0x0f
        fields.append(FieldDescriptor(id=CoAPHeaderFields.OPTION_LENGTH, length=4, position=option_index, value=option_length))

        # option_length_extended: 
        option_length_extended: int = 0

        option_offset: int = 1 # to keep track of variable length fields

        if option_delta == CoAPDefinitions.OPTION_DELTA_EXTENDED_8BITS:
            # option_delta_extended: 8 bits
            option_delta_extended: int = option_bytes[1]
            fields.append(FieldDescriptor(id=CoAPHeaderFields.OPTION_DELTA_EXTENDED, length=8, position=option_index, value=option_delta_extended))
            option_offset = 2

        elif option_delta == CoAPDefinitions.OPTION_DELTA_EXTENDED_16BITS:
            # option_delta_extended: 16 bits
            option_delta_extended: int = (option_bytes[1] << 8) & option_bytes[2]
            fields.append(FieldDescriptor(id=CoAPHeaderFields.OPTION_DELTA_EXTENDED, length=16, position=option_index, value=option_delta_extended))
            option_offset = 3

        if option_length == CoAPDefinitions.OPTION_LENGTH_EXTENDED_8BITS:
            # option_length_extended: 8 bits
            option_length_extended: int = option_bytes[option_offset]
            fields.append(FieldDescriptor(id=CoAPHeaderFields.OPTION_LENGTH_EXTENDED, length=8, position=option_index, value=option_length_extended))
            option_offset += 1

        elif option_length == CoAPDefinitions.OPTION_LENGTH_EXTENDED_16BITS:
            # option_length_extended: 16 bits
            option_length_extended: int = (option_bytes[option_offset] << 8) & option_bytes[option_offset+1]
            fields.append(FieldDescriptor(id=CoAPHeaderFields.OPTION_LENGTH_EXTENDED, length=16, position=option_index, value=option_length_extended))
            option_offset += 2

        option_value_length = option_length + option_length_extended
        option_value: bytes = option_bytes[option_offset: option_offset+option_value_length]
        fields.append(FieldDescriptor(id=CoAPHeaderFields.OPTION_VALUE, length=option_value_length*8, position=option_index, value=option_value))

        option_offset += option_value_length
        cursor += option_offset

    # append payload marker field
    fields.append(FieldDescriptor(id=CoAPHeaderFields.PAYLOAD_MARKER, length=8, position=0, value=b'\xff'))

    # return CoAP fields descriptors list
    return fields