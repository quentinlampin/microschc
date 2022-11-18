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
from typing import List, Tuple
from microschc.binary.buffer import Buffer
from microschc.parser import HeaderParser
from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor


COAP_HEADER_ID = 'CoAP'


class CoAPFields(str, Enum):
    VERSION                 = f'{COAP_HEADER_ID}:Version'
    TYPE                    = f'{COAP_HEADER_ID}:Type'
    TOKEN_LENGTH            = f'{COAP_HEADER_ID}:Token Length'
    CODE                    = f'{COAP_HEADER_ID}:Code'
    MESSAGE_ID              = f'{COAP_HEADER_ID}:Message ID'
    TOKEN                   = f'{COAP_HEADER_ID}:Token'
    PAYLOAD_MARKER          = f'{COAP_HEADER_ID}:Payload Marker'
    OPTION_DELTA            = f'{COAP_HEADER_ID}:Option Delta'
    OPTION_LENGTH           = f'{COAP_HEADER_ID}:Option Length'
    OPTION_DELTA_EXTENDED   = f'{COAP_HEADER_ID}:Option Delta Extended'
    OPTION_LENGTH_EXTENDED  = f'{COAP_HEADER_ID}:Option Length Extended'
    OPTION_VALUE            = f'{COAP_HEADER_ID}:Option Value'


    HOP_LIMIT               = f'{COAP_HEADER_ID}:Hop Limit'
    SRC_ADDRESS             = f'{COAP_HEADER_ID}:Source Address'
    DST_ADDRESS             = f'{COAP_HEADER_ID}:Destination Address'

    
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


class CoAPDefinitions(bytes, Enum):
    OPTION_DELTA_EXTENDED_8BITS      = b'\x0d'
    OPTION_DELTA_EXTENDED_16BITS     = b'\x0e'
    OPTION_LENGTH_EXTENDED_8BITS     = b'\x0d'
    OPTION_LENGTH_EXTENDED_16BITS    = b'\x0e'


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
        version: bytes = ((header_bytes[0] & 0b1100_0000) >> 6).to_bytes(1, 'big')
        # type: 2 bits # noqa: F723 
        type: bytes = ((header_bytes[0] & 0b0011_0000) >> 4).to_bytes(1, 'big')
        # token_length: 4 bits
        token_length_int = (header_bytes[0] & 0x0f)
        token_length: bytes = (token_length_int).to_bytes(1, 'big')
        # code: 8 bits
        code: bytes = header_bytes[1:2]
        # message ID : 16 bits
        message_id: bytes = header_bytes[2:4]
        # token : token_length_int x 8 bits (token length is in bytes)
        token: bytes = header_bytes[4: 4+token_length_int]

        header_fields: List[FieldDescriptor] = [
                FieldDescriptor(id=CoAPFields.VERSION,          position=0,    value=Buffer(content=version, bit_length=2)),
                FieldDescriptor(id=CoAPFields.TYPE,             position=0,    value=Buffer(content=type, bit_length=2)),
                FieldDescriptor(id=CoAPFields.TOKEN_LENGTH,     position=0,    value=Buffer(content=token_length, bit_length=4)),
                FieldDescriptor(id=CoAPFields.CODE,             position=0,    value=Buffer(content=code, bit_length=8)),
                FieldDescriptor(id=CoAPFields.MESSAGE_ID,       position=0,    value=Buffer(content=message_id, bit_length=16)),
                FieldDescriptor(id=CoAPFields.TOKEN,            position=0,    value=Buffer(content=token, bit_length=token_length_int*8)),
        ]

        options_bytes: bytes = buffer[4+token_length_int:]
        options_fields, option_bits_consumed = _parse_options(options_bytes)
    
        header_descriptor:HeaderDescriptor = HeaderDescriptor(
            id= COAP_HEADER_ID,
            length= 4*8 + token_length_int*8 +  option_bits_consumed,
            fields= header_fields + options_fields
        )
        return header_descriptor

def _parse_options(buffer: bytes) -> Tuple[List[FieldDescriptor], int]:
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
        option_delta: bytes = ((option_bytes[0] & 0xf0) >> 4).to_bytes(1, 'big')
        fields.append(FieldDescriptor(id=CoAPFields.OPTION_DELTA, position=option_index, value=Buffer(content=option_delta, bit_length=4)))

        # option_length: 4 bits
        option_length_int: int = option_bytes[0] & 0x0f
        option_length: bytes = option_length_int.to_bytes(1, 'big')
        fields.append(FieldDescriptor(id=CoAPFields.OPTION_LENGTH, position=option_index, value=Buffer(content=option_length, bit_length=4)))

        # option_length_extended: 
        option_length_extended_int: int = 0

        option_offset: int = 1 # to keep track of variable length fields

        if option_delta == CoAPDefinitions.OPTION_DELTA_EXTENDED_8BITS:
            # option_delta_extended: 8 bits
            option_delta_extended: bytes = option_bytes[1:2]
            fields.append(FieldDescriptor(id=CoAPFields.OPTION_DELTA_EXTENDED, position=option_index, value=Buffer(content=option_delta_extended, bit_length=8)))
            option_offset = 2

        elif option_delta == CoAPDefinitions.OPTION_DELTA_EXTENDED_16BITS:
            # option_delta_extended: 16 bits
            option_delta_extended: bytes = option_bytes[1:3]
            fields.append(FieldDescriptor(id=CoAPFields.OPTION_DELTA_EXTENDED, position=option_index, value=Buffer(content=option_delta_extended, bit_length=16)))
            option_offset = 3

        if option_length == CoAPDefinitions.OPTION_LENGTH_EXTENDED_8BITS:
            # option_length_extended: 8 bits
            option_length_extended_int: int = option_bytes[option_offset]
            option_length_extended: bytes = option_length_extended_int.to_bytes(1, 'big')
            fields.append(FieldDescriptor(id=CoAPFields.OPTION_LENGTH_EXTENDED, position=option_index, value=Buffer(content=option_length_extended, bit_length=8)))
            option_offset += 1

        elif option_length == CoAPDefinitions.OPTION_LENGTH_EXTENDED_16BITS:
            # option_length_extended: 16 bits
            option_length_extended_int: int = (option_bytes[option_offset] << 8) & option_bytes[option_offset+1]
            option_length_extended: bytes = option_bytes[option_offset:option_offset+2]
            fields.append(FieldDescriptor(id=CoAPFields.OPTION_LENGTH_EXTENDED, position=option_index, value=Buffer(content=option_length_extended, bit_length=16)))
            option_offset += 2

        option_value_length = option_length_int + option_length_extended_int
        option_value: bytes = option_bytes[option_offset: option_offset+option_value_length]
        fields.append(FieldDescriptor(id=CoAPFields.OPTION_VALUE, position=option_index, value=Buffer(content=option_value, bit_length=option_value_length*8)))

        option_offset += option_value_length
        cursor += option_offset

    # append payload marker field
    cursor += 1
    fields.append(FieldDescriptor(id=CoAPFields.PAYLOAD_MARKER, position=0, value=Buffer(content=b'\xff', bit_length=8)))

    # return CoAP fields descriptors list
    return (fields, 8*cursor)