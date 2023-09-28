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
from microschc.parser import HeaderParser, ParserError
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
    PAYLOAD_MARKER_VALUE             = b'\xff'


class CoAPParser(HeaderParser):

    def __init__(self, interpret_options=False) -> None:
        super().__init__(name=COAP_HEADER_ID)

    def match(self, buffer: Buffer) -> bool:
        return (buffer.length >= 32)
        
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

        if buffer.length < 32:
            raise ParserError(buffer=buffer, message=f'length too short: {buffer.length} < 32')

        # version: 2 bits
        version: Buffer = buffer[0:2]
        # type: 2 bits # noqa: F723 
        type: Buffer = buffer[2:4]
        # token_length: 4 bits
        token_length: Buffer = buffer[4:8]
        token_length_int = token_length.content[0]
        # code: 8 bits
        code: Buffer = buffer[8:16]
        # message ID : 16 bits
        message_id: Buffer = buffer[16:32]
        try:
            # token : token_length_int x 8 bits (token length is in bytes)
            token: Buffer = buffer[32: 32+token_length_int*8]
        except Exception:
            raise ParserError(buffer=buffer, message=f'error parsing token at bits 32-{32+token_length_int}')

        header_fields: List[FieldDescriptor] = [
                FieldDescriptor(id=CoAPFields.VERSION,          position=0,    value=version),
                FieldDescriptor(id=CoAPFields.TYPE,             position=0,    value=type),
                FieldDescriptor(id=CoAPFields.TOKEN_LENGTH,     position=0,    value=token_length),
                FieldDescriptor(id=CoAPFields.CODE,             position=0,    value=code),
                FieldDescriptor(id=CoAPFields.MESSAGE_ID,       position=0,    value=message_id),
        ]
        if token_length_int > 0:
            token_field: FieldDescriptor = FieldDescriptor(id=CoAPFields.TOKEN, position=0, value=token)
            header_fields.append(token_field)

        options_bytes: Buffer = buffer[32+token_length_int*8:]
        if options_bytes.length > 0:
            try:
                options_fields, option_bits_consumed = _parse_options(options_bytes)
            except Exception:
                raise ParserError(buffer=options_bytes, message='error parsing options')
        else:
            option_bits_consumed = 0
            options_fields = []
    
        header_descriptor:HeaderDescriptor = HeaderDescriptor(
            id= COAP_HEADER_ID,
            length= 4*8 + token_length_int*8 +  option_bits_consumed,
            fields= header_fields + options_fields
        )
        return header_descriptor

def _parse_options(buffer: Buffer) -> Tuple[List[FieldDescriptor], int]:
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

    # parse options until reaching the payload marker byte or end of buffer
    while cursor < buffer.length and buffer[cursor:cursor+8] != CoAPDefinitions.PAYLOAD_MARKER_VALUE:
        option_index += 1
        option_bytes: Buffer = buffer[cursor:]
        
        # option_delta: 4 bits
        option_delta: Buffer = option_bytes[0:4]
        fields.append(FieldDescriptor(id=CoAPFields.OPTION_DELTA, position=option_index, value=option_delta))

        # option_length: 4 bits
        option_length: Buffer = option_bytes[4:8]
        option_length_int: int = option_length.content[0]
        fields.append(FieldDescriptor(id=CoAPFields.OPTION_LENGTH, position=option_index, value=option_length))

        # option_length_extended: 
        option_length_extended_int: int = 0

        option_offset: int = 8 # to keep track of variable length fields

        if option_delta == CoAPDefinitions.OPTION_DELTA_EXTENDED_8BITS:
            # option_delta_extended: 8 bits
            option_delta_extended: Buffer = option_bytes[option_offset:option_offset+8]
            fields.append(FieldDescriptor(id=CoAPFields.OPTION_DELTA_EXTENDED, position=option_index, value=option_delta_extended))
            option_offset += 8

        elif option_delta == CoAPDefinitions.OPTION_DELTA_EXTENDED_16BITS:
            # option_delta_extended: 16 bits
            option_delta_extended: bytes = option_bytes[option_offset:option_offset+16]
            fields.append(FieldDescriptor(id=CoAPFields.OPTION_DELTA_EXTENDED, position=option_index, value=option_delta_extended))
            option_offset += 16

        if option_length == CoAPDefinitions.OPTION_LENGTH_EXTENDED_8BITS:
            # option_length_extended: 8 bits
            option_length_extended: Buffer = option_bytes[option_offset:option_offset+8]
            option_length_extended_int: int = option_length_extended.content[0]
            fields.append(FieldDescriptor(id=CoAPFields.OPTION_LENGTH_EXTENDED, position=option_index, value=option_length_extended))
            option_offset += 8

        elif option_length == CoAPDefinitions.OPTION_LENGTH_EXTENDED_16BITS:
            # option_length_extended: 16 bits
            option_length_extended: Buffer = option_bytes[option_offset:option_offset+16]
            option_length_extended_int: int = (option_length_extended.content[0] << 8) + option_length_extended[1]
            fields.append(FieldDescriptor(id=CoAPFields.OPTION_LENGTH_EXTENDED, position=option_index, value=option_length_extended))
            option_offset += 16

        option_value_length = (option_length_int + option_length_extended_int) * 8
        if option_value_length > 0:
            option_value: Buffer = option_bytes[option_offset: option_offset+option_value_length]
            fields.append(FieldDescriptor(id=CoAPFields.OPTION_VALUE, position=option_index, value=option_value))

        option_offset += option_value_length
        cursor += option_offset

    # append payload marker field
    if cursor < buffer.length:
        cursor += 8
        fields.append(FieldDescriptor(id=CoAPFields.PAYLOAD_MARKER, position=0, value=Buffer(content=b'\xff', length=8)))

    # return CoAP fields descriptors list
    return (fields, cursor)