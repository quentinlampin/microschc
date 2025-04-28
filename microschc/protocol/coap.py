"""
CoAP header parser

Parser for the CoAP protocol header as defined in RFC7252 [1].
Additional options from RFC 7959 [2] included.

Note: The case of CoAP in the context of SCHC is a odd one.
      Compressing `Option Values` requires **interpreting** CoAP fields,
      specifically option deltas to identify options types.

      By default, this implementation strays away from SCHC philosophy: instead of
      interpreting fields values, i.e. provide absolute option types and
      option values, it only exposes the `raw` fields: option deltas and
      option lengths. The rationale for this choice is that options inside
      a CoAP packet are not expected to vary too much for a device, therefore
      rendering the need to access to option semantic useless.
      
      However, setting the interpret_option to CoAPOptionMode.SEMANTIC, the parser
      tries to decode the option delta fields and expose the decoded option name
      instead, therefore reducing the number of fields. This comes at the cost of extra
      processing on the decompressor side, requiring the reconstruction of option delta
      and option length fields from options numbers.




[1] "RFC7252: The Constrained Application Protocol (CoAP)", Z. Shelby et al.
[2] "RFC7959: Block-Wise Transfers in the Constrained Application Protocol (CoAP), C. Bormann et al."
"""


from enum import Enum, IntEnum
from microschc.compat import StrEnum
import re
from typing import Dict, List, Tuple
from microschc.binary.buffer import Buffer, Padding
from microschc.parser import HeaderParser, ParserError
from microschc.parser.parser import UnparserError
from microschc.protocol.registry import REGISTER_PARSER, ProtocolsIDs
from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor


COAP_HEADER_ID = 'CoAP'


class CoAPFields(StrEnum):
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

    # semantic option fields
    OPTION_IF_MATCH         = f'{COAP_HEADER_ID}:Option If-Match'
    OPTION_URI_HOST         = f'{COAP_HEADER_ID}:Option Uri-Host'
    OPTION_ETAG             = f'{COAP_HEADER_ID}:Option ETag'
    OPTION_IF_NONE_MATCH    = f'{COAP_HEADER_ID}:Option If-None-Match'
    OPTION_URI_PORT         = f'{COAP_HEADER_ID}:Option Uri-Port'
    OPTION_LOCATION_PATH    = f'{COAP_HEADER_ID}:Option Location-Path'
    OPTION_URI_PATH         = f'{COAP_HEADER_ID}:Option Uri-Path'
    OPTION_CONTENT_FORMAT   = f'{COAP_HEADER_ID}:Option Content-Format'
    OPTION_MAX_AGE          = f'{COAP_HEADER_ID}:Option Max-Age'
    OPTION_URI_QUERY        = f'{COAP_HEADER_ID}:Option Uri-Query'
    OPTION_ACCEPT           = f'{COAP_HEADER_ID}:Option Accept'
    OPTION_LOCATION_QUERY   = f'{COAP_HEADER_ID}:Option Location-Query'
    OPTION_BLOCK2           = f'{COAP_HEADER_ID}:Option Block2'
    OPTION_BLOCK1           = f'{COAP_HEADER_ID}:Option Block1'
    OPTION_PROXY_URI        = f'{COAP_HEADER_ID}:Option Proxy-Uri'
    OPTION_PROXY_SCHEME     = f'{COAP_HEADER_ID}:Option Proxy-Scheme'
    OPTION_SIZE1            = f'{COAP_HEADER_ID}:Option Size1'
    OPTION_UNKNOWN          = f'{COAP_HEADER_ID}:Option Unknown'


class CoAPOptionIDs(IntEnum):
    IF_MATCH            = 1
    URI_HOST            = 3
    ETAG                = 4
    IF_NONE_MATCH       = 5
    URI_PORT            = 7
    LOCATION_PATH       = 8
    URI_PATH            = 11
    CONTENT_FORMAT      = 12
    MAX_AGE             = 14
    URI_QUERY           = 15
    ACCEPT              = 17
    LOCATION_QUERY      = 20
    BLOCK2              = 23
    BLOCK1              = 27
    PROXY_URI           = 35
    PROXY_SCHEME        = 39
    SIZE1               = 60

COAP_OPTIONS_NUMBER_TO_NAME = {
    CoAPOptionIDs.IF_MATCH:         CoAPFields.OPTION_IF_MATCH,
    CoAPOptionIDs.URI_HOST:         CoAPFields.OPTION_URI_HOST,
    CoAPOptionIDs.ETAG:             CoAPFields.OPTION_ETAG,
    CoAPOptionIDs.IF_NONE_MATCH:    CoAPFields.OPTION_IF_NONE_MATCH,
    CoAPOptionIDs.URI_PORT:         CoAPFields.OPTION_URI_PORT,
    CoAPOptionIDs.LOCATION_PATH:    CoAPFields.OPTION_LOCATION_PATH,
    CoAPOptionIDs.URI_PATH:         CoAPFields.OPTION_URI_PATH,
    CoAPOptionIDs.CONTENT_FORMAT:   CoAPFields.OPTION_CONTENT_FORMAT,
    CoAPOptionIDs.MAX_AGE:          CoAPFields.OPTION_MAX_AGE,
    CoAPOptionIDs.URI_QUERY:        CoAPFields.OPTION_URI_QUERY,
    CoAPOptionIDs.ACCEPT:           CoAPFields.OPTION_ACCEPT,
    CoAPOptionIDs.LOCATION_QUERY:   CoAPFields.OPTION_LOCATION_QUERY,
    CoAPOptionIDs.BLOCK1:           CoAPFields.OPTION_BLOCK1,
    CoAPOptionIDs.PROXY_URI:        CoAPFields.OPTION_PROXY_URI,
    CoAPOptionIDs.PROXY_SCHEME:     CoAPFields.OPTION_PROXY_SCHEME,
    CoAPOptionIDs.SIZE1:            CoAPFields.OPTION_SIZE1
}

COAP_OPTIONS_NAME_TO_NUMBER = {v:k for k,v in COAP_OPTIONS_NUMBER_TO_NAME.items()}


class CoAPDefinitions(bytes, Enum):
    OPTION_DELTA_EXTENDED_8BITS      = b'\x0d'
    OPTION_DELTA_EXTENDED_16BITS     = b'\x0e'
    OPTION_LENGTH_EXTENDED_8BITS     = b'\x0d'
    OPTION_LENGTH_EXTENDED_16BITS    = b'\x0e'
    PAYLOAD_MARKER_VALUE             = b'\xff'

class CoAPOptionMode(StrEnum):
    SYNTACTIC   = 'syntactic'
    SEMANTIC    = 'semantic'


class CoAPParser(HeaderParser):

    def __init__(self, predict_next:bool=False, interpret_options:CoAPOptionMode=CoAPOptionMode.SYNTACTIC) -> None:
        super().__init__(name=COAP_HEADER_ID, predict_next=predict_next)
        self.interpret_options: CoAPOptionMode = interpret_options
        if self.interpret_options is CoAPOptionMode.SEMANTIC:
            self.unknown_option_pattern = rf'{CoAPFields.OPTION_UNKNOWN}\((\d+)\)'

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
                options_fields, option_bits_consumed = _parse_options(options_bytes, mode=self.interpret_options)
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
    
    def unparse(self, decompressed_fields: List[Tuple[str, Buffer]]) -> List[Tuple[str, Buffer]]:
        
        if self.interpret_options is CoAPOptionMode.SYNTACTIC:
            return decompressed_fields

            
        unparsed_fields: List[Tuple[str, Buffer]] = []
        previous_option_number: int = 0
        
        for (field_id, field_value) in decompressed_fields:

            if field_id in { CoAPFields.VERSION, CoAPFields.TYPE, CoAPFields.TOKEN_LENGTH, CoAPFields.CODE,
                             CoAPFields.MESSAGE_ID, CoAPFields.TOKEN, CoAPFields.PAYLOAD_MARKER }:
                unparsed_fields.append((field_id, field_value))
            else:
                try:
                    option_number = COAP_OPTIONS_NAME_TO_NUMBER[field_id]
                except KeyError:
                    match = re.match(self.unknown_option_pattern, field_id)
                    if match:
                        option_number = match.group(1)
                    else:
                        raise UnparserError(
                            decompressed_fields=decompressed_fields,
                            message=f'unrecognized field ID: {field_id}'
                        ) 
                finally:
                    option_delta: int = option_number - previous_option_number
                    
                    # option delta
                    if option_delta < 13:
                        unparsed_fields.append((CoAPFields.OPTION_DELTA, Buffer(content=option_delta.to_bytes(length=1, byteorder='little'), length=4, padding=Padding.LEFT)))
                    elif option_delta < 269:
                        unparsed_fields.append((CoAPFields.OPTION_DELTA, Buffer(content=(13).to_bytes(length=1, byteorder='little'), length=4, padding=Padding.LEFT)))
                    else:
                        unparsed_fields.append((CoAPFields.OPTION_DELTA, Buffer(content=(14).to_bytes(length=1, byteorder='little'), length=4, padding=Padding.LEFT)))

                    previous_option_number = option_number
                    
                    # option length
                    option_length_bytes: int = field_value.length//8
                    if option_length_bytes < 12:
                        unparsed_fields.append((CoAPFields.OPTION_LENGTH, Buffer(content=option_length_bytes.to_bytes(length=1, byteorder='little'), length=4, padding=Padding.LEFT)))
                    elif option_length_bytes < 269:   
                        unparsed_fields.append((CoAPFields.OPTION_LENGTH, Buffer(content=(13).to_bytes(length=1, byteorder='little'), length=4, padding=Padding.LEFT)))
                    else:
                        unparsed_fields.append((CoAPFields.OPTION_LENGTH, Buffer(content=(14).to_bytes(length=1, byteorder='little'), length=4, padding=Padding.LEFT)))
                    
                    # option delta extended
                    if option_delta > 13 and option_delta < 269:
                        unparsed_fields.append((CoAPFields.OPTION_DELTA_EXTENDED, Buffer(content=(option_delta-13).to_bytes(length=1, byteorder='little'), length=8, padding=Padding.LEFT)))
                    elif option_delta > 268:
                        unparsed_fields.append((CoAPFields.OPTION_DELTA_EXTENDED, Buffer(content=(option_delta-269).to_bytes(length=2, byteorder='little'), length=16, padding=Padding.LEFT)))
                        
                    # option length extended
                    if option_length_bytes > 11 and option_length_bytes < 269: 
                        unparsed_fields.append((CoAPFields.OPTION_LENGTH_EXTENDED, Buffer(content=(option_length_bytes-13).to_bytes(length=1, byteorder='little'), length=8, padding=Padding.LEFT)))
                    elif option_length_bytes > 268:
                        unparsed_fields.append((CoAPFields.OPTION_LENGTH_EXTENDED, Buffer(content=(option_length_bytes-269).to_bytes(length=2, byteorder='little'), length=16, padding=Padding.LEFT)))
                        
                    # option value
                    unparsed_fields.append((CoAPFields.OPTION_VALUE, field_value))
        return unparsed_fields
                                    
                    
        

def _parse_options(buffer: Buffer, mode:CoAPOptionMode) -> Tuple[List[FieldDescriptor], int]:
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
    option_field_positions: Dict[CoAPFields, int] = {oid: 0 for oid in CoAPFields}
    option_index: int = 0

    # parse options until reaching the payload marker byte or end of buffer
    while cursor < buffer.length and buffer[cursor:cursor+8] != CoAPDefinitions.PAYLOAD_MARKER_VALUE:
        option_bytes: Buffer = buffer[cursor:]

        option_delta: Buffer = option_bytes[0:4]
        option_length: Buffer = option_bytes[4:8]
        option_length_int: int = option_length.value()
        option_length_extended_int: int = 0

        option_offset: int = 8 # to keep track of variable length fields

        if option_delta == CoAPDefinitions.OPTION_DELTA_EXTENDED_8BITS:
            option_delta_extended: Buffer = option_bytes[option_offset:option_offset+8]
            option_field_positions[CoAPFields.OPTION_DELTA_EXTENDED] += 1
            option_offset += 8

        elif option_delta == CoAPDefinitions.OPTION_DELTA_EXTENDED_16BITS:
            option_delta_extended: bytes = option_bytes[option_offset:option_offset+16]
            option_field_positions[CoAPFields.OPTION_DELTA_EXTENDED] += 1
            option_offset += 16

        if option_length == CoAPDefinitions.OPTION_LENGTH_EXTENDED_8BITS:
            option_length_extended: Buffer = option_bytes[option_offset:option_offset+8]
            option_length_extended_int: int = option_length_extended.value()
            option_field_positions[CoAPFields.OPTION_LENGTH_EXTENDED] += 1
            option_offset += 8

        elif option_length == CoAPDefinitions.OPTION_LENGTH_EXTENDED_16BITS:
            # option_length_extended: 16 bits
            option_length_extended: Buffer = option_bytes[option_offset:option_offset+16]
            option_length_extended_int: int = option_length_extended.value()
            option_field_positions[CoAPFields.OPTION_LENGTH_EXTENDED] += 1
            option_offset += 16

        option_value_length = (option_length_int + option_length_extended_int) * 8

        if option_value_length > 0:
            option_value: Buffer = option_bytes[option_offset: option_offset+option_value_length]
            option_field_positions[CoAPFields.OPTION_VALUE] += 1

        option_offset += option_value_length
        cursor += option_offset

        if mode is CoAPOptionMode.SYNTACTIC:
            option_field_positions[CoAPFields.OPTION_DELTA] += 1
            option_field_positions[CoAPFields.OPTION_LENGTH] += 1

            fields.append(FieldDescriptor(id=CoAPFields.OPTION_DELTA, position=option_field_positions[CoAPFields.OPTION_DELTA], value=option_delta))
            fields.append(FieldDescriptor(id=CoAPFields.OPTION_LENGTH, position=option_field_positions[CoAPFields.OPTION_LENGTH], value=option_length))

            if option_delta in {CoAPDefinitions.OPTION_DELTA_EXTENDED_8BITS, CoAPDefinitions.OPTION_DELTA_EXTENDED_16BITS}:
                fields.append(FieldDescriptor(id=CoAPFields.OPTION_DELTA_EXTENDED, position=option_field_positions[CoAPFields.OPTION_DELTA_EXTENDED], value=option_delta_extended))

            if option_length in {CoAPDefinitions.OPTION_LENGTH_EXTENDED_8BITS, CoAPDefinitions.OPTION_LENGTH_EXTENDED_16BITS}:
                fields.append(FieldDescriptor(id=CoAPFields.OPTION_LENGTH_EXTENDED, position=option_field_positions[CoAPFields.OPTION_LENGTH_EXTENDED], value=option_length_extended))

            if option_value_length > 0:
                fields.append(FieldDescriptor(id=CoAPFields.OPTION_VALUE, position=option_field_positions[CoAPFields.OPTION_VALUE], value=option_value))

        elif mode is CoAPOptionMode.SEMANTIC:
            try:
                option_delta_int: int = option_delta.value()
                if option_delta_int < 13:
                    option_index += option_delta_int
                elif option_delta_int == 13:
                    option_delta_extended_int = option_delta_extended.value()
                    option_index += option_delta_extended_int + 13
                else:
                    option_index += option_delta_extended_int + 269
                interpreted_option_field_id = COAP_OPTIONS_NUMBER_TO_NAME[option_index]
                option_field_positions[interpreted_option_field_id] += 1

            except KeyError:
                interpreted_option_field_id = f"{CoAPFields.OPTION_UNKNOWN}({option_index})"
                try:
                    option_field_positions[interpreted_option_field_id] += 1
                except KeyError:
                    option_field_positions[interpreted_option_field_id] = 1
                    
            finally:
                fields.append(FieldDescriptor(id=interpreted_option_field_id, value=option_value, position=option_field_positions[interpreted_option_field_id]))

    # append payload marker field
    if cursor < buffer.length:
        cursor += 8
        fields.append(FieldDescriptor(id=CoAPFields.PAYLOAD_MARKER, position=0, value=Buffer(content=b'\xff', length=8)))

    # return CoAP fields descriptors list
    return (fields, cursor)

REGISTER_PARSER(protocol_id=ProtocolsIDs.COAP, parser_class=CoAPParser)
