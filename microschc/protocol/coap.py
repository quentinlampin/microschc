"""
CoAP header parser

Parser for the CoAP protocol header as defined in RFC7252 [1].
Additional options from RFC 7959 [2] and RFC 7641 [3] included.

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
[3] "RFC7641: Observing Resources in the Constrained Application Protocol (CoAP), Klaus Hartke"
"""


from enum import Enum, IntEnum
from microschc.compat import StrEnum
import re
from typing import Dict, List, Optional, Tuple, Type, Union
from microschc.binary.buffer import Buffer, Padding
from microschc.parser import HeaderParser, ParserError
from microschc.parser.parser import UnparserError
from microschc.protocol.registry import REGISTER_PARSER, ProtocolsIDs
from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor, MatchMapping, RuleFieldDescriptor, DirectionIndicator as DI, MatchingOperator as MO, CompressionDecompressionAction as CDA, TargetValue
from microschc.tools import create_target_value
from microschc.tools.mo import select_mo
from microschc.tools.cda import select_cda


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
    OPTION_OBSERVE          = f'{COAP_HEADER_ID}:Option Observe'
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
    OPTION_IF_MATCH            = 1
    OPTION_URI_HOST            = 3
    OPTION_ETAG                = 4
    OPTION_IF_NONE_MATCH       = 5
    OPTION_OBSERVE             = 6
    OPTION_URI_PORT            = 7
    OPTION_LOCATION_PATH       = 8
    OPTION_URI_PATH            = 11
    OPTION_CONTENT_FORMAT      = 12
    OPTION_MAX_AGE             = 14
    OPTION_URI_QUERY           = 15
    OPTION_ACCEPT              = 17
    OPTION_LOCATION_QUERY      = 20
    OPTION_BLOCK2              = 23
    OPTION_BLOCK1              = 27
    OPTION_PROXY_URI           = 35
    OPTION_PROXY_SCHEME        = 39
    OPTION_SIZE1               = 60

COAP_OPTIONS_NUMBER_TO_NAME = {
    CoAPOptionIDs.OPTION_IF_MATCH:         CoAPFields.OPTION_IF_MATCH,
    CoAPOptionIDs.OPTION_URI_HOST:         CoAPFields.OPTION_URI_HOST,
    CoAPOptionIDs.OPTION_ETAG:             CoAPFields.OPTION_ETAG,
    CoAPOptionIDs.OPTION_IF_NONE_MATCH:    CoAPFields.OPTION_IF_NONE_MATCH,
    CoAPOptionIDs.OPTION_OBSERVE:          CoAPFields.OPTION_OBSERVE,
    CoAPOptionIDs.OPTION_URI_PORT:         CoAPFields.OPTION_URI_PORT,
    CoAPOptionIDs.OPTION_LOCATION_PATH:    CoAPFields.OPTION_LOCATION_PATH,
    CoAPOptionIDs.OPTION_URI_PATH:         CoAPFields.OPTION_URI_PATH,
    CoAPOptionIDs.OPTION_CONTENT_FORMAT:   CoAPFields.OPTION_CONTENT_FORMAT,
    CoAPOptionIDs.OPTION_MAX_AGE:          CoAPFields.OPTION_MAX_AGE,
    CoAPOptionIDs.OPTION_URI_QUERY:        CoAPFields.OPTION_URI_QUERY,
    CoAPOptionIDs.OPTION_ACCEPT:           CoAPFields.OPTION_ACCEPT,
    CoAPOptionIDs.OPTION_LOCATION_QUERY:   CoAPFields.OPTION_LOCATION_QUERY,
    CoAPOptionIDs.OPTION_BLOCK1:           CoAPFields.OPTION_BLOCK1,
    CoAPOptionIDs.OPTION_PROXY_URI:        CoAPFields.OPTION_PROXY_URI,
    CoAPOptionIDs.OPTION_PROXY_SCHEME:     CoAPFields.OPTION_PROXY_SCHEME,
    CoAPOptionIDs.OPTION_SIZE1:            CoAPFields.OPTION_SIZE1
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
                        unparsed_fields.append((CoAPFields.OPTION_DELTA, create_target_value(option_delta, length=4)))
                    elif option_delta < 269:
                        unparsed_fields.append((CoAPFields.OPTION_DELTA, create_target_value(CoAPDefinitions.OPTION_DELTA_EXTENDED_8BITS, length=4)))
                    else:
                        unparsed_fields.append((CoAPFields.OPTION_DELTA, create_target_value(CoAPDefinitions.OPTION_DELTA_EXTENDED_16BITS, length=4)))

                    previous_option_number = option_number
                    
                    # option length
                    option_length_bytes: int = field_value.length//8
                    if option_length_bytes < 12:
                        unparsed_fields.append((CoAPFields.OPTION_LENGTH, create_target_value(option_length_bytes, length=4)))
                    elif option_length_bytes < 269:   
                        unparsed_fields.append((CoAPFields.OPTION_LENGTH, create_target_value(CoAPDefinitions.OPTION_LENGTH_EXTENDED_8BITS, length=4)))
                    else:
                        unparsed_fields.append((CoAPFields.OPTION_LENGTH, create_target_value(CoAPDefinitions.OPTION_LENGTH_EXTENDED_16BITS, length=4)))
                    
                    # option delta extended
                    if option_delta > 13 and option_delta < 269:
                        unparsed_fields.append((CoAPFields.OPTION_DELTA_EXTENDED, create_target_value(option_delta-13, length=8)))
                    elif option_delta > 268:
                        unparsed_fields.append((CoAPFields.OPTION_DELTA_EXTENDED, create_target_value(option_delta-269, length=8)))
                        
                    # option length extended
                    if option_length_bytes > 11 and option_length_bytes < 269: 
                        unparsed_fields.append((CoAPFields.OPTION_LENGTH_EXTENDED, create_target_value(option_length_bytes-13, length=8)))
                    elif option_length_bytes > 268:
                        unparsed_fields.append((CoAPFields.OPTION_LENGTH_EXTENDED, create_target_value(option_length_bytes-269, length=8)))
                        
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
            option_length_int = 269
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

COAP_BASE_HEADER_FIELDS: List[RuleFieldDescriptor] = [
    RuleFieldDescriptor(
        id=CoAPFields.VERSION,
        length=2,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=create_target_value(1, length=2)  # CoAP version 1
    ),
    RuleFieldDescriptor(
        id=CoAPFields.TYPE,
        length=2,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.IGNORE,
        compression_decompression_action=CDA.VALUE_SENT,
        target_value=None
    ),
    RuleFieldDescriptor(
        id=CoAPFields.TOKEN_LENGTH,
        length=4,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.IGNORE,
        compression_decompression_action=CDA.VALUE_SENT,
        target_value=None
    ),
    RuleFieldDescriptor(
        id=CoAPFields.CODE,
        length=8,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.IGNORE,
        compression_decompression_action=CDA.VALUE_SENT,
        target_value=None
    ),
    RuleFieldDescriptor(
        id=CoAPFields.MESSAGE_ID,
        length=16,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.IGNORE,
        compression_decompression_action=CDA.VALUE_SENT,
        target_value=None
    ),
    RuleFieldDescriptor(
        id=CoAPFields.TOKEN,
        length=0,  # Variable length based on TOKEN_LENGTH
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=None
    )
]

COAP_OPTION_TEMPLATE: List[RuleFieldDescriptor] = [
    RuleFieldDescriptor(
        id=CoAPFields.OPTION_DELTA,
        length=4,
        position=1,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.IGNORE,
        compression_decompression_action=CDA.VALUE_SENT,
        target_value=None
    ),
    RuleFieldDescriptor(
        id=CoAPFields.OPTION_LENGTH,
        length=4,
        position=1,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.IGNORE,
        compression_decompression_action=CDA.VALUE_SENT,
        target_value=None
    ),
    RuleFieldDescriptor(
        id=CoAPFields.OPTION_DELTA_EXTENDED,
        length=0,  # Variable length based on OPTION_DELTA
        position=1,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.IGNORE,
        compression_decompression_action=CDA.VALUE_SENT,
        target_value=None
    ),
    RuleFieldDescriptor(
        id=CoAPFields.OPTION_LENGTH_EXTENDED,
        length=0,  # Variable length based on OPTION_LENGTH
        position=1,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.IGNORE,
        compression_decompression_action=CDA.VALUE_SENT,
        target_value=None
    ),
    RuleFieldDescriptor(
        id=CoAPFields.OPTION_VALUE,
        length=0,  # Variable length based on OPTION_LENGTH
        position=1,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.IGNORE,
        compression_decompression_action=CDA.VALUE_SENT,
        target_value=None
    )
]

def coap_base_header_template(
    type: Union[bytes, Buffer, int],
    code: Union[bytes, Buffer, int],
    message_id: Union[bytes, Buffer, int, None] = None,
    token: Union[bytes, Buffer, int, None] = None,
) -> List[RuleFieldDescriptor]:
    """
    Rule descriptor template for CoAP header.
    
    Args:
        type: The CoAP message type (CON, NON, ACK, RST)
        code: The CoAP message code (GET, POST, etc.)
        message_id: The CoAP message ID
        token: Optional token value. If provided, its length will be used to set TOKEN_LENGTH
        
    Returns:
        List[RuleFieldDescriptor]: List of rule field descriptors for the CoAP header
        
    The function generates rule field descriptors for:
    - VERSION (fixed to 1)
    - TYPE
    - TOKEN_LENGTH (computed from token if provided)
    - CODE
    - MESSAGE_ID
    - TOKEN (only included if token is provided)
    """
    # Create target values for each field
    target_values = {
        CoAPFields.VERSION: create_target_value(1, length=2),  # CoAP version 1
        CoAPFields.TYPE: create_target_value(type, length=2),
        CoAPFields.CODE: create_target_value(code, length=8),
    }
    # Handle message ID
    if message_id is not None:
        target_values[CoAPFields.MESSAGE_ID] = create_target_value(message_id, length=16)
    # Handle token and token length
    if token is not None:
        token_value = create_target_value(token)
        token_length = token_value.length // 8 if isinstance(token_value, Buffer) else list(token_value.forward.keys())[0].length // 8
        target_values[CoAPFields.TOKEN_LENGTH] = create_target_value(token_length, length=4)
        target_values[CoAPFields.TOKEN] = token_value
    else:
        target_values[CoAPFields.TOKEN_LENGTH] = create_target_value(0, length=4)
    
    # Generate rule field descriptors
    field_descriptors = []
    
    # Add base fields
    for field in COAP_BASE_HEADER_FIELDS:
        if field.id == CoAPFields.TOKEN and token is None:
            continue  # Skip TOKEN field if no token provided
            
        target_value = target_values.get(field.id)
        field_length = field.length
        if field.id == CoAPFields.TOKEN and token is not None:
            field_length = token_length * 8
            
        field_descriptors.append(
            RuleFieldDescriptor(
                id=field.id,
                length=field_length,
                position=field.position,
                direction=field.direction,
                matching_operator=(
                    MO.MATCH_MAPPING if isinstance(target_value, MatchMapping)
                    else MO.MSB if isinstance(target_value, Buffer) and target_value.length < field_length
                    else MO.EQUAL if isinstance(target_value, Buffer) and target_value.length == field_length
                    else MO.IGNORE
                ),
                compression_decompression_action=(
                    CDA.MAPPING_SENT if isinstance(target_value, MatchMapping)
                    else CDA.LSB if isinstance(target_value, Buffer) and target_value.length < field_length
                    else CDA.NOT_SENT if isinstance(target_value, Buffer) and target_value.length == field_length
                    else CDA.VALUE_SENT
                ),
                target_value=target_value
            )
        )
    
    return field_descriptors

def coap_option_template(
    option_delta: Union[bytes, Buffer, int, None] = None,
    option_length: Union[bytes, Buffer, int, None] = None,
    option_value: Union[bytes, Buffer, int, None] = None,
    option_delta_extended: Union[bytes, Buffer, int, None] = None,
    option_length_extended: Union[bytes, Buffer, int, None] = None,
    option_name: Union[str, None] = None,
    last_option_name: Union[str, None] = None
) -> List[RuleFieldDescriptor]:
    """
    Rule descriptor template for CoAP option.

    This can be used in two ways:
    - If `option_name` is provided, generates descriptors for the Option Delta, Option Length, 
        Option Delta Extended, Option Length Extended (if needed) and Option Value.
        - If `option_length` is provided, `option_length` is assumed to be the length in bytes (int). In that case,
           the proper Option Length and Option Length Extended fields are generated and the length of the Option Value 
           is calculated.
        - If `option_length` is *not* provided, `option_value` must be a Buffer or bytes. 
            The length of the Option Value is calculated from the length of the buffer.

    - If no `option_name` is provided, `option_delta` and `option_length` and `option_value` are expected.
    
    Args:
        option_delta: The option delta value
        option_length: The option length value
        option_value: The option value
        option_delta_extended: Optional extended delta value
        option_length_extended: Optional extended length value
        
    Returns:
        List[RuleFieldDescriptor]: List of rule field descriptors for the CoAP option
    """

    # Calculate option value length in bits
    option_value_length = 0
    option_length_extended_length = None
    option_delta_extended_length = None
    
    # `option_name` is provided:
    if option_name is not None:
        # retrieve the option number for calculating the option delta
        option_field_id: str = coap_option_name_to_field_id(option_name)
        option_number: int = coap_option_field_id_to_number(option_field_id)
        if last_option_name is not None:
            last_option_field_id: str = coap_option_name_to_field_id(last_option_name)
            last_option_number: int = coap_option_field_id_to_number(last_option_field_id)
        else:
            last_option_number = 0
        
        target_values = {}
        option_delta: int = option_number - last_option_number
            
        if option_delta < 13:
            target_values[CoAPFields.OPTION_DELTA] = create_target_value(option_delta, length=4)
        elif option_delta < 269:
            target_values[CoAPFields.OPTION_DELTA] = create_target_value(CoAPDefinitions.OPTION_DELTA_EXTENDED_8BITS, length=4)
            target_values[CoAPFields.OPTION_DELTA_EXTENDED] = create_target_value(option_delta-13, length=8)
            option_delta_extended_length = 8
        else:
            target_values[CoAPFields.OPTION_DELTA] = create_target_value(CoAPDefinitions.OPTION_DELTA_EXTENDED_16BITS, length=4)
            target_values[CoAPFields.OPTION_DELTA_EXTENDED] = create_target_value(option_delta-269, length=16)
            option_delta_extended_length = 16
        
        # `option_length` is provided as a number of bytes
        if option_length is not None:
            option_value_length = option_length * 8
            option_value_tv: TargetValue = create_target_value(option_value, length=option_value_length)
            if option_length < 13:
                target_values[CoAPFields.OPTION_LENGTH] = create_target_value(option_length, length=4)
            elif option_length < 269:
                target_values[CoAPFields.OPTION_LENGTH] = create_target_value(CoAPDefinitions.OPTION_LENGTH_EXTENDED_8BITS, length=4)
                target_values[CoAPFields.OPTION_LENGTH_EXTENDED] = create_target_value(option_length-13, length=8)
                option_length_extended_length = 8
            else:
                target_values[CoAPFields.OPTION_LENGTH] = create_target_value(CoAPDefinitions.OPTION_LENGTH_EXTENDED_16BITS, length=4)
                target_values[CoAPFields.OPTION_LENGTH_EXTENDED] = create_target_value(option_length-269, length=16)
                option_length_extended_length = 16

        else:
            # If `option_length` is *not* provided, `option_value` must be a Buffer or bytes.
            option_value_tv: TargetValue = create_target_value(option_value)
            if isinstance(option_value_tv, Buffer):
                option_value_length = len(option_value_tv.content)
                option_value_byte_length = option_value_length//8
                if option_value_byte_length < 13:
                    target_values[CoAPFields.OPTION_LENGTH] = create_target_value(option_value_byte_length, length=4)
                elif option_value_byte_length < 269:
                    target_values[CoAPFields.OPTION_LENGTH] = create_target_value(CoAPDefinitions.OPTION_LENGTH_EXTENDED_8BITS, length=4)
                    target_values[CoAPFields.OPTION_LENGTH_EXTENDED] = create_target_value(option_value_byte_length-13, length=8)
                else:
                    target_values[CoAPFields.OPTION_LENGTH] = create_target_value(CoAPDefinitions.OPTION_LENGTH_EXTENDED_16BITS, length=4)
                    target_values[CoAPFields.OPTION_LENGTH_EXTENDED] = create_target_value(option_value_byte_length-269, length=416)

                
            else:
                raise ValueError(f"option value must be a Buffer or bytes if option length is not provided")

        target_values[CoAPFields.OPTION_VALUE] = option_value_tv

    else:

        # `option_name` is not provided:
        target_values = {
            CoAPFields.OPTION_DELTA: create_target_value(option_delta, length=4),
            CoAPFields.OPTION_LENGTH: create_target_value(option_length, length=4),
            CoAPFields.OPTION_VALUE: create_target_value(option_value) if option_value is not None else None,
        }
        
        

        # Handle extended length
        if isinstance(target_values[CoAPFields.OPTION_LENGTH], Buffer):
            if target_values[CoAPFields.OPTION_LENGTH].content == CoAPDefinitions.OPTION_LENGTH_EXTENDED_8BITS:
                option_value_length = (option_length_extended + 13) * 8
                target_values[CoAPFields.OPTION_LENGTH_EXTENDED] = create_target_value(option_length_extended, length=8)
                option_length_extended_length = 8
            elif target_values[CoAPFields.OPTION_LENGTH].content == CoAPDefinitions.OPTION_LENGTH_EXTENDED_16BITS:
                option_value_length = (option_length_extended + 269) * 8
                target_values[CoAPFields.OPTION_LENGTH_EXTENDED] = create_target_value(option_length_extended, length=16)
                option_length_extended_length = 16
            else:
                option_value_length = option_length * 8
        
        # Handle extended delta
        if isinstance(target_values[CoAPFields.OPTION_DELTA], Buffer):
            if target_values[CoAPFields.OPTION_DELTA].content == CoAPDefinitions.OPTION_DELTA_EXTENDED_8BITS:
                target_values[CoAPFields.OPTION_DELTA_EXTENDED] = create_target_value(option_delta_extended, length=8)
                option_delta_extended_length = 8
            elif target_values[CoAPFields.OPTION_DELTA].content == CoAPDefinitions.OPTION_DELTA_EXTENDED_16BITS:
                target_values[CoAPFields.OPTION_DELTA_EXTENDED] = create_target_value(option_delta_extended, length=16)
                option_delta_extended_length = 16
    
    # Generate rule field descriptors from option fields
    field_descriptors = []
    for field in COAP_OPTION_TEMPLATE:
        if field.id in target_values:
            # For OPTION_VALUE, use the calculated length from option_length and option_length_extended
            field_length = field.length
            if field.id == CoAPFields.OPTION_VALUE:
                field_length = option_value_length
            # for OPTION_DELTA_EXTENDED, use field_length = 8 if OPTION_DELTA is OPTION_DELTA_EXTENDED_8BITS
            #                            or  field_length = 16 if OPTION_DELTA is OPTION_DELTA_EXTENDED_16BITS
            elif field.id == CoAPFields.OPTION_DELTA_EXTENDED and option_delta_extended_length is not None:
                field_length = option_delta_extended_length
            elif field.id == CoAPFields.OPTION_LENGTH_EXTENDED and option_length_extended_length is not None:
                field_length = option_length_extended_length
            
            matching_operator = select_mo(target_values[field.id], field_length)
            compression_decompression_action = select_cda(matching_operator)
            field_descriptors.append(
                RuleFieldDescriptor(
                    id=field.id,
                    length=field_length,
                    position=field.position,
                    direction=field.direction,
                    matching_operator=matching_operator,
                    compression_decompression_action=compression_decompression_action,
                    target_value=target_values[field.id]
                )
            )
    
    return field_descriptors

def coap_semantic_option_template(option_name: str, option_value: Union[bytes, int, TargetValue, List[Buffer]], option_length=None, position:Optional[int] = 1) -> List[RuleFieldDescriptor]:
    """
    Creates a single RuleFieldDescriptor for a semantic CoAP option.

    Args:
        option_name: The name of the CoAP option (e.g., 'uri-path', 'content-format').
        option_value: The option_value of the CoAP option. Can be a bytes object, an integer, a TargetValue, or a list of Buffers.
        option_length: The length of the option in *bytes*. If None, it will be inferred from the option_value.
        position: The position of the option in the CoAP message. Default is 1.

    Returns:
        List[RuleFieldDescriptor]: A list containing one RuleFieldDescriptor for the semantic option.
    """
    field_id: str = coap_option_name_to_field_id(option_name)
        
    target_value = create_target_value(option_value)
    if option_length is not None:
        field_length = option_length * 8  # Convert bytes to bits
    else:
        field_length = target_value.length

    mo: MO = select_mo(target_value=target_value, field_length=field_length)
    cda: CDA = select_cda(matching_operator=mo, field_id=field_id)

    return [
        RuleFieldDescriptor(
            id=field_id,
            length=field_length,
            position=position,
            direction=DI.BIDIRECTIONAL,
            matching_operator=mo,
            compression_decompression_action=cda,
            target_value=target_value
        )
    ]

def coap_option_name_to_field_id(option_name: str) -> str:
    if option_name in CoAPFields:
        return option_name
    else:
        option_id: str = f"OPTION_{option_name.replace('-', '_').upper()}"
        try:
            field_id: str = getattr(CoAPFields, option_id)
        except KeyError:
            raise ValueError(f"Invalid CoAP option name: {option_name}")
        return field_id
    
def coap_option_field_id_to_number(option_id: str) -> int:
    if option_id in CoAPFields:
        return COAP_OPTIONS_NAME_TO_NUMBER[option_id]
    else:
        raise ValueError(f"Invalid CoAP option ID: {option_id}")
        

REGISTER_PARSER(protocol_id=ProtocolsIDs.COAP, parser_class=CoAPParser)
