"""
IPv4 header parser

Parser for the IPv4 protocol header as defined in RFC791 [1].

Note 1: Options parsing is not implemented yet.


[1] "RFC791: Internet Protocol, DARPA Internet Program, Protocol Specification", J. Postel et al.
"""

from microschc.compat import StrEnum
from functools import reduce
from typing import Dict, List, Tuple, Type, Union
from microschc.binary.buffer import Buffer, Padding
from microschc.parser import HeaderParser, ParserError
from microschc.protocol.compute import ComputeFunctionDependenciesType, ComputeFunctionType
from microschc.protocol.registry import PARSERS, REGISTER_COMPUTE_FUNCTIONS, REGISTER_PARSER, ProtocolsIDs
from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor, RuleFieldDescriptor, DirectionIndicator as DI, MatchingOperator as MO, CompressionDecompressionAction as CDA, TargetValue
from microschc.tools import create_target_value
from microschc.tools.cda import select_cda
from microschc.tools.mo import select_mo

IPV4_HEADER_ID = 'IPv4'

class IPv4Fields(StrEnum):
    VERSION                 = f'{IPV4_HEADER_ID}:Version'
    HEADER_LENGTH           = f'{IPV4_HEADER_ID}:Header Length'
    TYPE_OF_SERVICE         = f'{IPV4_HEADER_ID}:Type of Service'
    TOTAL_LENGTH            = f'{IPV4_HEADER_ID}:Total Length'
    IDENTIFICATION          = f'{IPV4_HEADER_ID}:Identification'
    FLAGS                   = f'{IPV4_HEADER_ID}:Flags'
    FRAGMENT_OFFSET         = f'{IPV4_HEADER_ID}:Fragment Offset'
    TIME_TO_LIVE            = f'{IPV4_HEADER_ID}:Time To Live'
    PROTOCOL                = f'{IPV4_HEADER_ID}:Protocol'
    HEADER_CHECKSUM         = f'{IPV4_HEADER_ID}:Header Checksum'
    SRC_ADDRESS             = f'{IPV4_HEADER_ID}:Source Address'
    DST_ADDRESS             = f'{IPV4_HEADER_ID}:Destination Address'

IPV4_SUPPORTED_PAYLOAD_PROTOCOLS: List[ProtocolsIDs] = [
    ProtocolsIDs.UDP,
    ProtocolsIDs.SCTP
]


class IPv4Parser(HeaderParser):

    def __init__(self, predict_next:bool=False) -> None:
        super().__init__(name=IPV4_HEADER_ID, predict_next=predict_next)

    def match(self, buffer: Buffer) -> bool:
        if buffer.length < 160:
            return False
        
        version:Buffer = buffer[0:4]
        
        return (version == b'\x04')

    def parse(self, buffer:Buffer) -> HeaderDescriptor:
        """
        
         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Version|  IHL  |Type of Service|          Total Length         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         Identification        |Flags|      Fragment Offset    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Time to Live |    Protocol   |         Header Checksum       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       Source Address                          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Destination Address                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        """

        if buffer.length < 160:
            raise ParserError(buffer=buffer, message=f'length too short: {buffer.length} < 160')

        # version: 4 bits
        version:Buffer = buffer[0:4]

        if version != b'\x04':
            raise ParserError(buffer=buffer, message=f"version mismatch: {version.content} != '\x04'")

        # header length(IHL): 4 bits
        header_length:Buffer = buffer[4:8]

        # type of service: 8 bits
        type_of_service:Buffer = buffer[8:16]
        
        # total length: 16 bits
        total_length:Buffer = buffer[16:32]
        
        # identification: 16 bits
        identification:Buffer = buffer[32:48]

        # flags: 3 bits
        flags:Buffer = buffer[48:51]
        
        # fragment offset: 13 bits
        fragment_offset:Buffer = buffer[51:64]

        # time to live: 8 bits
        time_to_live:Buffer = buffer[64:72]

        # protocol: 8 bits
        protocol:Buffer = buffer[72:80]

        # header checksum: 16 bits
        header_checksum:Buffer = buffer[80:96]

        # source address: 32 bits
        source_address:Buffer = buffer[96:128]

        # destination address: 32 bits
        destination_address:Buffer = buffer[128:160]

        
        header_descriptor:HeaderDescriptor = HeaderDescriptor(
            id=IPV4_HEADER_ID,
            length=160,
            fields=[
                FieldDescriptor(id=IPv4Fields.VERSION,         position=0, value=version),
                FieldDescriptor(id=IPv4Fields.HEADER_LENGTH,   position=0, value=header_length),
                FieldDescriptor(id=IPv4Fields.TYPE_OF_SERVICE, position=0, value=type_of_service),
                FieldDescriptor(id=IPv4Fields.TOTAL_LENGTH,    position=0, value=total_length),
                FieldDescriptor(id=IPv4Fields.IDENTIFICATION,  position=0, value=identification),
                FieldDescriptor(id=IPv4Fields.FLAGS,           position=0, value=flags),
                FieldDescriptor(id=IPv4Fields.FRAGMENT_OFFSET, position=0, value=fragment_offset),
                FieldDescriptor(id=IPv4Fields.TIME_TO_LIVE,    position=0, value=time_to_live),
                FieldDescriptor(id=IPv4Fields.PROTOCOL,        position=0, value=protocol),
                FieldDescriptor(id=IPv4Fields.HEADER_CHECKSUM, position=0, value=header_checksum),
                FieldDescriptor(id=IPv4Fields.SRC_ADDRESS,     position=0, value=source_address),
                FieldDescriptor(id=IPv4Fields.DST_ADDRESS,     position=0, value=destination_address),
            ]
        )
        if self.predict_next is True:
            next_header_value: int = protocol.value(type='unsigned int')
            if next_header_value in IPV4_SUPPORTED_PAYLOAD_PROTOCOLS:
                next_parser_class: Type[HeaderParser] = PARSERS[next_header_value]
                next_parser: HeaderParser = next_parser_class(predict_next=True)
                next_header_descriptor: HeaderDescriptor = next_parser.parse(buffer[160:])
                header_descriptor.fields.extend(next_header_descriptor.fields)
                header_descriptor.length += next_header_descriptor.length
        return header_descriptor
        
# def _parse_options(buffer: bytes) -> Tuple[List[FieldDescriptor], int]:
#     """
#       0   1   2   3   4   5   6   7
#     +---+---+---+---+---+---+---+---+
#     |   |       |                   |  F: Option Type Copied Flag, 1 bit
#     | F | Class |       number      |  Class: Option Type Class, 2 bits
#     |   |       |                   |  number: Option Type Number, 5 bits
#     +---------------+---------------+
#     |                               |
#     |         Option Length         |   1 byte
#     |                               |
#     +-------------------------------+
#     |                               |
#     |                               |
#     |                               |
#     |         Option Value          |   0 or more bytes
#     |                               |
#     |                               |
#     |                               |
#     +-------------------------------+
#     """
#     fields: List[FieldDescriptor] = []
#     cursor: int = 0
#     option_index: int = 0

#     # parse options until reaching the payload marker byte or end of buffer
#     while cursor < len(buffer):
#         option_index += 1
#         option_bytes: bytes = buffer[cursor:]
#         option_type: bytes = buffer[cursor:cursor+1]
#         fields.append(FieldDescriptor(id=IPv4Fields.OPTION_TYPE, position=option_index, value=Buffer(content=option_type, length=8)))

#         option_offset: int = 1 # to keep track of variable length fields

#         if option_type == b'\x00':
#             break
#         elif option_type == b'\x01':
#             # No-Operation option
#         elif option_type == b'\x07':
#             # Record-Route option
#             option_length = buffer[cursor+1:cursor+2]
#             option_bytelength_int:int = option_length[0]
#             option_value_bytelength:int = option_bytelength_int - 2
#             option_value: bytes = buffer[cursor+2:cursor+option_value_bytelength]
#             fields.append(FieldDescriptor(id=IPv4Fields.OPTION_LENGTH, position=option_index, value=Buffer(content=option_length, length=8)))
#             fields.append(FieldDescriptor(id=IPv4Fields.OPTION_VALUE, position=option_index, value=Buffer(content=option_length, length=option_value_bytelength*8)))
#             option_offset += option_value_bytelength + 1
#             pass
#         elif option_type == b'\x89':
#             # Strict-Source-Route option
#             pass
#         elif option_type == b'\x83':
#             # Loose-Source-Route option
#             pass
#         elif option_type == b'\x44':
#             # Timestamp option
#             pass

#         cursor += option_offset

def _compute_total_length( decompressed_fields: List[Tuple[str, Buffer]], rule_field_position:int) -> Buffer:
    fields_values: List[Buffer] = [field_value for _, field_value in decompressed_fields]
    ipv4_fields: List[Buffer] = [field for field in fields_values[rule_field_position-2:]]
    ipv4_buffer: Buffer = reduce(lambda x, y: x+y, ipv4_fields, Buffer(content=b'', length=0))

    total_length: int = ipv4_buffer.length // 8 if ipv4_buffer.length%8 == 0 else ipv4_buffer.length // 8 + 1
    buffer: Buffer = Buffer(content=total_length.to_bytes(2, 'big'), length=16, padding=Padding.LEFT)
    return buffer

def _compute_checksum(decompressed_fields: List[Tuple[str, Buffer]], rule_field_position: int) -> Buffer:
    """
    Checksum is the 16-bit one's complement of the one's complement sum of a
    IPv4 header.

    If the computed  checksum  is zero,  it is transmitted  as all ones (the
    equivalent  in one's complement  arithmetic).   An all zero  transmitted
    checksum  value means that the transmitter  generated  no checksum  (for
    debugging or for higher level protocols that don't care).
    """

    # retrieve IPv4 header fields
    ipv4_header_fields: List[Buffer] = [ field_value for _, field_value in decompressed_fields[rule_field_position-9:rule_field_position+3]]
    ipv4_header: Buffer = reduce(lambda x, y: x+y, ipv4_header_fields, Buffer(content=b'', length=0))
    
    checksum_value: int = 0
    header_checksum: int = 0
    # compute the sum of the 2-bytes chunks of the IPv4 header
    for chunk in ipv4_header.chunks(length=16):
        header_checksum += chunk.value(type='unsigned int')
        carry = header_checksum >> 16
        header_checksum = (header_checksum + carry) & 0xffff 
    
    checksum_value = ~header_checksum & 0xffff

    # if checksum is 0x0000 return 0xffff
    checksum_value = 0xffff if checksum_value == 0x0000 else checksum_value    
    checksum_buffer: Buffer = Buffer(content=checksum_value.to_bytes(2, 'big'), length=16)
    return checksum_buffer


IPv4ComputeFunctions: Dict[str, Tuple[ComputeFunctionType, ComputeFunctionDependenciesType]] = {
    IPv4Fields.TOTAL_LENGTH: (_compute_total_length, {}),
    IPv4Fields.HEADER_CHECKSUM: (_compute_checksum, { 
                                                        IPv4Fields.VERSION, 
                                                        IPv4Fields.HEADER_LENGTH,
                                                        IPv4Fields.TYPE_OF_SERVICE,
                                                        IPv4Fields.TOTAL_LENGTH, 
                                                        IPv4Fields.IDENTIFICATION,
                                                        IPv4Fields.FLAGS,
                                                        IPv4Fields.FRAGMENT_OFFSET,
                                                        IPv4Fields.TIME_TO_LIVE,
                                                        IPv4Fields.PROTOCOL,
                                                        IPv4Fields.SRC_ADDRESS,
                                                        IPv4Fields.DST_ADDRESS,
                                                    }),
}

REGISTER_PARSER(protocol_id=ProtocolsIDs.IPV4, parser_class=IPv4Parser)
REGISTER_COMPUTE_FUNCTIONS(IPv4ComputeFunctions)

IPV4_BASE_HEADER_FIELDS: List[RuleFieldDescriptor] = [
    RuleFieldDescriptor(
        id=IPv4Fields.VERSION,
        length=4,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=create_target_value(4, length=4)
    ),
    RuleFieldDescriptor(
        id=IPv4Fields.HEADER_LENGTH,
        length=4,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=create_target_value(5, length=4)
    ),
    RuleFieldDescriptor(
        id=IPv4Fields.TYPE_OF_SERVICE,
        length=8,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=create_target_value(0, length=8)
    ),
    RuleFieldDescriptor(
        id=IPv4Fields.TOTAL_LENGTH,
        length=16,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.IGNORE,
        compression_decompression_action=CDA.COMPUTE,
        target_value=None
    ),
    RuleFieldDescriptor(
        id=IPv4Fields.IDENTIFICATION,
        length=16,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=None
    ),
    RuleFieldDescriptor(
        id=IPv4Fields.FLAGS,
        length=3,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=create_target_value(0, length=3)
    ),
    RuleFieldDescriptor(
        id=IPv4Fields.FRAGMENT_OFFSET,
        length=13,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=create_target_value(0, length=13)
    ),
    RuleFieldDescriptor(
        id=IPv4Fields.TIME_TO_LIVE,
        length=8,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=create_target_value(64, length=8)
    ),
    RuleFieldDescriptor(
        id=IPv4Fields.PROTOCOL,
        length=8,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=create_target_value(ProtocolsIDs.UDP, length=8)
    ),
    RuleFieldDescriptor(
        id=IPv4Fields.HEADER_CHECKSUM,
        length=16,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.IGNORE,
        compression_decompression_action=CDA.COMPUTE,
        target_value=None
    ),
    RuleFieldDescriptor(
        id=IPv4Fields.SRC_ADDRESS,
        length=32,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=None
    ),
    RuleFieldDescriptor(
        id=IPv4Fields.DST_ADDRESS,
        length=32,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=None
    )
]

def ipv4_field_descriptors_template(
    src_address: Union[bytes, Buffer, int],
    dst_address: Union[bytes, Buffer, int],
    protocol: Union[bytes, Buffer, int, None] = ProtocolsIDs.UDP,
    ttl: Union[bytes, Buffer, int, None] = 64,
    tos: Union[bytes, Buffer, int, None] = 0,
    flags: Union[bytes, Buffer, int, None] = 0,
    fragment_offset: Union[bytes, Buffer, int, None] = 0
) -> List[RuleFieldDescriptor]:
    """
    Rule descriptor template for IPv4 header.
    """
    # Create target values for each field
    target_values = {
        IPv4Fields.VERSION: create_target_value(4, length=4),
        IPv4Fields.HEADER_LENGTH: create_target_value(5, length=4),
        IPv4Fields.TYPE_OF_SERVICE: create_target_value(tos, length=8),
        IPv4Fields.FLAGS: create_target_value(flags, length=3),
        IPv4Fields.FRAGMENT_OFFSET: create_target_value(fragment_offset, length=13),
        IPv4Fields.TIME_TO_LIVE: create_target_value(ttl, length=8),
        IPv4Fields.PROTOCOL: create_target_value(protocol, length=8),
        IPv4Fields.SRC_ADDRESS: create_target_value(src_address, length=32),
        IPv4Fields.DST_ADDRESS: create_target_value(dst_address, length=32)
    }
    
    # Generate rule field descriptors from header fields
    rule_field_descriptors = []
    for field in IPV4_BASE_HEADER_FIELDS:
        mo: MO = select_mo(target_values.get(field.id), field_length=field.length)
        cda: CDA = select_cda(matching_operator=mo)

        rule_field_descriptors.append(
            RuleFieldDescriptor(
                id=field.id,
                length=field.length,
                position=field.position,
                direction=field.direction,
                matching_operator=mo,
                compression_decompression_action=cda,
                target_value=target_values.get(field.id)
            )
        )
    return rule_field_descriptors