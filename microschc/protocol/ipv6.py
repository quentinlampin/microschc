"""
IPv6 header parser

Parser for the IPv6 protocol header as defined in RFC8200 [1].

Note 1: Hop by Hop Options, Routing header parsing is not implemented yet.
Note 2: Fragment header parsing is not implemented as fragmentation and reassembly
        are handled by SCHC-RF.
Note 3: Authentication and Encapsulating Security payload parsing is not implemented yet.

[1] "RFC8200: Internet Protocol, Version 6 (IPv6) Specification", S. Deering et al.
"""

from microschc.compat import StrEnum
from functools import reduce
from typing import Callable, Dict, List, Tuple, Type, Union
from microschc.binary.buffer import Buffer, Padding
from microschc.parser import HeaderParser, ParserError
from microschc.protocol.compute import ComputeFunctionDependenciesType, ComputeFunctionType
from microschc.protocol.registry import REGISTER_COMPUTE_FUNCTIONS, ProtocolsIDs, REGISTER_PARSER, PARSERS
from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor, MatchMapping, RuleFieldDescriptor, DirectionIndicator as DI, MatchingOperator as MO, CompressionDecompressionAction as CDA, TargetValue
from microschc.tools import create_target_value
from microschc.tools.cda import select_cda
from microschc.tools.mo import select_mo

IPV6_HEADER_ID = 'IPv6'

class IPv6Fields(StrEnum):
    VERSION         = f'{IPV6_HEADER_ID}:Version'
    TRAFFIC_CLASS   = f'{IPV6_HEADER_ID}:Traffic Class'
    FLOW_LABEL      = f'{IPV6_HEADER_ID}:Flow Label'
    PAYLOAD_LENGTH  = f'{IPV6_HEADER_ID}:Payload Length'
    NEXT_HEADER     = f'{IPV6_HEADER_ID}:Next Header'
    HOP_LIMIT       = f'{IPV6_HEADER_ID}:Hop Limit'
    SRC_ADDRESS     = f'{IPV6_HEADER_ID}:Source Address'
    DST_ADDRESS     = f'{IPV6_HEADER_ID}:Destination Address'

class IPv6Parser(HeaderParser):

    def __init__(self, predict_next:bool=False) -> None:
        super().__init__(name=IPV6_HEADER_ID, predict_next=predict_next)

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
            id=IPV6_HEADER_ID,
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
        
        if self.predict_next is True:
            next_header_value: int = next_header.value(type='unsigned int')
            if next_header_value in IPV6_SUPPORTED_PAYLOAD_PROTOCOLS:
                next_parser_class: Type[HeaderParser] = PARSERS[next_header_value]
                next_parser: HeaderParser = next_parser_class(predict_next=True)
                next_header_descriptor: HeaderDescriptor = next_parser.parse(buffer[320:])
                header_descriptor.fields.extend(next_header_descriptor.fields)
                header_descriptor.length += next_header_descriptor.length
        return header_descriptor
    
def _compute_payload_length( decompressed_fields: List[Tuple[str, Buffer]], rule_field_position:int) -> Buffer:
    fields_ids: List[str] = [field_id for field_id, _ in decompressed_fields]
    fields_values: List[Buffer] = [field_value for _, field_value in decompressed_fields]
    payload_fields: List[Buffer] = [field for field in fields_values[rule_field_position+5:]]
    payload_buffer: Buffer = reduce(lambda x, y: x+y, payload_fields, Buffer(content=b'', length=0))

    payload_length: int = payload_buffer.length // 8 if payload_buffer.length%8 == 0 else payload_buffer.length // 8 + 1
    buffer: Buffer = Buffer(content=payload_length.to_bytes(2, 'big'), length=16, padding=Padding.LEFT)
    return buffer


IPv6ComputeFunctions: Dict[str, Tuple[ComputeFunctionType, ComputeFunctionDependenciesType]] = {
    IPv6Fields.PAYLOAD_LENGTH: (_compute_payload_length, {})
}

IPV6_BASE_HEADER_FIELDS: List[RuleFieldDescriptor] = [
    RuleFieldDescriptor(
        id=IPv6Fields.VERSION,
        length=4,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=create_target_value(6, length=4)
    ),
    RuleFieldDescriptor(
        id=IPv6Fields.TRAFFIC_CLASS,
        length=8,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=create_target_value(0, length=8)
    ),
    RuleFieldDescriptor(
        id=IPv6Fields.FLOW_LABEL,
        length=20,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=create_target_value(0, length=20)
    ),
    RuleFieldDescriptor(
        id=IPv6Fields.PAYLOAD_LENGTH,
        length=16,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.IGNORE,
        compression_decompression_action=CDA.COMPUTE,
        target_value=None
    ),
    RuleFieldDescriptor(
        id=IPv6Fields.NEXT_HEADER,
        length=8,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=create_target_value(ProtocolsIDs.UDP, length=8)
    ),
    RuleFieldDescriptor(
        id=IPv6Fields.HOP_LIMIT,
        length=8,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=create_target_value(64, length=8)
    ),
    RuleFieldDescriptor(
        id=IPv6Fields.SRC_ADDRESS,
        length=128,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=None
    ),
    RuleFieldDescriptor(
        id=IPv6Fields.DST_ADDRESS,
        length=128,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=None
    )
]

def ipv6_base_header_template(
    src_address: Union[bytes, Buffer, int], 
    dst_address: Union[bytes, Buffer, int],
    traffic_class: Union[bytes, Buffer, int, None]  = 0,
    flow_label: Union[bytes, Buffer, int, None]     = 0, 
    next_header: Union[bytes, Buffer, int, None]    = 11, 
    hop_limit: Union[bytes, Buffer, int, None]      = 64, 
    ) -> List[RuleFieldDescriptor]:
    """
    Rule descriptor template for IPv6 header.
    """
    # Create target values for each field
    target_values = {
        IPv6Fields.VERSION: create_target_value(6, length=4),
        IPv6Fields.TRAFFIC_CLASS: create_target_value(traffic_class, length=8),
        IPv6Fields.FLOW_LABEL: create_target_value(flow_label, length=20),
        IPv6Fields.NEXT_HEADER: create_target_value(next_header, length=8),
        IPv6Fields.HOP_LIMIT: create_target_value(hop_limit, length=8),
        IPv6Fields.SRC_ADDRESS: create_target_value(src_address, length=128),
        IPv6Fields.DST_ADDRESS: create_target_value(dst_address, length=128)
    }
    
    # Generate rule field descriptors from header fields
    rule_field_descriptors = []
    for field in IPV6_BASE_HEADER_FIELDS:
        mo: MO = select_mo(target_values.get(field.id), field_length=field.length)
        cda: CDA = select_cda(matching_operator=mo, field_id=field.id)

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

    
IPV6_SUPPORTED_PAYLOAD_PROTOCOLS: List[ProtocolsIDs] = [
    ProtocolsIDs.UDP,
    ProtocolsIDs.SCTP
]
    
REGISTER_PARSER(protocol_id=ProtocolsIDs.IPV6, parser_class=IPv6Parser)
REGISTER_COMPUTE_FUNCTIONS(IPv6ComputeFunctions)

