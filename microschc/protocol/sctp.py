"""
SCTP header declarations

Declarations for the SCTP protocol header as defined in RFC9260 [1].

[1] "RFC9260: Stream Control Transmission Protocol, R. Stewart et al.
"""


from enum import Enum, IntEnum
from microschc.compat import StrEnum
from functools import reduce
from typing import Dict, List, Tuple, Type, Union
from microschc.crypto.crc import CRC32C_TABLE, crc32c
from microschc.protocol.registry import PARSERS, REGISTER_PARSER, ProtocolsIDs
from microschc.binary.buffer import Buffer, Padding
from microschc.parser import HeaderParser, ParserError
from microschc.protocol.compute import ComputeFunctionDependenciesType, ComputeFunctionType
from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor, RuleFieldDescriptor, DirectionIndicator as DI, MatchingOperator as MO, CompressionDecompressionAction as CDA, TargetValue
from microschc.tools import create_target_value


SCTP_HEADER_ID = 'SCTP'

class SCTPFields(StrEnum):
    SOURCE_PORT                                             = f'{SCTP_HEADER_ID}:Source Port'
    DESTINATION_PORT                                        = f'{SCTP_HEADER_ID}:Destination Port'
    VERIFICATION_TAG                                        = f'{SCTP_HEADER_ID}:Verification Tag'
    CHECKSUM                                                = f'{SCTP_HEADER_ID}:Checksum'
    CHUNK_TYPE                                              = f'{SCTP_HEADER_ID}:Chunk Type'
    CHUNK_FLAGS                                             = f'{SCTP_HEADER_ID}:Chunk Flags'
    CHUNK_LENGTH                                            = f'{SCTP_HEADER_ID}:Chunk Length'
    CHUNK_VALUE                                             = f'{SCTP_HEADER_ID}:Chunk Value'
    CHUNK_PADDING                                           = f'{SCTP_HEADER_ID}:Chunk Padding'

    CHUNK_DATA_TSN                                          = f'{SCTP_HEADER_ID}:Data TSN'
    CHUNK_DATA_STREAM_IDENTIFIER                            = f'{SCTP_HEADER_ID}:Data Stream Identifier S'
    CHUNK_DATA_STREAM_SEQUENCE_NUMBER                       = f'{SCTP_HEADER_ID}:Data Stream Sequence Number n'
    CHUNK_DATA_PAYLOAD_PROTOCOL_IDENTIFIER                  = f'{SCTP_HEADER_ID}:Data Payload Protocol Identifier'
    CHUNK_DATA_PAYLOAD                                      = f'{SCTP_HEADER_ID}:Data Payload'

    CHUNK_INIT_INITIATE_TAG                                 = f'{SCTP_HEADER_ID}:Init Initiate Tag'
    CHUNK_INIT_ADVERTISED_RECEIVER_WINDOW_CREDIT            = f'{SCTP_HEADER_ID}:Init Advertised Receiver Window Credit'
    CHUNK_INIT_NUMBER_OF_OUTBOUND_STREAMS                   = f'{SCTP_HEADER_ID}:Init Number of Outbound Streams'
    CHUNK_INIT_NUMBER_OF_INBOUND_STREAMS                    = f'{SCTP_HEADER_ID}:Init Number of Inbound Streams'
    CHUNK_INIT_INITIAL_TSN                                  = f'{SCTP_HEADER_ID}:Init Initial TSN'

    CHUNK_INIT_ACK_INITIATE_TAG                             = f'{SCTP_HEADER_ID}:Init Ack Initiate Tag'
    CHUNK_INIT_ACK_ADVERTISED_RECEIVER_WINDOW_CREDIT        = f'{SCTP_HEADER_ID}:Init Ack Advertised Receiver Window Credit'
    CHUNK_INIT_ACK_NUMBER_OF_OUTBOUND_STREAMS               = f'{SCTP_HEADER_ID}:Init Ack Number of Outbound Streams'
    CHUNK_INIT_ACK_NUMBER_OF_INBOUND_STREAMS                = f'{SCTP_HEADER_ID}:Init Ack Number of Inbound Streams'
    CHUNK_INIT_ACK_INITIAL_TSN                              = f'{SCTP_HEADER_ID}:Init Ack Initial TSN'
    
    CHUNK_SACK_CUMULATIVE_TSN_ACK                           = f'{SCTP_HEADER_ID}:Selective Ack Cumulative TSN Ack'
    CHUNK_SACK_ADVERTISED_RECEIVER_WINDOW_CREDIT            = f'{SCTP_HEADER_ID}:Selective Ack Advertised Receiver Window Credit'
    CHUNK_SACK_NUMBER_GAP_ACK_BLOCKS                        = f'{SCTP_HEADER_ID}:Selective Ack Number Gap Ack Blocks'
    CHUNK_SACK_NUMBER_DUPLICATE_TSNS                        = f'{SCTP_HEADER_ID}:Selective Ack Number Duplicate TSNs'
    CHUNK_SACK_GAP_ACK_BLOCK_START                          = f'{SCTP_HEADER_ID}:Selective Ack Gap Ack BLock Start'
    CHUNK_SACK_GAP_ACK_BLOCK_END                            = f'{SCTP_HEADER_ID}:Selective Ack Gap Ack BLock End'
    CHUNK_SACK_DUPLICATE_TSN                                = f'{SCTP_HEADER_ID}:Selective Ack Duplicate TSN'
    
    CHUNK_SHUTDOWN_CUMULATIVE_TSN_ACK                       = f'{SCTP_HEADER_ID}:Shutdown Cumulative TSN'
    
    CHUNK_COOKIE_ECHO_COOKIE                                = f'{SCTP_HEADER_ID}:Cookie Echo Cookie'

    PARAMETER_TYPE                                          = f'{SCTP_HEADER_ID}:Parameter Type'
    PARAMETER_LENGTH                                        = f'{SCTP_HEADER_ID}:Parameter Length'
    PARAMETER_VALUE                                         = f'{SCTP_HEADER_ID}:Parameter Value'
    PARAMETER_PADDING                                       = f'{SCTP_HEADER_ID}:Parameter Padding'
    
SCTP_SUPPORTED_PAYLOAD_PROTOCOLS: List[ProtocolsIDs] = [
    
]
    
    
    
class SCTPChunkTypes(IntEnum):
    # ID Value    Chunk Type
    # -----       ----------
    # 0          - Payload Data (DATA)
    # 1          - Initiation (INIT)
    # 2          - Initiation Acknowledgement (INIT ACK)
    # 3          - Selective Acknowledgement (SACK)
    # 4          - Heartbeat Request (HEARTBEAT)
    # 5          - Heartbeat Acknowledgement (HEARTBEAT ACK)
    # 6          - Abort (ABORT)
    # 7          - Shutdown (SHUTDOWN)
    # 8          - Shutdown Acknowledgement (SHUTDOWN ACK)
    # 9          - Operation Error (ERROR)
    # 10         - State Cookie (COOKIE ECHO)
    # 11         - Cookie Acknowledgement (COOKIE ACK)
    # 12         - Reserved for Explicit Congestion Notification Echo (ECNE)
    # 13         - Reserved for Congestion Window Reduced (CWR)
    # 14         - Shutdown Complete (SHUTDOWN COMPLETE)
    # 15 to 62   - reserved by IETF
    # 63         - IETF-defined Chunk Extensions
    # 64 to 126  - reserved by IETF
    # 127        - IETF-defined Chunk Extensions
    # 128 to 190 - reserved by IETF
    # 191        - IETF-defined Chunk Extensions
    # 192 to 254 - reserved by IETF
    # 255        - IETF-defined Chunk Extensions
    DATA                =  0
    INIT                =  1
    INIT_ACK            =  2
    SACK                =  3
    HEARTBEAT           =  4
    HEARTBEAT_ACK       =  5
    ABORT               =  6
    SHUTDOWN            =  7
    SHUTDOWN_ACK        =  8
    ERROR               =  9
    COOKIE_ECHO         = 10
    COOKIE_ACK          = 11
    ECNE                = 12
    CWR                 = 13
    SHUTDOWN_COMPLETE   = 14 
    

    
class SCTPParser(HeaderParser):
    def __init__(self, predict_next:bool=False) -> None:
        super().__init__(name=SCTP_HEADER_ID, predict_next=predict_next)
        
    def match(self, buffer: Buffer) -> bool:
        return buffer.length >= 12 * 8  # SCTP header is at least 12 bytes

    def parse(self, buffer: Buffer) -> HeaderDescriptor:
        """
         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Source Port Number        |     Destination Port Number   |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                      Verification Tag                         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                           Checksum                            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        |                        Chunk #1                               |
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        |                        Chunk #2                               |
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        if buffer.length < 12 * 8:
            raise ParserError(buffer=buffer, message=f'length too short: {buffer.length} < 96')

        # Source Port: 16 bits
        source_port: Buffer = buffer[0:16]
        # Destination Port: 16 bits
        destination_port: Buffer = buffer[16:32]
        # Verification Tag: 32 bits
        verification_tag: Buffer = buffer[32:64]
        # Checksum: 32 bits
        checksum: Buffer = buffer[64:96]

        header_fields: List[FieldDescriptor] = [
            FieldDescriptor(id=SCTPFields.SOURCE_PORT,      position=0, value=source_port),
            FieldDescriptor(id=SCTPFields.DESTINATION_PORT, position=0, value=destination_port),
            FieldDescriptor(id=SCTPFields.VERIFICATION_TAG, position=0, value=verification_tag),
            FieldDescriptor(id=SCTPFields.CHECKSUM,         position=0, value=checksum),
        ]

        chunks: Buffer = buffer[96:]
        
        while  chunks.length > 0:
            chunks_fields, chunks_bits_consumed = self._parse_chunk(chunks)
            chunks = chunks[chunks_bits_consumed:]
            header_fields.extend(chunks_fields)
            

        header_descriptor: HeaderDescriptor = HeaderDescriptor(
            id=SCTP_HEADER_ID,
            length=buffer.length,
            fields=header_fields
        )
        return header_descriptor
    

    def _parse_chunk(self, buffer: Buffer) -> Tuple[List[FieldDescriptor], int]:
        fields: List[FieldDescriptor] = []    

        # Chunk Type: 8 bits
        chunk_type: Buffer = buffer[0:8]
        fields.append(FieldDescriptor(id=SCTPFields.CHUNK_TYPE, position=0, value=chunk_type))

        # Chunk Flags: 8 bits
        chunk_flags: Buffer = buffer[8:16]
        fields.append(FieldDescriptor(id=SCTPFields.CHUNK_FLAGS, position=0, value=chunk_flags))

        # Chunk Length: 16 bits
        chunk_length: Buffer = buffer[16:32]
        fields.append(FieldDescriptor(id=SCTPFields.CHUNK_LENGTH, position=0, value=chunk_length))
        
        chunk_length_value: int = chunk_length.value(type='unsigned int') * 8
            
        # Chunk Value: variable length
        chunk_value_length = chunk_length_value - 32  # Length includes the 4 bytes of type, flags, and length
        if chunk_value_length > 0:
            chunk_type_value: int = chunk_type.value()
            chunk_value: Buffer = buffer[32: 32 + chunk_value_length]
            
            if chunk_type_value == SCTPChunkTypes.DATA:
                chunk_fields: List[FieldDescriptor] = self._parse_chunk_data(chunk_value)
            elif chunk_type_value == SCTPChunkTypes.INIT:
                chunk_fields: List[FieldDescriptor] = self._parse_chunk_init(chunk_value)
            elif chunk_type_value == SCTPChunkTypes.INIT_ACK:
                chunk_fields: List[FieldDescriptor] = self._parse_chunk_init_ack(chunk_value)
            elif chunk_type_value == SCTPChunkTypes.SACK:
                chunk_fields: List[FieldDescriptor] = self._parse_chunk_selective_ack(chunk_value)
            elif chunk_type_value == SCTPChunkTypes.HEARTBEAT:
                chunk_fields: List[FieldDescriptor] = self._parse_chunk_heartbeat(chunk_value)
            elif chunk_type_value == SCTPChunkTypes.HEARTBEAT_ACK:
                chunk_fields: List[FieldDescriptor] = self._parse_chunk_heartbeat_ack(chunk_value)
            elif chunk_type_value == SCTPChunkTypes.ABORT:
                chunk_fields: List[FieldDescriptor] = self._parse_chunk_abort(chunk_value)
            elif chunk_type_value == SCTPChunkTypes.SHUTDOWN:
                chunk_fields: List[FieldDescriptor] = self._parse_chunk_shutdown(chunk_value)
            elif chunk_type_value == SCTPChunkTypes.SHUTDOWN_ACK:
                chunk_fields: List[FieldDescriptor] = self._parse_chunk_shutdown_ack(chunk_value)
            elif chunk_type_value == SCTPChunkTypes.ERROR:
                chunk_fields: List[FieldDescriptor] = self._parse_chunk_error(chunk_value)
            elif chunk_type_value == SCTPChunkTypes.COOKIE_ECHO:
                chunk_fields: List[FieldDescriptor] = self._parse_chunk_cookie_echo(chunk_value)
            elif chunk_type_value == SCTPChunkTypes.COOKIE_ACK:
                chunk_fields: List[FieldDescriptor] = self._parse_chunk_cookie_ack(chunk_value)
            elif chunk_type_value == SCTPChunkTypes.SHUTDOWN_COMPLETE:
                chunk_fields: List[FieldDescriptor] = self._parse_chunk_shutdown_complete(chunk_value)
            else:    
                chunk_fields: List[FieldDescriptor] = [FieldDescriptor(id=SCTPFields.CHUNK_VALUE, position=0, value=chunk_value)]
            fields.extend(chunk_fields)
            
        chunk_padding_length: int = (32 - chunk_length_value%32)%32
        if chunk_padding_length > 0:
            chunk_padding: Buffer = buffer[chunk_length_value: chunk_length_value+chunk_padding_length]
            if chunk_padding.length > 0: # apparently some NG-AP implementations have a liberal interpretation of the specification
                fields.append(FieldDescriptor(id=SCTPFields.CHUNK_PADDING, position=0, value=chunk_padding))
                

        bits_consumed = chunk_length_value  + chunk_padding_length

        return fields, bits_consumed
    
    
    def _parse_chunk_data(self, buffer: Buffer) -> List[FieldDescriptor]:
        r"""
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Type = 0    | Reserved|U|B|E|    Length                     |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                              TSN                              |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |      Stream Identifier S      |   Stream Sequence Number n    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                  Payload Protocol Identifier                  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        \                                                               \
        /                 User Data (seq n of Stream S)                 /
        \                                                               \
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        fields: List[FieldDescriptor] = []
        tsn: Buffer = buffer[0:32]
        stream_identifier_s: Buffer = buffer[32:48]
        stream_sequence_number_n: Buffer = buffer[48:64]
        payload_protocol_identifier: Buffer = buffer[64:96]
    
        fields.extend([
                FieldDescriptor(id=SCTPFields.CHUNK_DATA_TSN, value=tsn, position=0),
                FieldDescriptor(id=SCTPFields.CHUNK_DATA_STREAM_IDENTIFIER, value=stream_identifier_s, position=0),
                FieldDescriptor(id=SCTPFields.CHUNK_DATA_STREAM_SEQUENCE_NUMBER, value=stream_sequence_number_n, position=0),
                FieldDescriptor(id=SCTPFields.CHUNK_DATA_PAYLOAD_PROTOCOL_IDENTIFIER, value=payload_protocol_identifier, position=0)
        ])
        payload_protocol_identifier_value: int = payload_protocol_identifier.value()
        user_data: Buffer = buffer[96:]
        if self.predict_next is True and payload_protocol_identifier_value in SCTP_SUPPORTED_PAYLOAD_PROTOCOLS:
            next_parser_class: Type[HeaderParser] = PARSERS[payload_protocol_identifier_value]
            next_parser: HeaderParser = next_parser_class(predict_next=True)
            next_header_descriptor: HeaderDescriptor = next_parser.parse(user_data)
            fields.extend(next_header_descriptor.fields)
        else:
            fields.append(FieldDescriptor(id=SCTPFields.CHUNK_DATA_PAYLOAD, value=user_data, position=0))
        
        return fields
    
    def _parse_chunk_init(self, buffer: Buffer) -> List[FieldDescriptor]:
        r"""
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Type = 1    |  Chunk Flags  |      Chunk Length             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                         Initiate Tag                          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |          Advertised Receiver Window Credit (a_rwnd)           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Number of Outbound Streams   |   Number of Inbound Streams   |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                          Initial TSN                          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        \                                                               \
        /              Optional/Variable-Length Parameters              /
        \                                                               \
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        fields: List[FieldDescriptor] = []
        initiate_tag: Buffer = buffer[0:32]
        advertised_receiver_window_credit: Buffer = buffer[32:64]
        number_outbound_streams: Buffer = buffer[64:80]
        number_inbound_streams: Buffer = buffer[80:96]
        initial_tsn: Buffer = buffer[96:128]
        
        fields.extend([
            FieldDescriptor(id=SCTPFields.CHUNK_INIT_INITIATE_TAG, value=initiate_tag, position=0),
            FieldDescriptor(id=SCTPFields.CHUNK_INIT_ADVERTISED_RECEIVER_WINDOW_CREDIT, value=advertised_receiver_window_credit, position=0),
            FieldDescriptor(id=SCTPFields.CHUNK_INIT_NUMBER_OF_OUTBOUND_STREAMS, value=number_outbound_streams, position=0),
            FieldDescriptor(id=SCTPFields.CHUNK_INIT_NUMBER_OF_INBOUND_STREAMS, value=number_inbound_streams, position=0),
            FieldDescriptor(id=SCTPFields.CHUNK_INIT_INITIAL_TSN, value=initial_tsn, position=0)
        ])
        
        parameters = buffer[128:]
        while parameters.length > 0:
            parameter_fields, bits_consumed = self._parse_parameter(parameters)
            fields.extend(parameter_fields)
            parameters = parameters[bits_consumed:]
            
        return fields
    
    def _parse_chunk_init_ack(self, buffer: Buffer) -> List[FieldDescriptor]:
        r"""
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Type = 2    |  Chunk Flags  |      Chunk Length             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                         Initiate Tag                          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |          Advertised Receiver Window Credit (a_rwnd)           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Number of Outbound Streams   |   Number of Inbound Streams   |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                          Initial TSN                          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        \                                                               \
        /              Optional/Variable-Length Parameters              /
        \                                                               \
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        fields: List[FieldDescriptor] = []
        initiate_tag: Buffer = buffer[0:32]
        advertised_receiver_window_credit: Buffer = buffer[32:64]
        number_outbound_streams: Buffer = buffer[64:80]
        number_inbound_streams: Buffer = buffer[80:96]
        initial_tsn: Buffer = buffer[96:128]
        
        fields.extend([
            FieldDescriptor(id=SCTPFields.CHUNK_INIT_ACK_INITIATE_TAG, value=initiate_tag, position=0),
            FieldDescriptor(id=SCTPFields.CHUNK_INIT_ACK_ADVERTISED_RECEIVER_WINDOW_CREDIT, value=advertised_receiver_window_credit, position=0),
            FieldDescriptor(id=SCTPFields.CHUNK_INIT_ACK_NUMBER_OF_OUTBOUND_STREAMS, value=number_outbound_streams, position=0),
            FieldDescriptor(id=SCTPFields.CHUNK_INIT_ACK_NUMBER_OF_INBOUND_STREAMS, value=number_inbound_streams, position=0),
            FieldDescriptor(id=SCTPFields.CHUNK_INIT_ACK_INITIAL_TSN, value=initial_tsn, position=0)
        ])
        
        parameters = buffer[128:]
        while parameters.length > 0:
            parameter_fields, bits_consumed = self._parse_parameter(parameters)
            fields.extend(parameter_fields)
            parameters = parameters[bits_consumed:]
            
        return fields
    
    
    def _parse_chunk_selective_ack(self, buffer: Buffer) -> List[FieldDescriptor]:
        r"""
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Type = 3    |  Chunk Flags  |         Chunk Length          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                      Cumulative TSN Ack                       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |          Advertised Receiver Window Credit (a_rwnd)           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Number of Gap Ack Blocks = N  |  Number of Duplicate TSNs = M |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |    Gap Ack Block #1 Start     |     Gap Ack Block #1 End      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /                                                               /
        \                              ...                              \
        /                                                               /
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |    Gap Ack Block #N Start     |     Gap Ack Block #N End      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        Duplicate TSN 1                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /                                                               /
        \                              ...                              \
        /                                                               /
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        Duplicate TSN M                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        fields: List[FieldDescriptor] = []
        cumulative_tsn_ack: Buffer = buffer[0:32]
        advertised_receiver_window_credit: Buffer = buffer[32:64]
        number_gap_ack_blocks: Buffer = buffer[64:80]
        number_duplicate_tsns: Buffer = buffer[80:96]
        
        fields.extend([
            FieldDescriptor(id=SCTPFields.CHUNK_SACK_CUMULATIVE_TSN_ACK, value=cumulative_tsn_ack, position=0),
            FieldDescriptor(id=SCTPFields.CHUNK_SACK_ADVERTISED_RECEIVER_WINDOW_CREDIT, value=advertised_receiver_window_credit, position=0),
            FieldDescriptor(id=SCTPFields.CHUNK_SACK_NUMBER_GAP_ACK_BLOCKS, value=number_gap_ack_blocks, position=0),
            FieldDescriptor(id=SCTPFields.CHUNK_SACK_NUMBER_DUPLICATE_TSNS, value=number_duplicate_tsns, position=0)
        ])
        
        remainer: Buffer = buffer[96:]
        # Gap ack Blocks
        number_gap_ack_blocks_value: int = number_gap_ack_blocks.value()
        
        for _ in range(number_gap_ack_blocks_value):
            gap_ack_block_start: Buffer = remainer[0:16]
            gap_ack_block_end: Buffer = remainer[16:32]
            fields.extend([
                FieldDescriptor(id=SCTPFields.CHUNK_SACK_GAP_ACK_BLOCK_START, value=gap_ack_block_start),
                FieldDescriptor(id=SCTPFields.CHUNK_SACK_GAP_ACK_BLOCK_END, value=gap_ack_block_end)
            ])
            remainer = remainer[32:]
        
        # Duplicate TSNs
        number_duplicate_tsns_value: int = number_duplicate_tsns.value()
        for _ in range(number_duplicate_tsns_value):
            duplicate_tsn: Buffer = remainer[0:32]
            fields.extend([
                FieldDescriptor(id=SCTPFields.CHUNK_SACK_DUPLICATE_TSN, value=duplicate_tsn),
            ])
            remainer = remainer[32:]
        
        return fields
    
    def _parse_chunk_heartbeat(self, buffer: Buffer) -> List[FieldDescriptor]:
        r"""
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Type = 4    |  Chunk Flags  |       Heartbeat Length        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        \                                                               \
        /          Heartbeat Information TLV (Variable-Length)          /
        \                                                               \
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        fields: List[FieldDescriptor] = []
        
        parameters = buffer
        while parameters.length > 0:
            parameter_fields, bits_consumed = self._parse_parameter(parameters)
            fields.extend(parameter_fields)
            parameters = parameters[bits_consumed:]
            
        return fields
    
    def _parse_chunk_heartbeat_ack(self, buffer: Buffer) -> List[FieldDescriptor]:
        r"""
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Type = 5    |  Chunk Flags  |       Heartbeat Length        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        \                                                               \
        /          Heartbeat Information TLV (Variable-Length)          /
        \                                                               \
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        fields: List[FieldDescriptor] = []
        
        parameters = buffer
        while parameters.length > 0:
            parameter_fields, bits_consumed = self._parse_parameter(parameters)
            fields.extend(parameter_fields)
            parameters = parameters[bits_consumed:]
            
        return fields
    
    def _parse_chunk_abort(self, buffer: Buffer) -> List[FieldDescriptor]:
        r"""
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Type = 6    |  Reserved   |T|            Length             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        \                                                               \
        /                   zero or more Error Causes                   /
        \                                                               \
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        fields: List[FieldDescriptor] = []
        
        parameters = buffer
        while parameters.length > 0:
            parameter_fields, bits_consumed = self._parse_parameter(parameters)
            fields.extend(parameter_fields)
            parameters = parameters[bits_consumed:]
            
        return fields
    
    def _parse_chunk_shutdown(self, buffer: Buffer) -> List[FieldDescriptor]:
        """
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Type = 7    |  Chunk Flags  |          Length = 8           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                      Cumulative TSN Ack                       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        fields: List[FieldDescriptor] = []
        
        fields: List[FieldDescriptor] = []
        cumulative_tsn_ack: Buffer = buffer[0:32]
        fields.append(FieldDescriptor(id=SCTPFields.CHUNK_SHUTDOWN_CUMULATIVE_TSN_ACK, value=cumulative_tsn_ack, position=0))
            
        return fields
    
    def _parse_chunk_shutdown_ack(self, buffer: Buffer) -> List[FieldDescriptor]:
        """
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Type = 8    |  Chunk Flags  |          Length = 4           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        fields: List[FieldDescriptor] = []    
        return fields
    
    def _parse_chunk_error(self, buffer: Buffer) -> List[FieldDescriptor]:
        r"""
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Type = 9    |  Chunk Flags  |            Length             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        \                                                               \
        /                   one or more Error Causes                    /
        \                                                               \
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        fields: List[FieldDescriptor] = []
        
        parameters = buffer
        while parameters.length > 0:
            parameter_fields, bits_consumed = self._parse_parameter(parameters)
            fields.extend(parameter_fields)
            parameters = parameters[bits_consumed:]
            
        return fields
    
    def _parse_chunk_cookie_echo(self, buffer: Buffer) -> List[FieldDescriptor]:
        r"""
         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Type = 10   |  Chunk Flags  |            Length             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        /                            Cookie                             /
        \                                                               \
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        fields: List[FieldDescriptor] = []
        
        cookie: Buffer = buffer
        fields.append(FieldDescriptor(id=SCTPFields.CHUNK_COOKIE_ECHO_COOKIE, value=cookie, position=0))
            
        return fields
    
    def _parse_chunk_cookie_ack(self, buffer: Buffer) -> List[FieldDescriptor]:
        """
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Type = 11   |  Chunk Flags  |          Length = 4           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        fields: List[FieldDescriptor] = []    
        return fields
    
    def _parse_chunk_shutdown_complete(self, buffer: Buffer) -> List[FieldDescriptor]:
        """
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Type = 14   |  Chunk Flags  |          Length = 4           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        fields: List[FieldDescriptor] = []    
        return fields
        
    def _parse_parameter(self, buffer: Buffer) -> Tuple[List[FieldDescriptor], int]:
        r"""
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |        Parameter Type         |       Parameter Length        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        \                                                               \ 
        /                        Parameter Value                        /
        \                                                               \ 
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        fields: List[FieldDescriptor] = []
        parameter_type: Buffer = buffer[0:16]
        parameter_length: Buffer = buffer[16:32]
        
        fields.extend([
            FieldDescriptor(id=SCTPFields.PARAMETER_TYPE, value=parameter_type, position=0),
            FieldDescriptor(id=SCTPFields.PARAMETER_LENGTH, value=parameter_length, position=0),
        ])
        
        parameter_length_value: int = parameter_length.value() * 8
        parameter_value_length: int = parameter_length_value - 32
        if parameter_value_length > 0:
            parameter_value: Buffer = buffer[32: parameter_length_value]
            fields.append(FieldDescriptor(id=SCTPFields.PARAMETER_VALUE, value=parameter_value, position=0))
        
        parameter_padding_length: int = (32 - parameter_value_length%32)%32
        if parameter_padding_length > 0:
            parameter_padding: Buffer = buffer[parameter_length_value: parameter_length_value + parameter_padding_length]
            fields.append(
                FieldDescriptor(id=SCTPFields.PARAMETER_PADDING, value=parameter_padding, position=0)
            )
        return fields, parameter_length_value + parameter_padding_length
    
    
def _compute_checksum(decompressed_fields: List[Tuple[str, Buffer]], rule_field_position: int) -> Buffer:
    """
    Checksum algorithm is the Castagnoli CRC32C Checksum Algorithm (CRC32c).
    """
    fields_values: List[Buffer] = [field_value for _, field_value in decompressed_fields]
    
    sctp_checksum_position: int = rule_field_position
    #   - SCTP checksum is the 4th field of UDP
    sctp_header_and_payload_fields: List[Buffer] = [field for field in fields_values[sctp_checksum_position-3:]]
    sctp_header_and_payload: Buffer = reduce(lambda x, y: x+y, sctp_header_and_payload_fields)
    
    crc_init: int = 0xffffffff    
    checksum = crc32c(buffer=sctp_header_and_payload, crc_init=crc_init)  
    checksum = ~checksum
    checksum_buffer = reduce(lambda x,y : x+y, list(checksum.chunks(length=8))[::-1])
    return checksum_buffer

SCTPComputeFunctions: Dict[str, Tuple[ComputeFunctionType, ComputeFunctionDependenciesType]] = {
    SCTPFields.CHECKSUM: (_compute_checksum, { f.value for f in SCTPFields if f is not SCTPFields.CHECKSUM })
}
    
REGISTER_PARSER(protocol_id=ProtocolsIDs.SCTP, parser_class=SCTPParser)

SCTP_BASE_HEADER_FIELDS: List[RuleFieldDescriptor] = [
    RuleFieldDescriptor(
        id=SCTPFields.SOURCE_PORT,
        length=16,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=None
    ),
    RuleFieldDescriptor(
        id=SCTPFields.DESTINATION_PORT,
        length=16,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=None
    ),
    RuleFieldDescriptor(
        id=SCTPFields.VERIFICATION_TAG,
        length=32,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.EQUAL,
        compression_decompression_action=CDA.NOT_SENT,
        target_value=None
    ),
    RuleFieldDescriptor(
        id=SCTPFields.CHECKSUM,
        length=32,
        position=0,
        direction=DI.BIDIRECTIONAL,
        matching_operator=MO.IGNORE,
        compression_decompression_action=CDA.COMPUTE,
        target_value=None
    )
]

def sctp_base_header_template(
    source_port: Union[bytes, Buffer, int],
    destination_port: Union[bytes, Buffer, int],
    verification_tag: Union[bytes, Buffer, int],
) -> List[RuleFieldDescriptor]:
    """
    Rule descriptor template for SCTP header.
    """
    # Create target values for each field
    target_values = {
        SCTPFields.SOURCE_PORT: create_target_value(source_port, length=16),
        SCTPFields.DESTINATION_PORT: create_target_value(destination_port, length=16),
        SCTPFields.VERIFICATION_TAG: create_target_value(verification_tag, length=32),
    }
    
    
    # Generate rule field descriptors from header fields
    return [
        RuleFieldDescriptor(
            id=field.id,
            length=field.length,
            position=field.position,
            direction=field.direction,
            matching_operator=field.matching_operator,
            compression_decompression_action=field.compression_decompression_action,
            target_value=target_values.get(field.id)
        ) for field in SCTP_BASE_HEADER_FIELDS
    ]