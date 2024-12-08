"""
SCTP header declarations

Declarations for the SCTP protocol header as defined in RFC9260 [1].

Note 1: Hop by Hop Options, Routing header parsing is not implemented yet.
Note 2: Fragment header parsing is not implemented as fragmentation and reassembly
        are handled by SCHC-RF.
Note 3: Authentication and Encapsulating Security payload parsing is not implemented yet.

[1] "RFC9260: Stream Control Transmission Protocol, R. Stewart et al.
"""


from enum import Enum

SCTP_HEADER_ID = 'SCTP'

class SCTPFields(str, Enum):
    SOURCE_PORT_NUMBER                      = f'{SCTP_HEADER_ID}:Source Port Number'
    DESTINATION_PORT_NUMBER                 = f'{SCTP_HEADER_ID}:Destination Port Number'
    VERIFICATION_TAG                        = f'{SCTP_HEADER_ID}:Verification Tag'
    CHECKSUM                                = f'{SCTP_HEADER_ID}:Checksum'
    CHUNK_TYPE                              = f'{SCTP_HEADER_ID}:Chunk Type'
    CHUNK_FLAGS                             = f'{SCTP_HEADER_ID}:Chunk Flags'
    CHUNK_LENGTH                            = f'{SCTP_HEADER_ID}:Chunk Length'
    DATA_RES                                = f'{SCTP_HEADER_ID}:Data Res'
    DATA_I                                  = f'{SCTP_HEADER_ID}:Data I'
    DATA_U                                  = f'{SCTP_HEADER_ID}:Data U'
    DATA_B                                  = f'{SCTP_HEADER_ID}:Data B'
    DATA_E                                  = f'{SCTP_HEADER_ID}:Data E'
    DATA_LENGTH                             = f'{SCTP_HEADER_ID}:Data Length'
    DATA_TSN                                = f'{SCTP_HEADER_ID}:Data TSN'
    DATA_STREAM_IDENTIFIER                  = f'{SCTP_HEADER_ID}:Data Stream Identifier S'
    DATA_STREAM_SEQUENCE_NUMBER             = f'{SCTP_HEADER_ID}:Data Stream Sequence Number n'
    DATA_PAYLOAD_PROTOCOL_IDENTIFIER        = f'{SCTP_HEADER_ID}:Data Payload Protocol Identifier'
    INIT_CHUNK_FLAGS                        = f'{SCTP_HEADER_ID}:Chunk Flags'
    INIT_CHUNK_LENGTH                       = f'{SCTP_HEADER_ID}:Chunk Length'
    INIT_INITIATE_TAG                       = f'{SCTP_HEADER_ID}:Initiate Tag'
    INIT_ADVERTISED_RECEIVER_WINDOW_CREDIT  = f'{SCTP_HEADER_ID}:Advertised Receiver Window Credit'
    INIT_NUMBER_OF_OUTBOUND_STREAMS         = f'{SCTP_HEADER_ID}:Number of Outbound Streams'
    INIT_NUMBER_OF_INBOUND_STREAMS          = f'{SCTP_HEADER_ID}:Number of Inbound Streams'
    INIT_INITIAL_TSN                        = f'{SCTP_HEADER_ID}:Initial TSN'

    INIT_ACK_CHUNK_FLAGS                        = f'{SCTP_HEADER_ID}:Chunk Flags'
    INIT_ACK_CHUNK_LENGTH                       = f'{SCTP_HEADER_ID}:Chunk Length'
    INIT_ACK_INITIATE_TAG                       = f'{SCTP_HEADER_ID}:Initiate Tag'
    INIT_ACK_ADVERTISED_RECEIVER_WINDOW_CREDIT  = f'{SCTP_HEADER_ID}:Advertised Receiver Window Credit'
    INIT_ACK_NUMBER_OF_OUTBOUND_STREAMS         = f'{SCTP_HEADER_ID}:Number of Outbound Streams'
    INIT_ACK_NUMBER_OF_INBOUND_STREAMS          = f'{SCTP_HEADER_ID}:Number of Inbound Streams'
    INIT_ACK_INITIAL_TSN                        = f'{SCTP_HEADER_ID}:Initial TSN'


from enum import Enum
from typing import Dict, List, Tuple
from microschc.binary.buffer import Buffer
from microschc.parser import HeaderParser, ParserError
from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor

SCTP_HEADER_ID = 'SCTP'

class SCTPFields(str, Enum):
    SOURCE_PORT                                   = f'{SCTP_HEADER_ID}:Source Port'
    DESTINATION_PORT                              = f'{SCTP_HEADER_ID}:Destination Port'
    VERIFICATION_TAG                              = f'{SCTP_HEADER_ID}:Verification Tag'
    CHECKSUM                                      = f'{SCTP_HEADER_ID}:Checksum'
    CHUNK_TYPE                                    = f'{SCTP_HEADER_ID}:Chunk Type'
    CHUNK_FLAGS                                   = f'{SCTP_HEADER_ID}:Chunk Flags'
    CHUNK_LENGTH                                  = f'{SCTP_HEADER_ID}:Chunk Length'
    CHUNK_VALUE                                   = f'{SCTP_HEADER_ID}:Chunk Value'
    CHUNK_PADDING                                 = f'{SCTP_HEADER_ID}:Chunk Padding'
                              
    CHUNK_DATA_TSN                                = f'{SCTP_HEADER_ID}:Data TSN'
    CHUNK_DATA_STREAM_IDENTIFIER                  = f'{SCTP_HEADER_ID}:Data Stream Identifier S'
    CHUNK_DATA_STREAM_SEQUENCE_NUMBER             = f'{SCTP_HEADER_ID}:Data Stream Sequence Number n'
    CHUNK_DATA_PAYLOAD_PROTOCOL_IDENTIFIER        = f'{SCTP_HEADER_ID}:Data Payload Protocol Identifier'
    CHUNK_DATA_PAYLOAD                            = f'{SCTP_HEADER_ID}:Data Payload'
    
class SCTPChunkTypes(int, Enum):
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
    def __init__(self) -> None:
        super().__init__(name=SCTP_HEADER_ID)
        
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
    

    def _parse_chunk(self, buffer: Buffer) -> tuple[List[FieldDescriptor], int]:
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
                fields.extend(chunk_fields)
            else:    
                fields.append(FieldDescriptor(id=SCTPFields.CHUNK_VALUE, position=0, value=chunk_value))
    
        chunk_padding_length: int = (32 - chunk_length_value%32)%32
        if chunk_padding_length > 0:
            chunk_padding: Buffer = buffer[chunk_length_value: chunk_length_value+chunk_padding_length]
            fields.append(FieldDescriptor(id=SCTPFields.CHUNK_PADDING, position=0, value=chunk_padding))
                

        bits_consumed = chunk_length_value  + chunk_padding_length

        return fields, bits_consumed
    
    
    def _parse_chunk_data(self, buffer: Buffer) -> List[FieldDescriptor]:
        """
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
        user_data: Buffer = buffer[96:]
        
        fields.extend(
            [
                FieldDescriptor(id=SCTPFields.CHUNK_DATA_TSN, value=tsn, position=0),
                FieldDescriptor(id=SCTPFields.CHUNK_DATA_STREAM_IDENTIFIER, value=stream_identifier_s, position=0),
                FieldDescriptor(id=SCTPFields.CHUNK_DATA_STREAM_SEQUENCE_NUMBER, value=stream_sequence_number_n, position=0),
                FieldDescriptor(id=SCTPFields.CHUNK_DATA_PAYLOAD_PROTOCOL_IDENTIFIER, value=payload_protocol_identifier, position=0),
                FieldDescriptor(id=SCTPFields.CHUNK_DATA_PAYLOAD, value=user_data, position=0)
            ]
        )
        return fields
            
    