"""
IPv4 header parser

Parser for the IPv4 protocol header as defined in RFC791 [1].

Note 1: Options parsing is not implemented yet.


[1] "RFC791: Internet Protocol, DARPA Internet Program, Protocol Specification", J. Postel et al.
"""

from enum import Enum
from typing import List, Tuple
from microschc.binary.buffer import Buffer
from microschc.parser import HeaderParser
from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor

IPV4_HEADER_ID = 'IPv4'

class IPv4Fields(str, Enum):
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
    # OPTION_TYPE             = f'{IPV4_HEADER_ID}:Option Type'
    # OPTION_TYPE_COPIED_FLAG = f'{IPV4_HEADER_ID}:Option Type Copied Flag'
    # OPTION_TYPE_CLASS       = f'{IPV4_HEADER_ID}:Option Type Class'
    # OPTION_TYPE_NUMBER      = f'{IPV4_HEADER_ID}:Option Type Number'
    # OPTION_LENGTH           = f'{IPV4_HEADER_ID}:Option Length'
    # OPTION_VALUE            = f'{IPV4_HEADER_ID}:Option Value'
    # PADDING                 = f'{IPV4_HEADER_ID}:Padding'

class IPv4Parser(HeaderParser):

    def __init__(self) -> None:
        super().__init__(name=IPV4_HEADER_ID)

    def match(self, buffer: Buffer) -> bool:
        if buffer.length < 160:
            return False
        
        version:Buffer = buffer[0:4]
        
        return (version == b'\x04')

    def parse(self, buffer:bytes) -> HeaderDescriptor:
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
        |                    Options                    |    Padding    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        """
        # version: 4 bits
        version:Buffer = buffer[0:4]

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


