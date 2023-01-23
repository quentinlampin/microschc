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
        header_bytes:bytes = buffer[0:20]

        # version: 4 bits
        version:bytes = ((header_bytes[0] & 0xf0) >> 4).to_bytes(1, 'big')
        # header length(IHL): 4 bits
        header_length:bytes = (header_bytes[0] & 0x0f).to_bytes(1, 'big')
        # type of service: 8 bits
        type_of_service:bytes = header_bytes[1:2]
        # total length: 16 bits
        total_length:bytes = header_bytes[2:4]
        # identification: 16 bits
        identification:bytes = header_bytes[4:6]
        # flags: 3 bits
        flags:bytes = ((header_bytes[6] & 0b11100000) >> 5).to_bytes(1, 'big')
        # fragment offset: 13 bits
        fragment_offset:bytes = (header_bytes[6] & 0b00011111).to_bytes(1, 'big') + header_bytes[7:8]
        # time to live: 8 bits
        time_to_live:bytes = header_bytes[8:9]
        # protocol: 8 bits
        protocol:bytes = header_bytes[9:10]
        # header checksum: 16 bits
        header_checksum:bytes = header_bytes[10:12]
        # source address: 32 bits
        source_address:bytes = header_bytes[12:16]
        # destination address: 32 bits
        destination_address:bytes = header_bytes[16:20]

        # header_length: int = 32 * ihl[0]
        # options_bytelength: int = 4*(ihl[0] - 5)
        # options_bytes: bytes = buffer[20:20 + options_bytelength]
        # if len(options_bytes):
        #     options_fields, option_bits_consumed = _parse_options(options_bytes)
        # else:
        #     option_bits_consumed = 0
        #     options_fields = []
        


        

        header_descriptor:HeaderDescriptor = HeaderDescriptor(
            id=IPV4_HEADER_ID,
            length=160,
            fields=[
                FieldDescriptor(id=IPv4Fields.VERSION,         position=0, value=Buffer(content=version, length=4)),
                FieldDescriptor(id=IPv4Fields.HEADER_LENGTH,   position=0, value=Buffer(content=header_length, length=4)),
                FieldDescriptor(id=IPv4Fields.TYPE_OF_SERVICE, position=0, value=Buffer(content=type_of_service, length=8)),
                FieldDescriptor(id=IPv4Fields.TOTAL_LENGTH,    position=0, value=Buffer(content=total_length, length=16)),
                FieldDescriptor(id=IPv4Fields.IDENTIFICATION,  position=0, value=Buffer(content=identification, length=16)),
                FieldDescriptor(id=IPv4Fields.FLAGS,           position=0, value=Buffer(content=flags, length=3)),
                FieldDescriptor(id=IPv4Fields.FRAGMENT_OFFSET, position=0, value=Buffer(content=fragment_offset, length=13)),
                FieldDescriptor(id=IPv4Fields.TIME_TO_LIVE,    position=0, value=Buffer(content=time_to_live, length=8)),
                FieldDescriptor(id=IPv4Fields.PROTOCOL,        position=0, value=Buffer(content=protocol, length=8)),
                FieldDescriptor(id=IPv4Fields.HEADER_CHECKSUM, position=0, value=Buffer(content=header_checksum, length=16)),
                FieldDescriptor(id=IPv4Fields.SRC_ADDRESS,     position=0, value=Buffer(content=source_address, length=32)),
                FieldDescriptor(id=IPv4Fields.DST_ADDRESS,     position=0, value=Buffer(content=destination_address, length=32)),
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


