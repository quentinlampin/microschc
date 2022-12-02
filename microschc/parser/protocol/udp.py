"""
UDP header parser

Parser for the UDP protocol header as defined in RFC768 [1].


[1] "RFC768: User Datagram Protocol", J. Postel
"""

from enum import Enum
from microschc.parser import HeaderParser
from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor
from microschc.binary.buffer import Buffer

UDP_HEADER_ID = 'UDP'

class UDPFields(str, Enum):
    SOURCE_PORT         = f'{UDP_HEADER_ID}:Source Port'
    DESTINATION_PORT    = f'{UDP_HEADER_ID}:Destination Port'
    LENGTH              = f'{UDP_HEADER_ID}:Length'
    CHECKSUM            = f'{UDP_HEADER_ID}:Checksum'


class UDPParser(HeaderParser):

    def __init__(self) -> None:
        super().__init__(name=UDP_HEADER_ID)

    def parse(self, buffer:bytes) -> HeaderDescriptor:
        """
         0      7 8     15 16    23 24    31
        +--------+--------+--------+--------+
        |     Source      |   Destination   |
        |      Port       |      Port       |
        +--------+--------+--------+--------+
        |                 |                 |
        |     Length      |    Checksum     |
        +--------+--------+--------+--------+
        |                                   |
        |          data octets ...          |
        +---------------- ... --------------|
        """
        header_bytes:bytes = buffer[0:8]

        # source port: 16 bits
        source_port:bytes = header_bytes[0:2]

        # destination port: 16 bits
        destination_port:bytes = header_bytes[2:4]

        # length
        length:bytes = header_bytes[4:6]

        # checksum
        checksum:bytes = header_bytes[6:8]

        header_descriptor:HeaderDescriptor = HeaderDescriptor(
            id=UDP_HEADER_ID,
            length=8*8,
            fields=[
                FieldDescriptor(id=UDPFields.SOURCE_PORT,       position=0, value=Buffer(content=source_port, length=16)),
                FieldDescriptor(id=UDPFields.DESTINATION_PORT,  position=0, value=Buffer(content=destination_port, length=16)),
                FieldDescriptor(id=UDPFields.LENGTH,            position=0, value=Buffer(content=length, length=16)),
                FieldDescriptor(id=UDPFields.CHECKSUM,          position=0, value=Buffer(content=checksum, length=16)),
            ]
        )
        return header_descriptor
        