"""
UDP header parser

Parser for the UDP protocol header as defined in RFC768 [1].


[1] "RFC768: User Datagram Protocol", J. Postel
"""

from enum import Enum
from microschc.parser import HeaderParser
from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor

UDP_HEADER_ID = 'UDP'

class UDPFields(str, Enum):
    SOURCE_PORT         = 'Source Port'
    DESTINATION_PORT    = 'Destination Port'
    LENGTH              = 'Length'
    CHECKSUM            = 'Checksum'


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
        source_port:int = ( header_bytes[0] << 8 ) | ( header_bytes[1] )

        # destination port: 16 bits
        destination_port:int = ( header_bytes[2] << 8 ) | ( header_bytes[3] )

        # length
        length:int = ( header_bytes[4] << 8 ) | ( header_bytes[5] )

        # checksum
        checksum:bytes = header_bytes[6:8]

        header_descriptor:HeaderDescriptor = HeaderDescriptor(
            id=UDP_HEADER_ID,
            length=8*8,
            fields=[
                FieldDescriptor(id=UDPFields.SOURCE_PORT,       length=16,  position=0, value=source_port),
                FieldDescriptor(id=UDPFields.DESTINATION_PORT,  length=16,  position=0, value=destination_port),
                FieldDescriptor(id=UDPFields.LENGTH,            length=16,  position=0, value=length),
                FieldDescriptor(id=UDPFields.CHECKSUM,          length=16,  position=0, value=checksum),
            ]
        )
        return header_descriptor
        