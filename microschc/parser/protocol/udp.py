"""
UDP header parser

Parser for the UDP protocol header as defined in RFC768 [1].


[1] "RFC768: User Datagram Protocol", J. Postel
"""

from enum import Enum
from microschc.parser import HeaderParser, ParserError
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

    def parse(self, buffer:Buffer) -> HeaderDescriptor:
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

        if buffer.length < 64:
            raise ParserError(buffer, message=f'length too short: {buffer.length} < 64')

        # source port: 16 bits
        source_port:Buffer = buffer[0:16]

        # destination port: 16 bits
        destination_port:Buffer = buffer[16:32]

        # length: 16 bits
        length:Buffer = buffer[32:48]

        # checksum: 16 bits
        checksum:Buffer = buffer[48:64]

        header_descriptor:HeaderDescriptor = HeaderDescriptor(
            id=UDP_HEADER_ID,
            length=64,
            fields=[
                FieldDescriptor(id=UDPFields.SOURCE_PORT,       position=0, value=source_port),
                FieldDescriptor(id=UDPFields.DESTINATION_PORT,  position=0, value=destination_port),
                FieldDescriptor(id=UDPFields.LENGTH,            position=0, value=length),
                FieldDescriptor(id=UDPFields.CHECKSUM,          position=0, value=checksum),
            ]
        )
        return header_descriptor
        