from copy import copy
from typing import List
from microschc.rfc8724 import DirectionIndicator, FieldDescriptor, HeaderDescriptor, PacketDescriptor
from microschc.rfc8724extras import ParserDefinitions


class HeaderParser:
    """Abstract Base Class for header parsers.

    Raises:
        NotImplementedError: This is an abstract base class. It is meant to be subclassed only.


    """
    def __init__(self, name: str) -> None:
        self.name = name

    def parse(self, buffer: bytes) -> HeaderDescriptor:
        raise NotImplementedError


class PacketParser:
    """Abstract Base Class for packet parsers.
    
    A packet parser is fed bytearrays and returns a PacketDescriptor.
    It may call several header parser to parse the bytearray.

    """
    def __init__(self, name: str, parsers: List[HeaderParser]) -> None:
        self.name = name
        self.parsers = parsers

    def parse(self, buffer: bytes, direction: DirectionIndicator) -> PacketDescriptor:
        header_descriptors: List[HeaderDescriptor] = []

        for parser in self.parsers:
            header_descriptor = parser.parse(buffer=buffer)
            header_descriptors.append(header_descriptor)

            # update buffer to pass on to the next parser
            bytes_consumed: int = header_descriptor.length // 8
            extra_bits_consumed: int = header_descriptor.length % 8
            if extra_bits_consumed != 0:
                # TODO: circular shift on the buffer
                pass
            buffer = buffer[bytes_consumed:]
        if buffer != b'':
            payload_field:FieldDescriptor = FieldDescriptor(id=ParserDefinitions.PAYLOAD, length=len(buffer), position=0, value=buffer)
            payload_descriptor: HeaderDescriptor = HeaderDescriptor(id=ParserDefinitions.PAYLOAD, length=len(buffer), fields=[payload_field])
            header_descriptors.append(payload_descriptor)
        
        packet_descriptor: PacketDescriptor = PacketDescriptor(direction=direction, headers=header_descriptors)
        return packet_descriptor













