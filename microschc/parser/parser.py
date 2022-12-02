from typing import List
from microschc.rfc8724 import DirectionIndicator, FieldDescriptor, HeaderDescriptor, PacketDescriptor
from microschc.binary.buffer import Buffer

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

    def parse(self, buffer: Buffer, direction: DirectionIndicator) -> PacketDescriptor:
        header_descriptors: List[HeaderDescriptor] = []

        packet_length: int = buffer.length
        for parser in self.parsers:
            header_descriptor = parser.parse(buffer=buffer.content)
            header_descriptors.append(header_descriptor)

            # update buffer to pass on to the next parser
            buffer = buffer[header_descriptor.length:]
        
        packet_fields: List[FieldDescriptor] = []
        
        for header_descriptor in header_descriptors:
            header_fields: List[FieldDescriptor] = [FieldDescriptor(id=f.id, value=f.value, position=f.position)  for f in header_descriptor.fields]
            packet_fields += header_fields

        packet_descriptor: PacketDescriptor = PacketDescriptor(
            direction=direction,
            fields=packet_fields,
            payload=buffer,
            length=packet_length
        )
        
        return packet_descriptor













