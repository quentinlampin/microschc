from typing import Dict, List, Optional, Tuple, Union
from microschc.rfc8724 import DirectionIndicator, FieldDescriptor, HeaderDescriptor, PacketDescriptor
from microschc.binary.buffer import Buffer
from microschc.rfc8724extras import ParserDefinitions

class HeaderParser:
    """Abstract Base Class for header parsers.

    Raises:
        NotImplementedError: This is an abstract base class. It is meant to be subclassed only.


    """
    def __init__(self, name: str, predict_next: bool = False) -> None:
        self.name: str = name
        self.predict_next: bool = predict_next

    def parse(self, buffer: Buffer) -> HeaderDescriptor:
        raise NotImplementedError


class PacketParser:
    """Base Class for packet parsers.
    
    A packet parser is fed bytearrays and returns a PacketDescriptor.
    It may call several header parser to parse the bytearray.

    """
    def __init__(self, name: str, parsers: List[HeaderParser]) -> None:
        self.name = name
        self.parsers = parsers
            
    def parse(self, buffer: Buffer) -> PacketDescriptor:
        raw: Buffer = buffer.copy()
        header_descriptors: List[HeaderDescriptor] = []

        for parser in self.parsers:
            header_descriptor = parser.parse(buffer=buffer)
            header_descriptors.append(header_descriptor)
            # update buffer to pass on to the next parser
            buffer = buffer[header_descriptor.length:]                    
        packet_fields: List[FieldDescriptor] = []
        
        for header_descriptor in header_descriptors:
            header_fields: List[FieldDescriptor] = [FieldDescriptor(id=f.id, value=f.value, position=f.position)  for f in header_descriptor.fields]
            packet_fields += header_fields

        packet_descriptor: PacketDescriptor = PacketDescriptor(
            direction=DirectionIndicator.DOWN, # default value
            fields=packet_fields,
            payload=buffer,
            raw=raw,
        )
        
        return packet_descriptor

class ParserError(Exception):
    def __init__(self, buffer: Buffer, message=None):
        exception_message: str = f"error: {message} while parsing buffer: {buffer}"
        super().__init__(message=exception_message)











