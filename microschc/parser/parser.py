from microschc.rfc8724 import DirectionIndicator, HeaderDescriptor, PacketDescriptor


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

    Raises:
        NotImplementedError: This is an abstract base class. It is meant to be subclassed only.

    """
    def __init__(self, name: str) -> None:
        self.name = name

    def parse(self, buffer: bytes, directionIndicator: DirectionIndicator) -> PacketDescriptor:
        raise NotImplementedError







