from typing import Dict, List, Tuple
from microschc.protocol.registry import Stack, factory
from microschc.protocol.udp import UDPComputeFunctions, UDPParser, UDPFields
from microschc.parser.parser import HeaderDescriptor, PacketParser
from microschc.rfc8724 import FieldDescriptor, PacketDescriptor
from microschc.binary.buffer import Buffer
from microschc.rfc8724extras import ParserDefinitions

def test_udp_parser_import():
    """test: UDP header parser import and instanciation
    The test instanciate a UDP parser and checks for import errors
    """
    parser = UDPParser()
    assert( isinstance(parser, UDPParser) )

def test_udp_parser_parse():
    """test: UDP header parser parses UDP packet

    The packet is made of a UDP header with following fields:
        - id='Source Port'          length=16    position=0  value=9001
        - id='Destination Port'     length=16    position=0  value=9002
        - id='Length'               length=16    position=0  value=16
        - id='Checksum'             length=16    position=0  value=b'\x2d\xa1'

    """

    valid_udp_packet:bytes = bytes( b"\x23\x29\x23\x2a\x00\x10\x2d\xa1"
                                    b"\x64\x65\x61\x64\x62\x65\x65\x66"
    )
    valid_udp_packet_buffer:Buffer = Buffer(content=valid_udp_packet, length=len(valid_udp_packet)*8)
    parser:UDPParser = UDPParser()

    udp_header_descriptor: HeaderDescriptor = parser.parse(buffer=valid_udp_packet_buffer)

    # test udp_header_descriptor type
    assert isinstance(udp_header_descriptor, HeaderDescriptor)

    # test for udp_header_descriptor.fields length
    assert len(udp_header_descriptor.fields) == 4

    # test for udp_header_descriptor.fields types
    for field in udp_header_descriptor.fields:
        assert isinstance(field, FieldDescriptor)

    # assert field descriptors match UDP header content
    source_port_fd:FieldDescriptor = udp_header_descriptor.fields[0]
    assert source_port_fd.id == UDPFields.SOURCE_PORT
    assert source_port_fd.position == 0
    assert source_port_fd.value == Buffer(content=b'\x23\x29', length=16)

    destination_port_fd:FieldDescriptor = udp_header_descriptor.fields[1]
    assert destination_port_fd.id == UDPFields.DESTINATION_PORT
    assert destination_port_fd.position == 0
    assert destination_port_fd.value == Buffer(content=b'\x23\x2a', length=16)

    length_fd:FieldDescriptor = udp_header_descriptor.fields[2]
    assert length_fd.id == UDPFields.LENGTH
    assert length_fd.position == 0
    assert length_fd.value == Buffer(content=b'\x00\x10', length=16)

    checksum_fd:FieldDescriptor = udp_header_descriptor.fields[3]
    assert checksum_fd.id == UDPFields.CHECKSUM
    assert checksum_fd.position == 0
    assert checksum_fd.value == Buffer(content=b'\x2d\xa1', length=16)

def test_udp_compute_length():
    """
    The packet is made of:

    - an IPv6 header with following fields:
        - id='Version'              length=4    position=0  value=b'\x06'
        - id='Traffic Class'        length=8    position=0  value=b'\x00'
        - id='Flow Label'           length=20   position=0  value=b'\x00\xef\x2d'
        - id='Payload Length'       length=16   position=0  value=b'\x00\x68'
        - id='Next Header'          length=8    position=0  value=b'\x11'
        - id='Hop Limit'            length=8    position=0  value=b'\x40'
        - id='Source Address'       length=128  position=0  value=b"\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
        - id='Destination Address'  length=128  position=0  value=b"\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20"

    - a UDP header with following fields:
        - id='Source Port'          length=16    position=0  value=b'\xd1\x00'
        - id='Destination Port'     length=16    position=0  value=b'\x16\x33'
        - id='Length'               length=16    position=0  value=b'\x00\x68'
        - id='Checksum'             length=16    position=0  value=b'\x5c\x21'

    - a CoAP header with following fields:
        - id='Version'                length=2    position=0  value=b'\x01'
        - id='Type'                   length=2    position=0  value=b'\x02'
        - id='Token Length'           length=4    position=0  value=b'\x08'
        - id='Code'                   length=8    position=0  value=b'\x45'
        - id='message ID'             length=16   position=0  value=b\x22\xf6'
        - id='Token'                  length=32   position=0  value=b"\xb8\x30\x0e\xfe\xe6\x62\x91\x22"

        - id='Option Delta'           length=4    position=0  value=b'\x0c'
        - id='Option Length'          length=4    position=0  value=b'\x01'
        - id='Option Value'           length=16   position=0  value=b'\x6e'
        - id='Payload Marker'         length=8    position=0  value=b'\xff'
    - a Payload:
        - id='Payload'                length=648  position=0  value=b"\x5b\x7b\x22\x62\x6e\x22\x3a\x22\x2f\x36\x2f\x22\x2c\x22\x6e\x22" \
                                                                    b"\x3a\x22\x30\x2f\x30\x22\x2c\x22\x76\x22\x3a\x35\x34\x2e\x30\x7d" \
                                                                    b"\x2c\x7b\x22\x6e\x22\x3a\x22\x30\x2f\x31\x22\x2c\x22\x76\x22\x3a" \
                                                                    b"\x34\x38\x2e\x30\x7d\x2c\x7b\x22\x6e\x22\x3a\x22\x30\x2f\x35\x22" \
                                                                    b"\x2c\x22\x76\x22\x3a\x31\x36\x36\x36\x32\x36\x33\x33\x33\x39\x7d\x5d"


    """
    partially_reconstructed_content:bytes = bytes(
        b"\x60\x00\xef\x2d\x00\x68\x11\x40\x20\x01\x0d\xb8\x00\x0a\x00\x00" \
        b"\x00\x00\x00\x00\x00\x00\x00\x02\x20\x01\x0d\xb8\x00\x0a\x00\x00" \
        b"\x00\x00\x00\x00\x00\x00\x00\x20\xd1\x00\x16\x33\x00\x68\x5c\x21" \
        b"\x68\x45\x22\xf6\xb8\x30\x0e\xfe\xe6\x62\x91\x22\xc1\x6e\xff\x5b" \
        b"\x7b\x22\x62\x6e\x22\x3a\x22\x2f\x36\x2f\x22\x2c\x22\x6e\x22\x3a" \
        b"\x22\x30\x2f\x30\x22\x2c\x22\x76\x22\x3a\x35\x34\x2e\x30\x7d\x2c" \
        b"\x7b\x22\x6e\x22\x3a\x22\x30\x2f\x31\x22\x2c\x22\x76\x22\x3a\x34" \
        b"\x38\x2e\x30\x7d\x2c\x7b\x22\x6e\x22\x3a\x22\x30\x2f\x35\x22\x2c" \
        b"\x22\x76\x22\x3a\x31\x36\x36\x36\x32\x36\x33\x33\x33\x39\x7d\x5d"
    )
    partially_reconstructed_buffer: Buffer = Buffer(content=partially_reconstructed_content, length=len(partially_reconstructed_content)*8)
    packet_parser: PacketParser = factory(stack_id=Stack.IPV6_UDP_COAP)

    packet_descriptor: PacketDescriptor = packet_parser.parse(buffer=partially_reconstructed_buffer)

    decompressed_fields: List[Tuple[str, Buffer]] = [(field.id,field.value) for field in packet_descriptor.fields]
    decompressed_fields.append((ParserDefinitions.PAYLOAD, packet_descriptor.payload))
    length_buffer: Buffer = UDPComputeFunctions[UDPFields.LENGTH][0](decompressed_fields, 10)
    assert length_buffer == Buffer(content=b'\x00\x68', length=16)


def test_udp_compute_checksum():
    
    
    partially_reconstructed_content: bytes = bytes(
        b"\x60\x00\x00\x00\x00\x34\x11\x01\x21\x00\x00\x00" \
        b"\x00\x00\x00\x01\xAB\xCD\x00\x00\x00\x00\x00\x01" \
        b"\xFD\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        b"\x00\x00\x01\x60\x26\x92\x26\x92\x00\x0C\x00\x00" \
        b"\x12\x34\x56\x78"                            
    )
    # checksum is 0x7ed5
    expected_checksum: Buffer = Buffer(content=b'\x7e\xd5', length=16)
    
    packet_parser: PacketParser = factory(stack_id=Stack.IPV6_UDP_COAP)
    partially_reconstructed_packet: Buffer = Buffer(content=partially_reconstructed_content, length=len(partially_reconstructed_content)*8)
    packet_descriptor: PacketDescriptor = packet_parser.parse(buffer=partially_reconstructed_packet)
    
    
    decompressed_fields: List[Tuple[str, Buffer]] = [ (field.id,field.value) for field in packet_descriptor.fields]
    checksum_buffer: Buffer = UDPComputeFunctions[UDPFields.CHECKSUM][0](decompressed_fields, 11)
    assert checksum_buffer == expected_checksum
