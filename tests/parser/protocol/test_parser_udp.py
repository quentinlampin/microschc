from microschc.parser.protocol.udp import UDPParser, UDPFields
from microschc.parser.parser import HeaderDescriptor
from microschc.rfc8724 import FieldDescriptor

def test_ipv6_parser_import():
    """test: IPv6 header parser import and instanciation
    The test instanciate an IPv6 parser and checks for import errors
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

    parser:UDPParser = UDPParser()
    udp_header_descriptor: HeaderDescriptor = parser.parse(buffer=valid_udp_packet)

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
    assert source_port_fd.length == 16
    assert source_port_fd.position == 0
    assert source_port_fd.value == 9001

    destination_port_fd:FieldDescriptor = udp_header_descriptor.fields[1]
    assert destination_port_fd.id == UDPFields.DESTINATION_PORT
    assert destination_port_fd.length == 16
    assert destination_port_fd.position == 0
    assert destination_port_fd.value == 9002

    length_fd:FieldDescriptor = udp_header_descriptor.fields[2]
    assert length_fd.id == UDPFields.LENGTH
    assert length_fd.length == 16
    assert length_fd.position == 0
    assert length_fd.value == 16

    checksum_fd:FieldDescriptor = udp_header_descriptor.fields[3]
    assert checksum_fd.id == UDPFields.CHECKSUM
    assert checksum_fd.length == 16
    assert checksum_fd.position == 0
    assert checksum_fd.value == b'\x2d\xa1'
