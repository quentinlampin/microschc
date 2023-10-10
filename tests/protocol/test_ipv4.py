from microschc.protocol.ipv4 import IPv4Parser, IPv4Fields
from microschc.parser.parser import HeaderDescriptor
from microschc.rfc8724 import FieldDescriptor
from microschc.binary.buffer import Buffer

def test_ipv4_parser_import():
    """test: IPv6 header parser import and instanciation
    The test instanciate an IPv6 parser and checks for import errors
    """
    parser = IPv4Parser()
    assert( isinstance(parser, IPv4Parser) )

def test_ipv4_parser_parse():
    """test: IPv4 header parser parses IPv4 packet

    The packet is made of an IPv6 header with following fields:
        - id='Version'              length=4    position=0  value=b'\x04'
        - id='Header Length'        length=4    position=0  value=b'\x05'
        - id='Type of Service'      length=8    position=0  value=b'\x00'
        - id='Total Length'         length=16   position=0  value=b'\x02\x5a'
        - id='Identification'       length=16   position=0  value=b'\x21\xfa'
        - id='Flags'                length=3    position=0  value=b'\x02'
        - id='Fragment Offset'      length=13   position=0  value=b'\x00\x00'
        - id='Time to Live'         length=8    position=0  value=b'\x40'
        - id='Protocol'             length=8    position=0  value=b'\x11'
        - id='Header Checksum'      length=16   position=0  value=b'\xbc\x52'
        - id='Source Address        length=32   position=0  value=b'\xac\x1e\x01\x08'
        - id='Destination Address   length=32   position=0  value=b'\xac\x1e\x01\x02'

    """

    valid_ipv4_packet:bytes = bytes(b'\x45\x00\x02\x5a\x21\xfa\x40\x00\x40\x11\xbc\x52\xac\x1e\x01\x08' \
                                    b'\xac\x1e\x01\x02'
    )
    valid_ipv4_packet_buffer:Buffer = Buffer(content=valid_ipv4_packet, length=len(valid_ipv4_packet)*8)

    parser:IPv4Parser = IPv4Parser()
    
    ipv4_header_descriptor: HeaderDescriptor = parser.parse(buffer=valid_ipv4_packet_buffer)

    # test ipv4_header_descriptor type
    assert isinstance(ipv4_header_descriptor, HeaderDescriptor)

    # test for ipv6_header_descriptor.fields length
    assert len(ipv4_header_descriptor.fields) == 12

    # test for ipv6_header_descriptor.fields types
    for field in ipv4_header_descriptor.fields:
        assert isinstance(field, FieldDescriptor)

    # assert field descriptors match IPv6 header content
    version_fd:FieldDescriptor = ipv4_header_descriptor.fields[0]
    assert version_fd.id == IPv4Fields.VERSION
    assert version_fd.position == 0
    assert version_fd.value == Buffer(content=b'\x04', length=4)

    header_length_fd:FieldDescriptor = ipv4_header_descriptor.fields[1]
    assert header_length_fd.id == IPv4Fields.HEADER_LENGTH
    assert header_length_fd.position == 0
    assert header_length_fd.value == Buffer(content=b'\x05', length=4)

    type_of_service_fd:FieldDescriptor = ipv4_header_descriptor.fields[2]
    assert type_of_service_fd.id == IPv4Fields.TYPE_OF_SERVICE
    assert type_of_service_fd.position == 0
    assert type_of_service_fd.value == Buffer(content=b'\x00', length=8)

    total_length_fd:FieldDescriptor = ipv4_header_descriptor.fields[3]
    assert total_length_fd.id == IPv4Fields.TOTAL_LENGTH
    assert total_length_fd.position == 0
    assert total_length_fd.value == Buffer(content=b'\x02\x5a', length=16)

    identification_fd:FieldDescriptor = ipv4_header_descriptor.fields[4]
    assert identification_fd.id == IPv4Fields.IDENTIFICATION
    assert identification_fd.position == 0
    assert identification_fd.value == Buffer(content=b'\x21\xfa', length=16)

    flags_fd:FieldDescriptor = ipv4_header_descriptor.fields[5]
    assert flags_fd.id == IPv4Fields.FLAGS
    assert flags_fd.position == 0
    assert flags_fd.value == Buffer(content=b'\x02', length=3)

    fragment_offset_fd:FieldDescriptor = ipv4_header_descriptor.fields[6]
    assert fragment_offset_fd.id == IPv4Fields.FRAGMENT_OFFSET
    assert fragment_offset_fd.position == 0
    assert fragment_offset_fd.value == Buffer(content=b'\x00\x00', length=13)

    time_to_live_fd:FieldDescriptor = ipv4_header_descriptor.fields[7]
    assert time_to_live_fd.id == IPv4Fields.TIME_TO_LIVE
    assert time_to_live_fd.position == 0
    assert time_to_live_fd.value == Buffer(content=b'\x40', length=8)

    protocol_fd:FieldDescriptor = ipv4_header_descriptor.fields[8]
    assert protocol_fd.id == IPv4Fields.PROTOCOL
    assert protocol_fd.position == 0
    assert protocol_fd.value == Buffer(content=b'\x11', length=8)

    header_checksum_fd:FieldDescriptor = ipv4_header_descriptor.fields[9]
    assert header_checksum_fd.id == IPv4Fields.HEADER_CHECKSUM
    assert header_checksum_fd.position == 0
    assert header_checksum_fd.value == Buffer(content=b'\xbc\x52', length=16)

    source_address_fd:FieldDescriptor = ipv4_header_descriptor.fields[10]
    assert source_address_fd.id == IPv4Fields.SRC_ADDRESS
    assert source_address_fd.position == 0
    assert source_address_fd.value == Buffer(content=b'\xac\x1e\x01\x08', length=32)

    destination_address_fd:FieldDescriptor = ipv4_header_descriptor.fields[11]
    assert destination_address_fd.id == IPv4Fields.DST_ADDRESS
    assert destination_address_fd.position == 0
    assert destination_address_fd.value == Buffer(content=b'\xac\x1e\x01\x02', length=32)

    


