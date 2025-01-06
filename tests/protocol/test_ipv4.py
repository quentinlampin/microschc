from typing import List, Tuple
from microschc.protocol.ipv4 import IPv4Parser, IPv4Fields, IPv4ComputeFunctions
from microschc.parser.parser import HeaderDescriptor
from microschc.rfc8724 import FieldDescriptor
from microschc.binary.buffer import Buffer
from microschc.rfc8724extras import ParserDefinitions

def test_ipv4_parser_import():
    """test: IPv6 header parser import and instanciation
    The test instanciate an IPv6 parser and checks for import errors
    """
    parser = IPv4Parser()
    assert( isinstance(parser, IPv4Parser) )

def test_ipv4_parser_parse():
    """test: IPv4 header parser parses IPv4 packet

    The packet is made of an IPv4 header with following fields:
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

    
def test_ipv4_compute_total_length():

    parser:IPv4Parser = IPv4Parser()
    partially_reconstructed_ipv4_content:bytes = bytes(b"\x45\x00\x00\x00\x21\xfa\x40\x00\x40\x11\xbc\x52\xac\x1e\x01\x08" # total length is \x00\x00, should be \x02\x5c
                                                       b"\xac\x1e\x01\x02")
    ipv4_payload_content:bytes                 = bytes(b"\xc8\xe2\x16\x33\x02\x46\x5c\x9e"
                                                       b"\x48\x02\xba\xbf\x98\x13\xbd\x0e\x51\x2d\xbc\xf7\xb2\x72\x64\x11"
                                                       b"\x28\x33\x62\x3d\x55\x09\x6c\x77\x6d\x32\x6d\x3d\x31\x2e\x31\x06"
                                                       b"\x6c\x74\x3d\x33\x30\x30\x0d\x02\x65\x70\x3d\x65\x32\x63\x61\x37"
                                                       b"\x38\x37\x65\x64\x32\x66\x35\xc1\x0d\xd2\x14\x07\x2b\xff\x3c\x2f"
                                                       b"\x3e\x3b\x72\x74\x3d\x22\x6f\x6d\x61\x2e\x6c\x77\x6d\x32\x6d\x22"
                                                       b"\x3b\x63\x74\x3d\x22\x36\x30\x20\x31\x31\x30\x20\x31\x31\x32\x20"
                                                       b"\x31\x31\x35\x34\x32\x20\x31\x31\x35\x34\x33\x22\x2c\x3c\x2f\x31"
                                                       b"\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x31\x2c\x3c\x2f\x31\x2f\x30\x3e"
                                                       b"\x2c\x3c\x2f\x33\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x32\x2c\x3c\x2f"
                                                       b"\x33\x2f\x30\x3e\x2c\x3c\x2f\x36\x2f\x30\x3e\x2c\x3c\x2f\x33\x33"
                                                       b"\x30\x31\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x31\x2c\x3c\x2f\x33\x33"
                                                       b"\x30\x31\x2f\x30\x3e\x2c\x3c\x2f\x33\x33\x30\x32\x3e\x3b\x76\x65"
                                                       b"\x72\x3d\x31\x2e\x31\x2c\x3c\x2f\x33\x33\x30\x32\x2f\x30\x3e\x2c"
                                                       b"\x3c\x2f\x33\x33\x30\x33\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x31\x2c"
                                                       b"\x3c\x2f\x33\x33\x30\x33\x2f\x30\x3e\x2c\x3c\x2f\x33\x33\x30\x34"
                                                       b"\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x31\x2c\x3c\x2f\x33\x33\x30\x34"
                                                       b"\x2f\x30\x3e\x2c\x3c\x2f\x33\x33\x30\x35\x3e\x3b\x76\x65\x72\x3d"
                                                       b"\x31\x2e\x31\x2c\x3c\x2f\x33\x33\x30\x35\x2f\x30\x3e\x2c\x3c\x2f"
                                                       b"\x33\x33\x30\x36\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x31\x2c\x3c\x2f"
                                                       b"\x33\x33\x30\x36\x2f\x30\x3e\x2c\x3c\x2f\x33\x33\x30\x38\x3e\x3b"
                                                       b"\x76\x65\x72\x3d\x31\x2e\x31\x2c\x3c\x2f\x33\x33\x30\x38\x2f\x30"
                                                       b"\x3e\x2c\x3c\x2f\x33\x33\x31\x30\x3e\x3b\x76\x65\x72\x3d\x31\x2e"
                                                       b"\x31\x2c\x3c\x2f\x33\x33\x31\x30\x2f\x30\x3e\x2c\x3c\x2f\x33\x33"
                                                       b"\x31\x31\x2f\x30\x3e\x2c\x3c\x2f\x33\x33\x31\x32\x3e\x3b\x76\x65"
                                                       b"\x72\x3d\x31\x2e\x31\x2c\x3c\x2f\x33\x33\x31\x32\x2f\x30\x3e\x2c"
                                                       b"\x3c\x2f\x33\x33\x31\x33\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x31\x2c"
                                                       b"\x3c\x2f\x33\x33\x31\x33\x2f\x30\x3e\x2c\x3c\x2f\x33\x33\x31\x34"
                                                       b"\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x31\x2c\x3c\x2f\x33\x33\x31\x34"
                                                       b"\x2f\x30\x3e\x2c\x3c\x2f\x33\x33\x31\x35\x3e\x3b\x76\x65\x72\x3d"
                                                       b"\x31\x2e\x31\x2c\x3c\x2f\x33\x33\x31\x35\x2f\x30\x3e\x2c\x3c\x2f"
                                                       b"\x33\x33\x31\x36\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x31\x2c\x3c\x2f"
                                                       b"\x33\x33\x31\x36\x2f\x30\x3e\x2c\x3c\x2f\x33\x33\x31\x37\x3e\x3b"
                                                       b"\x76\x65\x72\x3d\x31\x2e\x31\x2c\x3c\x2f\x33\x33\x31\x37\x2f\x30"
                                                       b"\x3e\x2c\x3c\x2f\x33\x33\x31\x38\x3e\x3b\x76\x65\x72\x3d\x31\x2e"
                                                       b"\x31\x2c\x3c\x2f\x33\x33\x31\x38\x2f\x30\x3e\x2c\x3c\x2f\x33\x33"
                                                       b"\x31\x39\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x31\x2c\x3c\x2f"
    )

    partially_reconstructed_ipv4_packet_buffer: Buffer = Buffer(content=partially_reconstructed_ipv4_content, length=len(partially_reconstructed_ipv4_content)*8)
    ipv4_payload_buffer: Buffer = Buffer(content=ipv4_payload_content, length=len(ipv4_payload_content)*8)
    ipv4_header_descriptor: HeaderDescriptor = parser.parse(buffer=partially_reconstructed_ipv4_packet_buffer)
    decompressed_fields: List[Tuple[str, Buffer]] = [ (field.id,field.value) for field in ipv4_header_descriptor.fields]
    decompressed_fields.append((ParserDefinitions.PAYLOAD, ipv4_payload_buffer))
   

    total_length_buffer: Buffer = IPv4ComputeFunctions[IPv4Fields.TOTAL_LENGTH][0](decompressed_fields, 2)
    assert total_length_buffer == Buffer(content=b'\x02\x5a', length=16)
    
    
def test_ipv4_compute_checksum():

    parser:IPv4Parser = IPv4Parser()
    partially_reconstructed_ipv4_content:bytes = bytes(b"\x45\x00\x02\x5a\x21\xfa\x40\x00\x40\x11\x00\x00\xac\x1e\x01\x08" # checksum is \x00\x00, should be \xbc\x52
                                                       b"\xac\x1e\x01\x02")
    ipv4_payload_content:bytes                 = bytes(b"\xc8\xe2\x16\x33\x02\x46\x5c\x9e"
                                                       b"\x48\x02\xba\xbf\x98\x13\xbd\x0e\x51\x2d\xbc\xf7\xb2\x72\x64\x11"
                                                       b"\x28\x33\x62\x3d\x55\x09\x6c\x77\x6d\x32\x6d\x3d\x31\x2e\x31\x06"
                                                       b"\x6c\x74\x3d\x33\x30\x30\x0d\x02\x65\x70\x3d\x65\x32\x63\x61\x37"
                                                       b"\x38\x37\x65\x64\x32\x66\x35\xc1\x0d\xd2\x14\x07\x2b\xff\x3c\x2f"
                                                       b"\x3e\x3b\x72\x74\x3d\x22\x6f\x6d\x61\x2e\x6c\x77\x6d\x32\x6d\x22"
                                                       b"\x3b\x63\x74\x3d\x22\x36\x30\x20\x31\x31\x30\x20\x31\x31\x32\x20"
                                                       b"\x31\x31\x35\x34\x32\x20\x31\x31\x35\x34\x33\x22\x2c\x3c\x2f\x31"
                                                       b"\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x31\x2c\x3c\x2f\x31\x2f\x30\x3e"
                                                       b"\x2c\x3c\x2f\x33\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x32\x2c\x3c\x2f"
                                                       b"\x33\x2f\x30\x3e\x2c\x3c\x2f\x36\x2f\x30\x3e\x2c\x3c\x2f\x33\x33"
                                                       b"\x30\x31\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x31\x2c\x3c\x2f\x33\x33"
                                                       b"\x30\x31\x2f\x30\x3e\x2c\x3c\x2f\x33\x33\x30\x32\x3e\x3b\x76\x65"
                                                       b"\x72\x3d\x31\x2e\x31\x2c\x3c\x2f\x33\x33\x30\x32\x2f\x30\x3e\x2c"
                                                       b"\x3c\x2f\x33\x33\x30\x33\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x31\x2c"
                                                       b"\x3c\x2f\x33\x33\x30\x33\x2f\x30\x3e\x2c\x3c\x2f\x33\x33\x30\x34"
                                                       b"\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x31\x2c\x3c\x2f\x33\x33\x30\x34"
                                                       b"\x2f\x30\x3e\x2c\x3c\x2f\x33\x33\x30\x35\x3e\x3b\x76\x65\x72\x3d"
                                                       b"\x31\x2e\x31\x2c\x3c\x2f\x33\x33\x30\x35\x2f\x30\x3e\x2c\x3c\x2f"
                                                       b"\x33\x33\x30\x36\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x31\x2c\x3c\x2f"
                                                       b"\x33\x33\x30\x36\x2f\x30\x3e\x2c\x3c\x2f\x33\x33\x30\x38\x3e\x3b"
                                                       b"\x76\x65\x72\x3d\x31\x2e\x31\x2c\x3c\x2f\x33\x33\x30\x38\x2f\x30"
                                                       b"\x3e\x2c\x3c\x2f\x33\x33\x31\x30\x3e\x3b\x76\x65\x72\x3d\x31\x2e"
                                                       b"\x31\x2c\x3c\x2f\x33\x33\x31\x30\x2f\x30\x3e\x2c\x3c\x2f\x33\x33"
                                                       b"\x31\x31\x2f\x30\x3e\x2c\x3c\x2f\x33\x33\x31\x32\x3e\x3b\x76\x65"
                                                       b"\x72\x3d\x31\x2e\x31\x2c\x3c\x2f\x33\x33\x31\x32\x2f\x30\x3e\x2c"
                                                       b"\x3c\x2f\x33\x33\x31\x33\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x31\x2c"
                                                       b"\x3c\x2f\x33\x33\x31\x33\x2f\x30\x3e\x2c\x3c\x2f\x33\x33\x31\x34"
                                                       b"\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x31\x2c\x3c\x2f\x33\x33\x31\x34"
                                                       b"\x2f\x30\x3e\x2c\x3c\x2f\x33\x33\x31\x35\x3e\x3b\x76\x65\x72\x3d"
                                                       b"\x31\x2e\x31\x2c\x3c\x2f\x33\x33\x31\x35\x2f\x30\x3e\x2c\x3c\x2f"
                                                       b"\x33\x33\x31\x36\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x31\x2c\x3c\x2f"
                                                       b"\x33\x33\x31\x36\x2f\x30\x3e\x2c\x3c\x2f\x33\x33\x31\x37\x3e\x3b"
                                                       b"\x76\x65\x72\x3d\x31\x2e\x31\x2c\x3c\x2f\x33\x33\x31\x37\x2f\x30"
                                                       b"\x3e\x2c\x3c\x2f\x33\x33\x31\x38\x3e\x3b\x76\x65\x72\x3d\x31\x2e"
                                                       b"\x31\x2c\x3c\x2f\x33\x33\x31\x38\x2f\x30\x3e\x2c\x3c\x2f\x33\x33"
                                                       b"\x31\x39\x3e\x3b\x76\x65\x72\x3d\x31\x2e\x31\x2c\x3c\x2f"
    )

    partially_reconstructed_ipv4_packet_buffer: Buffer = Buffer(content=partially_reconstructed_ipv4_content, length=len(partially_reconstructed_ipv4_content)*8)
    ipv4_payload_buffer: Buffer = Buffer(content=ipv4_payload_content, length=len(ipv4_payload_content)*8)
    ipv4_header_descriptor: HeaderDescriptor = parser.parse(buffer=partially_reconstructed_ipv4_packet_buffer)
    decompressed_fields: List[Tuple[str, Buffer]] = [ (field.id,field.value) for field in ipv4_header_descriptor.fields]
    decompressed_fields.append((ParserDefinitions.PAYLOAD, ipv4_payload_buffer))
   

    header_checksum_buffer: Buffer = IPv4ComputeFunctions[IPv4Fields.HEADER_CHECKSUM][0](decompressed_fields, 9)
    assert header_checksum_buffer == Buffer(content=b'\xbc\x52', length=16)