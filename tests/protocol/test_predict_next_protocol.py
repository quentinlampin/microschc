from microschc.binary.buffer import Buffer
from microschc.protocol.coap import CoAPFields
from microschc.protocol.ipv6 import IPv6Fields, IPv6Parser
from microschc.protocol.udp import UDPFields
from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor


def test_predictive_parser_parse():
    """test: IPv6/UDP/CoAP packet parsing using predictive heuristic for next protocol parser.

    The packet is made of a CoAP header with following fields:
        - id='Version'                length=2    position=0  value=b'\x01'
        - id='Type'                   length=2    position=0  value=b'\x00'
        - id='Token Length'           length=4    position=0  value=b'\x08'
        - id='Code'                   length=8    position=0  value=b'\x02'
        - id='message ID'             length=16   position=0  value=b'\x84\x99'
        - id='Token'                  length=32   position=0  value=b'\x74\xcd\xe8\xcb\x4e\x8c\x0d\xb7'

        - id='Option Delta'           length=4    position=0  value=b'\x0B'
        - id='Option Length'          length=4    position=0  value=b'\x02'
        - id='Option Value'           length=16   position=0  value=b'\x72\x64'

        - id='Option Delta'           length=4    position=1  value=b'\x01'
        - id='Option Length'          length=4    position=1  value=b'\x01'
        - id='Option Value'           length=8    position=1  value=b'\x28'

        - id='Option Delta'           length=4    position=2  value=b'\x03'
        - id='Option Length'          length=4    position=2  value=b'\x03'
        - id='Option Value'           length=24   position=2  value=b'\x62\x3d\x55'

        - id='Option Delta'           length=4    position=3  value=b'\x00'
        - id='Option Length'          length=4    position=3  value=b'\x09'
        - id='Option Value'           length=72   position=3  value=b'\x6c\x77\x6d\x32\x6d\x3d\x31\x2e\x31'

        - id='Option Delta'           length=4    position=4  value=b'\x00'
        - id='Option Length'          length=4    position=4  value=b'\x06'
        - id='Option Value'           length=48   position=4  value=b'\x6c\x74\x3d\x33\x30\x30'

        - id='Option Delta'           length=4    position=5  value=b'\x00'
        - id='Option Length'          length=4    position=5  value=b'\x0d'
        - id='Option Length Extended' length=8    position=0  value=b'\x02'
        - id='Option Value'           length=120  position=5  value=b'\x65\x70\x3d\x38\x35\x62\x61\x39\x62\x64\x61\x63\x30\x62\x65'
        
        - id='Option Delta'           length=4    position=6  value=b'\x0c'
        - id='Option Length'          length=4    position=6  value=b'\x01'
        - id='Option Value'           length=8    position=6  value=b'\x0d'

        - id='Option Delta'           length=4    position=7  value=b'\x0d'
        - id='Option Length'          length=4    position=7  value=b'\x02'
        - id='Option Delta Extended'  length=8    position=0  value=b'\x14'
        - id='Option Value'           length=8    position=7  value=b'\x07\x2b'

        - id='Payload Marker'          length=8    position=0  value=b'\xff'

    """

    valid_ipv6_udp_coap_packet:bytes = bytes(b'\x60\x0f\xf8\x5f\x00\x20\x11\x40\x20\x01\x0d\xb8\x00\x0a\x00\x00'
                                             b'\x00\x00\x00\x00\x00\x00\x00\x03\x20\x01\x0d\xb8\x00\x0a\x00\x00'
                                             b'\x00\x00\x00\x00\x00\x00\x00\x20'
                                             b'\x90\xa0\x16\x33\x00\x20\x58\x21'
                                             b'\x52\x45\x14\x5e\xd1\x59\x61\x19\x62\x2d\x16\xff\xe8\x16\x44\x08'
                                             b'\x40\x47\x8c\xcc\xcc\xcc\xcc\xcd'
                                        ) 
    valid_ipv6_udp_coap_packet_buffer: Buffer = Buffer(content=valid_ipv6_udp_coap_packet, length=len(valid_ipv6_udp_coap_packet)*8)

    parser:IPv6Parser = IPv6Parser(predict_next=True)

    header_descriptor: HeaderDescriptor = parser.parse(buffer=valid_ipv6_udp_coap_packet_buffer)

    # test ipv6_header_descriptor type
    assert isinstance(header_descriptor, HeaderDescriptor)

    # test for ipv6_header_descriptor.fields length
    assert len(header_descriptor.fields) == 25

    # test for ipv6_header_descriptor.fields types
    for field in header_descriptor.fields:
        assert isinstance(field, FieldDescriptor)

    # assert field descriptors match CoAP header content
    version_fd:FieldDescriptor = header_descriptor.fields[0]
    assert version_fd.id == IPv6Fields.VERSION
    assert version_fd.position == 0
    assert version_fd.value == Buffer(content=b'\x06', length=4)

    flow_label_fd:FieldDescriptor = header_descriptor.fields[1]
    assert flow_label_fd.id == IPv6Fields.TRAFFIC_CLASS
    assert flow_label_fd.position == 0
    assert flow_label_fd.value == Buffer(content=b'\x00', length=8)
    
    payload_length_fd:FieldDescriptor = header_descriptor.fields[3]
    assert payload_length_fd.id == IPv6Fields.PAYLOAD_LENGTH
    assert payload_length_fd.position == 0
    assert payload_length_fd.value == Buffer(content=b'\x00\x20', length=16)
    
    next_header_fd:FieldDescriptor = header_descriptor.fields[4]
    assert next_header_fd.id == IPv6Fields.NEXT_HEADER
    assert next_header_fd.position == 0
    assert next_header_fd.value == Buffer(content=b'\x11', length=8)

    hop_limit_fd:FieldDescriptor = header_descriptor.fields[5]
    assert hop_limit_fd.id == IPv6Fields.HOP_LIMIT
    assert hop_limit_fd.position == 0
    assert hop_limit_fd.value == Buffer(content=b'\x40', length=8)

    source_address_fd:FieldDescriptor = header_descriptor.fields[6]
    assert source_address_fd.id == IPv6Fields.SRC_ADDRESS
    assert source_address_fd.position == 0
    assert source_address_fd.value == Buffer(content=b'\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03', length=128)

    destination_address_fd:FieldDescriptor = header_descriptor.fields[7]
    assert destination_address_fd.id == IPv6Fields.DST_ADDRESS
    assert destination_address_fd.position == 0
    assert destination_address_fd.value == Buffer(content=b'\x20\x01\x0d\xb8\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20', length=128)
    
    # assert field descriptors match UDP header content
    source_port_fd:FieldDescriptor = header_descriptor.fields[8]
    assert source_port_fd.id == UDPFields.SOURCE_PORT
    assert source_port_fd.position == 0
    assert source_port_fd.value == Buffer(content=b'\x90\xa0', length=16)

    destination_port_fd:FieldDescriptor = header_descriptor.fields[9]
    assert destination_port_fd.id == UDPFields.DESTINATION_PORT
    assert destination_port_fd.position == 0
    assert destination_port_fd.value == Buffer(content=b'\x16\x33', length=16)

    length_fd:FieldDescriptor = header_descriptor.fields[10]
    assert length_fd.id == UDPFields.LENGTH
    assert length_fd.position == 0
    assert length_fd.value == Buffer(content=b'\x00\x20', length=16)

    checksum_fd:FieldDescriptor = header_descriptor.fields[11]
    assert checksum_fd.id == UDPFields.CHECKSUM
    assert checksum_fd.position == 0
    assert checksum_fd.value == Buffer(content=b'\x58\x21', length=16)

    # assert field descriptors match CoAP header content
    version_fd:FieldDescriptor = header_descriptor.fields[12]
    assert version_fd.id == CoAPFields.VERSION
    assert version_fd.position == 0
    assert version_fd.value == Buffer(content=b'\x01', length=2)

    type_fd:FieldDescriptor = header_descriptor.fields[13]
    assert type_fd.id == CoAPFields.TYPE
    assert type_fd.position == 0
    assert type_fd.value == Buffer(content=b'\x01', length=2)

    token_length_fd:FieldDescriptor = header_descriptor.fields[14]
    assert token_length_fd.id == CoAPFields.TOKEN_LENGTH
    assert token_length_fd.position == 0
    assert token_length_fd.value == Buffer(content=b'\x02', length=4)

    code_fd:FieldDescriptor = header_descriptor.fields[15]
    assert code_fd.id == CoAPFields.CODE
    assert code_fd.position == 0
    assert code_fd.value == Buffer(content=b'\x45', length=8)

    message_id_fd:FieldDescriptor = header_descriptor.fields[16]
    assert message_id_fd.id == CoAPFields.MESSAGE_ID
    assert message_id_fd.position == 0
    assert message_id_fd.value == Buffer(content=b'\x14\x5e', length=16)

    token_fd:FieldDescriptor = header_descriptor.fields[17]
    assert token_fd.id == CoAPFields.TOKEN
    assert token_fd.position == 0
    assert token_fd.value == Buffer(content=b'\xd1\x59', length=16)