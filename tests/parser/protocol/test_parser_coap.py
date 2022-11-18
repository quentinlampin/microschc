from microschc.parser.protocol.coap import CoAPFields, CoAPParser
from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor
from microschc.binary.buffer import Buffer

def test_coap_parser_import():
    """test: IPv6 header parser import and instanciation
    The test instanciate an IPv6 parser and checks for import errors
    """
    parser = CoAPParser()
    assert( isinstance(parser, CoAPParser) )

def test_coap_parser_parse():
    """test: CoAP header parser parses CoAP packet

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

    valid_coap_packet:bytes = bytes(b"\x48\x02\x84\x99\x74\xcd\xe8\xcb\x4e\x8c\x0d\xb7\xb2\x72\x64\x11" \
                                    b"\x28\x33\x62\x3d\x55\x09\x6c\x77\x6d\x32\x6d\x3d\x31\x2e\x31\x06" \
                                    b"\x6c\x74\x3d\x33\x30\x30\x0d\x02\x65\x70\x3d\x38\x35\x62\x61\x39" \
                                    b"\x62\x64\x61\x63\x30\x62\x65\xc1\x0d\xd2\x14\x07\x2b\xff"
    )

    parser:CoAPParser = CoAPParser()
    coap_header_descriptor: HeaderDescriptor = parser.parse(buffer=valid_coap_packet)

    # test ipv6_header_descriptor type
    assert isinstance(coap_header_descriptor, HeaderDescriptor)

    # test for ipv6_header_descriptor.fields length
    assert len(coap_header_descriptor.fields) == 33

    # test for ipv6_header_descriptor.fields types
    for field in coap_header_descriptor.fields:
        assert isinstance(field, FieldDescriptor)

    # assert field descriptors match CoAP header content
    version_fd:FieldDescriptor = coap_header_descriptor.fields[0]
    assert version_fd.id == CoAPFields.VERSION
    assert version_fd.position == 0
    assert version_fd.value == Buffer(content=b'\x01', bit_length=2)

    type_fd:FieldDescriptor = coap_header_descriptor.fields[1]
    assert type_fd.id == CoAPFields.TYPE
    assert type_fd.position == 0
    assert type_fd.value == Buffer(content=b'\x00', bit_length=2)

    token_length_fd:FieldDescriptor = coap_header_descriptor.fields[2]
    assert token_length_fd.id == CoAPFields.TOKEN_LENGTH
    assert token_length_fd.position == 0
    assert token_length_fd.value == Buffer(content=b'\x08', bit_length=4)

    code_fd:FieldDescriptor = coap_header_descriptor.fields[3]
    assert code_fd.id == CoAPFields.CODE
    assert code_fd.position == 0
    assert code_fd.value == Buffer(content=b'\x02', bit_length=8)

    message_id_fd:FieldDescriptor = coap_header_descriptor.fields[4]
    assert message_id_fd.id == CoAPFields.MESSAGE_ID
    assert message_id_fd.position == 0
    assert message_id_fd.value == Buffer(content=b'\x84\x99', bit_length=16)

    token_fd:FieldDescriptor = coap_header_descriptor.fields[5]
    assert token_fd.id == CoAPFields.TOKEN
    assert token_fd.position == 0
    assert token_fd.value == Buffer(content=b'\x74\xcd\xe8\xcb\x4e\x8c\x0d\xb7', bit_length=64)


    # TODO: assert the list of options field descriptors match the CoAP options
