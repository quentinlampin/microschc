from typing import List, Tuple
from microschc.protocol.coap import CoAPFields, CoAPOptionMode, CoAPParser
from microschc.rfc8724 import FieldDescriptor, HeaderDescriptor
from microschc.binary.buffer import Buffer

def test_coap_parser_import():
    """test: CoAP header parser import and instanciation
    The test instanciate an CoAP parser and checks for import errors
    """
    parser = CoAPParser()
    assert( isinstance(parser, CoAPParser) )

def test_coap_parser_parse_syntactic():
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
                                   b"\x62\x64\x61\x63\x30\x62\x65\xc1\x0d\xd2\x14\x07\x2b\xff")
    
    valid_coap_packet_buffer: Buffer = Buffer(content=valid_coap_packet, length=len(valid_coap_packet)*8)
    parser:CoAPParser = CoAPParser()
    coap_header_descriptor: HeaderDescriptor = parser.parse(buffer=valid_coap_packet_buffer)

    assert isinstance(coap_header_descriptor, HeaderDescriptor)
    assert len(coap_header_descriptor.fields) == 33
    for field in coap_header_descriptor.fields:
        assert isinstance(field, FieldDescriptor)

    # Header fields
    version_fd = coap_header_descriptor.fields[0]
    assert version_fd.id == CoAPFields.VERSION
    assert version_fd.position == 0
    assert version_fd.value == Buffer(content=b'\x01', length=2)

    type_fd = coap_header_descriptor.fields[1]
    assert type_fd.id == CoAPFields.TYPE
    assert type_fd.position == 0
    assert type_fd.value == Buffer(content=b'\x00', length=2)

    token_length_fd = coap_header_descriptor.fields[2]
    assert token_length_fd.id == CoAPFields.TOKEN_LENGTH
    assert token_length_fd.position == 0
    assert token_length_fd.value == Buffer(content=b'\x08', length=4)

    code_fd = coap_header_descriptor.fields[3]
    assert code_fd.id == CoAPFields.CODE
    assert code_fd.position == 0
    assert code_fd.value == Buffer(content=b'\x02', length=8)

    message_id_fd = coap_header_descriptor.fields[4]
    assert message_id_fd.id == CoAPFields.MESSAGE_ID
    assert message_id_fd.position == 0
    assert message_id_fd.value == Buffer(content=b'\x84\x99', length=16)

    token_fd = coap_header_descriptor.fields[5]
    assert token_fd.id == CoAPFields.TOKEN
    assert token_fd.position == 0
    assert token_fd.value == Buffer(content=b'\x74\xcd\xe8\xcb\x4e\x8c\x0d\xb7', length=64)

    # Option 1
    option_1_delta_fd = coap_header_descriptor.fields[6]
    assert option_1_delta_fd.id == CoAPFields.OPTION_DELTA
    assert option_1_delta_fd.position == 1
    assert option_1_delta_fd.value == Buffer(content=b'\x0B', length=4)

    option_1_length_fd = coap_header_descriptor.fields[7]
    assert option_1_length_fd.id == CoAPFields.OPTION_LENGTH
    assert option_1_length_fd.position == 1
    assert option_1_length_fd.value == Buffer(content=b'\x02', length=4)

    option_1_value_fd = coap_header_descriptor.fields[8]
    assert option_1_value_fd.id == CoAPFields.OPTION_VALUE
    assert option_1_value_fd.position == 1
    assert option_1_value_fd.value == Buffer(content=b'\x72\x64', length=16)

    # Option 2
    option_2_delta_fd = coap_header_descriptor.fields[9]
    assert option_2_delta_fd.id == CoAPFields.OPTION_DELTA
    assert option_2_delta_fd.position == 2
    assert option_2_delta_fd.value == Buffer(content=b'\x01', length=4)

    option_2_length_fd = coap_header_descriptor.fields[10]
    assert option_2_length_fd.id == CoAPFields.OPTION_LENGTH
    assert option_2_length_fd.position == 2
    assert option_2_length_fd.value == Buffer(content=b'\x01', length=4)

    option_2_value_fd = coap_header_descriptor.fields[11]
    assert option_2_value_fd.id == CoAPFields.OPTION_VALUE
    assert option_2_value_fd.position == 2
    assert option_2_value_fd.value == Buffer(content=b'\x28', length=8)

    # Option 3
    option_3_delta_fd = coap_header_descriptor.fields[12]
    assert option_3_delta_fd.id == CoAPFields.OPTION_DELTA
    assert option_3_delta_fd.position == 3
    assert option_3_delta_fd.value == Buffer(content=b'\x03', length=4)

    option_3_length_fd = coap_header_descriptor.fields[13]
    assert option_3_length_fd.id == CoAPFields.OPTION_LENGTH
    assert option_3_length_fd.position == 3
    assert option_3_length_fd.value == Buffer(content=b'\x03', length=4)

    option_3_value_fd = coap_header_descriptor.fields[14]
    assert option_3_value_fd.id == CoAPFields.OPTION_VALUE
    assert option_3_value_fd.position == 3
    assert option_3_value_fd.value == Buffer(content=b'\x62\x3d\x55', length=24)

    # Option 4
    option_4_delta_fd = coap_header_descriptor.fields[15]
    assert option_4_delta_fd.id == CoAPFields.OPTION_DELTA
    assert option_4_delta_fd.position == 4
    assert option_4_delta_fd.value == Buffer(content=b'\x00', length=4)

    option_4_length_fd = coap_header_descriptor.fields[16]
    assert option_4_length_fd.id == CoAPFields.OPTION_LENGTH
    assert option_4_length_fd.position == 4
    assert option_4_length_fd.value == Buffer(content=b'\x09', length=4)

    option_4_value_fd = coap_header_descriptor.fields[17]
    assert option_4_value_fd.id == CoAPFields.OPTION_VALUE
    assert option_4_value_fd.position == 4
    assert option_4_value_fd.value == Buffer(content=b'\x6c\x77\x6d\x32\x6d\x3d\x31\x2e\x31', length=72)

    # Option 5
    option_5_delta_fd = coap_header_descriptor.fields[18]
    assert option_5_delta_fd.id == CoAPFields.OPTION_DELTA
    assert option_5_delta_fd.position == 5
    assert option_5_delta_fd.value == Buffer(content=b'\x00', length=4)

    option_5_length_fd = coap_header_descriptor.fields[19]
    assert option_5_length_fd.id == CoAPFields.OPTION_LENGTH
    assert option_5_length_fd.position == 5
    assert option_5_length_fd.value == Buffer(content=b'\x06', length=4)

    option_5_value_fd = coap_header_descriptor.fields[20]
    assert option_5_value_fd.id == CoAPFields.OPTION_VALUE
    assert option_5_value_fd.position == 5
    assert option_5_value_fd.value == Buffer(content=b'\x6c\x74\x3d\x33\x30\x30', length=48)

    # Option 6
    option_6_delta_fd = coap_header_descriptor.fields[21]
    assert option_6_delta_fd.id == CoAPFields.OPTION_DELTA
    assert option_6_delta_fd.position == 6
    assert option_6_delta_fd.value == Buffer(content=b'\x00', length=4)

    option_6_length_fd = coap_header_descriptor.fields[22]
    assert option_6_length_fd.id == CoAPFields.OPTION_LENGTH
    assert option_6_length_fd.position == 6
    assert option_6_length_fd.value == Buffer(content=b'\x0d', length=4)

    option_6_length_ext_fd = coap_header_descriptor.fields[23]
    assert option_6_length_ext_fd.id == CoAPFields.OPTION_LENGTH_EXTENDED
    assert option_6_length_ext_fd.position == 1
    assert option_6_length_ext_fd.value == Buffer(content=b'\x02', length=8)

    option_6_value_fd = coap_header_descriptor.fields[24]
    assert option_6_value_fd.id == CoAPFields.OPTION_VALUE
    assert option_6_value_fd.position == 6
    assert option_6_value_fd.value == Buffer(content=b'\x65\x70\x3d\x38\x35\x62\x61\x39\x62\x64\x61\x63\x30\x62\x65', length=120)

    # Option 7
    option_7_delta_fd = coap_header_descriptor.fields[25]
    assert option_7_delta_fd.id == CoAPFields.OPTION_DELTA
    assert option_7_delta_fd.position == 7
    assert option_7_delta_fd.value == Buffer(content=b'\x0c', length=4)

    option_7_length_fd = coap_header_descriptor.fields[26]
    assert option_7_length_fd.id == CoAPFields.OPTION_LENGTH
    assert option_7_length_fd.position == 7
    assert option_7_length_fd.value == Buffer(content=b'\x01', length=4)

    option_7_value_fd = coap_header_descriptor.fields[27]
    assert option_7_value_fd.id == CoAPFields.OPTION_VALUE
    assert option_7_value_fd.position == 7
    assert option_7_value_fd.value == Buffer(content=b'\x0d', length=8)

    # Option 8
    option_8_delta_fd = coap_header_descriptor.fields[28]
    assert option_8_delta_fd.id == CoAPFields.OPTION_DELTA
    assert option_8_delta_fd.position == 8
    assert option_8_delta_fd.value == Buffer(content=b'\x0d', length=4)

    option_8_length_fd = coap_header_descriptor.fields[29]
    assert option_8_length_fd.id == CoAPFields.OPTION_LENGTH
    assert option_8_length_fd.position == 8
    assert option_8_length_fd.value == Buffer(content=b'\x02', length=4)

    option_8_delta_ext_fd = coap_header_descriptor.fields[30]
    assert option_8_delta_ext_fd.id == CoAPFields.OPTION_DELTA_EXTENDED
    assert option_8_delta_ext_fd.position == 1
    assert option_8_delta_ext_fd.value == Buffer(content=b'\x14', length=8)

    option_8_value_fd = coap_header_descriptor.fields[31]
    assert option_8_value_fd.id == CoAPFields.OPTION_VALUE
    assert option_8_value_fd.position == 8
    assert option_8_value_fd.value == Buffer(content=b'\x07\x2b', length=16)

    # Payload Marker
    payload_marker_fd = coap_header_descriptor.fields[32]
    assert payload_marker_fd.id == CoAPFields.PAYLOAD_MARKER
    assert payload_marker_fd.position == 0
    assert payload_marker_fd.value == Buffer(content=b'\xff', length=8)
    
def test_coap_parser_parse_semantic():
    """test: CoAP header parser parses CoAP packet

    The packet is made of a CoAP header with following fields:
        - id='Version'                length=2    position=0  value=b'\x01'
        - id='Type'                   length=2    position=0  value=b'\x00'
        - id='Token Length'           length=4    position=0  value=b'\x08'
        - id='Code'                   length=8    position=0  value=b'\x02'
        - id='message ID'             length=16   position=0  value=b'\x84\x99'
        - id='Token'                  length=32   position=0  value=b'\x74\xcd\xe8\xcb\x4e\x8c\x0d\xb7'

        - id='Option Uri-Path'        length=16   position=1  value=b'\x72\64'

        - id='Option Content-Format'  length=8    position=1  value=b'\x28'
        
        - id='Option Uri-Query'       length=24   position=1  value=b'\x62\x3d\x55'

        - id='Option Uri-Query'       length=72   position=2  value=b'\x6c\x77\x6d\x32\x6d\x3d\x31\x2e\x31'

        - id='Option Uri-Query'       length=48   position=3  value=b'\x6c\x74\x3d\x33\x30\x30'

        - id='Option Uri-Query'       length=120  position=4  value=b'\x65\x70\x3d\x38\x35\x62\x61\x39\x62\x64\x61\x63\x30\x62\x65'
        
        - id='Option Block1'          length=8    position=1  value=b'\x0d'

        - id='Option Size1'           length=16   position=1  value=b'\x07\x2b'

        - id='Payload Marker'         length=8    position=0  value=b'\xff'

    """
    valid_coap_packet:bytes = bytes(b"\x48\x02\x84\x99\x74\xcd\xe8\xcb\x4e\x8c\x0d\xb7\xb2\x72\x64\x11" \
                                   b"\x28\x33\x62\x3d\x55\x09\x6c\x77\x6d\x32\x6d\x3d\x31\x2e\x31\x06" \
                                   b"\x6c\x74\x3d\x33\x30\x30\x0d\x02\x65\x70\x3d\x38\x35\x62\x61\x39" \
                                   b"\x62\x64\x61\x63\x30\x62\x65\xc1\x0d\xd2\x14\x07\x2b\xff")
    
    valid_coap_packet_buffer: Buffer = Buffer(content=valid_coap_packet, length=len(valid_coap_packet)*8)
    parser:CoAPParser = CoAPParser(interpret_options=CoAPOptionMode.SEMANTIC)
    coap_header_descriptor: HeaderDescriptor = parser.parse(buffer=valid_coap_packet_buffer)

    assert isinstance(coap_header_descriptor, HeaderDescriptor)
    assert len(coap_header_descriptor.fields) == 15
    for field in coap_header_descriptor.fields:
        assert isinstance(field, FieldDescriptor)

    # Header fields
    version_fd = coap_header_descriptor.fields[0]
    assert version_fd.id == CoAPFields.VERSION
    assert version_fd.position == 0
    assert version_fd.value == Buffer(content=b'\x01', length=2)

    type_fd = coap_header_descriptor.fields[1]
    assert type_fd.id == CoAPFields.TYPE
    assert type_fd.position == 0
    assert type_fd.value == Buffer(content=b'\x00', length=2)

    token_length_fd = coap_header_descriptor.fields[2]
    assert token_length_fd.id == CoAPFields.TOKEN_LENGTH
    assert token_length_fd.position == 0
    assert token_length_fd.value == Buffer(content=b'\x08', length=4)

    code_fd = coap_header_descriptor.fields[3]
    assert code_fd.id == CoAPFields.CODE
    assert code_fd.position == 0
    assert code_fd.value == Buffer(content=b'\x02', length=8)

    message_id_fd = coap_header_descriptor.fields[4]
    assert message_id_fd.id == CoAPFields.MESSAGE_ID
    assert message_id_fd.position == 0
    assert message_id_fd.value == Buffer(content=b'\x84\x99', length=16)

    token_fd = coap_header_descriptor.fields[5]
    assert token_fd.id == CoAPFields.TOKEN
    assert token_fd.position == 0
    assert token_fd.value == Buffer(content=b'\x74\xcd\xe8\xcb\x4e\x8c\x0d\xb7', length=64)
    
    option_uri_path_fd = coap_header_descriptor.fields[6]
    assert option_uri_path_fd.id == CoAPFields.OPTION_URI_PATH
    assert option_uri_path_fd.position == 1
    assert option_uri_path_fd.value == Buffer(content=b'\x72\x64', length=16)
    
    option_content_format_fd = coap_header_descriptor.fields[7]
    assert option_content_format_fd.id == CoAPFields.OPTION_CONTENT_FORMAT
    assert option_content_format_fd.position == 1
    assert option_content_format_fd.value == Buffer(content=b'\x28', length=8)
    
    option_uri_query_1_fd = coap_header_descriptor.fields[8]
    assert option_uri_query_1_fd.id == CoAPFields.OPTION_URI_QUERY
    assert option_uri_query_1_fd.position == 1
    assert option_uri_query_1_fd.value == Buffer(content=b'\x62\x3d\x55', length=24)
    
    option_uri_query_2_fd = coap_header_descriptor.fields[9]
    assert option_uri_query_2_fd.id == CoAPFields.OPTION_URI_QUERY
    assert option_uri_query_2_fd.position == 2
    assert option_uri_query_2_fd.value == Buffer(content=b'\x6c\x77\x6d\x32\x6d\x3d\x31\x2e\x31', length=72)
    
    option_uri_query_3_fd = coap_header_descriptor.fields[10]
    assert option_uri_query_3_fd.id == CoAPFields.OPTION_URI_QUERY
    assert option_uri_query_3_fd.position == 3
    assert option_uri_query_3_fd.value == Buffer(content=b'\x6c\x74\x3d\x33\x30\x30', length=48)
    
    option_uri_query_4_fd = coap_header_descriptor.fields[11]
    assert option_uri_query_4_fd.id == CoAPFields.OPTION_URI_QUERY
    assert option_uri_query_4_fd.position == 4
    assert option_uri_query_4_fd.value == Buffer(content=b'\x65\x70\x3d\x38\x35\x62\x61\x39\x62\x64\x61\x63\x30\x62\x65', length=120)
    
    option_block1_fd = coap_header_descriptor.fields[12]
    assert option_block1_fd.id == CoAPFields.OPTION_BLOCK1
    assert option_block1_fd.position == 1
    assert option_block1_fd.value == Buffer(content=b'\x0d', length=8)
    
    option_size1_fd = coap_header_descriptor.fields[13]
    assert option_size1_fd.id == CoAPFields.OPTION_SIZE1
    assert option_size1_fd.position == 1
    assert option_size1_fd.value == Buffer(content=b'\x07\x2b', length=16)
    
    payload_marker_fd = coap_header_descriptor.fields[14]
    assert payload_marker_fd.id == CoAPFields.PAYLOAD_MARKER
    assert payload_marker_fd.position == 0
    assert payload_marker_fd.value == Buffer(content=b'\xff', length=8)
    
    
def test_coap_parser_unparse_semantic():
    
    decompressed_fields = [
        (CoAPFields.VERSION, Buffer(content=b'\x01', length=2)),
        (CoAPFields.TYPE, Buffer(content=b'\x00', length=2)),
        (CoAPFields.TOKEN_LENGTH, Buffer(content=b'\x08', length=4)),
        (CoAPFields.CODE, Buffer(content=b'\x02', length=8)),
        (CoAPFields.MESSAGE_ID, Buffer(content=b'\x84\x99', length=16)),
        (CoAPFields.TOKEN, Buffer(content=b'\x74\xcd\xe8\xcb\x4e\x8c\x0d\xb7', length=64)),
        (CoAPFields.OPTION_URI_PATH, Buffer(content=b'\x72\x64', length=16)),
        (CoAPFields.OPTION_CONTENT_FORMAT, Buffer(content=b'\x28', length=8)),
        (CoAPFields.OPTION_URI_QUERY, Buffer(content=b'\x62\x3d\x55', length=24)),
        (CoAPFields.OPTION_URI_QUERY, Buffer(content=b'\x6c\x77\x6d\x32\x6d\x3d\x31\x2e\x31', length=72)),
        (CoAPFields.OPTION_URI_QUERY, Buffer(content=b'\x6c\x74\x3d\x33\x30\x30', length=48)),
        (CoAPFields.OPTION_URI_QUERY, Buffer(content=b'\x65\x70\x3d\x38\x35\x62\x61\x39\x62\x64\x61\x63\x30\x62\x65', length=120)),
        (CoAPFields.OPTION_BLOCK1, Buffer(content=b'\x0d', length=8)),
        (CoAPFields.OPTION_SIZE1, Buffer(content=b'\x07\x2b', length=16)),
        (CoAPFields.PAYLOAD_MARKER, Buffer(content=b'\xff', length=8))
    ]
    parser:CoAPParser = CoAPParser(interpret_options=CoAPOptionMode.SEMANTIC)
    unparsed_fields: List[Tuple[str, Buffer]] = parser.unparse(decompressed_fields=decompressed_fields)
    assert len(unparsed_fields) == 33
    
    unparsed_field_id_0, unparsed_field_value_0  = unparsed_fields[0]
    assert unparsed_field_id_0 == CoAPFields.VERSION
    assert unparsed_field_value_0 == Buffer(content=b'\x01', length=2)

    unparsed_field_id_1, unparsed_field_value_1  = unparsed_fields[1]
    assert unparsed_field_id_1 == CoAPFields.TYPE
    assert unparsed_field_value_1 == Buffer(content=b'\x00', length=2)

    unparsed_field_id_2, unparsed_field_value_2  = unparsed_fields[2]
    assert unparsed_field_id_2 == CoAPFields.TOKEN_LENGTH
    assert unparsed_field_value_2 == Buffer(content=b'\x08', length=4)

    unparsed_field_id_3, unparsed_field_value_3  = unparsed_fields[3]
    assert unparsed_field_id_3 == CoAPFields.CODE
    assert unparsed_field_value_3 == Buffer(content=b'\x02', length=8)

    unparsed_field_id_4, unparsed_field_value_4  = unparsed_fields[4]
    assert unparsed_field_id_4 == CoAPFields.MESSAGE_ID
    assert unparsed_field_value_4 == Buffer(content=b'\x84\x99', length=16)

    unparsed_field_id_5, unparsed_field_value_5  = unparsed_fields[5]
    assert unparsed_field_id_5 == CoAPFields.TOKEN
    assert unparsed_field_value_5 == Buffer(content=b'\x74\xcd\xe8\xcb\x4e\x8c\x0d\xb7', length=64)

    # Option 1
    unparsed_field_id_6, unparsed_field_value_6  = unparsed_fields[6]
    assert unparsed_field_id_6 == CoAPFields.OPTION_DELTA
    assert unparsed_field_value_6 == Buffer(content=b'\x0B', length=4)

    unparsed_field_id_7, unparsed_field_value_7  = unparsed_fields[7]
    assert unparsed_field_id_7 == CoAPFields.OPTION_LENGTH
    assert unparsed_field_value_7 == Buffer(content=b'\x02', length=4)

    unparsed_field_id_8, unparsed_field_value_8  = unparsed_fields[8]
    assert unparsed_field_id_8 == CoAPFields.OPTION_VALUE
    assert unparsed_field_value_8 == Buffer(content=b'\x72\x64', length=16)

    # Option 2
    unparsed_field_id_9, unparsed_field_value_9  = unparsed_fields[9]
    assert unparsed_field_id_9 == CoAPFields.OPTION_DELTA
    assert unparsed_field_value_9 == Buffer(content=b'\x01', length=4)

    unparsed_field_id_10, unparsed_field_value_10  = unparsed_fields[10]
    assert unparsed_field_id_10 == CoAPFields.OPTION_LENGTH
    assert unparsed_field_value_10 == Buffer(content=b'\x01', length=4)

    unparsed_field_id_11, unparsed_field_value_11  = unparsed_fields[11]
    assert unparsed_field_id_11 == CoAPFields.OPTION_VALUE
    assert unparsed_field_value_11 == Buffer(content=b'\x28', length=8)

    # Option 3
    unparsed_field_id_12, unparsed_field_value_12  = unparsed_fields[12]
    assert unparsed_field_id_12 == CoAPFields.OPTION_DELTA
    assert unparsed_field_value_12 == Buffer(content=b'\x03', length=4)

    unparsed_field_id_13, unparsed_field_value_13  = unparsed_fields[13]
    assert unparsed_field_id_13 == CoAPFields.OPTION_LENGTH
    assert unparsed_field_value_13 == Buffer(content=b'\x03', length=4)

    unparsed_field_id_14, unparsed_field_value_14  = unparsed_fields[14]
    assert unparsed_field_id_14 == CoAPFields.OPTION_VALUE
    assert unparsed_field_value_14 == Buffer(content=b'\x62\x3d\x55', length=24)

    # Option 4
    unparsed_field_id_15, unparsed_field_value_15  = unparsed_fields[15]
    assert unparsed_field_id_15 == CoAPFields.OPTION_DELTA
    assert unparsed_field_value_15 == Buffer(content=b'\x00', length=4)

    unparsed_field_id_16, unparsed_field_value_16  = unparsed_fields[16]
    assert unparsed_field_id_16 == CoAPFields.OPTION_LENGTH
    assert unparsed_field_value_16 == Buffer(content=b'\x09', length=4)

    unparsed_field_id_17, unparsed_field_value_17  = unparsed_fields[17]
    assert unparsed_field_id_17 == CoAPFields.OPTION_VALUE
    assert unparsed_field_value_17 == Buffer(content=b'\x6c\x77\x6d\x32\x6d\x3d\x31\x2e\x31', length=72)

    # Option 5
    unparsed_field_id_18, unparsed_field_value_18  = unparsed_fields[18]
    assert unparsed_field_id_18 == CoAPFields.OPTION_DELTA
    assert unparsed_field_value_18 == Buffer(content=b'\x00', length=4)

    unparsed_field_id_19, unparsed_field_value_19  = unparsed_fields[19]
    assert unparsed_field_id_19 == CoAPFields.OPTION_LENGTH
    assert unparsed_field_value_19 == Buffer(content=b'\x06', length=4)

    unparsed_field_id_20, unparsed_field_value_20  = unparsed_fields[20]
    assert unparsed_field_id_20 == CoAPFields.OPTION_VALUE
    assert unparsed_field_value_20 == Buffer(content=b'\x6c\x74\x3d\x33\x30\x30', length=48)

    # Option 6
    unparsed_field_id_21, unparsed_field_value_21  = unparsed_fields[21]
    assert unparsed_field_id_21 == CoAPFields.OPTION_DELTA
    assert unparsed_field_value_21 == Buffer(content=b'\x00', length=4)

    unparsed_field_id_22, unparsed_field_value_22  = unparsed_fields[22]
    assert unparsed_field_id_22 == CoAPFields.OPTION_LENGTH
    assert unparsed_field_value_22 == Buffer(content=b'\x0d', length=4)

    unparsed_field_id_23, unparsed_field_value_23  = unparsed_fields[23]
    assert unparsed_field_id_23 == CoAPFields.OPTION_LENGTH_EXTENDED
    assert unparsed_field_value_23 == Buffer(content=b'\x02', length=8)

    unparsed_field_id_24, unparsed_field_value_24  = unparsed_fields[24]
    assert unparsed_field_id_24 == CoAPFields.OPTION_VALUE
    assert unparsed_field_value_24 == Buffer(content=b'\x65\x70\x3d\x38\x35\x62\x61\x39\x62\x64\x61\x63\x30\x62\x65', length=120)

    # Option 7
    unparsed_field_id_25, unparsed_field_value_25  = unparsed_fields[25]
    assert unparsed_field_id_25 == CoAPFields.OPTION_DELTA
    assert unparsed_field_value_25 == Buffer(content=b'\x0c', length=4)

    unparsed_field_id_26, unparsed_field_value_26  = unparsed_fields[26]
    assert unparsed_field_id_26 == CoAPFields.OPTION_LENGTH
    assert unparsed_field_value_26 == Buffer(content=b'\x01', length=4)

    unparsed_field_id_27, unparsed_field_value_27  = unparsed_fields[27]
    assert unparsed_field_id_27 == CoAPFields.OPTION_VALUE
    assert unparsed_field_value_27 == Buffer(content=b'\x0d', length=8)

    # Option 8
    unparsed_field_id_28, unparsed_field_value_28  = unparsed_fields[28]
    assert unparsed_field_id_28 == CoAPFields.OPTION_DELTA
    assert unparsed_field_value_28 == Buffer(content=b'\x0d', length=4)

    unparsed_field_id_29, unparsed_field_value_29  = unparsed_fields[29]
    assert unparsed_field_id_29 == CoAPFields.OPTION_LENGTH
    assert unparsed_field_value_29 == Buffer(content=b'\x02', length=4)

    unparsed_field_id_30, unparsed_field_value_30  = unparsed_fields[30]
    assert unparsed_field_id_30 == CoAPFields.OPTION_DELTA_EXTENDED
    assert unparsed_field_value_30 == Buffer(content=b'\x14', length=8)

    unparsed_field_id_31, unparsed_field_value_31  = unparsed_fields[31]
    assert unparsed_field_id_31 == CoAPFields.OPTION_VALUE
    assert unparsed_field_value_31 == Buffer(content=b'\x07\x2b', length=16)

    # Payload Marker
    unparsed_field_id_32, unparsed_field_value_32  = unparsed_fields[32]
    assert unparsed_field_id_32 == CoAPFields.PAYLOAD_MARKER
    assert unparsed_field_value_32 == Buffer(content=b'\xff', length=8)