from typing import Dict, List, Tuple
from microschc.protocol.sctp import SCTPParser, SCTPFields
from microschc.parser.parser import HeaderDescriptor
from microschc.rfc8724 import FieldDescriptor
from microschc.binary.buffer import Buffer

def test_sctp_parser_import():
    """test: SCTP header parser import and instanciation
    The test instanciate an SCTP parser and checks for import errors
    """
    parser = SCTPParser()
    assert( isinstance(parser, SCTPParser) )

def test_sctp_parser_parse_data():
    """test: SCTP header parser parses SCTP Header with DATA chunk

    The packet is made of a SCTP header with the following fields:
        - id='Source Port Number'                  length=16   position=0  value=b'\x25\x0f'
        - id='Destination Port Number'             length=16   position=0  value=b'\x96\x0c'
        - id='Verification Tag'                    length=32   position=0  value=b'\xc9\x59\x6d\xb9'
        - id='Checksum'                            length=32   position=0  value=b'\x00\x00\x00\x00'
        - id='Chunk Type'                          length=8    position=0  value=b'\x00'
        - id='Chunk Flags'                         length=8    position=0  value=b'\x03'
        - id='Chunk Length'                        length=16    position=0  value=b'\x00\x49'
        - id='Data TSN'                            length=32   position=0  value=b'\xbc\x5b\xc0\x68'
        - id='Data Stream Identifier S'            length=16   position=0  value=b'\x00\x00'
        - id='Data Stream Sequence Number n'       length=16   position=0  value=b'\x00\x00'
        - id='Data Payload Protocol Identifier'    length=16   position=0  value=b'\x00\x00\x00\x3c'
        - id='Data Payload'                        length=32   position=0  value=b'\x00\x15\x00\x35\x00\x00\x04\x00\x1b\x00\x08\x00\x02\xf8\x39\x10'
                                                                                 b'\x00\x01\x02\x00\x52\x40\x09\x03\x00\x66\x72\x65\x65\x35\x67\x63'
                                                                                 b'\x00\x66\x00\x10\x00\x00\x00\x00\x01\x00\x02\xf8\x39\x00\x00\x10'
                                                                                 b'\x08\x01\x02\x03\x00\x15\x40\x01\x40'
        - id='Chunk Padding'                        length=32  position=0  value=b'\x00\x00\x00'

    """

    valid_sctp_packet:bytes = bytes(b'\x25\x0f\x96\x0c\xc9\x59\x6d\xb9\x00\x00\x00\x00\x00\x03\x00\x49'
                                    b'\xbc\x5b\xc0\x68\x00\x00\x00\x00\x00\x00\x00\x3c'
                                    b'\x00\x15\x00\x35\x00\x00\x04\x00\x1b\x00\x08\x00\x02\xf8\x39\x10'
                                    b'\x00\x01\x02\x00\x52\x40\x09\x03\x00\x66\x72\x65\x65\x35\x67\x63'
                                    b'\x00\x66\x00\x10\x00\x00\x00\x00\x01\x00\x02\xf8\x39\x00\x00\x10'
                                    b'\x08\x01\x02\x03\x00\x15\x40\x01\x40\x00\x00\x00'
    )
    valid_sctp_packet_buffer: Buffer = Buffer(content=valid_sctp_packet, length=len(valid_sctp_packet)*8)
    parser:SCTPParser = SCTPParser()
    
    sctp_header_descriptor: HeaderDescriptor = parser.parse(buffer=valid_sctp_packet_buffer)

    # test sctp_header_descriptor type
    assert isinstance(sctp_header_descriptor, HeaderDescriptor)

    # test for sctp_header_descriptor.fields length
    assert len(sctp_header_descriptor.fields) == 13

    # test for sctp_header_descriptor.fields types
    for field in sctp_header_descriptor.fields:
        assert isinstance(field, FieldDescriptor)

    # assert field descriptors match SCTP header content
    # - common header fields
    source_port_fd:FieldDescriptor = sctp_header_descriptor.fields[0]
    assert source_port_fd.id == SCTPFields.SOURCE_PORT
    assert source_port_fd.position == 0
    assert source_port_fd.value == Buffer(content=b'\x25\x0f', length=16)
    
    destination_port_fd:FieldDescriptor = sctp_header_descriptor.fields[1]
    assert destination_port_fd.id == SCTPFields.DESTINATION_PORT
    assert destination_port_fd.position == 0
    assert destination_port_fd.value == Buffer(content=b'\x96\x0c', length=16)
    
    verification_tag_fd:FieldDescriptor = sctp_header_descriptor.fields[2]
    assert verification_tag_fd.id == SCTPFields.VERIFICATION_TAG
    assert verification_tag_fd.position == 0
    assert verification_tag_fd.value == Buffer(content=b'\xc9\x59\x6d\xb9', length=32)
        
    checksum_fd:FieldDescriptor = sctp_header_descriptor.fields[3]
    assert checksum_fd.id == SCTPFields.CHECKSUM
    assert checksum_fd.position == 0
    assert checksum_fd.value == Buffer(content=b'\x00\x00\x00\x00', length=32)


    # - chunk common header fields
    chunk_type_fd:FieldDescriptor = sctp_header_descriptor.fields[4]
    assert chunk_type_fd.id == SCTPFields.CHUNK_TYPE
    assert chunk_type_fd.position == 0
    assert chunk_type_fd.value == Buffer(content=b'\x00', length=8)
    
    chunk_flags_fd:FieldDescriptor = sctp_header_descriptor.fields[5]
    assert chunk_flags_fd.id == SCTPFields.CHUNK_FLAGS
    assert chunk_flags_fd.position == 0
    assert chunk_flags_fd.value == Buffer(content=b'\x03', length=8)
    
    chunk_length_fd:FieldDescriptor = sctp_header_descriptor.fields[6]
    assert chunk_length_fd.id == SCTPFields.CHUNK_LENGTH
    assert chunk_length_fd.position == 0
    assert chunk_length_fd.value == Buffer(content=b'\x00\x49', length=16)
    
    # - data chunk header fields
    data_tsn_fd:FieldDescriptor = sctp_header_descriptor.fields[7]
    assert data_tsn_fd.id == SCTPFields.CHUNK_DATA_TSN
    assert data_tsn_fd.position == 0
    assert data_tsn_fd.value == Buffer(content=b'\xbc\x5b\xc0\x68', length=32)
    
    data_stream_identifier_fd:FieldDescriptor = sctp_header_descriptor.fields[8]
    assert data_stream_identifier_fd.id == SCTPFields.CHUNK_DATA_STREAM_IDENTIFIER
    assert data_stream_identifier_fd.position == 0
    assert data_stream_identifier_fd.value == Buffer(content=b'\x00\x00', length=16)
    
    data_stream_sequence_number_fd:FieldDescriptor = sctp_header_descriptor.fields[9]
    assert data_stream_sequence_number_fd.id == SCTPFields.CHUNK_DATA_STREAM_SEQUENCE_NUMBER
    assert data_stream_sequence_number_fd.position == 0
    assert data_stream_sequence_number_fd.value == Buffer(content=b'\x00\x00', length=16)
    
    data_payload_protocol_identifier_fd:FieldDescriptor = sctp_header_descriptor.fields[10]
    assert data_payload_protocol_identifier_fd.id == SCTPFields.CHUNK_DATA_PAYLOAD_PROTOCOL_IDENTIFIER
    assert data_payload_protocol_identifier_fd.position == 0
    assert data_payload_protocol_identifier_fd.value == Buffer(content=b'\x00\x00\x00\x3c', length=32)
    
    
    data_payload_fd:FieldDescriptor = sctp_header_descriptor.fields[11]
    assert data_payload_fd.id == SCTPFields.CHUNK_DATA_PAYLOAD
    assert data_payload_fd.position == 0
    assert data_payload_fd.value == Buffer(content= b'\x00\x15\x00\x35\x00\x00\x04\x00\x1b\x00\x08\x00\x02\xf8\x39\x10'
                                                    b'\x00\x01\x02\x00\x52\x40\x09\x03\x00\x66\x72\x65\x65\x35\x67\x63'
                                                    b'\x00\x66\x00\x10\x00\x00\x00\x00\x01\x00\x02\xf8\x39\x00\x00\x10'
                                                    b'\x08\x01\x02\x03\x00\x15\x40\x01\x40',
                                            length=456)
    
    chunk_padding_fd:FieldDescriptor = sctp_header_descriptor.fields[12]
    assert chunk_padding_fd.id == SCTPFields.CHUNK_PADDING
    assert chunk_padding_fd.position == 0
    assert chunk_padding_fd.value == Buffer(content=b'\x00\x00\x00', length=24)
    
    
def test_sctp_parser_parse_init():
    """test: SCTP header parser parses SCTP Header with INIT chunk

    The packet is made of a SCTP header with the following fields:
        - id='Source Port Number'                  length=16   position=0  value=b'\x00\x07'
        - id='Destination Port Number'             length=16   position=0  value=b'\x00\x07'
        - id='Verification Tag'                    length=32   position=0  value=b'\x00\x00\x00\x00'
        - id='Checksum'                            length=32   position=0  value=b'\x37\x61\xa7\x46'
        - id='Chunk Type'                          length=8    position=0  value=b'\x01'
        - id='Chunk Flags'                         length=8    position=0  value=b'\x00'
        - id='Chunk Length'                        length=16   position=0  value=b'\x00\x20'
        - id='Initiate Tag                         length=32   position=0  value=b'\x43\x23\x25\x44'
        - id='Advertised Receiver Window Credit'   length=32   position=0  value=b'\x00\x00\xff\xff'
        - id='Number of Outbound Streams'          length=16   position=0  value=b'\x00\x11'
        - id='Number of Inbound Streams'           length=16   position=0  value=b'\x00\x11'
        - id='Initial TSN                          length=32   position=0  value=b'\x5c\xfe\x37\x9f'
        - id='Parameter Type'                      length=16   position=0  value=b'\xc0\x00'
        - id='Parameter Length'                    length=16   position=0  value=b'\x00\x04'
        - id='Parameter Type'                      length=16   position=0  value=b'\x00\x0c'
        - id='Parameter Length'                    length=16   position=0  value=b'\x00\x06'
        - id='Parameter Value'                     length=16   position=0  value=b'\x00\x05'
        - id='Parameter Padding'                   length=16   position=0  value=b'\x00\x00'

    """

    valid_sctp_packet:bytes = bytes(b'\x00\x07\x00\x07\x00\x00\x00\x00\x37\x61\xa7\x46\x01\x00\x00\x20'
                                    b'\x43\x23\x25\x44\x00\x00\xff\xff\x00\x11\x00\x11\x5c\xfe\x37\x9f'
                                    b'\xc0\x00\x00\x04\x00\x0c\x00\x06\x00\x05\x00\x00'
    )
    valid_sctp_packet_buffer: Buffer = Buffer(content=valid_sctp_packet, length=len(valid_sctp_packet)*8)
    parser:SCTPParser = SCTPParser()
    
    sctp_header_descriptor: HeaderDescriptor = parser.parse(buffer=valid_sctp_packet_buffer)

    # test sctp_header_descriptor type
    assert isinstance(sctp_header_descriptor, HeaderDescriptor)

    # test for sctp_header_descriptor.fields length
    assert len(sctp_header_descriptor.fields) == 18

    # test for sctp_header_descriptor.fields types
    for field in sctp_header_descriptor.fields:
        assert isinstance(field, FieldDescriptor)

    # assert field descriptors match SCTP header content
    # - common header fields
    source_port_fd:FieldDescriptor = sctp_header_descriptor.fields[0]
    assert source_port_fd.id == SCTPFields.SOURCE_PORT
    assert source_port_fd.position == 0
    assert source_port_fd.value == Buffer(content=b'\x00\x07', length=16)
    
    destination_port_fd:FieldDescriptor = sctp_header_descriptor.fields[1]
    assert destination_port_fd.id == SCTPFields.DESTINATION_PORT
    assert destination_port_fd.position == 0
    assert destination_port_fd.value == Buffer(content=b'\x00\x07', length=16)
    
    verification_tag_fd:FieldDescriptor = sctp_header_descriptor.fields[2]
    assert verification_tag_fd.id == SCTPFields.VERIFICATION_TAG
    assert verification_tag_fd.position == 0
    assert verification_tag_fd.value == Buffer(content=b'\x00\x00\x00\x00', length=32)
        
    checksum_fd:FieldDescriptor = sctp_header_descriptor.fields[3]
    assert checksum_fd.id == SCTPFields.CHECKSUM
    assert checksum_fd.position == 0
    assert checksum_fd.value == Buffer(content=b'\x37\x61\xa7\x46', length=32)


    # - chunk common header fields
    chunk_type_fd:FieldDescriptor = sctp_header_descriptor.fields[4]
    assert chunk_type_fd.id == SCTPFields.CHUNK_TYPE
    assert chunk_type_fd.position == 0
    assert chunk_type_fd.value == Buffer(content=b'\x01', length=8)
    
    chunk_flags_fd:FieldDescriptor = sctp_header_descriptor.fields[5]
    assert chunk_flags_fd.id == SCTPFields.CHUNK_FLAGS
    assert chunk_flags_fd.position == 0
    assert chunk_flags_fd.value == Buffer(content=b'\x00', length=8)
    
    chunk_length_fd:FieldDescriptor = sctp_header_descriptor.fields[6]
    assert chunk_length_fd.id == SCTPFields.CHUNK_LENGTH
    assert chunk_length_fd.position == 0
    assert chunk_length_fd.value == Buffer(content=b'\x00\x20', length=16)
    
    initiate_tag_fd:FieldDescriptor = sctp_header_descriptor.fields[7]
    assert initiate_tag_fd.id == SCTPFields.CHUNK_INIT_INITIATE_TAG
    assert initiate_tag_fd.position == 0
    assert initiate_tag_fd.value == Buffer(content=b'\x43\x23\x25\x44', length=32)
    
    advertised_receiver_window_credit_fd:FieldDescriptor = sctp_header_descriptor.fields[8]
    assert advertised_receiver_window_credit_fd.id == SCTPFields.CHUNK_INIT_ADVERTISED_RECEIVER_WINDOW_CREDIT
    assert advertised_receiver_window_credit_fd.position == 0
    assert advertised_receiver_window_credit_fd.value == Buffer(content=b'\x00\x00\xff\xff', length=32)
    
    number_outbound_streams_fd:FieldDescriptor = sctp_header_descriptor.fields[9]
    assert number_outbound_streams_fd.id == SCTPFields.CHUNK_INIT_NUMBER_OF_OUTBOUND_STREAMS
    assert number_outbound_streams_fd.position == 0
    assert number_outbound_streams_fd.value == Buffer(content=b'\x00\x11', length=16)
    
    number_inbound_streams_fd:FieldDescriptor = sctp_header_descriptor.fields[10]
    assert number_inbound_streams_fd.id == SCTPFields.CHUNK_INIT_NUMBER_OF_INBOUND_STREAMS
    assert number_inbound_streams_fd.position == 0
    assert number_inbound_streams_fd.value == Buffer(content=b'\x00\x11', length=16)
    
    initial_tsn_fd:FieldDescriptor = sctp_header_descriptor.fields[11]
    assert initial_tsn_fd.id == SCTPFields.CHUNK_INIT_INITIAL_TSN
    assert initial_tsn_fd.position == 0
    assert initial_tsn_fd.value == Buffer(content=b'\x5c\xfe\x37\x9f', length=32)
    
    parameter_type_fd:FieldDescriptor = sctp_header_descriptor.fields[12]
    assert parameter_type_fd.id == SCTPFields.PARAMETER_TYPE
    assert parameter_type_fd.position == 0
    assert parameter_type_fd.value == Buffer(content=b'\xc0\x00', length=16)

    parameter_length_fd:FieldDescriptor = sctp_header_descriptor.fields[13]
    assert parameter_length_fd.id == SCTPFields.PARAMETER_LENGTH
    assert parameter_length_fd.position == 0
    assert parameter_length_fd.value == Buffer(content=b'\x00\x04', length=16)

    parameter_type_fd:FieldDescriptor = sctp_header_descriptor.fields[14]
    assert parameter_type_fd.id == SCTPFields.PARAMETER_TYPE
    assert parameter_type_fd.position == 0
    assert parameter_type_fd.value == Buffer(content=b'\x00\x0c', length=16)

    parameter_length_fd:FieldDescriptor = sctp_header_descriptor.fields[15]
    assert parameter_length_fd.id == SCTPFields.PARAMETER_LENGTH
    assert parameter_length_fd.position == 0
    assert parameter_length_fd.value == Buffer(content=b'\x00\x06', length=16)

    parameter_value_fd:FieldDescriptor = sctp_header_descriptor.fields[16]
    assert parameter_value_fd.id == SCTPFields.PARAMETER_VALUE
    assert parameter_value_fd.position == 0
    assert parameter_value_fd.value == Buffer(content=b'\x00\x05', length=16)

    parameter_padding_fd:FieldDescriptor = sctp_header_descriptor.fields[17]
    assert parameter_padding_fd.id == SCTPFields.PARAMETER_PADDING
    assert parameter_padding_fd.position == 0
    assert parameter_padding_fd.value == Buffer(content=b'\x00\x00', length=16)
    
    
    


def test_sctp_parser_parse_init_ack():
    """test: SCTP header parser parses SCTP Header with INIT_ACK chunk

    The packet is made of a SCTP header with the following fields:
        - id='Source Port Number'                  length=16   position=0  value=b'\x00\x07'
        - id='Destination Port Number'             length=16   position=0  value=b'\x00\x07'
        - id='Verification Tag'                    length=32   position=0  value=b'\x43\x23\x25\x44'
        - id='Checksum'                            length=32   position=0  value=b'\xc9\x01\x85\x24'
        - id='Chunk Type'                          length=8    position=0  value=b'\x02'
        - id='Chunk Flags'                         length=8    position=0  value=b'\x00'
        - id='Chunk Length'                        length=16   position=0  value=b'\x00\x80'
        - id='Initiate Tag                         length=32   position=0  value=b'\x00\x00\x0e\xb0'
        - id='Advertised Receiver Window Credit'   length=32   position=0  value=b'\x00\x00\x10\x00'
        - id='Number of Outbound Streams'          length=16   position=0  value=b'\x00\x11'
        - id='Number of Inbound Streams'           length=16   position=0  value=b'\x00\x11'
        - id='Initial TSN                          length=32   position=0  value=b'\x00\x00\x36\x14'
        - id='Parameter Type'                      length=16   position=0  value=b'\x00\x07'
        - id='Parameter Length'                    length=16   position=0  value=b'\x00\x68'
        - id='Parameter Value'                     length=800  position=0  value=b'\x00\x00\x0e\xb0\x00\x00\x10\x00\x00\x11\x00\x11'
                                                                                 b'\x00\x00\x36\x14\x43\x23\x25\x44\x00\x00\xff\xff\x00\x11\x00\x11'
                                                                                 b'\x5c\xfe\x37\x9f\x07\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                                                                                 b'\xa2\x85\xb1\x3f\x10\x27\x00\x00\x17\xcd\x8f\x1c\x11\x76\x9b\x04'
                                                                                 b'\x55\xc0\xd0\xf2\x2c\x3e\x7c\x35\x00\x01\x00\x01\x00\x00\x00\x00'
                                                                                 b'\x00\x00\x00\x00\x00\x05\x00\x08\xc0\xa8\xaa\x38\x00\x05\x00\x08'
                                                                                 b'\xc0\xa8\xaa\x08\xc0\x00\x00\x04'
        - id='Parameter Type'                      length=16   position=0  value=b'\xc0\x00'
        - id='Parameter Length'                    length=16   position=0  value=b'\x00\x04'

    """

    valid_sctp_packet:bytes = bytes(b'\x00\x07\x00\x07\x43\x23\x25\x44\xc9\x01\x85\x24\x02\x00\x00\x80'
                                    b'\x00\x00\x0e\xb0\x00\x00\x10\x00\x00\x11\x00\x11\x00\x00\x36\x14'
                                    b'\x00\x07\x00\x68\x00\x00\x0e\xb0\x00\x00\x10\x00\x00\x11\x00\x11'
                                    b'\x00\x00\x36\x14\x43\x23\x25\x44\x00\x00\xff\xff\x00\x11\x00\x11'
                                    b'\x5c\xfe\x37\x9f\x07\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                                    b'\xa2\x85\xb1\x3f\x10\x27\x00\x00\x17\xcd\x8f\x1c\x11\x76\x9b\x04'
                                    b'\x55\xc0\xd0\xf2\x2c\x3e\x7c\x35\x00\x01\x00\x01\x00\x00\x00\x00'
                                    b'\x00\x00\x00\x00\x00\x05\x00\x08\xc0\xa8\xaa\x38\x00\x05\x00\x08'
                                    b'\xc0\xa8\xaa\x08\xc0\x00\x00\x04\xc0\x00\x00\x04'
    )
    valid_sctp_packet_buffer: Buffer = Buffer(content=valid_sctp_packet, length=len(valid_sctp_packet)*8)
    parser:SCTPParser = SCTPParser()
    
    sctp_header_descriptor: HeaderDescriptor = parser.parse(buffer=valid_sctp_packet_buffer)

    # test sctp_header_descriptor type
    assert isinstance(sctp_header_descriptor, HeaderDescriptor)

    # test for sctp_header_descriptor.fields length
    assert len(sctp_header_descriptor.fields) == 17

    # test for sctp_header_descriptor.fields types
    for field in sctp_header_descriptor.fields:
        assert isinstance(field, FieldDescriptor)

    # assert field descriptors match SCTP header content
    # - common header fields
    source_port_fd:FieldDescriptor = sctp_header_descriptor.fields[0]
    assert source_port_fd.id == SCTPFields.SOURCE_PORT
    assert source_port_fd.position == 0
    assert source_port_fd.value == Buffer(content=b'\x00\x07', length=16)
    
    destination_port_fd:FieldDescriptor = sctp_header_descriptor.fields[1]
    assert destination_port_fd.id == SCTPFields.DESTINATION_PORT
    assert destination_port_fd.position == 0
    assert destination_port_fd.value == Buffer(content=b'\x00\x07', length=16)
    
    verification_tag_fd:FieldDescriptor = sctp_header_descriptor.fields[2]
    assert verification_tag_fd.id == SCTPFields.VERIFICATION_TAG
    assert verification_tag_fd.position == 0
    assert verification_tag_fd.value == Buffer(content=b'\x43\x23\x25\x44', length=32)
        
    checksum_fd:FieldDescriptor = sctp_header_descriptor.fields[3]
    assert checksum_fd.id == SCTPFields.CHECKSUM
    assert checksum_fd.position == 0
    assert checksum_fd.value == Buffer(content=b'\xc9\x01\x85\x24', length=32)


    # - chunk common header fields
    chunk_type_fd:FieldDescriptor = sctp_header_descriptor.fields[4]
    assert chunk_type_fd.id == SCTPFields.CHUNK_TYPE
    assert chunk_type_fd.position == 0
    assert chunk_type_fd.value == Buffer(content=b'\x02', length=8)
    
    chunk_flags_fd:FieldDescriptor = sctp_header_descriptor.fields[5]
    assert chunk_flags_fd.id == SCTPFields.CHUNK_FLAGS
    assert chunk_flags_fd.position == 0
    assert chunk_flags_fd.value == Buffer(content=b'\x00', length=8)
    
    chunk_length_fd:FieldDescriptor = sctp_header_descriptor.fields[6]
    assert chunk_length_fd.id == SCTPFields.CHUNK_LENGTH
    assert chunk_length_fd.position == 0
    assert chunk_length_fd.value == Buffer(content=b'\x00\x80', length=16)

    initiate_tag_fd:FieldDescriptor = sctp_header_descriptor.fields[7]
    assert initiate_tag_fd.id == SCTPFields.CHUNK_INIT_ACK_INITIATE_TAG
    assert initiate_tag_fd.position == 0
    assert initiate_tag_fd.value == Buffer(content=b'\x00\x00\x0e\xb0', length=32)

    advertised_receiver_window_credit_fd:FieldDescriptor = sctp_header_descriptor.fields[8]
    assert advertised_receiver_window_credit_fd.id == SCTPFields.CHUNK_INIT_ACK_ADVERTISED_RECEIVER_WINDOW_CREDIT
    assert advertised_receiver_window_credit_fd.position == 0
    assert advertised_receiver_window_credit_fd.value == Buffer(content=b'\x00\x00\x10\x00', length=32)

    number_outbound_streams_fd:FieldDescriptor = sctp_header_descriptor.fields[9]
    assert number_outbound_streams_fd.id == SCTPFields.CHUNK_INIT_ACK_NUMBER_OF_OUTBOUND_STREAMS
    assert number_outbound_streams_fd.position == 0
    assert number_outbound_streams_fd.value == Buffer(content=b'\x00\x11', length=16)

    number_inbound_streams_fd:FieldDescriptor = sctp_header_descriptor.fields[10]
    assert number_inbound_streams_fd.id == SCTPFields.CHUNK_INIT_ACK_NUMBER_OF_INBOUND_STREAMS
    assert number_inbound_streams_fd.position == 0
    assert number_inbound_streams_fd.value == Buffer(content=b'\x00\x11', length=16)

    initial_tsn_fd:FieldDescriptor = sctp_header_descriptor.fields[11]
    assert initial_tsn_fd.id == SCTPFields.CHUNK_INIT_ACK_INITIAL_TSN
    assert initial_tsn_fd.position == 0
    assert initial_tsn_fd.value == Buffer(content=b'\x00\x00\x36\x14', length=32)

    parameter_type_fd:FieldDescriptor = sctp_header_descriptor.fields[12]
    assert parameter_type_fd.id == SCTPFields.PARAMETER_TYPE
    assert parameter_type_fd.position == 0
    assert parameter_type_fd.value == Buffer(content=b'\x00\x07', length=16)

    parameter_length_fd:FieldDescriptor = sctp_header_descriptor.fields[13]
    assert parameter_length_fd.id == SCTPFields.PARAMETER_LENGTH
    assert parameter_length_fd.position == 0
    assert parameter_length_fd.value == Buffer(content=b'\x00\x68', length=16)

    parameter_value_fd:FieldDescriptor = sctp_header_descriptor.fields[14]
    assert parameter_value_fd.id == SCTPFields.PARAMETER_VALUE
    assert parameter_value_fd.position == 0
    assert parameter_value_fd.value == Buffer(content=b'\x00\x00\x0e\xb0\x00\x00\x10\x00\x00\x11\x00\x11'
                                                      b'\x00\x00\x36\x14\x43\x23\x25\x44\x00\x00\xff\xff\x00\x11\x00\x11'
                                                      b'\x5c\xfe\x37\x9f\x07\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                                                      b'\xa2\x85\xb1\x3f\x10\x27\x00\x00\x17\xcd\x8f\x1c\x11\x76\x9b\x04'
                                                      b'\x55\xc0\xd0\xf2\x2c\x3e\x7c\x35\x00\x01\x00\x01\x00\x00\x00\x00'
                                                      b'\x00\x00\x00\x00\x00\x05\x00\x08\xc0\xa8\xaa\x38\x00\x05\x00\x08'
                                                      b'\xc0\xa8\xaa\x08\xc0\x00\x00\x04', 
                                              length=800)

    parameter_type_fd:FieldDescriptor = sctp_header_descriptor.fields[15]
    assert parameter_type_fd.id == SCTPFields.PARAMETER_TYPE
    assert parameter_type_fd.position == 0
    assert parameter_type_fd.value == Buffer(content=b'\xc0\x00', length=16)

    parameter_length_fd:FieldDescriptor = sctp_header_descriptor.fields[16]
    assert parameter_length_fd.id == SCTPFields.PARAMETER_LENGTH
    assert parameter_length_fd.position == 0
    assert parameter_length_fd.value == Buffer(content=b'\x00\x04', length=16)
    
    
def test_sctp_parser_selective_ack():
    """test: SCTP header parser parses SCTP Header with SACK chunk

    The packet is made of a SCTP header with the following fields:
        - id='Source Port Number'                  length=16   position=0  value=b'\x00\x07'
        - id='Destination Port Number'             length=16   position=0  value=b'\x00\x07'
        - id='Verification Tag'                    length=32   position=0  value=b'\x00\x00\x0e\xb0'
        - id='Checksum'                            length=32   position=0  value=b'\xba\x04\x32\x58'
        - id='Chunk Type'                          length=8    position=0  value=b'\x03'
        - id='Chunk Flags'                         length=8    position=0  value=b'\x00'
        - id='Chunk Length'                        length=16   position=0  value=b'\x00\x10'
        - id='Cumulative TSN Ack'                  length=32   position=0  value=b'\x00\x00\x36\x1c'
        - id='Advertised Receiver Window Credit'   length=32   position=0  value=b'\x00\x00\xff\xff'
        - id='Number of Gap Ack Blocks'            length=16   position=0  value=b'\x00\x00'
        - id='Number of Duplicate TSNs'            length=16   position=0  value=b'\x00\x00'
    """
    #TODO: Find SACK chunk with Gap Ack Blocks and Duplicate TSNs.
    
    valid_sctp_packet:bytes = bytes(b'\x00\x07\x00\x07\x00\x00\x0e\xb0\xba\x04\x32\x58\x03\x00\x00\x10'
                                    b'\x00\x00\x36\x1c\x00\x00\xff\xff\x00\x00\x00\x00')
    valid_sctp_packet_buffer: Buffer = Buffer(content=valid_sctp_packet, length=len(valid_sctp_packet)*8)
    parser:SCTPParser = SCTPParser()
    
    sctp_header_descriptor: HeaderDescriptor = parser.parse(buffer=valid_sctp_packet_buffer)

    # test sctp_header_descriptor type
    assert isinstance(sctp_header_descriptor, HeaderDescriptor)

    # test for sctp_header_descriptor.fields length
    assert len(sctp_header_descriptor.fields) == 11

    # test for sctp_header_descriptor.fields types
    for field in sctp_header_descriptor.fields:
        assert isinstance(field, FieldDescriptor)

    # assert field descriptors match SCTP header content
    # - common header fields
    source_port_fd:FieldDescriptor = sctp_header_descriptor.fields[0]
    assert source_port_fd.id == SCTPFields.SOURCE_PORT
    assert source_port_fd.position == 0
    assert source_port_fd.value == Buffer(content=b'\x00\x07', length=16)
    
    destination_port_fd:FieldDescriptor = sctp_header_descriptor.fields[1]
    assert destination_port_fd.id == SCTPFields.DESTINATION_PORT
    assert destination_port_fd.position == 0
    assert destination_port_fd.value == Buffer(content=b'\x00\x07', length=16)
    
    verification_tag_fd:FieldDescriptor = sctp_header_descriptor.fields[2]
    assert verification_tag_fd.id == SCTPFields.VERIFICATION_TAG
    assert verification_tag_fd.position == 0
    assert verification_tag_fd.value == Buffer(content=b'\x00\x00\x0e\xb0', length=32)
        
    checksum_fd:FieldDescriptor = sctp_header_descriptor.fields[3]
    assert checksum_fd.id == SCTPFields.CHECKSUM
    assert checksum_fd.position == 0
    assert checksum_fd.value == Buffer(content=b'\xba\x04\x32\x58', length=32)


    # - chunk common header fields
    chunk_type_fd:FieldDescriptor = sctp_header_descriptor.fields[4]
    assert chunk_type_fd.id == SCTPFields.CHUNK_TYPE
    assert chunk_type_fd.position == 0
    assert chunk_type_fd.value == Buffer(content=b'\x03', length=8)
    
    chunk_flags_fd:FieldDescriptor = sctp_header_descriptor.fields[5]
    assert chunk_flags_fd.id == SCTPFields.CHUNK_FLAGS
    assert chunk_flags_fd.position == 0
    assert chunk_flags_fd.value == Buffer(content=b'\x00', length=8)
    
    chunk_length_fd:FieldDescriptor = sctp_header_descriptor.fields[6]
    assert chunk_length_fd.id == SCTPFields.CHUNK_LENGTH
    assert chunk_length_fd.position == 0
    assert chunk_length_fd.value == Buffer(content=b'\x00\x10', length=16)

    cumulative_tsn_ack_fd:FieldDescriptor = sctp_header_descriptor.fields[7]
    assert cumulative_tsn_ack_fd.id == SCTPFields.CHUNK_SACK_CUMULATIVE_TSN_ACK
    assert cumulative_tsn_ack_fd.position == 0
    assert cumulative_tsn_ack_fd.value == Buffer(content=b'\x00\x00\x36\x1c', length=32)

    advertised_receiver_window_credit_fd:FieldDescriptor = sctp_header_descriptor.fields[8]
    assert advertised_receiver_window_credit_fd.id == SCTPFields.CHUNK_SACK_ADVERTISED_RECEIVER_WINDOW_CREDIT
    assert advertised_receiver_window_credit_fd.position == 0
    assert advertised_receiver_window_credit_fd.value == Buffer(content=b'\x00\x00\xff\xff', length=32)

    number_gap_ack_blocks_fd:FieldDescriptor = sctp_header_descriptor.fields[9]
    assert number_gap_ack_blocks_fd.id == SCTPFields.CHUNK_SACK_NUMBER_GAP_ACK_BLOCKS
    assert number_gap_ack_blocks_fd.position == 0
    assert number_gap_ack_blocks_fd.value == Buffer(content=b'\x00\x00', length=16)

    number_inbound_streams_fd:FieldDescriptor = sctp_header_descriptor.fields[10]
    assert number_inbound_streams_fd.id == SCTPFields.CHUNK_SACK_NUMBER_DUPLICATE_TSNS
    assert number_inbound_streams_fd.position == 0
    assert number_inbound_streams_fd.value == Buffer(content=b'\x00\x00', length=16)


def test_sctp_parser_parse_heartbeat():
    """test: SCTP header parser parses SCTP Header with HEARTBEAT chunk

    The packet is made of a SCTP header with the following fields:
        - id='Source Port Number'                  length=16   position=0  value=b'\x0b\x59'
        - id='Destination Port Number'             length=16   position=0  value=b'\x0b\x59'
        - id='Verification Tag'                    length=32   position=0  value=b'\x00\x00\x0e\x50'
        - id='Checksum'                            length=32   position=0  value=b'\x53\xc3\x05\x5f'
        - id='Chunk Type'                          length=8    position=0  value=b'\x04'
        - id='Chunk Flags'                         length=8    position=0  value=b'\x00'
        - id='Chunk Length'                        length=16   position=0  value=b'\x00\x18'
        - id='Parameter Type'                      length=16   position=0  value=b'\x00\x01'
        - id='Parameter Length'                    length=16   position=0  value=b'\x00\x14'
        - id='Parameter Value'                     length=16   position=0  value=b'\x40\xe4\x4b\x92\x0a\x1c\x06\x2c\x1b\x66\xaf\x7e\x00\x00\x00\x00'

    """

    valid_sctp_packet:bytes = bytes(b'\x0b\x59\x0b\x59\x00\x00\x0e\x50\x53\xc3\x05\x5f\x04\x00\x00\x18'
                                    b'\x00\x01\x00\x14\x40\xe4\x4b\x92\x0a\x1c\x06\x2c\x1b\x66\xaf\x7e'
                                    b'\x00\x00\x00\x00'

                                    )
    
    valid_sctp_packet_buffer: Buffer = Buffer(content=valid_sctp_packet, length=len(valid_sctp_packet)*8)
    parser:SCTPParser = SCTPParser()
    
    sctp_header_descriptor: HeaderDescriptor = parser.parse(buffer=valid_sctp_packet_buffer)

    # test sctp_header_descriptor type
    assert isinstance(sctp_header_descriptor, HeaderDescriptor)

    # test for sctp_header_descriptor.fields length
    assert len(sctp_header_descriptor.fields) == 10

    # test for sctp_header_descriptor.fields types
    for field in sctp_header_descriptor.fields:
        assert isinstance(field, FieldDescriptor)

    # assert field descriptors match SCTP header content
    # - common header fields
    source_port_fd:FieldDescriptor = sctp_header_descriptor.fields[0]
    assert source_port_fd.id == SCTPFields.SOURCE_PORT
    assert source_port_fd.position == 0
    assert source_port_fd.value == Buffer(content=b'\x0b\x59', length=16)
    
    destination_port_fd:FieldDescriptor = sctp_header_descriptor.fields[1]
    assert destination_port_fd.id == SCTPFields.DESTINATION_PORT
    assert destination_port_fd.position == 0
    assert destination_port_fd.value == Buffer(content=b'\x0b\x59', length=16)
    
    verification_tag_fd:FieldDescriptor = sctp_header_descriptor.fields[2]
    assert verification_tag_fd.id == SCTPFields.VERIFICATION_TAG
    assert verification_tag_fd.position == 0
    assert verification_tag_fd.value == Buffer(content=b'\x00\x00\x0e\x50', length=32)
        
    checksum_fd:FieldDescriptor = sctp_header_descriptor.fields[3]
    assert checksum_fd.id == SCTPFields.CHECKSUM
    assert checksum_fd.position == 0
    assert checksum_fd.value == Buffer(content=b'\x53\xc3\x05\x5f', length=32)

    # - chunk common header fields
    chunk_type_fd:FieldDescriptor = sctp_header_descriptor.fields[4]
    assert chunk_type_fd.id == SCTPFields.CHUNK_TYPE
    assert chunk_type_fd.position == 0
    assert chunk_type_fd.value == Buffer(content=b'\x04', length=8)
    
    chunk_flags_fd:FieldDescriptor = sctp_header_descriptor.fields[5]
    assert chunk_flags_fd.id == SCTPFields.CHUNK_FLAGS
    assert chunk_flags_fd.position == 0
    assert chunk_flags_fd.value == Buffer(content=b'\x00', length=8)
    
    chunk_length_fd:FieldDescriptor = sctp_header_descriptor.fields[6]
    assert chunk_length_fd.id == SCTPFields.CHUNK_LENGTH
    assert chunk_length_fd.position == 0
    assert chunk_length_fd.value == Buffer(content=b'\x00\x18', length=16)
    
    parameter_type_fd:FieldDescriptor = sctp_header_descriptor.fields[7]
    assert parameter_type_fd.id == SCTPFields.PARAMETER_TYPE
    assert parameter_type_fd.position == 0
    assert parameter_type_fd.value == Buffer(content=b'\x00\x01', length=16)

    parameter_length_fd:FieldDescriptor = sctp_header_descriptor.fields[8]
    assert parameter_length_fd.id == SCTPFields.PARAMETER_LENGTH
    assert parameter_length_fd.position == 0
    assert parameter_length_fd.value == Buffer(content=b'\x00\x14', length=16)

    parameter_value_fd:FieldDescriptor = sctp_header_descriptor.fields[9]
    assert parameter_value_fd.id == SCTPFields.PARAMETER_VALUE
    assert parameter_value_fd.position == 0
    assert parameter_value_fd.value == Buffer(content=b'\x40\xe4\x4b\x92\x0a\x1c\x06\x2c\x1b\x66\xaf\x7e\x00\x00\x00\x00', length=128)
    

def test_sctp_parser_parse_heartbeat_ack():
    """test: SCTP header parser parses SCTP Header with HEARTBEAT ACK chunk

    The packet is made of a SCTP header with the following fields:
        - id='Source Port Number'                  length=16   position=0  value=b'\x0b\x59'
        - id='Destination Port Number'             length=16   position=0  value=b'\x0b\x59'
        - id='Verification Tag'                    length=32   position=0  value=b'\x0d\x53\xe6\xfe'
        - id='Checksum'                            length=32   position=0  value=b'\x8c\x8e\x07\x46'
        - id='Chunk Type'                          length=8    position=0  value=b'\x05'
        - id='Chunk Flags'                         length=8    position=0  value=b'\x00'
        - id='Chunk Length'                        length=16   position=0  value=b'\x00\x18'
        - id='Parameter Type'                      length=16   position=0  value=b'\x00\x01'
        - id='Parameter Length'                    length=16   position=0  value=b'\x00\x14'
        - id='Parameter Value'                     length=16   position=0  value=b'\x40\xe4\x4b\x92\x0a\x1c\x06\x2c\x1b\x66\xaf\x7e\x00\x00\x00\x00'

    """

    valid_sctp_packet:bytes = bytes(b'\x0b\x59\x0b\x59\x0d\x53\xe6\xfe\x8c\x8e\x07\x46\x05\x00\x00\x18'
                                    b'\x00\x01\x00\x14\x40\xe4\x4b\x92\x0a\x1c\x06\x2c\x1b\x66\xaf\x7e'
                                    b'\x00\x00\x00\x00')
    
    valid_sctp_packet_buffer: Buffer = Buffer(content=valid_sctp_packet, length=len(valid_sctp_packet)*8)
    parser:SCTPParser = SCTPParser()
    
    sctp_header_descriptor: HeaderDescriptor = parser.parse(buffer=valid_sctp_packet_buffer)

    # test sctp_header_descriptor type
    assert isinstance(sctp_header_descriptor, HeaderDescriptor)

    # test for sctp_header_descriptor.fields length
    assert len(sctp_header_descriptor.fields) == 10

    # test for sctp_header_descriptor.fields types
    for field in sctp_header_descriptor.fields:
        assert isinstance(field, FieldDescriptor)

    # assert field descriptors match SCTP header content
    # - common header fields
    source_port_fd:FieldDescriptor = sctp_header_descriptor.fields[0]
    assert source_port_fd.id == SCTPFields.SOURCE_PORT
    assert source_port_fd.position == 0
    assert source_port_fd.value == Buffer(content=b'\x0b\x59', length=16)
    
    destination_port_fd:FieldDescriptor = sctp_header_descriptor.fields[1]
    assert destination_port_fd.id == SCTPFields.DESTINATION_PORT
    assert destination_port_fd.position == 0
    assert destination_port_fd.value == Buffer(content=b'\x0b\x59', length=16)
    
    verification_tag_fd:FieldDescriptor = sctp_header_descriptor.fields[2]
    assert verification_tag_fd.id == SCTPFields.VERIFICATION_TAG
    assert verification_tag_fd.position == 0
    assert verification_tag_fd.value == Buffer(content=b'\x0d\x53\xe6\xfe', length=32)
        
    checksum_fd:FieldDescriptor = sctp_header_descriptor.fields[3]
    assert checksum_fd.id == SCTPFields.CHECKSUM
    assert checksum_fd.position == 0
    assert checksum_fd.value == Buffer(content=b'\x8c\x8e\x07\x46', length=32)

    # - chunk common header fields
    chunk_type_fd:FieldDescriptor = sctp_header_descriptor.fields[4]
    assert chunk_type_fd.id == SCTPFields.CHUNK_TYPE
    assert chunk_type_fd.position == 0
    assert chunk_type_fd.value == Buffer(content=b'\x05', length=8)
    
    chunk_flags_fd:FieldDescriptor = sctp_header_descriptor.fields[5]
    assert chunk_flags_fd.id == SCTPFields.CHUNK_FLAGS
    assert chunk_flags_fd.position == 0
    assert chunk_flags_fd.value == Buffer(content=b'\x00', length=8)
    
    chunk_length_fd:FieldDescriptor = sctp_header_descriptor.fields[6]
    assert chunk_length_fd.id == SCTPFields.CHUNK_LENGTH
    assert chunk_length_fd.position == 0
    assert chunk_length_fd.value == Buffer(content=b'\x00\x18', length=16)
    
    parameter_type_fd:FieldDescriptor = sctp_header_descriptor.fields[7]
    assert parameter_type_fd.id == SCTPFields.PARAMETER_TYPE
    assert parameter_type_fd.position == 0
    assert parameter_type_fd.value == Buffer(content=b'\x00\x01', length=16)

    parameter_length_fd:FieldDescriptor = sctp_header_descriptor.fields[8]
    assert parameter_length_fd.id == SCTPFields.PARAMETER_LENGTH
    assert parameter_length_fd.position == 0
    assert parameter_length_fd.value == Buffer(content=b'\x00\x14', length=16)

    parameter_value_fd:FieldDescriptor = sctp_header_descriptor.fields[9]
    assert parameter_value_fd.id == SCTPFields.PARAMETER_VALUE
    assert parameter_value_fd.position == 0
    assert parameter_value_fd.value == Buffer(content=b'\x40\xe4\x4b\x92\x0a\x1c\x06\x2c\x1b\x66\xaf\x7e\x00\x00\x00\x00', length=128)