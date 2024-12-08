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

def test_sctp_parser_parse():
    """test: SCTP header parser parses SCTP Header

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