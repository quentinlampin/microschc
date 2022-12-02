from math import ceil
from microschc.actions.compression import not_sent, value_sent, mapping_sent, least_significant_bits
from microschc.binary.buffer import Buffer
from microschc.rfc8724 import FieldDescriptor, Mapping, MatchMapping


SOME_ID = 'ID'

def test_not_sent():
    """test: `not-sent` compression action
    Test that residue is of size 0 and empty
    """

    field_descriptor: FieldDescriptor = FieldDescriptor(id=SOME_ID, value=Buffer(content=b'\xff', length=8), position=0)
    
    field_residue: Buffer = not_sent(field_descriptor)

    assert field_residue.length == 0
    assert field_residue.content == b''

def test_value_sent():
    """test: `value-sent` compression action
    Test that residue is identical the the field descriptor value
    """

    # test on bytes value
    bytes_value = b'\x13\xff'
    bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, position=0, value=Buffer(content=bytes_value, length=16))
    field_residue: Buffer = value_sent(field_descriptor=bytes_field)
    assert field_residue.content == bytes_value
    assert field_residue.length == bytes_field.value.length

def test_mapping_sent():
    """test: `mapping-sent` compression action
    Test that residue is equal to the value stored in the forward mapping at the key of the field value
    """
    
    # test on bytes value
    bytes_value = Buffer(content=b'\x13\xff', length=16)
    bytes_forward_mapping: Mapping = {
        Buffer(content=b'\xff', length=8): Buffer(content=b'\x01', length=3), 
        Buffer(content=b'\x13\xff', length=16): Buffer(content=b'\x02', length=3)
    }

    bytes_match_mapping : MatchMapping = MatchMapping(forward_mapping=bytes_forward_mapping)
    bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, position=0, value=bytes_value)
    field_residue: Buffer = mapping_sent(field_descriptor=bytes_field, mapping=bytes_match_mapping)
    assert field_residue.content == b'\x02'
    assert field_residue.length == 3

def test_least_significant_bits():
    """test: `LSB` compression action
    Test that residue is equal to bits not included in the pattern matched by the `MSB(x)` Matching Operator.

    Suppose the following field value: b'\x33\xff\x23\xdb\xda' of length 38 bits, pattern: b'\x01\x9f\xf9' of length 17 bits
                                    field value
        |---------------------------------------------------------------------------|
          0x33             0xff            0x23           0xdb           0xda
     0 0 1 1 0 0 1 1 1 1 1 1 1 1 1 1 0 0 1 0 0 0 1 1 1 1 0 1 1 0 1 1 1 1 0 1 1 0 1 0
    |     byte0     |   byte1       |     byte2     |     byte3     |    byte4      |
        |--------------pattern------------|-----------------residue-----------------|
  | [...] |     byte1     |     byte2     |
     0x01       0x9f            0xf9

    The expected residue is:  
                            0x3              0xdb           0xda
                       0 0 0 0 0 0 1 1 1 1 0 1 1 0 1 1 1 1 0 1 1 0 1 0
                      |     byte2     |     byte3     |    byte4      |
                      |  0s |                                         | 
    
    """

    pattern: Buffer = Buffer(content=b'\x01\x9f\xf9', length=17)

    field_value: Buffer = Buffer(content=b'\x33\xff\x23\xdb\xda', length=38)

    expected_residue: Buffer = Buffer(content=b'\x03\xdb\xda', length=field_value.length - pattern.length)

    bytes_field: FieldDescriptor = FieldDescriptor(id=SOME_ID, position=0, value=field_value)

    field_residue: Buffer = least_significant_bits(field_descriptor=bytes_field, bit_length=field_value.length - pattern.length)
    assert field_residue.length == expected_residue.length
    assert field_residue.content == expected_residue.content
