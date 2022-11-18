
from microschc.binary.buffer import Buffer, Padding

def test_shift():
    # left shift is larger than padding, prepend null bytes to buffer prior to shifting
    #                  10 bits left shift
    #                <|< < < < < < < <|< v            |
    # |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|  (|) byte delimiter
    #                +|+ + + + + + + +|- 0 1 0 1 1 0 1|  (-) existing padding 
    # |- - - - - - - 0|1 0 1 1 0 1 0 0|0 0 0 0 0 0 0 0|  (+) extra bits required
    buffer: Buffer = Buffer(content=bytes(b'\x2d'), bit_length=7, padding_side=Padding.LEFT)
    shift_value = - 10

    shifted_buffer: Buffer = buffer.shift(shift=shift_value, inplace=False)
    assert len(shifted_buffer.content) == 3
    assert shifted_buffer.content  == bytes(b'\x00\xb4\00')
    assert shifted_buffer.bit_length == 17

    # left shift is smaller than padding
    #                  10 bits left shift
    #                 |    < < v      |               |
    #  7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|  (|) byte delimiter
    # |- - - - - - - -|- - - - 1 0 0 0|0 0 1 0 1 1 0 1|  (-) existing padding 
    # |- - - - - - - -|- - 1 0 0 0 0 0|1 0 1 1 0 1 0 0|  (+) extra bits required
    buffer: Buffer = Buffer(content=bytes(b'\x00\x08\x2d'), bit_length=12, padding_side=Padding.LEFT)
    shift_value = -2

    shifted_buffer = buffer.shift(shift=shift_value, inplace=False)

    assert len(shifted_buffer.content) == 3
    assert shifted_buffer.content == bytes(b'\x00\x20\xb4')

    #                                   left shift, right padding
    #                                       2 bits left shift
    #      |            < <|v              |               |               |
    #      |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|  (|) byte delimiter
    #                      |0 0 0 0 1 0 0 0|0 0 1 0 1 - - -|- - - - - - - -|  (-) existing padding 
    #                      |0 0 0 0 1 0 0 0|0 0 1 0 1 0 0 -|- - - - - - - -|  (+) extra bits required
    buffer: Buffer = Buffer(content=bytes(b'\x08\x28\x00'), bit_length=13, padding_side=Padding.RIGHT)
    shift_value: int = -2

    shifted_buffer = buffer.shift(shift=shift_value, inplace=False)
    assert len(shifted_buffer.content) == 3
    assert shifted_buffer.content == bytes(b'\x08\x28\x00')
    assert shifted_buffer.bit_length == 15

    # right shift, left padding
    #                  3 bits right shift
    #                 |               |        v > > >|
    #  7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|  (|) byte delimiter
    # |- - - - - - - -|- - - - 1 0 0 0|0 0 1 0 1 1 0 1|  (-) existing padding 
    # |- - - - - - - -|- - - - - - - 1|0 0 0 0 0 1 0 1|  (+) extra bits required
    buffer: Buffer = Buffer(content=bytes(b'\x00\x08\x2d'), bit_length=12, padding_side=Padding.LEFT)
    shift_value = 3
    shifted_buffer = buffer.shift(shift=shift_value, inplace=False)
    assert len(shifted_buffer.content) == 3
    assert shifted_buffer.content == bytes(b'\x00\x01\x05')
    assert shifted_buffer.bit_length == 9

    # right shift, left padding
    #                  6 bits right shift
    #                 |               |  v > > > > > >|
    #  7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|  (|) byte delimiter
    # |- - - - - - - -|- - - - 1 0 0 0|0 0 1 0 1 1 0 1|  (-) existing padding 
    # |- - - - - - - -|- - - - - - - -|- - 1 0 0 0 0 0|  (+) extra bits required
    buffer: Buffer = Buffer(content=bytes(b'\x00\x08\x2d'), bit_length=12, padding_side=Padding.LEFT)
    shift_value = 6
    shifted_buffer = buffer.shift(shift=shift_value, inplace=False)
    assert len(shifted_buffer.content) == 3
    assert shifted_buffer.content == bytes(b'\x00\x00\x20')
    assert shifted_buffer.bit_length == 6

def test_trim_padding():
    # right padding trimming
    #                      |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|  (|) byte delimiter
    #                      |0 0 0 0 1 0 0 0|0 0 1 0 1 - - -|- - - - - - - -|  (-) existing padding 
    #                      |0 0 0 0 1 0 0 0|0 0 1 0 1 - - -|                  (-) expected result
    buffer: Buffer = Buffer(content=bytes(b'\x08\x28\x00'), bit_length=13, padding_side=Padding.RIGHT)
    
    expected_buffer: Buffer = Buffer(content=bytes(b'\x08\x28'), bit_length=13, padding_side=Padding.RIGHT)

    assert buffer.trim_padding(inplace=False) == expected_buffer


def test_repr():
    # 11 bits padding on the right
    # |0 0 0 0 1 0 0 0|0 0 1 0 1 - - -|- - - - - - - -|  (-) padding 
    buffer: Buffer = Buffer(content=bytes(b'\x08\x28\x00'), bit_length=13, padding_side=Padding.RIGHT)
    repr: str = buffer.__repr__()

    assert repr == '[00001000 00101--- --------] | len: 13 | pad: 11 right'

    # 11 bits padding on the left
    # |- - - - - - - -|- - - 0 1 0 0 0|0 0 1 0 1 0 0 0|  (-) padding 
    buffer: Buffer = Buffer(content=bytes(b'\x00\x08\x28'), bit_length=13, padding_side=Padding.LEFT)
    repr: str = buffer.__repr__()

    assert repr == '[-------- ---01000 00101000] | len: 13 | pad: 11 left'

    # 3 bits padding on the right
    # |0 0 0 0 1 0 0 0|0 0 1 0 1 - - -|  (-)  padding 
    buffer: Buffer = Buffer(content=bytes(b'\x08\x28'), bit_length=13, padding_side=Padding.RIGHT)
    repr: str = buffer.__repr__()

    assert repr == '[00001000 00101---] | len: 13 | pad: 3 right'

    # 3 bits padding on the left
    # |- - - 0 1 0 0 0|0 0 1 0 1 0 0 0|  (-) padding 
    buffer: Buffer = Buffer(content=bytes(b'\x08\x28'), bit_length=13, padding_side=Padding.LEFT)
    repr: str = buffer.__repr__()

    assert repr == '[---01000 00101000] | len: 13 | pad: 3 left'

    # b'\x33\xff\x60' ('b'3\xff`') len: 24 padding: right
    # |0 0 1 1 0 0 1 1| 1 1 1 1 1 1 1 1| 0 1 1 0 0 0 0 0|
    buffer: Buffer = Buffer(content=bytes(b'\x33\xff\x60'), bit_length=24, padding_side=Padding.RIGHT)
    repr: str = buffer.__repr__()

    assert repr == '[00110011 11111111 01100000] | len: 24 | pad: 0 right'



