
from typing import List
from microschc.binary.buffer import Buffer, Padding

def test_shift():
    # left shift is larger than padding, prepend null bytes to buffer prior to shifting
    #                  10 bits left shift
    #                <|< < < < < < < <|< v            |
    # |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|  (|) byte delimiter
    #                +|+ + + + + + + +|- 0 1 0 1 1 0 1|  (-) existing padding 
    # |- - - - - - - 0|1 0 1 1 0 1 0 0|0 0 0 0 0 0 0 0|  (+) extra bits required
    buffer: Buffer = Buffer(content=bytes(b'\x2d'), length=7, padding=Padding.LEFT)
    shift_value = - 10

    shifted_buffer: Buffer = buffer.shift(shift=shift_value, inplace=False)
    assert len(shifted_buffer.content) == 3
    assert shifted_buffer.content  == bytes(b'\x00\xb4\00')
    assert shifted_buffer.length == 17
    # [----1000 00101101](12)
    buffer: Buffer = Buffer(content=bytes(b'\x08\x2d'), length=12, padding=Padding.LEFT)
    shift_value = -2

    shifted_buffer = buffer.shift(shift=shift_value, inplace=False)

    assert len(shifted_buffer.content) == 2
    # [--10 0000 1011 0100](14)
    assert shifted_buffer.content == bytes(b'\x20\xb4')

    #                                   left shift, right padding
    #                                       2 bits left shift
    #      |            < <|v              |               |               |
    #      |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|  (|) byte delimiter
    #                      |0 0 0 0 1 0 0 0|0 0 1 0 1 - - -|- - - - - - - -|  (-) existing padding  --> 1 + 4 + 256 = 261 
    #                      |0 0 0 0 1 0 0 0|0 0 1 0 1 0 0 -|- - - - - - - -|  (+) extra bits required
    
    # [0000 1000 0010 1---](13)
    buffer: Buffer = Buffer(content=bytes(b'\x08\x28\x00'), length=13, padding=Padding.RIGHT)
    shift_value: int = -2

    # [0000 1000 0010 100-](15)
    shifted_buffer = buffer.shift(shift=shift_value, inplace=False)
    assert len(shifted_buffer.content) == 2
    assert shifted_buffer.content == bytes(b'\x08\x28')
    assert shifted_buffer.length == 15

    # right shift, left padding
    #                  3 bits right shift
    #                 |               |        v > > >|
    #  7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|  (|) byte delimiter
    # |- - - - - - - -|- - - - 1 0 0 0|0 0 1 0 1 1 0 1|  (-) existing padding 
    # |- - - - - - - -|- - - - - - - 1|0 0 0 0 0 1 0 1|  (+) extra bits required
    buffer: Buffer = Buffer(content=bytes(b'\x00\x08\x2d'), length=12, padding=Padding.LEFT)
    shift_value = 3
    shifted_buffer = buffer.shift(shift=shift_value, inplace=False)
    assert len(shifted_buffer.content) == 2
    assert shifted_buffer.content == bytes(b'\x01\x05')
    assert shifted_buffer.length == 9

    # right shift, left padding
    #                  6 bits right shift
    #                 |               |  v > > > > > >|
    #  7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|  (|) byte delimiter
    # |- - - - - - - -|- - - - 1 0 0 0|0 0 1 0 1 1 0 1|  (-) existing padding 
    # |- - - - - - - -|- - - - - - - -|- - 1 0 0 0 0 0|  (+) extra bits required
    buffer: Buffer = Buffer(content=bytes(b'\x00\x08\x2d'), length=12, padding=Padding.LEFT)
    shift_value = 6
    shifted_buffer = buffer.shift(shift=shift_value, inplace=False)
    assert len(shifted_buffer.content) == 1
    assert shifted_buffer.content == bytes(b'\x20')
    assert shifted_buffer.length == 6

def test_repr():
    # 11 bits padding on the right
    # |0 0 0 0 1 0 0 0|0 0 1 0 1 - - -|- - - - - - - -|  (-) padding 
    buffer: Buffer = Buffer(content=bytes(b'\x08\x28\x00'), length=13, padding=Padding.RIGHT)
    repr: str = buffer.__repr__()

    assert repr == '[00001000 00101---](13)'

    # 11 bits padding on the left
    # |- - - - - - - -|- - - 0 1 0 0 0|0 0 1 0 1 0 0 0|  (-) padding 
    buffer: Buffer = Buffer(content=bytes(b'\x00\x08\x28'), length=13, padding=Padding.LEFT)
    repr: str = buffer.__repr__()

    assert repr == '[---01000 00101000](13)'

    # 3 bits padding on the right
    # |0 0 0 0 1 0 0 0|0 0 1 0 1 - - -|  (-)  padding 
    buffer: Buffer = Buffer(content=bytes(b'\x08\x28'), length=13, padding=Padding.RIGHT)
    repr: str = buffer.__repr__()

    assert repr == '[00001000 00101---](13)'

    # 3 bits padding on the left
    # |- - - 0 1 0 0 0|0 0 1 0 1 0 0 0|  (-) padding 
    buffer: Buffer = Buffer(content=bytes(b'\x08\x28'), length=13, padding=Padding.LEFT)
    repr: str = buffer.__repr__()

    assert repr == '[---01000 00101000](13)'

    # b'\x33\xff\x60' ('b'3\xff`') len: 24 padding: right
    # |0 0 1 1 0 0 1 1| 1 1 1 1 1 1 1 1| 0 1 1 0 0 0 0 0|
    buffer: Buffer = Buffer(content=bytes(b'\x33\xff\x60'), length=24, padding=Padding.RIGHT)
    repr: str = buffer.__repr__()

    assert repr == '[33ff60](24)'

def test_pad():
    # 11 bits padding on the right
    # |0 0 0 0 1 0 0 0|0 0 1 0 1 - - -|- - - - - - - -|  (-) padding 
    # |- - - - - - - -|- - - 0 0 0 0 1|0 0 0 0 0 1 0 1|  (-) padding 
    buffer: Buffer = Buffer(content=bytes(b'\x08\x28\x00'), length=13, padding=Padding.RIGHT)

    padded: Buffer = buffer.pad(padding=Padding.LEFT, inplace=False)
    expected: Buffer = Buffer(content=b'\x01\x05', length=buffer.length, padding=Padding.LEFT)
    
    assert padded == expected

    reverted: Buffer = padded.pad(padding=Padding.RIGHT, inplace=False)
    assert reverted == buffer


def test_get():
    # retrieve bits 1 to 10 
    # 
    #                          0x01            0x0d
    #                  |- - - 0 0 0 0 1|0 0 0 0 1 1 0 1|  (-) padding (3 bits padding on the left)
    #                  |0 0 0 0 1 0 0 0|0 1 1 0 1 - - -|  (-) padding (3 bits padding on the right)
    #                     + + + + + + + + +               (+) bits to output
    #                  |0 0 0 1 0 0 0 0|1 - - - - - -|  (-) padding (7 bits padding on the right)
    #   -->            |- - - - - - - 0|0 0 1 0 0 0 0 1|
    #                          0x00          0x21
    buffer: Buffer = Buffer(content=bytes(b'\x01\x0d'), length=13, padding=Padding.LEFT)
    expected: Buffer = Buffer(content=bytes(b'\x00\x21'), length=9, padding=Padding.LEFT)
    buffer_subset: Buffer = buffer[1:10]
    assert buffer_subset == expected
    assert buffer_subset.padding == Padding.LEFT

    # retrieve bits 1 to 14  --> retrieve 1 to 13
    #
    #         0x01            0x0d
    # | - - - 0 0 0 0 1|0 0 0 0 1 1 0 1|  (-) padding (11 bits padding on the left)
    #           + + + + + + + + + + + +   (+) bits to output
    # | - - - - 0 0 0 1|0 0 0 0 1 1 0 1|
    #                          0x01           0x0d
    
    buffer_subset: Buffer = buffer[1:13]
    expected: Buffer = Buffer(content=b'\x01\x0d', length=12, padding=Padding.LEFT)
    assert buffer_subset == expected
    assert buffer_subset.padding == Padding.LEFT

    # retrieve bits 0 to 13 
    #  
    #          0x01            0x0d
    #  | - - - 0 0 0 0 1|0 0 0 0 1 1 0 1|  (-) padding (11 bits padding on the left)
    #          + + + + + + + + + + + + +   (+) bits to output
    #  | - - - 0 0 0 0 1|0 0 0 0 1 1 0 1|
    #                          0x01          0x41
    buffer: Buffer = Buffer(content=bytes(b'\x01\x0d'), length=13, padding=Padding.LEFT)
    expected: Buffer = Buffer(content=bytes(b'\x01\x0d'), length=13, padding=Padding.LEFT)
    buffer_subset: Buffer = buffer[0:13]
    assert buffer_subset == expected
    assert buffer_subset.padding == Padding.LEFT

    # retrieve last 4 bits (9 to 13)
    # 
    #         0x01            0x0d
    # | - - - 0 0 0 0 1|0 0 0 0 1 1 0 1|  (-) padding (11 bits padding on the left)
    #                           + + + +   (+) bits to output
    #                  |- - - - 1 1 0 1|
    #                                          0x01
    buffer: Buffer = Buffer(content=bytes(b'\x01\x0d'), length=13, padding=Padding.LEFT)
    expected: Buffer = Buffer(content=bytes(b'\x0d'), length=4, padding=Padding.LEFT)
    buffer_subset: Buffer = buffer[-4:]
    assert buffer_subset == expected
    assert buffer_subset.padding == Padding.LEFT


    # retrieve bits 1 to 10 
    # 
    #              0x08          0x68        
    #       |0 0 0 0 1 0 0 0|0 1 1 0 1 - - -| (-) padding (11 bits padding on the right)
    #          + + + + + + + + +              (+) bits to output
    #  -->  |0 0 0 1 0 0 0 0|1 - - - - - - -|
    #              0x10           0x80
    buffer: Buffer = Buffer(content=bytes(b'\x08\x68'), length=13, padding=Padding.RIGHT)
    expected: Buffer = Buffer(content=bytes(b'\x10\x80'), length=9, padding=Padding.RIGHT)
    buffer_subset: Buffer = buffer[1:10]
    assert buffer_subset == expected
    assert buffer_subset.padding == Padding.RIGHT

    # retrieve bits 0 to 13 
    # 
    #              0x08          0x68              0x00
    #       |0 0 0 0 1 0 0 0|0 1 1 0 1 - - -|- - - - - - - -|  (-) padding (11 bits padding on the right)
    #          + + + + + + + + + + + +                         (+) bits to output
    #  -->  |0 0 0 1 0 0 0 0|0 1 1 0 1 - - -|
    #              0x08          0x68
    buffer: Buffer = Buffer(content=bytes(b'\x08\x68'), length=13, padding=Padding.RIGHT)
    expected: Buffer = Buffer(content=bytes(b'\x08\x68'), length=13, padding=Padding.RIGHT)
    buffer_subset: Buffer = buffer[0:13]
    assert buffer_subset == expected
    assert buffer_subset.padding == Padding.RIGHT


    # retrieve last 4 bits (9 to 13)
    # 
    #              0x08          0x68              0x00
    #       |0 0 0 0 1 0 0 0|0 1 1 0 1 - - -|- - - - - - - -|  (-) padding (11 bits padding on the right)
    #                          + + + +                         (+) bits to output
    #  -->  |1 1 0 1 - - - -|
    #              0xd0      
    buffer: Buffer = Buffer(content=bytes(b'\x01\x68'), length=13, padding=Padding.RIGHT)
    expected: Buffer = Buffer(content=bytes(b'\xd0'), length=4, padding=Padding.RIGHT)
    buffer_subset: Buffer = buffer[-4:]
    assert buffer_subset == expected
    assert buffer_subset.padding == Padding.RIGHT
    
    buffer: Buffer = Buffer(content=bytes(b'\xc0'), length=8, padding=Padding.LEFT)
    expected: Buffer = Buffer(content=bytes(b'\x03'), length=2, padding=Padding.LEFT)
    buffer_subset: Buffer = buffer[0:2]
    assert buffer_subset == expected
    
    buffer: Buffer = Buffer(content=bytes(b'\x68'), length=8, padding=Padding.LEFT)
    buffer_02: Buffer = buffer[0:2]
    buffer_24: Buffer = buffer[2:4]
    
    assert buffer_02 == Buffer(content=bytes(b'\x01'), length=2, padding=Padding.LEFT)
    assert buffer_24 == Buffer(content=bytes(b'\x02'), length=2, padding=Padding.LEFT)
    
    

def test_set():
    buffer: Buffer = Buffer(content=bytes(b'\xf0\x01\x0d'), length=24, padding=Padding.LEFT)
    expected: Buffer = Buffer(content=bytes(b'\xff\x01\x0d'), length=24, padding=Padding.LEFT)
    buffer[4:8] = Buffer(content=b'\x0f', length=4, padding=Padding.LEFT)

    assert buffer == expected
    assert buffer.padding == Padding.LEFT
    assert buffer.length == 24

    buffer: Buffer = Buffer(content=bytes(b'\x00\x01\x0d'), length=24, padding=Padding.LEFT)
    expected: Buffer = Buffer(content=bytes(b'\x00\x01\x00\xff'), length=32, padding=Padding.LEFT)
    
    buffer[16:32] = Buffer(content=bytes(b'\x00\xff'),length=16, padding=Padding.LEFT)
    assert buffer == expected
    assert buffer.padding == Padding.LEFT
    assert buffer.length == 32



def test_add():
    left: Buffer = Buffer(content=b'\x40', length=2, padding=Padding.RIGHT)
    right: Buffer = Buffer(content=b'\x80', length=2, padding=Padding.RIGHT)
    left_right = left + right
    expected: Buffer = Buffer(content=b'\x60', length=4, padding=Padding.RIGHT)
    assert left_right == expected

    left: Buffer = Buffer(content=b'\x40', length=2, padding=Padding.RIGHT)
    right: Buffer = Buffer(content=b'\x80', length=8, padding=Padding.RIGHT)
    left_right = left + right
    expected: Buffer = Buffer(content=b'\x60\x00', length=10, padding=Padding.RIGHT)
    assert left_right == expected

    left: Buffer = Buffer(content=b'\x60', length=4, padding=Padding.RIGHT)
    right: Buffer = Buffer(content=b'\x80', length=4, padding=Padding.RIGHT)
    left_right = left + right
    expected: Buffer = Buffer(content=b'\x68', length=8, padding=Padding.RIGHT)
    assert left_right == expected

    left: Buffer = Buffer(content=b'\x0f', length=4, padding=Padding.LEFT)
    right: Buffer = Buffer(content=b'\x0f', length=4, padding=Padding.LEFT)
    left_right = left + right
    expected: Buffer = Buffer(content=b'\xff', length=8, padding=Padding.LEFT)
    assert left_right == expected

    left: Buffer = Buffer(content=b'\xf0', length=4, padding=Padding.RIGHT)
    right: Buffer = Buffer(content=b'\x0f', length=4, padding=Padding.LEFT)
    left_right = left + right
    expected: Buffer = Buffer(content=b'\xff', length=8, padding=Padding.RIGHT)
    assert left_right == expected

    left: Buffer = Buffer(content=b'\x0f', length=4, padding=Padding.LEFT)
    right: Buffer = Buffer(content=b'\xf0', length=4, padding=Padding.RIGHT)
    left_right = left + right
    expected: Buffer = Buffer(content=b'\xff', length=8, padding=Padding.LEFT)
    assert left_right == expected
    
    left:Buffer = Buffer(content=b'\xc0', length=2, padding=Padding.RIGHT)
    right: Buffer = Buffer(content=b'\x01', length=8, padding=Padding.LEFT)
    left_right: Buffer = left + right 
    
    expected: Buffer = Buffer(content=b'\xc0\x40', length=10, padding=Padding.RIGHT)
    assert left_right == expected
    
    left:Buffer = Buffer(content=b'', length=0, padding=Padding.LEFT)
    right: Buffer = Buffer(content=b'\x06', length=4, padding=Padding.LEFT)
    left_right: Buffer = left + right 
    
    expected: Buffer = Buffer(content=b'\x06', length=4, padding=Padding.LEFT)
    assert left_right == expected
    
    left:Buffer = Buffer(content=b'\xe0', length=7, padding=Padding.RIGHT)
    right: Buffer = Buffer(content=b'\x05', length=4, padding=Padding.LEFT)
    left_right: Buffer = left + right
    
    expected: Buffer = Buffer(content=b'\xe0\xa0', length=11, padding=Padding.RIGHT)
    assert left_right == expected
    
    left:Buffer = Buffer(content=b'\xff\xfe', length=15, padding=Padding.RIGHT)
    right: Buffer = Buffer(content=b'\x3f\xff', length=14, padding=Padding.LEFT)
    left_right: Buffer = left + right
    
    expected: Buffer = Buffer(content=b'\xff\xff\xff\xf8', length=29, padding=Padding.RIGHT)
    assert left_right == expected
    

def test_or():
    #              0x08          0x68        
    #       |0 0 0 0 1 0 0 0|0 1 1 0 1 - - -|  (-) padding (3 bits padding on the right)
    buffer_1: Buffer = Buffer(content=bytes(b'\x08\x68'), length=13, padding=Padding.RIGHT)
    buffer_1_or_1: Buffer = buffer_1 | buffer_1
    expected_1_or_1: Buffer = Buffer(content=b'\x08\x68', length=13, padding=Padding.RIGHT)
    assert buffer_1_or_1 == expected_1_or_1

    #              0x04          0x78        
    #       |0 0 0 0 0 1 0 0|0 1 1 1 1 - - -|  (-) padding (3 bits padding on the right)
    buffer_2: Buffer = Buffer(content=bytes(b'\x04\x78'), length=13, padding=Padding.RIGHT)
    buffer_1_or_2: Buffer = buffer_1 | buffer_2

    #              0x0c          0x78        
    #       |0 0 0 0 1 1 0 0|0 1 1 1 1 - - -|  (-) padding (3 bits padding on the right)
    expected_1_or_2: Buffer = Buffer(content=b'\x0c\x78', length=13, padding=Padding.RIGHT)
    assert buffer_1_or_2 == expected_1_or_2

    #              0xf0          0x0f        
    #       |1 1 1 1 0 0 0 0|1 1 1 1 0 0 0 0|  (-) padding (0 bits padding on the right)
    buffer_3: Buffer = Buffer(content=bytes(b'\xf0\xf0'), length=16, padding=Padding.RIGHT)
    #              0x0f          0xf0        
    #       |0 0 0 0 1 1 1 1|1 1 1 1 0 0 0 0|  (-) padding (0 bits padding on the right)
    buffer_4: Buffer = Buffer(content=bytes(b'\x0f\x0f'), length=16, padding=Padding.RIGHT)
    buffer_3_or_4: Buffer = buffer_3 | buffer_4
    buffer_3_or_4_expected: Buffer = Buffer(content=bytes(b'\xff\xff'), length=16, padding=Padding.RIGHT)

    assert buffer_3_or_4 == buffer_3_or_4_expected


def test_and():
    #              0x08          0x68        
    #       |0 0 0 0 1 0 0 0|0 1 1 0 1 - - -|  (-) padding (3 bits padding on the right)
    buffer_1: Buffer = Buffer(content=bytes(b'\x08\x68'), length=13, padding=Padding.RIGHT)
    buffer_1_and_1: Buffer = buffer_1 & buffer_1
    expected_1_and_1: Buffer = Buffer(content=b'\x08\x68', length=13, padding=Padding.RIGHT)
    assert buffer_1_and_1 == expected_1_and_1

    #              0x03          0x78        
    #       |0 0 0 0 0 1 0 0|0 1 1 1 1 - - -|  (-) padding (3 bits padding on the right)
    buffer_2: Buffer = Buffer(content=bytes(b'\x03\x78'), length=13, padding=Padding.RIGHT)
    buffer_1_and_2: Buffer = buffer_1 & buffer_2
    expected_1_and_2: Buffer = Buffer(content=b'\x00\x68', length=13, padding=Padding.RIGHT)
    assert buffer_1_and_2 == expected_1_and_2

    #              0x08          0x68        
    #       |0 0 0 0 1 0 0 0|0 1 1 0 1 - - -|  (-) padding (3 bits padding on the right)
    buffer_1: Buffer = Buffer(content=bytes(b'\x08\x68'), length=13, padding=Padding.RIGHT)

    #              0x01          0x0D        
    #       |- - - 0 0 0 0 1|0 0 0 0 1 1 0 1|  (-) padding (3 bits padding on the left)
    buffer_1_pad_left: Buffer = Buffer(content=bytes(b'\x01\x0d'), length=13, padding=Padding.LEFT)

    buffer_1_and_1_left: Buffer = buffer_1 & buffer_1_pad_left
    expected_1_and_1_left: Buffer = Buffer(content=b'\x08\x68', length=13, padding=Padding.RIGHT)
    assert buffer_1_and_1_left == expected_1_and_1_left


def test_value():

    buffer: Buffer = Buffer(content=b'\x00\x01', length=16)
    value: int = buffer.value()
    assert value == 1

    buffer: Buffer = Buffer(content=b'\x00\x11', length=16)
    value: int = buffer.value()
    assert value == 17

    #              0x01          0x0D        
    #       |- - - 0 0 0 0 1|0 0 0 0 1 1 0 1|  (-) padding (3 bits padding on the left)
    buffer: Buffer = Buffer(content=b'\x01\x0d', length=13, padding=Padding.LEFT)
    value: int = buffer.value()
    assert value == 1 + 4 + 8 + 256 

    #              0x08          0x68        
    #       |0 0 0 0 1 0 0 0| 0 1 1 0 1 - - -|  (-) padding (3 bits padding on the right)
    buffer: Buffer = Buffer(content=b'\x08\x68', length=13, padding=Padding.RIGHT)
    value: int = buffer.value()
    assert value == 1 + 4 + 8 + 256 

    buffer: Buffer = Buffer(content=b'Hello, World! \xe9', length=120)
    value: str = buffer.value('str', encoding='iso-8859-1')
    assert value == 'Hello, World! é'
    
    buffer: Buffer = Buffer(content=b'\x80', length=1, padding=Padding.LEFT)
    assert buffer.value(type='unsigned int') == 0

def test_iter():
    #              0x08          0x68              0x00
    #       |0 0 0 0 1 0 0 0|0 1 1 0 1 - - -|- - - - - - - -|  (-) padding (11 bits padding on the right)
    buffer: Buffer = Buffer(content=bytes(b'\x08\x68'), length=13, padding=Padding.RIGHT)

    bits = list(buffer)
    assert bits == [0, 0, 0, 0, 1, 0 , 0, 0, 0, 1, 1, 0, 1]

    #         0x01            0x0d
    # | - - - 0 0 0 0 1|0 0 0 0 1 1 0 1|  (-) padding (3 bits padding on the left)
    buffer = Buffer(content=bytes(b'\x01\x0d'), length=13, padding=Padding.LEFT)
    bits = list(buffer)
    assert bits == [0, 0, 0, 0, 1, 0 , 0, 0, 0, 1, 1, 0, 1]

def test_chunks():
    #              0x1B          0xE8        
    #       |0 0 0 1 1 0 1 1|1 1 1 0 1 - - -| (-) padding (3 bits padding on the right)
    buffer: Buffer = Buffer(content=bytes(b'\x1b\xe8'), length=13, padding=Padding.RIGHT)
    chunks: List[Buffer] = [c for c in buffer.chunks(2)]
    assert chunks[0] == Buffer(content=b'\x00', length=2, padding=Padding.RIGHT)
    assert chunks[1] == Buffer(content=b'\x40', length=2, padding=Padding.RIGHT)
    assert chunks[2] == Buffer(content=b'\x80', length=2, padding=Padding.RIGHT)
    assert chunks[3] == Buffer(content=b'\xC0', length=2, padding=Padding.RIGHT)
    assert chunks[4] == Buffer(content=b'\xC0', length=2, padding=Padding.RIGHT)
    assert chunks[5] == Buffer(content=b'\x80', length=2, padding=Padding.RIGHT)
    assert chunks[6] == Buffer(content=b'\x80', length=1, padding=Padding.RIGHT)

    chunks_padded: List[Buffer] = [c for c in buffer.chunks(2, padding=True)]
    assert chunks_padded[6] == Buffer(content=b'\x80', length=2, padding=Padding.RIGHT)

def test_json_str():
    """
    test JSON serialization of buffer objects
    """
    buffer: Buffer = Buffer(content=b"\xaa\xf0", length=12)
    json_str: str = buffer.json()
    assert json_str == '{"content": "0af0", "length": 12, "padding": "left"}'

def test_from_json():
    """
    test JSON serialized to object instance
    """
    json_str = '{"content": "0af0", "length": 12, "padding": "left"}'
    buffer: Buffer = Buffer.from_json(json_str=json_str)
    assert buffer.content == b"\x0a\xf0"
    assert buffer.length == 12
    assert buffer.padding == Padding.LEFT