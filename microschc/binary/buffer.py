"""
Buffer data model

Data model for buffers of bits.

The Buffer class is the data model to manipulate bits sequences.
It provides equivalent primitives for usual binary operations extended
to bits sequences spanning over multiple bytes, e.g. shift, equality.
On top of those binary operations, the Buffer data model enables left-padded 
as well as right-padded bits sequences, provides concatenation and padding
adjustement out-of-the-box and allows indexing and slicing bit sequences 
using slicing notations.
"""

from enum import Enum

class Padding(str, Enum):
    LEFT = 'left'
    RIGHT = 'right'

class Buffer:
    def __init__(self, content: bytes, length:int, padding=Padding.LEFT) -> None:
        self.content:bytes = content
        self.length:int = length
        self.padding:Padding = padding
        self.padding_length:int = 8*len(self.content) - self.length
        
    def _update_padding(self):
        self.padding_length = 8*len(self.content) - self.length

    def shift(self, shift: int, inplace=True):
        '''
        shift buffer, eventually expanding it in the process.
        negative value means shifting to the left, positive value to the right
        '''

        shifted_buffer: Buffer = Buffer(content=b'', length=self.length, padding=self.padding)
        padding_length = self.padding_length

        temp_buffer_content = self.content

        if shift < 0:
            # left shift
            shift *= -1
            shifted_buffer.length += shift
            if self.padding == Padding.LEFT:
                if shift > self.padding_length:
                    # left shift is larger than padding, prepend null bytes to buffer prior to shifting
                    #                  10 bits left shift
                    #                <|< < < < < < < <|< v            |
                    #  7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|  (|) byte delimiter
                    #                +|+ + + + + + + +|- 0 1 0 1 1 0 1|  (-) existing padding 
                    # |- - - - - - - 0|1 0 1 1 0 1 0 0|0 0 0 0 0 0 0 0|  (+) extra bits required

                    extra_bits_required: int = shift - padding_length

                    extra_bytes_right: int = (shift // 8)
                    
                    temp_buffer_content  += bytes(extra_bytes_right)
                    if extra_bits_required > 8 *  extra_bytes_right:
                        temp_buffer_content = bytes(b'\x00') + temp_buffer_content

                    shift %= 8
                shift_complement: int = (- shift)%8
                
                # residual left shift is smaller than padding
                #                  10 bits left shift
                #                 |    < < v      |               |
                #  7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|  (|) byte delimiter
                # |- - - - - - - -|- - - - 1 0 0 0|0 0 1 0 1 1 0 1|  (-) existing padding 
                # |- - - - - - - -|- - 1 0 0 0 0 0|1 0 1 1 0 1 0 0|  (+) extra bits required

                # bit-level shift 
                for i in range(len(temp_buffer_content)-1):
                    shifted_buffer.content += (((temp_buffer_content[i] << shift) & 0xff) + (temp_buffer_content[i+1] >> shift_complement)).to_bytes(1, 'big')
                shifted_buffer.content += ((temp_buffer_content[-1] << shift) & 0xff).to_bytes(1, 'big')
            elif self.padding == Padding.RIGHT:
                if shift > padding_length:
                    extra_bytes_right: int = (shift-padding_length) // 8
                    temp_buffer_content  += bytes(extra_bytes_right)
                shifted_buffer.content = temp_buffer_content
        elif shift > 0:
            # right shift
            if shift < self.length:
                shifted_buffer.length -= shift
                if self.padding == Padding.LEFT:
                    bytes_to_remove: int = shift // 8
                    temp_buffer_content = temp_buffer_content[0:len(temp_buffer_content)-bytes_to_remove]
                    shift %= 8
                    if shift > 0:
                        shift_complement = (-shift)% 8
                        temp_buffer_content = bytes(b'\x00') + temp_buffer_content
                        for i in range(1, len(temp_buffer_content)):
                            shifted_buffer.content += (((temp_buffer_content[i-1]<<shift_complement) & 0xff) | (temp_buffer_content[i]>>shift)).to_bytes(1, 'big')
                    else:
                        shifted_buffer.content = temp_buffer_content
                elif self.padding == Padding.RIGHT:
                    shift_complement = (-shift)% 8
                    temp_buffer_content = bytes(b'\x00') + temp_buffer_content
                    for i in range(1, len(temp_buffer_content)):
                        shifted_buffer.content += (((temp_buffer_content[i-1]<<shift_complement) & 0xff) | (temp_buffer_content[i]>>shift)).to_bytes(1, 'big')
        else:
            shifted_buffer.content = temp_buffer_content
        if inplace == True:
            self.content = shifted_buffer.content
            self.length = shifted_buffer.length
            self._update_padding()
            return self
        else:
            shifted_buffer._update_padding()
            return shifted_buffer

    def trim(self, inplace=True):
        self_byte_length: int = self.length // 8
        self_offset: int = -self.length % 8

        if self.padding == Padding.LEFT:
            self_content = self.content[-self_byte_length:] if self_byte_length > 0 else b""
            if self_offset != 0:
                self_bit_mask: int = 0xff >> (self_offset%8)
                self_content = (self.content[-(self_byte_length+1)] & self_bit_mask).to_bytes(1, 'big') + self_content
        else:
            self_content = self.content[:self_byte_length]
            if self_offset != 0:
                self_bit_mask: int = (0xff << (self_offset%8) & 0xff)
                self_content += (self.content[self_byte_length] & self_bit_mask).to_bytes(1, 'big')

        if inplace == True:
            self.content = self_content
            self._update_padding()
            return self
        else:
            new_buffer: Buffer = Buffer(content=self_content, length=self.length, padding=self.padding)
            return new_buffer

    def pad(self, padding: Padding, inplace=True):

        if inplace == True and padding == self.padding:
            return self

        if inplace == False and padding == self.padding:
            return Buffer(content=self.content, length=self.length, padding=self.padding)

        self_copy: Buffer = self.copy()

        padding_length: int = self.padding_length
        if padding == Padding.RIGHT:
            # self padding is Padding.LEFT
            # we shift left
            shift_value = - padding_length
        else:
            # self padding is Padding.RIGHT
            # we shift right
            self_copy.length = 8*len(self.content)
            self_copy._update_padding()
            self_copy.padding = padding
            shift_value = + padding_length
        
        buffer: Buffer = self_copy.shift(shift=shift_value, inplace=True)
        buffer.length = self.length
        buffer.padding = padding
        buffer._update_padding()
        if inplace == True:
            self.content = buffer.content
            self.length = buffer.length
            self.padding = buffer.padding
        return buffer

    def copy(self):
        return Buffer(content=self.content, length=self.length, padding=self.padding)

    def __eq__(self, another: object) -> bool:
        '''
        returns True if `another` has the same first `bit_length` bits (excluding padding)
        '''
        if isinstance(another, Buffer) is False:
            return False
        assert isinstance(another, Buffer) # for linter
        if self.length != another.length:
            return False

        trimmed_self = self.trim(inplace=False)
        trimmed_another = another.trim(inplace=False)

        if self.padding != another.padding:
            trimmed_another.pad(padding=self.padding, inplace=True)
        
        return trimmed_self.content == trimmed_another.content

    def __hash__(self) -> int:
        trimmed_buffer: Buffer = self.trim(inplace=False)
        return trimmed_buffer.content.__hash__()

    def __add__(self, another):
        self_copy: Buffer = self.copy()
        another_copy: Buffer = another.copy()
        self_copy_offset = 0
        another_copy_offset = 0
        # remove excess padding
        if self_copy.padding == Padding.RIGHT:
            self_copy.trim(inplace=True)
            self_copy_offset = self_copy.length % 8
        if another_copy.padding == Padding.LEFT:
            another_copy.trim(inplace=True)
            another_copy_offset = (- another_copy.length)%8 

        if another_copy_offset != self_copy_offset:
            # need realignment of another_copy
            shift:int = self_copy_offset - another_copy_offset
            if shift > 0:
                if another_copy.padding == Padding.LEFT:
                    another_copy.content += b'\x00'
                    another_copy.length += 8
                elif another_copy.padding == Padding.RIGHT:
                    if shift <= another_copy.padding_length:
                        another_copy.length += shift
                    else:
                        another_copy.length += shift
                        another_copy.content += b'\x00'

            elif shift < 0:
                if another_copy.padding == Padding.RIGHT or shift < - another_copy.padding_length:
                    another_copy.content = b'\x00' + another_copy.content
                    another_copy.length += 8
            another_copy.shift(shift=shift, inplace=True)
        
        if self_copy_offset == 0:
            self_copy.content += another_copy.content
        else:
            self_copy.content = self_copy.content[0:-1] + (self_copy.content[-1] + another_copy.content[0]).to_bytes(1, 'big') + another_copy.content[1:]
        self_copy.length += another.length
        self_copy._update_padding()
        return self_copy

    def __getitem__(self, items):
        
        assert isinstance(items, (slice, int))

        if isinstance(items, slice):
            start_bit, stop_bit, _ = items.indices(self.length)

        else:
            start_bit = items
            stop_bit = start_bit + 1
       
        
        subset_bit_length: int = stop_bit - start_bit

        if self.padding == Padding.LEFT:
            # retrieve bits 1 to 10 
            # 
            #       0x00              0x01            0x0d
            # |- - - - - - - -| - - - 0 0 0 0 1|0 0 0 0 1 1 0 1|  (-) padding (11 bits padding on the left)
            #                           + + + + + + + + +         (+) bits to output
            #   -->            |- - - - - - 0 0|0 0 1 0 0 0 0 1|
            #                          0x00          0x41


            # |- - - - - - - -|- - - 0 0 0 0 1|0 0 0 0 1 1 0 1|  
            #                          ^               ^ 
            #                      start_bit        stop_bit
            #                 ^---------------^---------------^
            #                    start_byte       stop_byte
            start_bit += self.padding_length
            stop_bit += self.padding_length
            start_byte = start_bit//8
            stop_byte = stop_bit//8 if stop_bit%8 == 0 else 1 + stop_bit//8
            
            # |- - - 0 0 0 0 1|0 0 0 0 0 1 0 1|      subset_content
            #          + + + + + + + + +         (+) bits to output
            content_of_interest = self.content[start_byte:stop_byte]
            subset_content = b''

            # remove rightmost unneeded bits by right-shifting
            # |- - - 0 0 0 0 1|0 0 0 0 1 1 0 1|      subset_content
            #          + + + + + + + + +         (+) bits to output
            # |- - - - - - 0 0|0 0 1 0 0 0 0 1|x x x|
            #                ^               ^
            #            start_bit          stop_bit
            # ^---------------^---------------^
            #    start_byte       stop_byte
            shift: int = stop_byte * 8 - stop_bit
            if shift > 0:
                content_of_interest = b'\x00' + content_of_interest
                shift_c: int = (-shift)%8
                bitmask: int = 0xff >> (-shift)%8
                for i in range(len(content_of_interest)-1, 0, -1):
                    byte_i = content_of_interest[i]
                    byte_i_1 = content_of_interest[i-1]
                    subset_content = (((byte_i_1 & bitmask) << shift_c) | (byte_i >> shift)).to_bytes(1, 'big') + subset_content
            else:
                subset_content = content_of_interest
            
            # remove leftmost unneeded bits using padding
            # |- - - - - - - 0|0 1 0 0 0 0 0 1|
            #                ^               ^
            #            start_bit       stop_bit
            # ^---------------^---------------^
            #    start_byte       stop_byte
            subset: Buffer = Buffer(content=subset_content, length=subset_bit_length, padding=self.padding)

            return subset
        
        else:
            # retrieve bits 1 to 10 
            # 
            #              0x08          0x68              0x00
            #       |0 0 0 0 1 0 0 0|0 1 1 0 1 - - -|- - - - - - - -|  (-) padding (11 bits padding on the right)
            #          + + + + + + + + +                               (+) bits to output
            #  -->  |0 0 0 1 0 0 0 0|1 - - - - - - -|
            #              0x10           0x80
            
            #              0x08          0x68              0x00
            #       |0 0 0 0 1 0 0 0|0 1 1 0 1 - - -|- - - - - - - -|  (-) padding (11 bits padding on the right)
            #          + + + + + + + + +                               (+) bits to output
            #          ^               ^ 
            #      start_bit        stop_bit
            #       ^---------------^---------------^
            #                    start_byte       stop_byte
            start_byte = start_bit//8
            stop_byte = stop_bit//8 if stop_bit%8 == 0 else 1 + stop_bit//8

            #         0x08          0x68        
            #  |0 0 0 0 1 0 0 0|0 1 1 0 1 - - -|    content of interest
            #     + + + + + + + + +             
            #     ^               ^ 
            # start_bit        stop_bit
            #  ^---------------^---------------^
            content_of_interest = self.content[start_byte:stop_byte]

            # remove leftmost unneeded bits by shifting left
            #         0x08          0x68        
            #  |0 0 0 0 1 0 0 0|0 1 1 0 1 - - -|    content of interest
            #     + + + + + + + + +             
            #     ^               ^ 
            # x|0 0 0 1 0 0 0 0|1 1 0 1 - - - -|    content of interest
            subset_content = b''

            shift = (start_bit)%8
            shift_c: int = (-shift)%8
            if shift > 0:
                shift_c: int = (-shift)%8
                content_of_interest +=  b'\x00'
                for i in range(0, len(content_of_interest)-1):
                    byte_i = content_of_interest[i]
                    byte_i_p_1 = content_of_interest[i+1]
                    subset_content += (((byte_i << shift)& 0xff) | (byte_i_p_1 >> shift_c)).to_bytes(1, 'big')
            else:
                subset_content = content_of_interest
            # and rightmost unneeded bits by padding
            subset: Buffer = Buffer(content=subset_content, length=subset_bit_length, padding=self.padding)
            subset.trim(inplace=True)
            return subset

    def __iter__(self):
        padding_offset: int = self.padding_length if self.padding == Padding.LEFT else 0
        for i in range(self.length):

            byte_index = (i+padding_offset)//8
            bit_offset = (i+padding_offset)%8

            byte = self.content[byte_index]
            bit = (byte & 2**(8-bit_offset-1)) >> (8-bit_offset-1)
            yield bit

    def __len__(self):
        return self.length

    def __repr__(self) -> str:
        content_repr:str = ""
        padding_length: int = self.padding_length
        index:int = 0
        
        if self.padding == Padding.LEFT and padding_length > 0:
            padding_str: str = ""
            if padding_length // 8 > 0:
                index += padding_length//8
                padding_str += "-------- " * (padding_length//8)
                padding_length %= 8
            padding_str += "-" * padding_length
            format = f"0{8-padding_length}b"
            content_repr += f"{padding_str}{self.content[index]:{format}} "
            index += 1
        if self.length < 65:
            content_repr += " ".join([f"{b:08b}" for b in self.content[index:index + (self.length//8)]])
            
        else:
            content_repr += " ".join([f"{b:08b}" for b in self.content[index:index + 4]])
            content_repr += " ... "
            content_repr += " ".join([f"{b:08b}" for b in self.content[(self.length//8) -4:self.length//8]])
        
        index += (self.length//8)
        if self.padding == Padding.RIGHT and padding_length > 0:
            padding_str: str = " "
            if padding_length // 8 > 0:
                padding_str += "-------- " * (padding_length//8)
                padding_length %= 8
            padding_str = "-" * padding_length + padding_str[:-1]
            format = f"0{8-padding_length}b"
            last_byte = self.content[index] >> padding_length
            content_repr += f" {last_byte:{format}}{padding_str}"

        return f"[{content_repr}] | len: {self.length} | pad: {self.padding_length} {self.padding}"
