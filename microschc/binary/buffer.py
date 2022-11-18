from dataclasses import dataclass
from enum import Enum

from attr import field

class Padding(str, Enum):
    LEFT = 'left'
    RIGHT = 'right'

@dataclass
class Buffer:
    content: bytes
    bit_length: int
    padding: int = field(init=False)
    padding_side: Padding = Padding.LEFT

    def _update_padding(self):
        self.padding = 8*len(self.content) - self.bit_length

    def __post_init__(self):
        self._update_padding()

    def shift(self, shift: int, inplace=True):
        '''
        shift buffer, eventually expanding it in the process.
        negative value means shifting to the left, positive value to the right
        '''

        shifted_buffer: Buffer = Buffer(content=b'', bit_length=self.bit_length, padding_side=self.padding_side)
        padding_length = self.padding

        temp_buffer_content = self.content

        if shift < 0:
            # left shift
            shift *= -1
            shifted_buffer.bit_length += shift
            if self.padding_side == Padding.LEFT:
                if shift > padding_length:
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
            elif self.padding_side == Padding.RIGHT:

                # residual left shift is smaller than padding
                #                  10 bits left shift
                #                <|< < v          |               |
                #  7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|  (|) byte delimiter
                # |1 0 0 0 0 0 1 0|1 1 0 1 - - - -|                  (-) existing padding 
                # |1 0 0 0 0 0 1 0|1 1 0 1 0 0 0 -|                  (+) extra bits required

                if shift > padding_length:
                    extra_bytes_right: int = (shift-padding_length) // 8
                    temp_buffer_content  += bytes(extra_bytes_right)
                shifted_buffer.content = temp_buffer_content
        elif shift > 0:
            # right shift
            if shift < self.bit_length:
                shifted_buffer.bit_length -= shift
                if self.padding_side == Padding.LEFT:
                    # left shift is larger than padding, prepend null bytes to buffer prior to shifting
                    #                  10 bits left shift
                    #                 |          v > >| 
                    #                 |7 6 5 4 3 2 1 0|  (|) byte delimiter
                    # |- - - - 1 1 1 0|1 0 1 0 1 1 0 1|  (-) existing padding 
                    # |- - - - - - 1 1|1 0 1 0 1 0 1 1|  (+) extra bits required
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
        if inplace == True:
            self.content = shifted_buffer.content
            self.bit_length = shifted_buffer.bit_length
            self._update_padding()
            return self
        else:
            shifted_buffer._update_padding()
            return shifted_buffer

    def trim_padding(self, inplace=True):
        self_byte_length: int = self.bit_length // 8
        self_offset: int = -self.bit_length % 8

        if self.padding_side == Padding.LEFT:
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
            new_buffer: Buffer = Buffer(content=self_content, bit_length=self.bit_length, padding_side=self.padding_side)
            return new_buffer

    def pad(self, padding: Padding, inplace=True):

        if inplace == True and padding == self.padding_side:
            return self

        if inplace == False and padding == self.padding_side:
            return Buffer(content=self.content, bit_length=self.bit_length, padding_side=self.padding_side)

        padding_length: int = self.padding
        if padding == Padding.RIGHT:
            # self padding is Padding.LEFT
            # we shift left
            shift_value = - padding_length
        else:
            # self padding is Padding.RIGHT
            # we shift right
            shift_value = + padding_length

        buffer: Buffer = self.shift(shift=shift_value, inplace=inplace)
        buffer.padding_side = padding
        return buffer

    def copy(self):
        return Buffer(content=self.content, bit_length= self.bit_length, padding_side=self.padding_side)

    def __eq__(self, another: object) -> bool:
        '''
        returns True if `another` has the same first `bit_length` bits (excluding padding)
        '''
        if isinstance(another, Buffer) is False:
            return False
        assert isinstance(another, Buffer) # for linter
        if self.bit_length != another.bit_length:
            return False

        trimmed_self = self.trim_padding(inplace=False)
        trimmed_another = another.trim_padding(inplace=False)

        if self.padding_side != another.padding_side:
            trimmed_another.pad(padding=self.padding_side, inplace=True)
        
        return trimmed_self.content == trimmed_another.content

    def __hash__(self) -> int:
        trimmed_buffer: Buffer = self.trim_padding(inplace=False)
        return trimmed_buffer.content.__hash__()

    def __add__(self, another):
        self_copy: Buffer = self.copy()
        another_copy: Buffer = another.copy()
        self_copy_offset = 0
        another_copy_offset = 0
        # remove excess padding
        if self_copy.padding_side == Padding.RIGHT:
            self_copy.trim_padding(inplace=True)
            self_copy_offset = self_copy.bit_length % 8
        if another_copy.padding_side == Padding.LEFT:
            another_copy.trim_padding(inplace=True)
            another_copy_offset = (- another_copy.bit_length)%8 

        if another_copy_offset != self_copy_offset:
            # need realignment of another_copy
            shift:int = self_copy_offset - another_copy_offset
            if shift > 0 and another_copy.padding_side == Padding.LEFT:
                another_copy.content += b'\x00'
                another_copy.bit_length += 8
            elif shift < 0 and another_copy.padding_side == Padding.RIGHT:
                another_copy.content = b'\x00' + another_copy.content
            another_copy.shift(shift=shift, inplace=True)
        
        if self_copy_offset == 0:
            self_copy.content += another_copy.content
        else:
            #TODO merge last self_copy byte with first another_copy
            self_copy.content = self_copy.content[0:-1] + (self_copy.content[-1] + another_copy.content[0]).to_bytes(1, 'big') + another_copy.content[1:]
        self_copy.bit_length += another.bit_length
        self_copy._update_padding()
        return self_copy

    def __repr__(self) -> str:
        content_repr:str = ""
        padding_length: int = self.padding
        index:int = 0
        
        if self.padding_side == Padding.LEFT and padding_length > 0:
            padding_str: str = ""
            if padding_length // 8 > 0:
                index += padding_length//8
                padding_str += "-------- " * (padding_length//8)
                padding_length %= 8
            padding_str += "-" * padding_length
            format = f"0{8-padding_length}b"
            content_repr += f"{padding_str}{self.content[index]:{format}} "
            index += 1
        
        content_repr += " ".join([f"{b:08b}" for b in self.content[index:index + (self.bit_length//8)]])
        index += (self.bit_length//8)

        if self.padding_side == Padding.RIGHT and padding_length > 0:
            padding_str: str = " "
            if padding_length // 8 > 0:
                padding_str += "-------- " * (padding_length//8)
                padding_length %= 8
            padding_str = "-" * padding_length + padding_str[:-1]
            format = f"0{8-padding_length}b"
            last_byte = self.content[index] >> padding_length
            content_repr += f" {last_byte:{format}}{padding_str}"

        return f"[{content_repr}] | len: {self.bit_length} | pad: {self.padding} {self.padding_side}"




