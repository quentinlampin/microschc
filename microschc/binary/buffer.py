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
import json
from typing import Iterable

class Padding(str, Enum):
    LEFT = 'left'
    RIGHT = 'right'

class Buffer:

    def __init__(self, content: bytes, length:int, padding=Padding.LEFT) -> None:
        
        padding_length: int = _calculate_padding_length(length=length)
        byte_length: int = length // 8 if padding_length == 0 else length // 8 + 1
        content_length: int = len(content)
        if padding is Padding.LEFT:
            if content_length < byte_length:
                content = b'\x00' * (byte_length - len(content)) + content
            content = content[-byte_length:]
            if padding_length > 0:
                mask: bytes = (0xff >> padding_length) & 0xff
                first_byte = (content[0] & mask).to_bytes(1, 'big')
                content = first_byte + content[1:]
        elif padding is Padding.RIGHT:
            if content_length < byte_length:
                content += b'\x00' * (byte_length - len(content))
            content = content[0:byte_length]
            if padding_length > 0:
                mask: bytes = (0xff << padding_length) & 0xff
                last_byte = (content[-1] & mask).to_bytes(1, 'big')
                content = content[:-1] + last_byte
            
        self.content:bytes = content
        self.length:int = length
        self.padding:Padding = padding
        self.padding_length:int = padding_length
        
        
    def _update_padding(self):
        self.padding_length = _calculate_padding_length(self.length)
        
    def shift(self, shift: int, inplace=True) -> 'Buffer':
        """
        Shift buffer contents by specified number of bits.
        
        Args:
            shift (int): Number of bits to shift. Negative for left shift, positive for right shift
            inplace (bool): If True, modify current buffer, if False return new buffer
        
        Returns:
            Buffer: Shifted buffer (self if inplace=True, new buffer if inplace=False)
        """
        if shift == 0:
            return self if inplace else self.copy()
            
        # Create new buffer or work on copy if not inplace
        buffer = self if inplace else self.copy()
        
        if shift < 0:  # Left shift
            return buffer._shift_left(abs(shift))
        else:  # Right shift
            return buffer._shift_right(shift)

    def _shift_left(self, shift: int) -> 'Buffer':
        """Helper method for left shift operation"""
        # Calculate new length
        new_length = self.length + shift
        new_byte_length = (new_length + 7) // 8
        
        if self.padding == Padding.LEFT:
            # For LEFT padding, we need to shift the actual bits
            temp_content: bytes = bytes(shift//8)
            # Perform bit-level shift
            shift_bits = shift % 8
            carry = 0
            carry_mask = (1 << shift_bits) - 1
            
            # Process original content from right to left
            for i in range(0, len(self.content)):
                c_index: int = len(self.content) - 1 - i 
                byte = self.content[c_index]
                new_byte = ((byte << shift_bits) & 0xFF) | carry
                carry = (byte >> (8 - shift_bits)) & carry_mask
                temp_content = new_byte.to_bytes(1, 'big') + temp_content
            
            if len(temp_content) < new_byte_length:
                temp_content = carry.to_bytes(1, 'big') + temp_content
                
            self.content = temp_content
            
        else:  # Padding.RIGHT
            # For RIGHT padding, we just move the padding boundary
            extra_bytes: int = new_byte_length - len(self.content)
            self.content += bytes(extra_bytes)
        
        self.length = new_length
        self._update_padding()
        return self

    def _shift_right(self, shift: int) -> 'Buffer':
        """Helper method for right shift operation"""
        # If shift is larger than buffer length, result is all zeros
        if shift >= self.length:
            self.content = b''
            self.length = 0
            self._update_padding()
            return self
        
        # Calculate new length
        new_length = self.length - shift
        new_byte_length = (new_length + 7) // 8
        
        temp_content:bytes = self.content
        
        if self.padding == Padding.LEFT:
            bytes_to_remove: int = shift // 8
            temp_content = temp_content[0:len(temp_content)-bytes_to_remove]
            
            shift %= 8
            if shift > 0:
                carry_mask = (1 << shift) - 1
                temp_content:bytes = bytes(b'\x00') + temp_content
                new_content: bytes = b''
                for i in range(1, len(temp_content)):
                    left_byte = temp_content[i-1]
                    current_byte = temp_content[i]
                    carry_over:int = (left_byte & carry_mask) << (8 - shift)
                    shifted_byte:int = current_byte >> shift
                    new_content += (carry_over + shifted_byte).to_bytes(1, 'big')
            else:
                new_content:bytes = temp_content
            
            self.content = bytes(new_content[-new_byte_length:])
              
            
        else:  # RIGHT padding
            temp_content = b'\x00' + self.content
            new_content = bytes()
            shift_bits = shift % 8
            
            if shift_bits > 0:
                carry_mask = (1 << shift_bits) - 1
                for i in range(len(temp_content) - 1):
                    current_byte = temp_content[i]
                    next_byte = temp_content[i + 1]
                    new_byte = ((current_byte >> shift_bits) & 0xFF) | \
                            ((next_byte & carry_mask) << (8 - shift_bits))
                    new_content += new_byte.to_bytes(1, 'big')
                    
                # Handle last byte
                last_byte = temp_content[-1] >> shift_bits
                if last_byte:
                    new_content += last_byte.to_bytes(1, 'big')
            else:
                new_content += temp_content
            
            # Take required bytes
            self.content = bytes(new_content[:new_byte_length])
        
        self.length = new_length
        self._update_padding()
        return self

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
            self_copy.padding = padding
            shift_value = + padding_length
            self_copy.length += shift_value
        
        buffer: Buffer = self_copy.shift(shift=shift_value, inplace=True)
        buffer.length = self.length
        buffer.padding = padding
        buffer.padding_length = padding_length
        if inplace == True:
            self.content = buffer.content
            self.length = buffer.length
            self.padding = buffer.padding
        return buffer

    def copy(self):
        return Buffer(content=self.content, length=self.length, padding=self.padding)
    
    def value(self, type:str='unsigned int', encoding:str='big-endian'):
        """
        returns the content of the buffer, decoded with given parameters.
        """
        if self.padding is Padding.RIGHT:
            buffer = self.pad(padding=Padding.LEFT)
        else:
            buffer = self
        
        padding_length: int = buffer.padding_length
        mask: bytes = (0xff >> padding_length) & 0xff
        first_byte = (buffer.content[0] & mask).to_bytes(1, 'big')
        content = first_byte + buffer.content[1:]

        if 'int' in type:
            encoding: str = 'big' if encoding == 'big-endian' else 'little'
            signed: bool = False if 'unsigned' in type else True
            value:int = int.from_bytes(content, encoding, signed=signed)
        elif 'str' in type:
            value:str = self.content.decode(encoding=encoding)
        else:
            raise ValueError('unknown type/decoding requirements')
        return value
    
    def chunks(self, length: int, padding: bool = False) -> Iterable['Buffer']:
        chunks_count = self.length // length if self.length % length == 0 else self.length//length + 1
        cursor = 0 
        for chunk in range(chunks_count-1):
            chunk = self[cursor:cursor+length]
            yield chunk
            cursor += length
        chunk = self[cursor:cursor+length]
        if padding is True and chunk.length < 16:
            pad_content = bytes(length//8 if length%8==0 else length//8 + 1)
            pad: Buffer = Buffer(content=pad_content, length=length-chunk.length, padding=Padding.RIGHT)
            chunk+=pad
        yield chunk


    def __eq__(self, another: object) -> bool:
        '''
        returns True if `another` has the same first `bit_length` bits (excluding padding)
        '''
        if isinstance(another, bytes):
            return self.content == another
        elif isinstance(another, Buffer):
            if self.length != another.length:
                return False
            another_same_padding = another.pad(padding=self.padding, inplace=False)
            return self.content == another_same_padding.content
        else:
            return False

    def __hash__(self) -> int:
        return self.content.__hash__()
    
    def __add__(self, other: 'Buffer') -> 'Buffer':
        if not isinstance(other, Buffer):
            raise TypeError("Can only concatenate Buffer objects")
        
        left:Buffer = self
        right:Buffer = other
        
        # Calculate new length
        new_length: int = left.length + right.length
        
        if left.padding is Padding.LEFT:
            # case: left is left padded
            if right.padding_length == 0:
                # case: right is byte aligned, concatenate contents as-is.
                new_content: bytes = left.content + right.content
            else:
                right = right.pad(Padding.LEFT, inplace=False)
                bit_shift: int = right.padding_length
                carry_mask: int = (1 << bit_shift) - 1
                carry:int = 0
                new_content: bytes = b''
                
                for b in left.content:
                    sb:int = (b >> bit_shift) + carry
                    carry = (b & carry_mask) << (8 - bit_shift)
                    new_content += sb.to_bytes(1, 'big')
                new_content += (right.content[0] + carry).to_bytes(1, 'big')
                new_content += right.content[1:]
                
                if left.padding_length + bit_shift > 7:
                    # remove unwanted left padding
                    new_content = new_content[1:]
        else:
            # case: left is right padded
            if left.padding_length == 0:
                # no padding on the left chunk
                if right.padding_length == 0 or right.padding is Padding.RIGHT:
                    # no padding on the right chunk left
                    new_content: bytes = left.content + right.content
                else:
                    # case: right is left padded
                    right = right.pad(Padding.RIGHT, inplace=False)
                    new_content = left.content + right.content
            else:
                # case: left is right padded and there is padding
                if right.padding is Padding.LEFT:
                    # right is left padded
                    if left.padding_length + right.padding_length == 8:
                        # right padding is aligned with left padding
                        new_content = left.content[0:-1] + (left.content[-1] + right.content[0]).to_bytes(1, 'big') + right.content[1:]
                    else:
                        # right padding is not aligned with left padding
                        bit_shift: int = abs(right.padding_length - left.padding_length)
                        if right.padding_length > left.padding_length:
                            new_content: bytes = b''
                            # shift right to the right
                            carry: int = 0
                            carry_mask: int = (1 << bit_shift) - 1
                            for b in right.content[::]:
                                sb:int = (b >> bit_shift) + carry
                                carry = (b & carry_mask) << (8 - bit_shift)
                                new_content += sb.to_bytes(1, 'big')
                            new_content = left.content[0:-1] + (left.content[-1] + new_content[0]).to_bytes(1, 'big') + new_content[1:] + carry.to_bytes(1, 'big')
                        else:
                            # shift right to the left, careful with the carry that will spill over right's left boundary
                            new_content: bytes = b''
                            carry: int = 0
                            for b in right.content[::-1]:
                                sb:int = ((b << bit_shift) & 0xff) + carry
                                new_content = sb.to_bytes(1, 'big') + new_content
                                carry = b >> (8-bit_shift)
                            new_content = left.content[0:-1] + (left.content[-1] + carry).to_bytes(1, 'big') + new_content
                else:
                    # right is right padded
                    # shift right to the right
                    bit_shift: int = 8 - left.padding_length
                    carry_mask: int = (1 << bit_shift) - 1
                    new_content: bytes = b''
                    carry: int = 0
                    for b in right.content:
                        sb:int = (b >> bit_shift) + carry
                        new_content += sb.to_bytes(1, 'big')
                        carry = (b & carry_mask) << (8 - bit_shift)
                    new_content = left.content[0:-1] + (left.content[-1] + new_content[0]).to_bytes(1, 'big') + new_content[1:]
        
        new_buffer: Buffer = Buffer(content=new_content, length=new_length, padding=left.padding)
        return new_buffer
                                                
    
    def __and__(self, another: 'Buffer'):
        if self.length != another.length:
            raise ValueError('buffers must be of the same length')
        if another.padding != self.padding:
            another = another.pad(self.padding)

        bitwise_and_content: bytes = b''
        for (self_chunk, another_chunk) in  zip(iter(self.content), iter(another.content)):
            bitwise_and_content += (self_chunk & another_chunk).to_bytes(1,'big')

        bitwise_and_buffer: Buffer = Buffer(content=bitwise_and_content, length=self.length, padding=self.padding)
        return bitwise_and_buffer
    
    def __or__(self, another: 'Buffer'):
        if self.length != another.length:
            raise ValueError('buffers must be of the same length')
        if another.padding != self.padding:
            another = another.pad(self.padding)

        bitwise_or_content: bytes = b''
        for (self_chunk, another_chunk) in  zip(iter(self.content), iter(another.content)):
            bitwise_or_content += (self_chunk | another_chunk).to_bytes(1,'big')

        bitwise_or_buffer: Buffer = Buffer(content=bitwise_or_content, length=self.length, padding=self.padding)
        return bitwise_or_buffer
    
    def __xor__(self, another: 'Buffer'):
        if self.length != another.length:
            raise ValueError('buffers must be of the same length')
        if another.padding != self.padding:
            another = another.pad(self.padding)

        bitwise_xor_content: bytes = b''
        for (self_chunk, another_chunk) in  zip(iter(self.content), iter(another.content)):
            bitwise_xor_content += (self_chunk ^ another_chunk).to_bytes(1,'big')

        bitwise_xor_buffer: Buffer = Buffer(content=bitwise_xor_content, length=self.length, padding=self.padding)
        return bitwise_xor_buffer
    

    
    def __setitem__(self,items, values):

        assert isinstance(items, (slice, int))
        assert isinstance(values, Buffer)

        if isinstance(items, slice):
            start_bit, stop_bit, _ = items.indices(self.length)
        else:
            start_bit = items
            stop_bit = start_bit + 1

        prefix: Buffer = self[0:start_bit]
        postfix: Buffer = self[stop_bit:]

        new_buffer: Buffer = prefix + values + postfix

        self.content = new_buffer.content
        self.length = new_buffer.length
        self.padding_length = new_buffer.padding_length
        return self

    def __getitem__(self, items):
        
        assert isinstance(items, (slice, int))

        if isinstance(items, slice):
            start_bit, stop_bit, _ = items.indices(self.length)

        else:
            start_bit = items
            stop_bit = start_bit + 1
       
        new_length: int = stop_bit - start_bit
        
        if new_length == 0:
            return Buffer(content=b'', length=0, padding=self.padding)
        
        if self.padding is Padding.LEFT:
            start_bit += self.padding_length
            stop_bit += self.padding_length
            start_byte: int = start_bit // 8
            stop_byte: int = (stop_bit+7) // 8
            
            first_byte_mask: int = (1 << (8-start_bit%8)) - 1
            shift_bits: int = (8-(stop_bit%8))%8
            carry_mask: int = (1 << shift_bits) - 1
            
            new_content: bytes = ((self.content[start_byte] & first_byte_mask) >> shift_bits).to_bytes(1, 'big')
            carry: int = (self.content[start_byte] & carry_mask) << (8 - shift_bits)
            for b in self.content[start_byte+1: stop_byte]:
                sb:int = (b >> shift_bits) + carry
                carry = (b & carry_mask) << (8 - shift_bits)
                new_content += sb.to_bytes(1, 'big')
        
        else:
            start_byte: int = start_bit // 8
            stop_byte: int = (stop_bit+7) // 8
            shift_bits: int = (start_bit%8)
            carry_mask: int = (1 << shift_bits) - 1
            last_byte_mask: int = (0xff << (8-stop_bit%8)) & 0xff
            last_byte: bytes = self.content[stop_byte-1]
            new_content: bytes =(( (last_byte & last_byte_mask) << shift_bits) & 0xff).to_bytes(1, 'big')
            carry = (last_byte >> (8 - shift_bits)) & carry_mask
            
            for b in self.content[start_byte: stop_byte][::-1]:
                sb = ((b << shift_bits) & 0xff) + carry
                carry = (b >> (8 - shift_bits)) & carry_mask
                new_content = sb.to_bytes(1, 'big') + new_content
                
        new_buffer: Buffer = Buffer(
            content=new_content,
            length=new_length,
            padding=self.padding
        )
        return new_buffer
        

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
        
        if self.length <= 16:
            # return bit representation
            if self.padding == Padding.LEFT and padding_length > 0:
                padding_str: str = ""
                padding_str += "-" * padding_length
                format = f"0{8-padding_length}b"
                content_repr += f"{padding_str}{self.content[index]:{format}} "
                index += 1
            content_repr += " ".join([f"{b:08b}" for b in self.content[index:index + (self.length//8)]])
            index += (self.length//8)
            if self.padding == Padding.RIGHT and padding_length > 0:
                padding_str: str = " "
                padding_str = "-" * padding_length + padding_str[:-1]
                format = f"0{8-padding_length}b"
                last_byte = self.content[index] >> padding_length
                content_repr += f" {last_byte:{format}}{padding_str}"
        else:
            # return hex representation
            content_repr = self.content.hex()
        
        return f"[{content_repr}]({self.length})"

    def __json__(self) -> dict:
        json_object: dict = {
            'content': self.content.hex(),
            'length': self.length,
            'padding': self.padding
        }
        return json_object

    def json(self, indent=None, separators=None) -> str:
        return json.dumps(self.__json__(), indent=indent, separators=separators)

    def __from_json_object__(json_object:object):
        return Buffer(
            content=bytes.fromhex(json_object['content']), 
            length=json_object['length'],
            padding=json_object['padding']
        )

    def from_json(json_str: str):
        json_object: dict = json.loads(json_str)
        return Buffer.__from_json_object__(json_object=json_object)
    
def _calculate_padding_length(length: int) -> int:
    return (8 - length % 8) % 8