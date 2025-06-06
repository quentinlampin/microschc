from math import ceil, log2
from microschc.binary.buffer import Padding
from microschc.rfc8724 import TargetValue, Buffer, MatchMapping
from microschc.binary import Padding

def create_target_value(value, length=None, padding=None) -> TargetValue:
    """Factory function to create a TargetValue (Buffer or MatchMapping) from various input types.
    
    Args:
        value: The input value. Can be:
            - int: Creates a Buffer with the integer value
            - bytes: Creates a Buffer with the bytes content
            - list of int or bytes: Creates a MatchMapping from the list
            - list of (bytes, bytes) or (int, int) or (int, bytes): Creates a MatchMapping from pairs
            - dict with Buffer keys and values: Creates a MatchMapping from the dictionary
            - MatchMapping or Buffer: Returns the value unchanged
            - None
        length: For Buffer creation, the bit length (required for int and bytes inputs)
        padding: For Buffer creation, the padding type (defaults to LEFT padding)
    
    Returns:
        TargetValue: Either a Buffer or MatchMapping depending on input type
        
    Raises:
        TypeError: If input type is not supported
        ValueError: If required parameters are missing for the input type
    """
    # If already a TargetValue, return as is
    if isinstance(value, (Buffer, MatchMapping)) or (value is None):
        return value
    
    # Handle integer input - create Buffer
    if isinstance(value, int):
        if length is None:
            raise ValueError("Length must be provided when creating Buffer from integer")
        
        # Check if the value fits within the specified bit length
        max_value = (1 << length) - 1
        if value < 0 or value > max_value:
            raise ValueError(f"Integer value {value} doesn't fit in {length} bits (max: {max_value})")
        
        # Calculate how many bytes we need for this integer
        byte_length = (length + 7) // 8
        
        # Convert int to bytes
        content = value.to_bytes(byte_length, byteorder='big')
        
        # Use default LEFT padding if not specified
        actual_padding = padding if padding is not None else Padding.LEFT
        
        return Buffer(content=content, length=length, padding=actual_padding)
    
    # Handle bytes input - create Buffer
    elif isinstance(value, bytes):
        if length is None:
            # Assume full byte length if not specified
            length = len(value) * 8
        
        # Use default LEFT padding if not specified
        actual_padding = padding if padding is not None else Padding.LEFT
        
        return Buffer(content=value, length=length, padding=actual_padding)
    
    # Handle list input - create MatchMapping
    elif isinstance(value, list):
        # For empty list, raise a ValueError
        if len(value) == 0:
            raise ValueError("a non empty list is required for MatchMapping")
    
        # case where list contains integers or bytes
        if all(isinstance(item, (int, bytes, Buffer)) for item in value):
            # create a MatchMapping from the list using a default index
            keys = [i for i in range(len(value))]
            key_length = int(ceil(log2(len(keys))))
            values = [create_target_value(item, length=length) for item in value]
            forward_mapping = {val:create_target_value(key, length=key_length) for key, val in zip(keys, values)}
            return MatchMapping(forward_mapping=forward_mapping)
        
        # case where list contains tuples
        if all(isinstance(item, (list, tuple)) and len(item) == 2 for item in value):
            # Create a MatchMapping from the list of tuples
            forward_mapping = {}
            
            for item in value:
                key, val = item
                key_buffer = create_target_value(key, length=length) if not isinstance(key, Buffer) else key
                val_buffer = create_target_value(val, length=length) if not isinstance(val, Buffer) else val
                
                # Buffer check
                if not isinstance(key_buffer, Buffer) or not isinstance(val_buffer, Buffer):
                    raise TypeError("MatchMapping keys and values must be convertible to Buffer")
                
                forward_mapping[key_buffer] = val_buffer
            
            return MatchMapping(forward_mapping=forward_mapping)
        

        
        return MatchMapping(forward_mapping=forward_mapping)
    
    # Handle dictionary input - create MatchMapping
    elif isinstance(value, dict):
        # For empty dict, create empty mapping
        if len(value) == 0:
            raise ValueError("a non empty dict is required for MatchMapping")
        
        forward_mapping = {}
        
        for key, val in value.items():
            key_buffer = create_target_value(key, length=length)
            val_buffer = create_target_value(val, length=length)
            
            # Buffer check
            if not isinstance(key_buffer, Buffer) or not isinstance(val_buffer, Buffer):
                raise TypeError("MatchMapping keys and values must be convertible to Buffer")
            
            forward_mapping[key_buffer] = val_buffer
        
        return MatchMapping(forward_mapping=forward_mapping)
    
    # Unsupported input type
    else:
        raise TypeError(f"Cannot create TargetValue from {type(value).__name__}")