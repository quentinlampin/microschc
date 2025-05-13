
import pytest
from microschc.rfc8724 import MatchMapping
from microschc.tools import create_target_value
from microschc.binary.buffer import Buffer, Padding


def test_create_buffer_from_int():
    """Test creating a Buffer from an integer."""
    # Create a Buffer from an int
    value = 42
    length = 8  # 8 bits
    buffer = create_target_value(value, length)
    
    # Check the type and value
    assert isinstance(buffer, Buffer)
    assert buffer.length == length
    assert buffer.value() == value

def test_create_buffer_from_bytes():
    """Test creating a Buffer from bytes."""
    # Create a Buffer from bytes
    value = b'\x01\x02\x03\x04'
    buffer = create_target_value(value)
    
    # Check the type and content
    assert isinstance(buffer, Buffer)
    assert buffer.content == value
    assert buffer.length == len(value) * 8
    
    # Test with specified length
    buffer = create_target_value(value, length=16)
    assert buffer.length == 16

def test_create_buffer_with_padding():
    """Test creating a Buffer with specified padding."""
    # Create a Buffer with RIGHT padding
    value = 42
    length = 8
    buffer = create_target_value(value, length, padding=Padding.RIGHT)
    
    # Check the padding
    assert buffer.padding == Padding.RIGHT

def test_create_match_mapping_from_list():
    """Test creating a MatchMapping from a list of pairs."""
    # Create a MatchMapping from a list of (key, value) pairs
    pairs = [
        (1, 100),
        (2, 200),
        (3, 300)
    ]
    length = 16  # 16 bits per value (large enough for all values)
    mapping = create_target_value(pairs, length)
    
    # Check the type and mappings
    assert isinstance(mapping, MatchMapping)
    
    # Create expected buffers for comparison
    buf1 = create_target_value(1, length)
    buf2 = create_target_value(2, length)
    buf3 = create_target_value(3, length)
    buf100 = create_target_value(100, length)
    buf200 = create_target_value(200, length)
    buf300 = create_target_value(300, length)
    
    # Check that mappings are correct
    assert mapping.forward[buf1] == buf100
    assert mapping.forward[buf2] == buf200
    assert mapping.forward[buf3] == buf300
    
    # Check reverse mappings
    assert mapping.reverse[buf100] == buf1
    assert mapping.reverse[buf200] == buf2
    assert mapping.reverse[buf300] == buf3

def test_create_match_mapping_from_dict():
    """Test creating a MatchMapping from a dictionary."""
    # Create key/value buffers
    key1 = Buffer(content=b'\x01', length=8)
    key2 = Buffer(content=b'\x02', length=8)
    val1 = Buffer(content=b'\x10', length=8)
    val2 = Buffer(content=b'\x20', length=8)
    
    # Create a dictionary with Buffer keys and values
    dict_obj = {
        key1: val1,
        key2: val2
    }
    
    # Create MatchMapping from dictionary
    mapping = create_target_value(dict_obj)
    
    # Check the type and mappings
    assert isinstance(mapping, MatchMapping)
    assert mapping.forward[key1] == val1
    assert mapping.forward[key2] == val2
    
    # Test with mixed types that need conversion
    dict_obj = {
        1: 10,
        2: 20
    }
    length = 8
    
    mapping = create_target_value(dict_obj, length)
    
    # Create expected buffers for comparison
    buf1 = create_target_value(1, length)
    buf2 = create_target_value(2, length)
    buf10 = create_target_value(10, length)
    buf20 = create_target_value(20, length)
    
    # Check mappings
    assert mapping.forward[buf1] == buf10
    assert mapping.forward[buf2] == buf20

def test_passthrough_existing_target_value():
    """Test that existing TargetValue objects are returned unchanged."""
    # Create a Buffer
    buffer = Buffer(content=b'\x01\x02', length=16)
    
    # Pass through factory
    result = create_target_value(buffer)
    
    # Should be the same object
    assert buffer is result
    
    # Create a MatchMapping
    mapping = MatchMapping(forward_mapping={buffer: buffer})
    
    # Pass through factory
    result = create_target_value(mapping)
    
    # Should be the same object
    assert mapping is result

def test_error_cases():
    """Test error cases for the factory function."""
    # Test missing length for int
    with pytest.raises(ValueError):
        create_target_value(42)
    
    # Test unsupported type
    with pytest.raises(TypeError):
        create_target_value(None)
    
    # Test invalid list items
    with pytest.raises(ValueError):
        create_target_value([1, 2, 3], length=8)  # not pairs
    
    # Test invalid mapping values
    with pytest.raises(TypeError):
        create_target_value({1: None}, length=8)  # None can't be a Buffer
        
    # Test out of range integer
    with pytest.raises(ValueError):
        create_target_value(300, length=8)  # 300 doesn't fit in 8 bits

def test_class_methods():
    """Test the class methods for creating MatchMapping objects."""
    # Test from_list
    pairs = [(1, 10), (2, 20)]
    length = 8
    
    mapping = MatchMapping.from_list(pairs, length)
    
    assert isinstance(mapping, MatchMapping)
    
    # Test from_dict
    dict_obj = {1: 10, 2: 20}
    
    mapping = MatchMapping.from_dict(dict_obj, length)
    
    assert isinstance(mapping, MatchMapping)

