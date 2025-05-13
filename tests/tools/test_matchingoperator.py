"""
Tests for the matching operator selection functionality.
"""

import pytest
from microschc.binary.buffer import Buffer
from microschc.rfc8724 import MatchMapping, MatchingOperator as MO
from microschc.tools.matchingoperator import select_matching_operator
from microschc.tools.targetvalue import create_target_value

def test_select_matching_operator_none():
    """Test matching operator selection with None target value."""
    assert select_matching_operator(None, 8) == MO.IGNORE
    assert select_matching_operator(None, 16) == MO.IGNORE
    assert select_matching_operator(None, 32) == MO.IGNORE

def test_select_matching_operator_match_mapping():
    """Test matching operator selection with MatchMapping target value."""
    mapping = create_target_value([Buffer(b"\x01"), Buffer(b"\x02")])
    assert select_matching_operator(mapping, 8) == MO.MATCH_MAPPING
    assert select_matching_operator(mapping, 16) == MO.MATCH_MAPPING
    assert select_matching_operator(mapping, 32) == MO.MATCH_MAPPING

def test_select_matching_operator_buffer():
    """Test matching operator selection with Buffer target values of different lengths."""
    # Test with Buffer shorter than field length
    short_buffer = Buffer(content=b"\x01")  # 8 bits
    assert select_matching_operator(short_buffer, 16) == MO.MSB
    assert select_matching_operator(short_buffer, 32) == MO.MSB

    # Test with Buffer equal to field length
    equal_buffer = Buffer(b"\x01\x02")  # 16 bits
    assert select_matching_operator(equal_buffer, 16) == MO.EQUAL

    # Test with Buffer longer than field length
    long_buffer = Buffer(b"\x01\x02\x03\x04")  # 32 bits
    assert select_matching_operator(long_buffer, 8) == MO.IGNORE
    assert select_matching_operator(long_buffer, 16) == MO.IGNORE
