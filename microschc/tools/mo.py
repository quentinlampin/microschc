"""
Matching Operator Selection

This module provides functions to determine the appropriate matching operator (MO)
based on the target value type, its length, and the field length.
"""

from typing import Union
from microschc.binary.buffer import Buffer
from microschc.rfc8724 import MatchMapping, MatchingOperator as MO

def select_mo(
    target_value: Union[Buffer, MatchMapping, None],
    field_length: int
) -> MO:
    """
    Select the appropriate matching operator based on the target value type and lengths.
    
    Args:
        target_value: The target value to match against, can be a Buffer, MatchMapping, or None
        field_length: The length of the field in bits
        
    Returns:
        MatchingOperator: The appropriate matching operator for the given target value
        
    The selection follows these rules:
    1. If target_value is None -> MO.IGNORE
    2. If target_value is a MatchMapping -> MO.MATCH_MAPPING
    3. If target_value is a Buffer:
        - If target_value.length < field_length -> MO.MSB
        - If target_value.length == field_length -> MO.EQUAL
        - If target_value.length > field_length -> MO.IGNORE
    """
    if target_value is None:
        return MO.IGNORE
        
    if isinstance(target_value, MatchMapping):
        return MO.MATCH_MAPPING
        
    if isinstance(target_value, Buffer):
        if target_value.length < field_length:
            return MO.MSB
        elif target_value.length == field_length:
            return MO.EQUAL
        else:
            return MO.IGNORE
            
    return MO.IGNORE
