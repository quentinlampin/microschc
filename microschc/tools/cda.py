"""
Compression/Decompression Action Selection

This module provides functions to determine the appropriate compression/decompression action (CDA)
based on the matching operator.
"""

from microschc.rfc8724 import MatchingOperator as MO, CompressionDecompressionAction as CDA

def select_cda(matching_operator: MO) -> CDA:
    """
    Select the appropriate compression/decompression action based on the matching operator.
    
    Args:
        matching_operator: The matching operator to base the selection on
        
    Returns:
        CompressionDecompressionAction: The appropriate compression/decompression action
        
    The selection follows these rules:
    1. If matching_operator is MO.MATCH_MAPPING -> CDA.MAPPING_SENT
    2. If matching_operator is MO.MSB -> CDA.LSB
    3. If matching_operator is MO.EQUAL -> CDA.NOT_SENT
    4. For any other case (including MO.IGNORE) -> CDA.VALUE_SENT
    """
    if matching_operator == MO.MATCH_MAPPING:
        return CDA.MAPPING_SENT
    elif matching_operator == MO.MSB:
        return CDA.LSB
    elif matching_operator == MO.EQUAL:
        return CDA.NOT_SENT
    else:
        return CDA.VALUE_SENT
