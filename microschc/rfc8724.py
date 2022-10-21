"""
definitions from RFC 8724 [1] and corresponding data models.

[1] "SCHC: Generic Framework for Static Context Header Compression and Fragmentation" , A. Minaburo et al.
"""

from enum import Enum
from dataclasses import dataclass
from typing import Any, List


class DirectionIndicator(str, Enum):
    UP = 'Up'
    DOWN = 'Dw'
    BIDIRECTIONAL = 'Bi'


class MatchingOperatorID(str, Enum):
    EQUAL = 'equal'
    IGNORE = 'ignore'
    MSB = 'MSB'
    MATCH_MAPPING = 'match-mapping'

@dataclass
class FieldDescriptor:
    id: str
    length: int
    position: int
    value: Any


@dataclass
class HeaderDescriptor:
    id: str
    length: int
    fields: List[FieldDescriptor]


@dataclass
class PacketDescriptor:
    direction: DirectionIndicator
    fields: List[FieldDescriptor]
