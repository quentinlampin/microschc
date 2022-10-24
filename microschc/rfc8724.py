"""
definitions from RFC 8724 [1] and corresponding data models.

[1] "SCHC: Generic Framework for Static Context Header Compression and Fragmentation" , A. Minaburo et al.
"""

from enum import Enum
from dataclasses import dataclass
from typing import  Dict, List, Union

Value = Union[int, bytes]

ReverseMapping = Dict[int, Value]
Mapping = Dict[Value, int]


class MatchMapping:
    def __init__(self, index_length: int, forward_mapping: Mapping):
        self.index_length: int = index_length
        self.forward: Mapping = forward_mapping
        self.reverse: ReverseMapping = {v: k for k, v in self.forward.items()}
        

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
    value: Value


@dataclass
class HeaderDescriptor:
    id: str
    length: int
    fields: List[FieldDescriptor]


@dataclass
class PacketDescriptor:
    direction: DirectionIndicator
    headers: List[HeaderDescriptor]


@dataclass
class FieldResidue:
    residue: bytes
    length: int
