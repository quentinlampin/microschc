"""
definitions of literals described in RFC 8724 [1] whose values are not specified.

[1] "SCHC: Generic Framework for Static Context Header Compression and Fragmentation" , A. Minaburo et al.
"""

from typing import Literal


PacketDirection = Literal["UP", "DOWN"]

