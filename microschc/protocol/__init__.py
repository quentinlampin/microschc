from typing import Callable, Dict

from microschc.binary import Buffer
from .ipv6 import IPv6ComputeFunctions, IPv6_HEADER_ID, IPv6Fields


ComputeFunction: Dict[str, Callable[[Buffer, int], Buffer]] = {
    IPv6Fields.PAYLOAD_LENGTH: IPv6ComputeFunctions[IPv6Fields.PAYLOAD_LENGTH]
}

