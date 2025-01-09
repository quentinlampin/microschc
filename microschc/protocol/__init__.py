from typing import Callable, Dict, List, Tuple

from microschc.binary import Buffer
from microschc.protocol.compute import ComputeFunctionDependenciesType, ComputeFunctionType

from .ipv4 import IPv4ComputeFunctions, IPv4Fields
from .ipv6 import IPv6ComputeFunctions, IPv6Fields
from .udp import UDPComputeFunctions, UDPFields
from .sctp import SCTPComputeFunctions, SCTPFields

ComputeFunctions: Dict[str, Tuple[ComputeFunctionType, ComputeFunctionDependenciesType]] = {
    IPv4Fields.TOTAL_LENGTH: IPv4ComputeFunctions[IPv4Fields.TOTAL_LENGTH],
    IPv4Fields.HEADER_CHECKSUM: IPv4ComputeFunctions[IPv4Fields.HEADER_CHECKSUM],
    IPv6Fields.PAYLOAD_LENGTH: IPv6ComputeFunctions[IPv6Fields.PAYLOAD_LENGTH],
    UDPFields.LENGTH: UDPComputeFunctions[UDPFields.LENGTH],
    UDPFields.CHECKSUM: UDPComputeFunctions[UDPFields.CHECKSUM],
    SCTPFields.CHECKSUM: SCTPComputeFunctions[SCTPFields.CHECKSUM]
}



