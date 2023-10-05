from typing import Callable, Dict, List, Tuple

from microschc.binary import Buffer


ComputeFunctionType = Callable[[Buffer, int, List[Tuple[str, Buffer]], int], Buffer]




