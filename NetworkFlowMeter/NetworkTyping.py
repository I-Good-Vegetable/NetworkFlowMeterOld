from typing import Callable, Optional, Collection, AnyStr, Any, List, Tuple, Dict, DefaultDict
from pyshark.packet.packet import Packet
from pandas import DataFrame


PacketList = List[Packet]
SessionKeyInfo = Tuple[AnyStr, AnyStr, AnyStr, AnyStr, AnyStr]
Sessions = DefaultDict[AnyStr, List[Packet]]
Flows = List[Packet]
Features = Dict[AnyStr, Any]
FeatureSet = List[Features]
