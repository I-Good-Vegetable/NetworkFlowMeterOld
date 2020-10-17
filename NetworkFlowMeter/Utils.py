import time

import pandas as pd

from NetworkFlowMeter.NetworkTyping import AnyStr
from NetworkFlowMeter.NetworkTyping import Packet, FeatureSet, DataFrame


def second2microsecond(t) -> float:
    return t * 1000000.0


def microsecond2second(t) -> float:
    return t / 1000000.0


def formatMicrosecond(t) -> AnyStr:
    seconds = microsecond2second(t)
    s = time.strftime('%Y-%m-%d %X', time.localtime(seconds))
    return s + '.' + (f'{seconds % 1:.6f}'[-6:])


def packetTsMicroseconds(packet: Packet) -> float:
    return second2microsecond(float(packet.sniff_timestamp))


def packetTs(packet: Packet) -> float:
    return float(packet.sniff_timestamp)


def featureSet2dataframe(featureSet: FeatureSet) -> DataFrame:
    return pd.DataFrame(featureSet)
