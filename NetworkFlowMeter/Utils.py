import time

from .NetworkTyping import AnyStr, Packet


def second2microsecond(t) -> float:
    return t * 1000000


def microsecond2second(t) -> float:
    return t / 1000000


def formatMicrosecond(t) -> AnyStr:
    seconds = microsecond2second(t)
    s = time.strftime('%Y-%m-%d %X', time.localtime(seconds))
    return s + '.' + (f'{seconds % 1:.6f}'[-6:])


def packetTsMicroseconds(packet: Packet) -> float:
    return second2microsecond(float(packet.sniff_timestamp))
