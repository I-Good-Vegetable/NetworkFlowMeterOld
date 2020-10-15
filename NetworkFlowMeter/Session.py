from collections import defaultdict

from pyprobar import probar

from NetworkFlowMeter.NetworkTyping import Optional, Callable, Any, AnyStr, List, Tuple, Packet, Sessions, \
    SessionKeyInfo
from NetworkFlowMeter.Settings import progressBarColor


def directionalField(field1: Any, field2: Any) -> (Any, Any, AnyStr):
    """
    Create Directional Field Info within a Packet
    field1 <= field2 => forward
    field1 >  field2 => backward
    :param field1: field within in p
    :param field2: field within in p
    :return: (sortedField1, sortedField2, direction)
    """
    field1, field2 = str(field1), str(field2)
    return (field1, field2, 'Forward') if field1 <= field2 else (field2, field1, 'Backward')


def defaultBidirectionalSessionExtractor(p: Packet) -> (AnyStr, AnyStr):
    """
    These messy codes are generating p's session key and indicating the direction of p
    :param p: Packet
    :return: (session key, direction)
    """
    sessionKey, pDirection = '', 'Forward'
    if 'WPAN' in p:
        if 'IPv6' in p:
            ip1, ip2, pDirection = directionalField(p.ip.src, p.ip.dst) if 'IP' in p \
                else directionalField(p.ipv6.src, p.ipv6.dst)
            if 'TCP' in p:
                port1, port2 = (p.tcp.srcport, p.tcp.dstport) if pDirection == 'Forward' \
                    else (p.tcp.dstport, p.tcp.srcport)
                sessionKey = f'TCP {ip1} {port1} {ip2} {port2}'
            elif 'UDP' in p:
                port1, port2 = (p.udp.srcport, p.udp.dstport) if pDirection == 'Forward' \
                    else (p.udp.dstport, p.udp.srcport)
                sessionKey = f'UDP {ip1} {port1} {ip2} {port2}'
            elif 'ICMP' in p:
                icmpType, icmpCode, icmpId = p.icmp.type, p.icmp.code, p.icmp.id
                sessionKey = f'ICMP {ip1} 0 {ip2} 0 {icmpType} {icmpCode} {icmpId}'
            # Scapy cannot guess ICMPv6 protocol, so we extract it under IPv6
            elif 'ICMPv6' in p:
                icmpv6Type, icmpv6Code = p.icmpv6.type, p.icmpv6.code
                sessionKey = f'ICMPv6 {ip1} 0 {ip2} 0 {icmpv6Type} {icmpv6Code}'
            else:
                sessionKey = f'IPv6 {ip1} 0 {ip2} 0 {p["IPv6.nh"]}'
        else:
            sessionKey = f'WPAN 0 0 0 0 {p.wpan.frame_type}'
    else:
        sessionKey, pDirection = 'OTHER 0 0 0 0', 'Forward'
    return sessionKey, pDirection


def defaultSessionKeyInfo(sessionKey: AnyStr) -> SessionKeyInfo:
    """
    This function will extract information from  session key,
    so that it must match the session extractor function
    :param sessionKey: string of session key
    :return: protocol, srcIp, srcPort, dstIp, dstPort
    """
    # session key list (skl)
    skl = sessionKey.split()
    protocol, srcIp, srcPort, dstIp, dstPort = \
        skl[0], skl[1], skl[2], skl[3], skl[4]
    return protocol, srcIp, srcPort, dstIp, dstPort


def generateSessions(packets: List[Packet], direction: AnyStr = 'bidirectional',
                     sessionExtractor: Optional[Callable[[Packet], Tuple[AnyStr, AnyStr]]] = None) -> Sessions:
    """
    generate sessions from packets
    :param packets: packet list
    :param direction: 'unidirectional' or 'bidirectional'.
                      If session extractor is not None,
                      this param won't work
    :param sessionExtractor: Optional[Callable[[Packet], (AnyStr, AnyStr)]]
    :return: sessions
    """
    if sessionExtractor is None:
        # use bidirectional session extractor as default
        # unidirectional session key is the bidirectional session key + direction
        sessionExtractor = defaultBidirectionalSessionExtractor
    # to mark the direction, we avoid using sessions provided by scapy
    sessions = defaultdict(list)
    for p in probar(packets, color=progressBarColor):
        sessionKey, pDirection = sessionExtractor(p)
        if direction == 'unidirectional':
            sessionKey = f'{sessionKey} {pDirection}'
        # add additional attribute on packet to mark the direction
        p.pDirection = pDirection
        sessions[sessionKey].append(p)
    return sessions
