"""
Network Flow Meter
"""

from collections import defaultdict
from scapy.all import rdpcap, PacketList, Packet
from pyprobar import probar
from typing import Callable, AnyStr, Tuple, Optional, List, Dict, Any, DefaultDict
import time
import csv

# some settings
progressBarColor = '5'


# utilities

def second2microsecond(t) -> float:
    return t * 1000000


def microsecond2second(t) -> float:
    return t / 1000000


def formatMicrosecond(t) -> AnyStr:
    seconds = microsecond2second(t)
    s = time.strftime('%Y-%m-%d %X', time.localtime(seconds))
    return s + '.' + (f'{seconds % 1:.6f}'[-6:])


def packetTsMicroseconds(packet: Packet) -> float:
    return second2microsecond(packet.time)


# PCAP file related


def readPackets(filepath, count=-1) -> PacketList:
    return rdpcap(str(filepath), count)


# session related


def directionalField(p: Packet, field1: AnyStr, field2: AnyStr) -> (Any, Any, AnyStr):
    """
    Create Directional Field Info within a Packet
    field1 <= field2 => forward
    field1 >  field2 => backward
    :param p: Packet
    :param field1: str of field within in p
    :param field2: str of field within in p
    :return: (sortedField1, sortedField2, direction)
    """
    field1, field2, pDirection = p[field1], p[field2], 'Forward'
    if field1 > field2:
        field1, field2, pDirection = field2, field1, 'Backward'
    return field1, field2, pDirection


def defaultBidirectionalSessionExtractor(p: Packet) -> (AnyStr, AnyStr):
    """
    These messy codes are generating p's session key and indicating the direction of p
    :param p: Packet
    :return: (session key, direction)
    """
    sessionKey, pDirection = '', 'Forward'
    if 'Dot15d4' in p or 'Ether' in p:
        if 'IP' in p or 'IPv6' in p:
            ip1, ip2, pDirection = directionalField(p, 'IP.src', 'IP.dst') if 'IP' in p \
                else directionalField(p, 'IPv6.src', 'IPv6.dst')
            if 'TCP' in p:
                port1, port2 = (p['TCP.sport'], p['TCP.dport']) if pDirection == 'Forward' \
                    else (p['TCP.dport'], p['TCP.sport'])
                sessionKey = f'TCP {ip1} {port1} {ip2} {port2}'
            elif 'UDP' in p:
                port1, port2 = (p['UDP.sport'], p['UDP.dport']) if pDirection == 'Forward' \
                    else (p['UDP.dport'], p['UDP.sport'])
                sessionKey = f'UDP {ip1} {port1} {ip2} {port2}'
            elif 'ICMP' in p:
                icmpType, icmpCode, icmpId = p['ICMP.type'], p['ICMP.code'], p['ICMP.id']
                sessionKey = f'ICMP {ip1} 0 {ip2} 0 {icmpType} {icmpCode} {icmpId}'
            # Scapy cannot guess ICMPv6 protocol, so we extract it under IPv6
            # elif 'ICMPv6' in p:
            #     icmpv6Type, icmpv6Code = p['ICMPv6.type'], p['ICMPv6.code']
            #     sessionKey = f'ICMPv6 {ip1} 0 {ip2} 0 {icmpv6Type} {icmpv6Code}'
            elif 'IPv6' in p:
                if p['IPv6.nh'] == 58:
                    # ICMPv6 and ICMPv6RPL
                    icmpv6 = p['IPv6'].payload
                    sessionKey = f'ICMPv6 {ip1} 0 {ip2} 0 {icmpv6.type} {icmpv6.code}'
                else:
                    sessionKey = f'IPv6 {ip1} 0 {ip2} 0 {p["IPv6.nh"]}'
            else:
                sessionKey = f'IP {ip1} 0 {ip2} 0 {p["IP.proto"]}'
        elif 'ARP' in p:
            psrc, pdst, pDirection = directionalField(p, 'ARP.psrc', 'ARP.pdst')
            sessionKey = f'ARP {psrc} 0 {pdst} 0'
        else:
            if 'Dot15d4' in p:
                sessionKey = f'Dot15d4 0 0 0 0 {p["Dot15d4"].fcf_frametype}'
            else:
                sessionKey = f'Ether 0 0 0 0 {p["Ether.type"]}'
    else:
        sessionKey, pDirection = 'OTHER 0 0 0 0', 'Forward'
    return sessionKey, pDirection


SessionKeyInfo = Tuple[AnyStr, AnyStr, AnyStr, AnyStr, AnyStr]


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


Sessions = DefaultDict[AnyStr, PacketList]


def generateSessions(packets: PacketList, direction: AnyStr = 'bidirectional',
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
    sessions = defaultdict(packets.__class__)
    for p in probar(packets.res, color=progressBarColor):
        sessionKey, pDirection = sessionExtractor(p)
        if direction == 'unidirectional':
            sessionKey = f'{sessionKey} {pDirection}'
        # add additional attribute on packet to mark the direction
        p.pDirection = pDirection
        sessions[sessionKey].append(p)
    return sessions


# Flow Related


class Flow(object):
    """
    All time related operation will be based on microseconds
    """
    # default timeout setting
    flowTimeout = 5000000
    activityTimeout = 3000000

    def __init__(self, sessionKey: AnyStr,
                 packet: Optional[Packet] = None,
                 sessionKeyInfoGenerator: Callable[[AnyStr], SessionKeyInfo] = defaultSessionKeyInfo):
        self.sessionKey = sessionKey
        self.sessionKeyInfo = sessionKeyInfoGenerator(sessionKey)
        # packet ts => microseconds
        self.initialPacketTs = 0
        self.lastPacketTs = 0
        # bidirectional packets
        self.packets = list()
        # unidirectional packets
        self.forwardPackets = list()
        self.backwardPackets = list()
        # no need to add label now. it can be added later on
        self.label = ''

        if packet is not None:
            self.initialPacketTs = self.lastPacketTs = packetTsMicroseconds(packet)
            self.appendPacket(packet)

    def __lt__(self, other):
        if not hasattr(other, 'initialPacketTs'):
            print('Error Type: does\'nt have initialPacketTs')
            return False
        if self.initialPacketTs < other.initialPacketTs:
            return True
        else:
            return False

    def __eq__(self, other):
        if not hasattr(other, 'initialPacketTs'):
            print('Error Type: does\'nt have initialPacketTs')
            return False
        if self.initialPacketTs == other.initialPacketTs:
            return True
        else:
            return False

    def __str__(self):
        protocol, src, sport, dst, dport = self.sessionKeyInfo
        readableInfo = f'Packets: {len(self)}\n' \
                       f'Protocol: {protocol}\n' \
                       f'Src: {src}:{sport}\n' \
                       f'Dst: {dst}:{dport}\n' \
                       f'    InitTime: {self.readableInitPacketTs()}\n' \
                       f'    LastTime: {self.readableLastPacketTs()}'
        return readableInfo

    def __len__(self):
        return len(self.packets)

    def readableInitPacketTs(self) -> AnyStr:
        return formatMicrosecond(self.initialPacketTs)

    def readableLastPacketTs(self) -> AnyStr:
        return formatMicrosecond(self.lastPacketTs)

    def duration(self) -> float:
        """microsecond"""
        return self.lastPacketTs - self.initialPacketTs

    def empty(self) -> bool:
        return len(self.packets) == 0

    def timeout(self, packet: Packet) -> bool:
        """
        Check whether the new packet is timeout
        Ts
        :param packet: new packet
        :return: True: timeout; False: the packet can be add into this flow
        """
        packetTs = packetTsMicroseconds(packet)
        if packetTs - self.initialPacketTs > self.flowTimeout or \
                packetTs - self.lastPacketTs > self.activityTimeout:
            return True
        return False

    def appendPacket(self, packet: Packet):
        """
        append packet to packets, forward packets, and backward packets without conditions
        :param packet: packet
        """
        self.packets.append(packet)
        if packet.pDirection == 'Forward':
            self.forwardPackets.append(packet)
        else:
            self.backwardPackets.append(packet)

    def add(self, packet: Packet) -> bool:
        """
        add new packet into flow
        :param packet: packet
        :return: True: success; False: timeout
        """
        packetTs = packetTsMicroseconds(packet)
        if self.empty():
            # if flow hasn't been initiated
            self.initialPacketTs = packetTs
        elif self.timeout(packet):
            return False

        self.lastPacketTs = packetTs
        self.appendPacket(packet)
        return True


Flows = List[Packet]


def generateFlows(sessions: Sessions, flowTimeout=Flow.flowTimeout, activityTimeout=Flow.activityTimeout) -> Flows:
    aliveFlows, flows = dict(), list()
    Flow.flowTimeout, Flow.activityTimeout = flowTimeout, activityTimeout
    # generate flows
    for sessionKey, session in probar(sessions.items(), color=progressBarColor):
        for p in session:
            if sessionKey not in aliveFlows:
                aliveFlows[sessionKey] = Flow(sessionKey, p)
            else:
                flow = aliveFlows[sessionKey]
                success = flow.add(p)
                if not success:
                    flows.append(flow)
                    aliveFlows[sessionKey] = Flow(sessionKey, p)
    # flush alive flows to flows
    for sessionKey, aliveFlow in aliveFlows.items():
        flows.append(aliveFlow)
    # sort the flows
    flows.sort()
    return flows


# Features Related


Features = Dict[AnyStr, Any]


class FeatureExtractor(object):
    extractors = list()

    def __init__(self):
        """
        This supper class method must be invoked at the end of sub-class init function
        """
        self.extractors.append(self)
        self.featureNames = list(self.extract(Flow('EMPTY 0 0 0 0')).keys())

    def existingExtractors(self):
        for index, extractor in enumerate(self.extractors):
            print(f'{index}. {extractor}')

    def name(self) -> AnyStr:
        return self.__class__.__name__

    def __str__(self):
        return f'{self.name()}' \
               f'    {self.featureNames}'

    def clear(self):
        self.extractors = list()

    def remove(self, extractorName):
        for extractor in self.extractors:
            if str(extractor) == extractorName:
                self.extractors.remove(extractor)

    def extract(self, flow: Flow) -> Features:
        raise NotImplementedError


FeatureSet = List[Features]


def generateFeatures(flows) -> Tuple[FeatureSet, List[AnyStr]]:
    """Generate Features According to Flows"""
    featureSet: FeatureSet = list()
    for index, flow in probar(flows, color=progressBarColor, enum=True):
        features = dict()
        for featureExtractor in FeatureExtractor.extractors:
            tmpFeatures = featureExtractor.extract(flow)
            features.update(tmpFeatures)
        featureSet.append(features)
    featureNames = list(featureSet[0].keys())
    return featureSet, featureNames


def featureSet2csv(filepath: str, featureSet: FeatureSet):
    """Save Feature Set to CSV File"""
    with open(filepath, 'w', newline='') as csvFile:
        featureNames = list(featureSet[0].keys())
        writer = csv.DictWriter(csvFile, featureNames)
        writer.writeheader()
        writer.writerows(featureSet)


# Built-in Feature Extractor


class BasicFlowInfo(FeatureExtractor):
    features: dict

    def extract(self, flow: Flow) -> Features:
        protocol, srcIp, srcPort, dstIp, dstPort = flow.sessionKeyInfo
        features = {
            'Session Key': flow.sessionKey,
            'Src IP': srcIp,
            'Src Port': srcPort,
            'Dst IP': dstIp,
            'Dst Port': dstPort,
            'Protocol': protocol,
            'Init Ts': flow.readableInitPacketTs(),
            'Last Ts': flow.readableLastPacketTs(),
            'Duration': flow.duration(),
        }
        return features


# Construct Feature Extractors
BasicFlowInfo()
