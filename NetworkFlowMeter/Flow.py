from pyprobar import probar

from NetworkFlowMeter.NetworkTyping import Callable, Optional, AnyStr, Packet, Sessions, SessionKeyInfo, PacketList, \
    Flows
from NetworkFlowMeter.Session import defaultSessionKeyInfo
from NetworkFlowMeter.Settings import progressBarColor
from NetworkFlowMeter.Utils import packetTsMicroseconds, formatMicrosecond, microsecond2second


class Flow(object):
    """
    All time related operation will be based on microseconds
    """
    # default timeout setting
    defaultFlowTimeout = 5000000
    defaultActivityTimeout = 3000000

    def __init__(self, sessionKey: AnyStr,
                 packet: Optional[Packet] = None,
                 sessionKeyInfoGenerator: Callable[[AnyStr], SessionKeyInfo] = defaultSessionKeyInfo,
                 flowTimeout: Optional[float] = None):
        self.sessionKey = sessionKey
        self.sessionKeyInfoGenerator = sessionKeyInfoGenerator
        self.sessionKeyInfo = sessionKeyInfoGenerator(sessionKey)
        self.flowTimeout = self.defaultFlowTimeout if flowTimeout is None else flowTimeout
        # packet ts => microseconds
        self.initialPacketTs = 0
        self.lastPacketTs = 0
        # bidirectional packets
        self.packets: PacketList = list()
        # unidirectional packets
        self.forwardPackets: PacketList = list()
        self.backwardPackets: PacketList = list()
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

    def protocol(self):
        return self.sessionKeyInfo[0]

    def readableInitPacketTs(self) -> AnyStr:
        return formatMicrosecond(self.initialPacketTs)

    def readableLastPacketTs(self) -> AnyStr:
        return formatMicrosecond(self.lastPacketTs)

    def duration(self, f='ms') -> float:
        """
        ms: microsecond
        s: second
        """
        if f == 's':
            return microsecond2second(self.lastPacketTs - self.initialPacketTs)
        return float(self.lastPacketTs - self.initialPacketTs)

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
        if packetTs - self.initialPacketTs > self.flowTimeout:
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


def sessions2flows(sessions: Sessions,
                   flowTimeout=Flow.defaultFlowTimeout,
                   activityTimeout=Flow.defaultActivityTimeout) -> Flows:
    aliveFlows, flows = dict(), list()
    Flow.defaultFlowTimeout, Flow.defaultActivityTimeout = flowTimeout, activityTimeout
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
