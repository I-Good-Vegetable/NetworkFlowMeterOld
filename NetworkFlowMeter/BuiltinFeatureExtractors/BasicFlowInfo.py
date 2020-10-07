from ..Feature import FeatureExtractor
from ..Flow import Flow
from ..NetworkTyping import FeatureSet, Features


class BasicFlowInfo(FeatureExtractor):
    """
    Extract Basic Flow Information, e.g., session key, ip, port, ts
    """

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
            'Ts': flow.initialPacketTs,
            'Duration': flow.duration(),
        }
        return features


def sortFeatures(featureSet: FeatureSet):
    """
    Must guarantee features having Ts item
    :param featureSet: List of Features
    :return: sorted feature set
    """
    featureSet.sort(key=lambda f: f['Ts'])
    return featureSet


BasicFlowInfo()
