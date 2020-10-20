from NetworkFlowMeter.Feature import FeatureExtractor
from NetworkFlowMeter.Flow import Flow
from NetworkFlowMeter.NetworkTyping import FeatureSet, Features


class BasicFlowInfo(FeatureExtractor):
    """
    Extract Basic Flow Information, e.g., session key, ip, port, ts
    """

    def extract(self, flow: Flow) -> Features:
        protocol, srcIp, srcPort, dstIp, dstPort = flow.sessionKeyInfo
        features = {
            'Session Key': flow.sessionKey,
            'Protocol': protocol,
            'Src IP': srcIp,
            'Src Port': srcPort,
            'Dst IP': dstIp,
            'Dst Port': dstPort,
            'Init Ts': flow.readableInitPacketTs(),
            'Last Ts': flow.readableLastPacketTs(),
            'Ts': flow.initialPacketTs,
            'Duration': flow.duration(),
            'Mac Addr': set(),
            # This Label is only a Placeholder
            # It can be manually labeled or create another feature extractor to generate labels
            'Label': ''
        }
        for p in flow.packets:
            if 'dst16' in p.wpan.field_names:
                features['Mac Addr'].add(p.wpan.dst16)
            if 'dst64' in p.wpan.field_names:
                features['Mac Addr'].add(p.wpan.dst64)
            if 'src16' in p.wpan.field_names:
                features['Mac Addr'].add(p.wpan.src16)
            if 'src64' in p.wpan.field_names:
                features['Mac Addr'].add(p.wpan.src64)
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
