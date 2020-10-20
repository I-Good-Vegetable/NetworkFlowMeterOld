from NetworkFlowMeter.Feature import FeatureExtractor, addBidirFlowMathChar2Features, addBidirFlowCountSpeed2features
from NetworkFlowMeter.Flow import Flow
from NetworkFlowMeter.NetworkTyping import Features


class PacketCounter(FeatureExtractor):
    """
    Count the Number, the Speed and the Length of Forward and Backward Packets
    """

    def extract(self, flow: Flow) -> Features:
        features = dict()
        addBidirFlowMathChar2Features(features, flow, 'Pkt Len', lambda p: p.frame_info.len)
        addBidirFlowCountSpeed2features(features, flow, 'Pkt', len)
        addBidirFlowCountSpeed2features(features, flow, 'Byte',
                                        lambda pl: sum(float(p.frame_info.len) for p in pl))

        return features


PacketCounter()
