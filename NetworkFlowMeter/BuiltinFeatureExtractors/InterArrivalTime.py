from NetworkFlowMeter.Feature import FeatureExtractor, addBidirFlowMathChar2Features
from NetworkFlowMeter.Flow import Flow
from NetworkFlowMeter.NetworkTyping import Features
from NetworkFlowMeter.Utils import packetTs


class InterArrivalTime(FeatureExtractor):
    def extract(self, flow: Flow) -> Features:
        features = dict()
        addBidirFlowMathChar2Features(features, flow, 'IAT',
                                      pktListOperator=lambda pl: [packetTs(pl[i]) - packetTs(pl[i-1])
                                                                  for i in range(1, len(pl))])
        return features


InterArrivalTime()
