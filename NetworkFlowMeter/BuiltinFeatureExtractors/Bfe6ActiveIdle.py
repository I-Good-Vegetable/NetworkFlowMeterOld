from NetworkFlowMeter.Feature import FeatureExtractor
from NetworkFlowMeter.Flow import Flow
from NetworkFlowMeter.NetworkTyping import Features


class ActiveIdle(FeatureExtractor):
    def extract(self, flow: Flow) -> Features:
        pass
