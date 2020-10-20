from NetworkFlowMeter.Feature import FeatureExtractor
from NetworkFlowMeter.Flow import Flow
from NetworkFlowMeter.NetworkTyping import Features


class SubFlow(FeatureExtractor):
    def generateSubFlows(self, flow):
        pass

    def extract(self, flow: Flow) -> Features:
        pass
