from NetworkFlowMeter.Feature import FeatureExtractor
from NetworkFlowMeter.NetworkTyping import Features
from NetworkFlowMeter.Flow import Flow


class FeatureExtractorTemplate(FeatureExtractor):
    def __init__(self):
        super(FeatureExtractorTemplate, self).__init__(enable=True)

    def extract(self, flow: Flow) -> Features:
        pass


# FeatureExtractorTemplate()
