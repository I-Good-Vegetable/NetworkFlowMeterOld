from pyprobar import probar
from NetworkFlowMeter.Settings import progressBarColor
from NetworkFlowMeter.NetworkTyping import AnyStr, List, Tuple, Flows, Features, FeatureSet
from NetworkFlowMeter.Flow import Flow


class FeatureExtractor(object):
    extractors = list()

    def __init__(self):
        """
        This supper class method must be invoked at the end of sub-class init function
        """
        if self not in FeatureExtractor.extractors:
            FeatureExtractor.extractors.append(self)
        self.featureNames = list(self.extract(Flow('EMPTY 0 0 0 0')).keys())

    @staticmethod
    def existingExtractors():
        for index, extractor in enumerate(FeatureExtractor.extractors):
            print(f'{index + 1}. {extractor}')

    def name(self) -> AnyStr:
        return self.__class__.__name__

    def __str__(self):
        return f'{self.name()}: \n' \
               f'    {"; ".join(self.featureNames)}'

    @staticmethod
    def clear():
        FeatureExtractor.extractors = list()

    @staticmethod
    def remove(extractorName):
        for extractor in FeatureExtractor.extractors:
            if str(extractor) == extractorName:
                FeatureExtractor.extractors.remove(extractor)

    def extract(self, flow: Flow) -> Features:
        raise NotImplementedError


def flow2feature(flow: Flow) -> Features:
    features = dict()
    for featureExtractor in FeatureExtractor.extractors:
        tmpFeatures = featureExtractor.extract(flow)
        features.update(tmpFeatures)
    return features


def generateFeatures(flows: Flows) -> Tuple[FeatureSet, List[AnyStr]]:
    """Generate Features According to Flows"""
    featureSet: FeatureSet = list()
    for flow in probar(flows, color=progressBarColor):
        flow: Flow
        features = flow2feature(flow)
        featureSet.append(features)
    featureNames = list(featureSet[0].keys())
    return featureSet, featureNames
