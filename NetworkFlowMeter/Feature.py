import statistics

from pyprobar import probar

from NetworkFlowMeter.Flow import Flow
from NetworkFlowMeter.NetworkTyping import Callable, Optional, Collection, AnyStr, Any
from NetworkFlowMeter.NetworkTyping import List, Tuple, Dict, Flows, Features, FeatureSet, Packet, PacketList
from NetworkFlowMeter.Settings import progressBarColor


class FeatureExtractor(object):
    extractors = list()

    def __init__(self, enable=True):
        """
        This supper class method must be invoked at the end of sub-class init function
        """
        if enable:
            self.enable()
        else:
            self.disable()
        self.featureNames = list(self.extract(Flow('EMPTY 0 0 0 0')).keys())

    def enable(self):
        if self not in FeatureExtractor.extractors:
            FeatureExtractor.extractors.append(self)

    def disable(self):
        if self in FeatureExtractor.extractors:
            FeatureExtractor.extractors.remove(self)

    activate = enable
    inactive = disable

    @staticmethod
    def existingExtractors():
        for index, extractor in enumerate(FeatureExtractor.extractors):
            print(f'{index + 1}. {extractor}')

    def name(self) -> AnyStr:
        return self.__class__.__name__

    def __str__(self):
        return f'{self.name()}({len(self.featureNames)}): \n' \
               f'    {"; ".join(self.featureNames)}'

    @staticmethod
    def clear():
        FeatureExtractor.extractors = list()

    @staticmethod
    def remove(extractorName):
        for extractor in FeatureExtractor.extractors:
            if extractor.name() == extractorName:
                FeatureExtractor.extractors.remove(extractor)

    def extract(self, flow: Flow) -> Features:
        raise NotImplementedError


def addMathChar2Dict(d: dict, baseName: Optional[str], numList: Collection[Any],
                     defaultValue: float = 0) -> Dict:
    numList = [float(n) for n in numList]
    baseName = '' if baseName is None else f'{baseName} '
    d[f'{baseName}Min'] = defaultValue
    d[f'{baseName}Max'] = defaultValue
    d[f'{baseName}Sum'] = defaultValue
    d[f'{baseName}Mean'] = defaultValue
    if len(numList) >= 1:
        d[f'{baseName}Min'] = min(numList)
        d[f'{baseName}Max'] = max(numList)
        d[f'{baseName}Sum'] = sum(numList)
        d[f'{baseName}Mean'] = statistics.mean(numList)

    d[f'{baseName}Std'] = defaultValue
    if len(numList) >= 2:
        d[f'{baseName}Std'] = statistics.stdev(numList)
    return d


def addBidirFlowMathChar2Features(d: Features, flow: Flow, baseName: str,
                                  pktOperator: Callable[[Packet], Any],
                                  defaultValue: float = 0) -> Features:
    """
    Get a number from pktOperator;
    Store it in a list;
    Calculate mathematical characteristics of the list;
    Add mathematical characteristics to the dict
    Bidirectional (Forward(Fwd) Backward(Bwd) Total(Flow))

    :param d: a dict
    :param flow: Flow
    :param baseName: 'Fwd/Bwd/Flow+baseName+MathCharName'
    :param pktOperator: Take packet as a input, and return something which can be convert to float/int
    :param defaultValue: Default value if math char is not available
    :return: The dict
    """
    fwdList = [pktOperator(p) for p in flow.forwardPackets]
    bwdList = [pktOperator(p) for p in flow.backwardPackets]
    pktList = [pktOperator(p) for p in flow.packets]
    addMathChar2Dict(d, f'Fwd {baseName}', fwdList, defaultValue)
    addMathChar2Dict(d, f'Bwd {baseName}', bwdList, defaultValue)
    addMathChar2Dict(d, f'Flow {baseName}', pktList, defaultValue)
    return d


def addBidirFlowCountSpeed2features(d: Features, flow: Flow, baseName: str,
                                    counter: Callable[[PacketList], Any]):
    """
    Take a number from counter;
    Calculate the speed of it by dividing the number by duration (second);
    Add count and the speed to the dict;
    Bidirectional (Forward(Fwd) Backward(Bwd) Total(Flow))

    :param d: A dict
    :param flow: Flow
    :param baseName: 'Fwd/Bwd/Flow+baseName+Num/Speed'
    :param counter: Take a packet list as a input, and return something which can be convert to float/int
    :return: The dict
    """
    fwdCount, bwdCount, flowCount =\
        counter(flow.forwardPackets), counter(flow.backwardPackets), counter(flow.packets)
    fwdCount, bwdCount, flowCount = float(fwdCount), float(bwdCount), float(flowCount)
    duration = flow.duration(f='s')
    if duration == 0:
        fwdSpeed, bwdSpeed, flowSpeed = 0, 0, 0
    else:
        fwdSpeed, bwdSpeed, flowSpeed = fwdCount / duration, bwdCount / duration, flowCount / duration
    d[f'Fwd {baseName} Num'], d[f'Bwd {baseName} Num'], d[f'Flow {baseName} Num'] =\
        fwdCount, bwdCount, flowCount
    d[f'Fwd {baseName} Speed'], d[f'Bwd {baseName} Speed'], d[f'Flow {baseName} Speed'] =\
        fwdSpeed, bwdSpeed, flowSpeed
    return d


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
