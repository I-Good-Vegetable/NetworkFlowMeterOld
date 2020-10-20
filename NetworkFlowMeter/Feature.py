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

    # activate = enable
    # inactivate = disable

    @staticmethod
    def getAllFeatureNames():
        allFeatureNames = list()
        for extractor in FeatureExtractor.extractors:
            allFeatureNames.extend(extractor.featureNames)
        return allFeatureNames

    @staticmethod
    def printExistingExtractors():
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
                     charMin=True, charMax=True, charSum=True, charAve=True, charStd=True,
                     defaultValue: float = 0) -> Dict:
    numList = [float(n) for n in numList]
    baseName = '' if baseName is None or baseName == '' else f'{baseName} '
    if charMin:
        d[f'{baseName}Min'] = min(numList) if len(numList) >= 1 else defaultValue
    if charMax:
        d[f'{baseName}Max'] = max(numList) if len(numList) >= 1 else defaultValue
    if charSum:
        d[f'{baseName}Sum'] = sum(numList) if len(numList) >= 1 else defaultValue
    if charAve:
        d[f'{baseName}Ave'] = statistics.mean(numList) if len(numList) >= 1 else defaultValue
    if charStd:
        d[f'{baseName}Std'] = statistics.stdev(numList) if len(numList) >= 2 else defaultValue
    return d


def addBidirFlowMathChar2Features(d: Features, flow: Flow, baseName: str,
                                  pktOperator: Optional[Callable[[Packet], Any]] = None,
                                  pktListOperator: Optional[Callable[[PacketList], Collection[Any]]] = None,
                                  defaultValue: float = 0) -> Features:
    """
    Get a number from pktOperator;
    Store it in a list;
    Calculate mathematical characteristics of the list;
    Add mathematical characteristics to the dict
    Bidirectional (Forward(Fwd) Backward(Bwd) Total(Flow))

    Since Flow = Fwd + Bwd, we do not specifically iterate flow packets again.
    Instead, we directly merge Fwd and Bwd list together to form Flow List.
    Hence we require pktOperator or pktListOperator to be linear, that is,
    if operator([l1 l2]) = [operator([l1]) operator([l2])]

    :param d: a dict
    :param flow: Flow
    :param baseName: 'Fwd/Bwd/Flow+baseName+MathCharName'
    :param pktOperator: (Linear) Take packet as an input, and return something which can be convert to float/int
    :param pktListOperator: (Linear) Take a packet list as an input, return a collection (list)
    :param defaultValue: Default value if math char is not available
    :return: The dict
    """
    if pktOperator is None and pktListOperator is None:
        raise Exception('pktOperator and pktListOperator can not be None at the same time')
    fwdList, bwdList, pktList = None, None, None
    if pktOperator is not None:
        fwdList = [pktOperator(p) for p in flow.forwardPackets]
        bwdList = [pktOperator(p) for p in flow.backwardPackets]
    if pktListOperator is not None:
        fwdList = pktListOperator(flow.forwardPackets)
        bwdList = pktListOperator(flow.backwardPackets)
    pktList = fwdList + bwdList
    addMathChar2Dict(d, f'Fwd {baseName}', fwdList, defaultValue=defaultValue)
    addMathChar2Dict(d, f'Bwd {baseName}', bwdList, defaultValue=defaultValue)
    addMathChar2Dict(d, f'Flow {baseName}', pktList, charSum=False, defaultValue=defaultValue)
    return d


def addBidirFlowCountSpeed2features(d: Features, flow: Flow, baseName: str,
                                    counter: Callable[[PacketList], Any],
                                    countFlow=False):
    """
    Take a number from counter;
    Calculate the speed of it by dividing the number by duration (second);
    Add count and the speed to the dict;
    Bidirectional (Forward(Fwd) Backward(Bwd))

    Since Count(Flow) = Count(Fwd) + Count(Bwd), Count(Flow) is linear dependent to Fwd and Bwd.
    Therefore, as default setting, we do not count total flow flags.

    :param d: A dict
    :param flow: Flow
    :param baseName: 'Fwd/Bwd/Flow+baseName+Num/Speed'
    :param counter: (Linear) Take a packet list as a input, and return something which can be convert to float/int
    :param countFlow: if it is true, then we will calculate total flow flags
    :return: The dict
    """
    fwdCount, bwdCount = \
        counter(flow.forwardPackets), counter(flow.backwardPackets)
    fwdCount, bwdCount = float(fwdCount), float(bwdCount)
    duration = flow.duration(f='s')
    if duration == 0:
        fwdSpeed, bwdSpeed = 0.0, 0.0
    else:
        fwdSpeed, bwdSpeed = fwdCount / duration, bwdCount / duration
    d[f'Fwd {baseName} Num'], d[f'Bwd {baseName} Num'], d[f'F/Bwd {baseName} Ratio'] = \
        fwdCount, bwdCount, fwdCount / bwdCount if bwdCount != 0 else 0
    d[f'Fwd {baseName} Speed'], d[f'Bwd {baseName} Speed'] = fwdSpeed, bwdSpeed
    if countFlow:
        flowCount = fwdCount + bwdCount
        flowSpeed = flowCount / duration if duration != 0 else 0
        d[f'Flow {baseName} Num'], d[f'Flow {baseName} Speed'] = flowCount, flowSpeed
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
    return featureSet, FeatureExtractor.getAllFeatureNames()
