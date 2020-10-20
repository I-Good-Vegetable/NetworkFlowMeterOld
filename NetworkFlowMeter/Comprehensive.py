from pathlib import Path
from pyprobar import probar

from NetworkFlowMeter.BuiltinFeatureExtractors.Bfe1BasicFlowInfo import sortFeatures
from NetworkFlowMeter.Settings import progressBarColor
from NetworkFlowMeter.IO import readPackets, featureSet2csv
from NetworkFlowMeter.TicToc import Timer
from NetworkFlowMeter.Session import defaultBidirectionalSessionExtractor
from NetworkFlowMeter.Flow import Flow
from NetworkFlowMeter.Feature import flow2feature, FeatureExtractor
from NetworkFlowMeter.NetworkTyping import Callable, Optional, AnyStr, List, Tuple, Packet, FeatureSet


def packets2features(packets: List[Packet], direction: AnyStr = 'bidirectional',
                     sessionExtractor: Optional[Callable[[Packet], Tuple[AnyStr, AnyStr]]] = None,
                     flowTimeout=Flow.defaultFlowTimeout,
                     activityTimeout=Flow.defaultActivityTimeout) -> Tuple[FeatureSet, List[AnyStr]]:
    """
    Take packets as input generate features
    :param packets: A list of packets
    :param direction: unidirectional or bidirectional
    :param sessionExtractor: session extractor
    :param flowTimeout: flow timeout in microseconds
    :param activityTimeout: activity timeout in microseconds
    :return: (Feature Set, Feature Names)
    """
    aliveFlows, flows = dict(), list()
    featureSet: FeatureSet = list()
    Flow.defaultFlowTimeout, Flow.defaultActivityTimeout = flowTimeout, activityTimeout
    if sessionExtractor is None:
        # use bidirectional session extractor as default
        # unidirectional session key is the bidirectional session key + direction
        sessionExtractor = defaultBidirectionalSessionExtractor
    for p in probar(packets, color=progressBarColor):
        sessionKey, pDirection = sessionExtractor(p)
        if direction == 'unidirectional':
            sessionKey = f'{sessionKey} {pDirection}'
        # add additional attribute on packet to mark the direction
        p.pDirection = pDirection

        if sessionKey not in aliveFlows:
            aliveFlows[sessionKey] = Flow(sessionKey, p)
        else:
            flow = aliveFlows[sessionKey]
            success = flow.add(p)
            if not success:
                features = flow2feature(flow)
                featureSet.append(features)
                aliveFlows[sessionKey] = Flow(sessionKey, p)
    # flush alive flows to flows
    for sessionKey, aliveFlow in aliveFlows.items():
        features = flow2feature(aliveFlow)
        featureSet.append(features)
    return featureSet, list(featureSet[0].keys())


def pcap2csv(pcapPath=None, csvPath=None, direction: AnyStr = 'bidirectional',
             sessionExtractor: Optional[Callable[[Packet], Tuple[AnyStr, AnyStr]]] = None,
             flowTimeout=Flow.defaultFlowTimeout,
             activityTimeout=Flow.defaultActivityTimeout):
    """
    Take PCAP/PCAPNG as input, and generate CSV file
    :param pcapPath: PCAP/PCAPNG file path; if it is None, user need to input the file path
    :param csvPath: CSV file path;
                    if it is None, CSV file will be generated in the same folder
                    as the one of PCAP file with same name
    :param direction: unidirectional or bidirectional
    :param sessionExtractor: session extractor
    :param flowTimeout: flow timeout in microseconds
    :param activityTimeout: activity timeout in microseconds
    :return:
    """
    if pcapPath is None:
        pcapPath = input('PCAP/PCAPNG File Path: ')
    pcapPath = Path(pcapPath)
    if csvPath is None:
        csvPath = pcapPath.with_suffix('.csv')
    print(f'{len(FeatureExtractor.extractors)} Feature Extractors are Invoked: ')
    FeatureExtractor.printExistingExtractors()
    with Timer(f'{pcapPath} Resolved'):
        print(f'Resolving {pcapPath}')
        packets = readPackets(pcapPath)
    with Timer('Features Generated'):
        print('Generating Features')
        featureSet, featureNames = packets2features(packets, direction, sessionExtractor, flowTimeout, activityTimeout)
    with Timer('Features Sorted'):
        print('Soring Features')
        featureSet = sortFeatures(featureSet)
    with Timer(f'Features Saved to {csvPath}'):
        print(f'Saving Features to {csvPath}')
        featureSet2csv(csvPath, featureSet)
    print(f'Flows: {len(featureSet)}')
    print(f'Features ({len(featureNames)}): \n'
          f'    {"; ".join(featureNames)}')
