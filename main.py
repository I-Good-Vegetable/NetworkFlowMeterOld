from TicToc import timing, Timer
from NetworkFlowMeter import *


@timing
def main():
    pcapPath = 'Data/filtered.pcap'
    csvFile = 'Data/filtered.csv'
    with Timer('Packets Loaded'):
        packets = readPackets(pcapPath)
    with Timer('Sessions Generated'):
        sessions = generateSessions(packets, 'bi-directional')
    with Timer('Flows Generated'):
        flows = generateFlows(sessions)
    with Timer('Features Generated'):
        featureSet, featureNames = generateFeatures(flows)
        print(f'Len: {len(featureSet)}')
    with Timer('Features Saved'):
        featureSet2csv(csvFile, featureSet)
    # for key, session in sessions.items():
    #     directions = set()
    #     for p in session:
    #         directions.add(p.pDirection)
    #     print(directions)
    print(len(sessions))
    pass


if __name__ == '__main__':
    main(timerPrefix='Total Time Costs: ', timerBeep=False)
