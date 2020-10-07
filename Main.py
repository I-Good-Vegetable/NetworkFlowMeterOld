from NetworkFlowMeter.TicToc import timing, Timer
from NetworkFlowMeter import *


@timing
def main():
    pcapPath = 'Data/filtered.pcap'
    csvFile = 'Data/filtered.csv'
    pcap2csv(pcapPath)
    pass


if __name__ == '__main__':
    main(timerPrefix='Total Time Costs: ', timerBeep=False)
