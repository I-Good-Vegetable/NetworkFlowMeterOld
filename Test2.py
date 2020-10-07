from NetworkFlowMeter.TicToc import timing
import pyshark


@timing
def main():
    pcapPath = 'Data/filtered.pcap'
    csvFile = 'Data/filtered.csv'
    packets = pyshark.FileCapture(pcapPath)
    for packet in packets:
        print('')
    pass


if __name__ == '__main__':
    main(timerPrefix='Total Time Costs: ', timerBeep=False)
