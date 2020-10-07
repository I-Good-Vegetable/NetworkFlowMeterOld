import csv
from pyshark import FileCapture
from NetworkFlowMeter.NetworkTyping import List, Packet, FeatureSet


# Input


def readPackets(filepath) -> List[Packet]:
    fileCapture = FileCapture(str(filepath))
    packets = [p for p in fileCapture]
    return packets


# Output


def featureSet2csv(filepath: str, featureSet: FeatureSet):
    """Save Feature Set to CSV File"""
    with open(filepath, 'w', newline='') as csvFile:
        featureNames = list(featureSet[0].keys())
        writer = csv.DictWriter(csvFile, featureNames)
        writer.writeheader()
        writer.writerows(featureSet)
