import csv
import pickle

from pyshark import FileCapture

from NetworkFlowMeter.NetworkTyping import PacketList, FeatureSet


# Input


def readPackets(filepath) -> PacketList:
    fileCapture = FileCapture(str(filepath))
    packets = [p for p in fileCapture]
    return packets


def readPacketsFromPkl(filepath) -> PacketList:
    with open(filepath, 'rb') as pklFile:
        packetList = pickle.load(pklFile)
    return packetList


# Output


def savePackets2pkl(filepath, packetList: PacketList):
    with open(filepath, 'wb') as pklFile:
        pickle.dump(packetList, pklFile)


def featureSet2csv(filepath: str, featureSet: FeatureSet):
    """Save Feature Set to CSV File"""
    with open(filepath, 'w', newline='') as csvFile:
        featureNames = list(featureSet[0].keys())
        writer = csv.DictWriter(csvFile, featureNames)
        writer.writeheader()
        writer.writerows(featureSet)
