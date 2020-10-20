import re
from collections import defaultdict

import pandas as pd

from NetworkFlowMeter.NetworkTyping import SessionKeyInfo, AttackRecords, CompiledRecords

maxTs = '23:59:59.999999'


def withinTsPair(startTs, endTs, ts):
    """
    Check whether the ts is within the given timestamp pair
    :param startTs: start ts
    :param endTs: end ts
    :param ts: ts
    :return: True: ts is within the time pair; False: otherwise
    """
    startTs = pd.to_datetime(startTs).time()
    if endTs == 'infinity':
        endTs = maxTs
    endTs = pd.to_datetime(endTs).time()
    ts = pd.to_datetime(ts).time()
    if startTs <= ts < endTs:
        return True
    return False


def getLabel(sessionKeyInfo: SessionKeyInfo, ts: str,
             compiledRecords: CompiledRecords, defaultLabel: str = 'NormalTraffic') -> str:
    """
    Get flow label according to session info and timestamp
    :param sessionKeyInfo: a tuple of (protocol sIP sPort dIP dPort)
    :param ts: a string of timestamp
    :param compiledRecords: compiled attack bases by compileAttackRecords
    :param defaultLabel: default label
    :return: label; if this function cannot find any label, it will return default label
    """
    sessionKeyInfo = ' '.join(sessionKeyInfo)

    for sessionKeyPattern, tsList in compiledRecords.items():
        if re.match(sessionKeyPattern, sessionKeyInfo) is not None:
            tsList = compiledRecords[sessionKeyPattern]

            for startTs, endTs, label in tsList:
                if withinTsPair(startTs, endTs, ts):
                    return label
    return defaultLabel


def compileAttackRecords(attackRecords: AttackRecords) -> CompiledRecords:
    """
    Reformat attack records to labelling bases
    attack records format/template:
    [
        {
            'direction': 'unidirectional/bidirectional',
            'protocol': 'UDP/TCP',
            'src ip': '',
            'dst ip': '',
            'start ts': '',
            'end ts': '',
            'label': 'InitialAttack/Reconnaissance/LateralMovement/Pivoting/DataExfiltration',
            'port list': [(,)],
        },
    ]
    labelling bases format:
    {
        'protocol sIP sPort dIP dPort': [(start ts, end ts, label),]
    }
    :param attackRecords: attack records
    :return: compiled records
    """
    compiledRecords = defaultdict(list)
    for attack in attackRecords:
        for sPort, dPort in attack['port list']:
            sessionKeyPattern = f"({attack['protocol']}) " \
                                f"({attack['src ip']}) ({sPort}) " \
                                f"({attack['dst ip']}) ({dPort})"
            compiledRecords[sessionKeyPattern].append((attack['start ts'], attack['end ts'], attack['label']))
            if attack['direction'] == 'bidirectional':
                sessionKeyPattern = f"({attack['protocol']}) " \
                                    f"({attack['dst ip']}) ({dPort}) " \
                                    f"({attack['src ip']}) ({sPort})"
                compiledRecords[sessionKeyPattern].append((attack['start ts'], attack['end ts'], attack['label']))

    return dict(compiledRecords)
