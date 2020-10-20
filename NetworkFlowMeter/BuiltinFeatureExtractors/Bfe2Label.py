from NetworkFlowMeter.Feature import FeatureExtractor
from NetworkFlowMeter.Flow import Flow
from NetworkFlowMeter.NetworkTyping import FeatureSet, Features, AttackRecords
from NetworkFlowMeter.Labelling import compileAttackRecords, getLabel


class Label(FeatureExtractor):
    def __init__(self, attackRecords: AttackRecords,
                 defaultLabel: str = 'NormalTraffic'):
        self.compiledRecords = compileAttackRecords(attackRecords)
        self.defaultLabel = defaultLabel
        super(Label, self).__init__()

    def extract(self, flow: Flow) -> Features:
        features = {
            'Label': getLabel(flow.sessionKeyInfo, flow.readableInitPacketTs(),
                              self.compiledRecords, self.defaultLabel)
        }
        return features
