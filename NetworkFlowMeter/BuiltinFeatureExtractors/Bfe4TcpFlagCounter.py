from NetworkFlowMeter.Feature import FeatureExtractor, addBidirFlowCountSpeed2features
from NetworkFlowMeter.Flow import Flow
from NetworkFlowMeter.NetworkTyping import Features


class TcpFlagCounter(FeatureExtractor):
    def extract(self, flow: Flow) -> Features:
        features = dict()
        flagDict = {
            'Flag Ack': lambda p: p.tcp.flags_ack,
            'Flag Cwr': lambda p: p.tcp.flags_cwr,
            'Flag Ecn': lambda p: p.tcp.flags_ecn,
            'Flag Fin': lambda p: p.tcp.flags_fin,
            # NS Flag: Experimental, and May Not be Useful
            'Flag Ns': lambda p: p.tcp.flags_ns,
            'Flag Push': lambda p: p.tcp.flags_push,
            'Flag Res': lambda p: p.tcp.flags_res,
            'Flag Reset': lambda p: p.tcp.flags_reset,
            'Flag Syn': lambda p: p.tcp.flags_syn,
            'Flag Urg': lambda p: p.tcp.flags_urg,
        }
        for flagName, flagExtractor in flagDict.items():
            addBidirFlowCountSpeed2features(features, flow, flagName,
                                            lambda pl: sum([float(flagExtractor(p)) for p in pl
                                                            if flow.protocol() == 'TCP']))
        return features


TcpFlagCounter()
