from ..NetworkTyping import Features
from ..Flow import Flow
from ..Feature import FeatureExtractor


class MacAddrInfo(FeatureExtractor):
    def extract(self, flow: Flow) -> Features:
        features = {
            'Mac Addr': set()
        }
        for p in flow.packets:
            if 'dst16' in p.wpan.field_names:
                features['Mac Addr'].add(p.wpan.dst16)
            if 'dst64' in p.wpan.field_names:
                features['Mac Addr'].add(p.wpan.dst64)
            if 'src16' in p.wpan.field_names:
                features['Mac Addr'].add(p.wpan.src16)
            if 'src64' in p.wpan.field_names:
                features['Mac Addr'].add(p.wpan.src64)
        return features


MacAddrInfo()
