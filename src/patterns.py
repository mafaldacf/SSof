from vulnerability_pattern import *
from types import SimpleNamespace
import json

class Patterns:
    def __init__(self, filename):
        self.patterns = list()
        self.build_patterns(filename)
        
    def build_patterns(self, filename):
        file = open(filename, 'r')
        data = file.read()
        patterns_ast = json.loads(data, object_hook=lambda d: SimpleNamespace(**d))
        file.close()
        for pattern in patterns_ast:
            self.patterns.append(VulnerabilityPattern(pattern.vulnerability, pattern.sources, pattern.sanitizers, pattern.sinks, pattern.implicit))
            
    def __repr__(self):
        return json.dumps([p.__dict__ for p in self.patterns])