import json

class Vulnerabilities:
    def __init__(self):
        self.vulnerabilities = list()
    
    def add_vulnerability(self, sink, label, pattern, flow,sanitized_flows):
        is_in = False
        for source in label:
            # create vulnerability if source is in pattern sources or corresponds to a not initialized variable
            if (self.is_valid_source(source, pattern) or self.is_uninitialized_variable(source, flow)) and self.is_valid_sink(sink, pattern):
                for v in self.vulnerabilities:
                    if v.get_vulnerability_name() == pattern.vulnerability_name and v.source == source and v.sink == sink:
                        if sanitized_flows != []:
                            for sanitizer in sanitized_flows:
                                if source in sanitizer[1] and sanitizer[0] not in v.sanitized_flows:
                                    v.add_sanitized_flow(sanitizer[0])
                                    v.unsanitized_flows = "no"
                        is_in = True
                        break
                if not is_in:
                    s = list()
                    unsanitized_flows = "yes"
                    for sanitizer in sanitized_flows:
                        if source in sanitizer[1] and sanitizer[0] not in s:
                            s.append(sanitizer[0])
                            unsanitized_flows = "no"
                    
                    self.vulnerabilities.append(Vulnerability(pattern.vulnerability_name, pattern.inc_index(), source, sink,unsanitized_flows, s))
                is_in = False
    
    def is_uninitialized_variable(self, source, flow):
        return flow.is_declared_variable(source) and not flow.is_initialized(source)
    
    def is_valid_source(self, source, pattern):
        return source in pattern.sources
    
    def is_valid_sink(self, sink, pattern):
        return sink in pattern.sinks
    
    def __repr__(self):
        output = list()
        for v in self.vulnerabilities:
            dict = {"vulnerability": v.vulnerability, "source": v.source, "sink": v.sink, "unsanitized flows": v.unsanitized_flows, "sanitized flows": v.sanitized_flows}
            output.append(dict)
        return json.dumps(output)

class Vulnerability:
    def __init__(self, name, index, source, sink, unsanitized_flows, sanitized_flows = []):
        self.vulnerability = name + '_' + str(index)
        self.source = source
        self.sink = sink
        self.unsanitized_flows = unsanitized_flows
        self.sanitized_flows = sanitized_flows

    def add_sanitized_flow(self, flow):
        self.sanitized_flows.append(flow)

    def get_vulnerability_name(self):
        return self.vulnerability.rsplit('_', 1)[0]
