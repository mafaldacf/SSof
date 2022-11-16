class Flow:
    def __init__(self):
        self.tainted_nodes = {}
        self.variables = {} # dictionary where key values are either True (initialized) or False (not unitialized)
        self.flow_paths = list() # list with lineno of different flow path nodes inside a loop node being analyzed
        self.loops = list() # list with lineno of loop nodes that are being analyzed
        self.implicit_label = () # current label according to an existing (or not) implicit flow
        self.sanitizers = []
        self.assign = False
        self.target = []
    
    def update_implicit_label(self, label, policy):
        self.implicit_label = policy.least_upper_bound(self.implicit_label, label)
    
    def add_tainted_node(self, id, label):
        self.tainted_nodes[id] = label
        
    def add_initialized_variables(self, id):
        self.variables[id] = True
    
    def add_sanitizer(self, sanitizer):
        if sanitizer not in self.sanitizers:
            self.sanitizers.append(sanitizer)
            
    def is_initialized(self, id):
        if id in self.variables:
            return self.variables[id]
        
        # add variable to dictionary
        self.variables[id] = False
        return False
    
    def is_declared_variable(self, id):
        return id in self.variables
    
    def get_tainted_label(self, id):
        if id in self.tainted_nodes:
            return self.tainted_nodes[id]
        return None
    
    # verify if current path is inside an outer loop
    def is_in_loop(self, lineno):
        if len(self.flow_paths) > 0 and len(self.loops) > 0 and self.loops[-1] != lineno:
            return True
        return False
    
    # Save node as a new flow path (usefull for Loop Node's)
    def add_new_path_to_loop(self, node):
        if node.lineno not in self.flow_paths:
            self.flow_paths[-1].append(node.lineno)
            
    def add_new_loop(self, loop_lineno):
        self.flow_paths.append(list())
        self.loops.append(loop_lineno)
        
    def remove_loop(self):
        self.flow_paths.pop()
        self.loops.pop()
    
    def __repr__(self):
        return 'Flow: Tainted_nodes=' + self.tainted_nodes.__repr__() + ', Variables=' + self.variables.__repr__()
