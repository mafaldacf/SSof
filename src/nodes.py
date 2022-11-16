#!/usr/bin/python3

from output_vulnerabilities import *
from flow import *
from copy import deepcopy

class Node:
    def __init__(self,lineno=None,parent=None):
        self.entry = None #TODO
        self.edges = None #TODO
        self.exit = None #TODO
        if parent == None:
            self.parents = list()
        else:
            self.parents = parent
        self.children = list()
        self.label = ()
        self.sanitizers = []
        self.tainted = False
        self.lineno = lineno
        
    def __repr__(self):
        return 'Node'

    def add_parent(self, parent_nodes):
        # append last body node and orelse node of if node
        if type(parent_nodes) == If_Node and parent_nodes.has_children():
            
            if parent_nodes.has_body():
                last_body_nodes = self.get_last_children(parent_nodes.children[0], list())
                for node in last_body_nodes:
                    self.add_parent(node)
                
            if parent_nodes.has_orelse():
                last_orelse_nodes = self.get_last_children(parent_nodes.children[1], list())
                for node in last_orelse_nodes:
                    self.add_parent(node)
        
        # append last body node if inside the same While Node to create a loop or append last orelse node
        elif (type(parent_nodes) == While_Node or type(parent_nodes) == For_Node) and parent_nodes.has_children():
            if parent_nodes.has_body():
                last_body_nodes = self.get_last_children(parent_nodes.children[0], list())
            
            # if node is the last body node of the current parent node   
            if self == last_body_nodes[0] and parent_nodes.has_body():
                self.add_parent(parent_nodes)
    
            elif parent_nodes.has_orelse():
                last_orelse_nodes = self.get_last_children(parent_nodes.children[1], list())
                for node in last_orelse_nodes:
                    self.add_parent(node)
                
        # non control flow node        
        else:
            self.parents.append(parent_nodes)
    
    def add_children(self, children_nodes):
        self.children.append(children_nodes)
            
    # Return inner nodes without children
    def get_last_children(self, node, last_children):
        if len(node.children) == 1:
            self.get_last_children(node.children[-1], last_children)
        elif len(node.children) == 2:
            self.get_last_children(node.children[-2], last_children)
            self.get_last_children(node.children[-1], last_children)
        else:
            last_children.append(node)
        return last_children
    
    def set_label(self, label):
        self.label = label
        
        # Set tainted if label includes vulnerable sources
        if len(label) > 0:
            self.tainted = True
    
    def is_tainted(self):
        return len(self.label) > 0
    
    def compute_label(self, policy, flow, initialized=True):
        
        # id corresponds to a security level or an non initialized variable
        if self.id in policy.get_security_levels() or not initialized:
            self.label = self.id
            self.tainted = True
            
        # node is untainted
        else:
            self.label = ()
            
        # check if current id was previously tainted and compute the
        # least upper bound between previous label and new label
        tainted_label = flow.get_tainted_label(self.id)
        if tainted_label != None:
            self.label = policy.least_upper_bound(self.label, tainted_label)
            self.tainted = True
        
    def get_label_str(self):
        return ''.join(self.label)
    
    def eval_children(self, policy, pattern, vulnerabilities, flow, parent=None):
        # evaluate possible flows
        for child in self.children:
            child.eval(policy, pattern, vulnerabilities, flow, parent)

    def add_direct_parent(self, parent=None):
        if parent != None and type(self.parents) == list and len(self.parents) == 0:
            self.parents.append(parent)
            
    # update current node's label in case of an existing implicit flow
    def compute_implicit_label(self, policy, pattern, flow):
        if pattern.implicit == 'yes':
            self.set_label(policy.least_upper_bound(flow.implicit_label, self.label))
    
    def eval(self, policy, pattern, vulnerabilities, flow, parent=None):
        self.add_direct_parent(parent)
        self.compute_implicit_label(policy, pattern, flow)
        for child in self.children:
            child.eval(policy, pattern, vulnerabilities, flow, self)

class Entry_Node(Node):
    def __init__(self, parent=None):
        super().__init__(parent)
        
    def __repr__(self):
        return 'Entry Node'
        
class Exit_Node(Node):
    def __init__(self, parent=None):
        super().__init__(parent)
        
    def __repr__(self):
        return 'Exit Node'

class Constant_Node(Node):
    def __init__(self, lineno, parent, value): # value: str
        super().__init__(lineno, parent)
        self.value = value
    
    def eval(self, policy, pattern, vulnerabilities, flow, parent=None):
        self.add_direct_parent(parent)
        self.label = ()
        self.compute_implicit_label(policy, pattern, flow)
        return self.label
    
    def __repr__(self):
        return 'Constant Node [Label=' + self.get_label_str() + ']: ' + self.value.__repr__()

class Name_Node(Node):
    def __init__(self, lineno, parent, id, ctx): # id: str, ctx: str ('Store'|'Load')
        super().__init__(lineno, parent)
        self.id = id
        self.ctx = ctx
    
    # node corresponds to a variable if it isn't a function id
    def is_variable(self):
        if type(self.parents) == list and len(self.parents) == 1 and type(self.parents[0]) != Call_Node:
            return True
            
        elif type(self.parents) == list and len(self.parents) == 1 and type(self.parents[0]) == Call_Node:
            return not self.id == self.parents[0].func.id
                
        return False
    
    def eval(self, policy, pattern, vulnerabilities, flow, parent=None):
        self.add_direct_parent(parent)
        sanitizers = list()
        flow_is_sanitized=False

        # if node corresponds to a declared variable, compute label according to its initialization state
        if self.is_variable():
            initialized = flow.is_initialized(self.id)
            self.compute_label(policy, flow, initialized)
        else:
            self.compute_label(policy, flow)
        
        self.compute_implicit_label(policy, pattern, flow)
        
        for target in flow.target:
            if type(target) == Name_Node:
                for sanitizer in flow.sanitizers:
                    if target.id in sanitizer[2]:
                        sanitizers.append(sanitizer)
        
        if pattern.is_sink(self.id) and self.tainted and type(parent) == Call_Node and parent.func.id in policy.get_security_levels():
            self.label += (parent.func.id, )
            vulnerabilities.add_vulnerability(self.id, self.label, pattern, flow, sanitizers)
            
        return self.label

    def __repr__(self):
        return 'Name Node [Label=' + self.get_label_str() + '] id: ' + self.id
    
class Expr_Node(Node):
    def __init__(self, lineno, parent, value): # value: Node
        super().__init__(lineno, parent)
        self.value = value
    
    # Gets the level of the variable
    def eval(self, policy, pattern, vulnerabilities, flow, parent=None):
        self.add_direct_parent(parent)
        self.set_label(self.value.eval(policy, pattern, vulnerabilities, flow, self))
        self.compute_implicit_label(policy, pattern, flow)
        
        self.eval_children(policy, pattern, vulnerabilities, flow, self)
        return self.label
    
    def __repr__(self):
        return 'Expr Node [Label=' + self.get_label_str() + ']: value: {' + self.value.__repr__() + '}'


class BinOp_Node(Node):
    def __init__(self, lineno, parent, left, right, op): # left: Node, right: Node, op: str
        super().__init__(lineno, parent)
        self.left = left
        self.right = right
        self.op = op
    
    # Gets the least upper bound of between left and right node  
    def eval(self, policy, pattern, vulnerabilities, flow, parent=None):
        self.add_direct_parent(parent)
        self.set_label(policy.least_upper_bound(self.left.eval(policy, pattern, vulnerabilities, flow, self), self.right.eval(policy, pattern, vulnerabilities, flow, self)))
        self.compute_implicit_label(policy, pattern, flow)
        return self.label
    
    def __repr__(self):
        return 'BinOp Node [Label=' + self.get_label_str() + '] left: {' + self.left.__repr__() + '}, right: {' + self.right.__repr__() + '}, op: ' + self.op + ''

class Compare_Node(Node):
    def __init__(self, lineno, parent, comparators, left, ops):
        super().__init__(lineno, parent)
        self.comparators = comparators
        self.left = left
        self.ops = ops
        
    # Get least upper bound between left and comparators
    def eval(self, policy, pattern, vulnerabilities, flow, parent=None):
        self.add_direct_parent(parent)
        
        # Get least upper bound between all arguments
        if len(self.comparators) > 0:
            label_prev_comp = self.comparators[0].eval(policy, pattern, vulnerabilities, flow, self)
            for comparator in self.comparators:
                comparator_label = comparator.eval(policy, pattern, vulnerabilities, flow, self)
                label_prev_comp = policy.least_upper_bound(label_prev_comp, comparator_label)
            
            left_label = self.left.eval(policy, pattern, vulnerabilities, flow, self)
            self.set_label(policy.least_upper_bound(label_prev_comp, left_label))
        
        else:
            self.set_label(self.left.eval(policy, pattern, vulnerabilities, flow, self))
            
        self.compute_implicit_label(policy, pattern, flow)
            
        return self.label
        
    def __repr__(self):
        return 'Compare Node [Label=' + self.get_label_str() + '] comparators: {' + self.comparators.__repr__() + '}, left: {' + self.left.__repr__() + '}, ops: {' + self.ops.__repr__() + '}'


class Call_Node(Node):
    def __init__(self, lineno, parent, args, func): # args: list of Node's, func: Name_Node
        super().__init__(lineno, parent)
        self.args = args
        self.func = func
    
    # Get least upper bound between arguments and function
    def eval(self, policy, pattern, vulnerabilities, flow, parent=None):
        self.add_direct_parent(parent)

        flow_is_sanitized = False
        sanitizers = list()
        sanitizers_in_args = list()
        
        # Get least upper bound between all arguments
        if len(self.args) > 0:
            label_prev_arg = self.args[0].eval(policy, pattern, vulnerabilities, flow, self)
            for arg in self.args:
                arg_label = arg.eval(policy, pattern, vulnerabilities, flow, self)
                label_prev_arg = policy.least_upper_bound(label_prev_arg, arg_label)
                if type(arg) == Name_Node:
                    if pattern.is_sanitizer(arg.id) and arg.tainted:
                        sanitizers_in_args.append(arg.id)
                        
                    for sanitizer in flow.sanitizers:
                        if arg.id in sanitizer[2]:
                            flow_is_sanitized=True
                            sanitizers.append(sanitizer)
                        if flow.assign and flow.loops != []:
                            for target in flow.target:
                                sanitizer[2].append(target.id)

                if type(arg) == Call_Node and arg.tainted:
                    if pattern.is_sanitizer(arg.func.id):
                        flow_is_sanitized=True
                        for sanitizer in flow.sanitizers:
                            if arg.func.id in sanitizer[0]:
                                sanitizers.append(sanitizer)
                        sanitizers_in_args.append(arg.func.id)
                
            func_label = self.func.eval(policy, pattern, vulnerabilities, flow, self)
            self.set_label(policy.least_upper_bound(label_prev_arg, func_label))
        
        else:
            self.set_label(self.func.eval(policy, pattern, vulnerabilities, flow, self))


        self.compute_implicit_label(policy, pattern, flow)
        # Found a vulnerable flow
        
        if pattern.is_sink(self.func.id) and self.tainted:
            vulnerabilities.add_vulnerability(self.func.id, self.label, pattern, flow,sanitizers)
        
        if pattern.is_sanitizer(self.func.id) and self.tainted:
            targets = list()
            len_san_args = len(sanitizers_in_args)
            
            for sanitizer in flow.sanitizers[::-1]:
                for san_arg in sanitizers_in_args:
                    if san_arg in sanitizer[0] and len_san_args != 0:
                        sanitizer[0].append(self.func.id)
                        len_san_args -= 1
            
            if flow.assign:
                for target in flow.target:
                    targets.append(target.id)
            
            flow.add_sanitizer([[self.func.id],self.label,targets])
        
        self.eval_children(policy, pattern, vulnerabilities, flow, self)
        return self.label
    
    def __repr__(self):
        return 'Call Node [Label=' + self.get_label_str() + '] args: {' + self.args.__repr__() + '}, ' + 'func: {' + self.func.__repr__() + '}'


class Attribute_Node(Node):
    def __init__(self, lineno, parent, attr, ctx, value): # attr: str, ctx: str ('Store'|'Load'), value: Name_Node
        super().__init__(lineno, parent)
        self.id = id
        self.ctx = ctx
        self.value = value
    
    # Gets the least upper bound between the attribute itself and the value
    def eval(self, policy, pattern, vulnerabilities, flow, parent=None):
        self.add_direct_parent(parent)
        self.compute_label(policy, flow)
        value_label = self.value.eval(policy, pattern, vulnerabilities, flow, self)
        self.set_label(policy.least_upper_bound(self.label, value_label))
        self.compute_implicit_label(policy, flow)
        return self.label
    
    def __repr__(self):
        return 'Attribute Node [Label=' + self.get_label_str() + '] attr: {' + self.id + '}, value: {' + self.value.__repr__() + '}'

class Assign_Node(Node):
    def __init__(self, lineno, parent, targets, value): # targets: list of Name_Node's, value: Node
        super().__init__(lineno, parent)
        self.targets = targets
        self.value = value
        self.lineno = lineno
        
    def eval(self, policy, pattern, vulnerabilities, flow, parent=None):
        self.add_direct_parent(parent)

        flow.assign = True
        flow.target = self.targets
        self.set_label(self.value.eval(policy, pattern, vulnerabilities, flow, self))

        self.compute_implicit_label(policy, pattern, flow)

        
        # store initialized targets' id
        for target in self.targets:
            flow.add_initialized_variables(target.id)
        
        # evaluate targets
        for target in self.targets:
            target.eval(policy, pattern, vulnerabilities, flow, self)
        
        # store tainted nodes and their corresponding vulnerable sources
        if self.value.tainted:
            for target in self.targets:
                target.tainted = True
                label = policy.least_upper_bound(self.label, target.label) # useful when target was previously tainted
                flow.add_tainted_node(target.id, label)
                
                for sanitizer in flow.sanitizers:
                    if type(self.value) == Name_Node and self.value.id in sanitizer[2]:
                        sanitizer[2].append(target.id)
                        
                sanitizers=list()
                # Found a vulnerable flow
                if pattern.is_sink(target.id) and self.tainted:
                    for sanitizer in flow.sanitizers:
                        if target.id in sanitizer[2]:
                            sanitizers.append(sanitizer)

                    vulnerabilities.add_vulnerability(target.id, self.label, pattern, flow, sanitizers)

        flow.assign = False
        flow.target = []
        
        self.eval_children(policy, pattern, vulnerabilities, flow, self)
        return self.label
    
    def __repr__(self):
        return 'Assign Node [Label=' + self.get_label_str() + '] targets: {' + self.targets.__repr__() + '}, value: {' + self.value.__repr__() + '}'
    
class Break_Node(Node):
    def __init__(self, lineno, parent): 
        super().__init__(lineno, parent)
    
    def eval(self, policy, pattern, vulnerabilities, flow, parent=None):
        self.add_direct_parent(parent)
        self.label = policy.top()
        self.compute_implicit_label(policy, pattern, flow)
        self.eval_children(policy, pattern, vulnerabilities, flow, self)
        return self.label
    
class Continue_Node(Node):
    def __init__(self, lineno, parent): 
        super().__init__(lineno, parent)
    
    def eval(self, policy, pattern, vulnerabilities, flow, parent=None):
        self.add_direct_parent(parent)
        self.label = policy.top()
        self.compute_implicit_label(policy, pattern, flow)
        return self.label

class Control_Flow_Node(Node):
    def __init__(self, lineno, test=None):
        super().__init__(lineno)
        self.test = test
    
    def has_children(self):
        return len(self.children) > 0
    
    def has_body(self):
        return len(self.children) > 0
    
    def has_orelse(self):
        return len(self.children) > 1
    
    def get_body(self):
        return self.children[0]
    
    def get_orelse(self):
        return self.children[1]
    
    # Append children either to last body branch node (0) or last orelse branch node (1)
    def add_children_to_branch(self, children_nodes, branch):
        last_children = self.get_last_children(self.children[branch], list())
        for child in last_children:
            child.add_children(children_nodes)

class If_Node(Control_Flow_Node):
    def __init__(self, lineno, test):
        super().__init__(lineno, test)
    
    def add_children(self, children_nodes, is_first_branch_node=False):
        # Append children inside a given If Node's branch flow
        if is_first_branch_node:
            super().add_children(children_nodes)
            
        # Append children to last nodes of both body and orelse branches of an already built If Node
        else:
            self.add_children_to_branch(children_nodes, 0) # body branch
            if self.has_orelse():
                self.add_children_to_branch(children_nodes, 1) # orelse branch
            else:
                super().add_children(children_nodes)
                
    # evaluate possible flows
    def eval(self, policy, pattern, vulnerabilities, flow, parent=None):
        self.add_direct_parent(parent)
        
        test_label = self.test.eval(policy, pattern, vulnerabilities, flow)
        self.set_label(policy.least_upper_bound(test_label, self.label))
        
        self.compute_implicit_label(policy, pattern, flow)
        flow.update_implicit_label(self.label, policy)
        
        for child in self.children:
            if flow.is_in_loop(self.lineno):
                flow.add_new_path_to_loop(child)
            child.eval(policy, pattern, vulnerabilities, deepcopy(flow), self)
        return self.label
    
    def __repr__(self):
        return 'If Node [Label=' + self.get_label_str() + '] test: {' + self.test.__repr__() + '}'

class Loop_Node(Control_Flow_Node):
    def __init__(self, lineno, test):
        super().__init__(lineno, test)
        self.flow_paths = list()
        self.first_time = True

    def add_children(self, children_nodes, is_first_branch_node=False):
        # Append children inside a given While Node's branch flow or add children as an orelse node
        if is_first_branch_node or not self.has_orelse():
            super().add_children(children_nodes)
            
        # Append children to last nodes of orelse branch of an already built Node
        else:
            self.add_children_to_branch(children_nodes, 1)
    
    # Verify if new flow paths have been added to the flow and add them to the Loop Node flow paths' list
    def compute_new_flow_paths(self, flow):
        new_flows = False
        for node in flow.flow_paths[-1]:
            if node not in self.flow_paths:
                new_flows = True
                self.flow_paths.append(node)
        return new_flows
    
    
    def reset_loop_flows(self, flow):
        self.flow_paths = list()
        self.first_time = True
        flow.remove_loop()
            
    def is_last_loop(self, flow):
        return len(flow.flow_paths[-1]) == len(self.flow_paths)
    
    # Evaluate possible flows
    def eval(self, policy, pattern, vulnerabilities, flow, parent=None):
        self.add_direct_parent(parent)
        
        test_label = self.test.eval(policy, pattern, vulnerabilities, flow)
        self.set_label(policy.least_upper_bound(test_label, self.label))
        
        self.compute_implicit_label(policy, pattern, flow)
        flow.update_implicit_label(self.label, policy)
        
        if self.first_time:
            flow.add_new_loop(self.lineno)
        
        new_flows = self.compute_new_flow_paths(flow)
        
        # first time evaluating Loop Node with given flows ==> diverge evaluation between body and orelse
        if self.first_time or new_flows:
            self.first_time = False
            for child in self.children:
                if flow.is_in_loop(self.lineno):
                    flow.add_new_path_to_loop(child)
                child.eval(policy, pattern, vulnerabilities, deepcopy(flow), self)
        
        # second time evaluating Loop Node with given flows ==> evaluate body
        else:
            if self.is_last_loop(flow):
                self.reset_loop_flows(flow)
            self.children[1].eval(policy, pattern, vulnerabilities, flow, self)
        
        return self.label
    
class While_Node(Loop_Node):
    def __init__(self, lineno, test):
        super().__init__(lineno, test)
    
    def __repr__(self):
        return 'While Node [Label=' + self.get_label_str() + '] test: {' + self.test.__repr__() + '}'

class For_Node(Loop_Node):
    def __init__(self, lineno, iter, target):
        super().__init__(lineno)
        self.iter = iter
        self.target = target
    
    def __repr__(self):
        return 'For Node [Label=' + self.get_label_str() + '] iter: {' + self.iter.__repr__() + '}, target: {' + self.target.__repr__() + '}'
