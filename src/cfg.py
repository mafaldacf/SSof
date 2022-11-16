#!/usr/bin/python3

import json
from types import SimpleNamespace
from cfg import *
from nodes import *
from flow import *

class CFG:
    def __init__(self, filename):
        self.entry = Entry_Node()
        self.exit = Exit_Node()
        self.build_cfg(filename)

    def build_cfg(self, filename):
        file = open(filename)
        slice = file.read()
        file.close()
        slice = json.loads(slice, object_hook=lambda d: SimpleNamespace(**d))
        f = self.visit(slice.ast_type)
        
        # Fix repetitive nodes on the returned node list and retrive the first entry node which can be transversed
        f(slice, self.entry)[1]
    
    def visit(self, type):
        f = getattr(self, 'on_' + type.lower()) # retrieve function to call later
        return f
    
    def eval(self, policy, patterns, vulnerabilities):
        for i in range(len(policy)):
            self.entry.eval(policy[i], patterns.patterns[i], vulnerabilities, Flow())
    
    def transverse(self):
        print('===== CFG =====')
        self.transverse_node(self.entry)
        
    def transverse_node(self, block):
        print(block)
        for children in block.children:
            self.transverse_node(children)
    
    def visit_body(self,nodes,data):
        if len(data) == 0:
            return []
        i = 0
        for item in data:
            f = self.visit(item.ast_type)
            parent = children = f(item,nodes[i])
            nodes[i].add_children(children)
            nodes.append(parent)
            i+=1
        return nodes
    
    def on_module(self, data,parent_node=None):
        # body is a list of nodes
        nodes = self.visit_body([parent_node],data.body)
        for node in nodes:
            if type(node) != list and len(node.children) == 0:
                node.add_children(self.exit)
                self.exit.add_parent(node)
        return nodes

    def on_expr(self, data, parent_node=None):
        f = self.visit(data.value.ast_type)
        value = f(data.value)

        return Expr_Node(data.lineno, parent_node, value)


    def on_call(self, data, parent_node=None):
        args = list()
        for item in data.args: # args is a list of arguments
            f = self.visit(item.ast_type)
            node = f(item)
            args.append(node)

        f = self.visit(data.func.ast_type)
        func = f(data.func)

        return Call_Node(data.lineno, parent_node, args, func)


    def on_constant(self, data, parent_node=None):
        return Constant_Node(data.lineno, parent_node, data.value)

    def on_name(self, data, parent_node=None):
        return Name_Node(data.lineno, parent_node, data.id, data.ctx.ast_type)
        
    def on_break(self, data, parent_node=None):
        return Break_Node(data.lineno,parent_node)

    def on_assign(self, data, parent_node=None):
        targets = list()
        for item in data.targets: # targets is a list of nodes to assign
            f = self.visit(item.ast_type)
            node = f(item)
            targets.append(node)
        
        f = self.visit(data.value.ast_type)
        value = f(data.value)
        
        return Assign_Node(data.lineno, parent_node, targets, value)

    def on_binop(self, data, parent_node=None):
        f = self.visit(data.left.ast_type)
        left = f(data.left)

        f = self.visit(data.right.ast_type)
        right = f(data.right)

        op = data.op.ast_type

        return BinOp_Node(data.lineno, parent_node, left, right, op)
    
    def on_compare(self, data, parent_node = None):
        f = self.visit(data.left.ast_type)
        left = f(data.left)
        comparators = list()
        for item in data.comparators: 
            f = self.visit(item.ast_type)
            node = f(item)
            comparators.append(node)
        ops = list()
        for item in data.ops:
            ops.append(item.ast_type)

        return Compare_Node(data.lineno, parent_node,comparators,left,ops)
    
    def on_attribute(self, data, parent_node=None):
        attr = data.attr
        ctx = data.ctx.ast_type
        
        f = self.visit(data.value.ast_type)
        value = f(data.value)

        return Attribute_Node(data.lineno, parent_node, attr, ctx, value)
    
    def visit_branch(self, root_node, nodes): # nodes can either be part of body or orelse branches
        last_node = None
        
        # visit first node
        if len(nodes) > 0:
            node = nodes[0]
            f = self.visit(node.ast_type)
            last_node = f(node)
            
            # link if node and first node
            last_node.add_parent(root_node)
            root_node.add_children(last_node, True) # True flag to signal that this is the first node in the branch
                    
        # visit remaining nodes
        for node in nodes[1:]:
            f = self.visit(node.ast_type)
            node = f(node)
            
            # link remaining children between themselves
            node.add_parent(last_node)
            last_node.add_children(node)   
            
            last_node = node
            
        return last_node
    
    def on_if(self, data, parent_node=None):
        #test
        test_f = self.visit(data.test.ast_type)
        test_node = test_f(data.test,parent_node)
        if_node = If_Node(data.lineno, test_node)
        self.visit_branch(if_node, data.body)
        self.visit_branch(if_node, data.orelse)
        return if_node

    def on_while(self, data, parent_node=None):
        #test
        test_f = self.visit(data.test.ast_type)
        test_node = test_f(data.test,parent_node)
        while_node = While_Node(data.lineno, test_node)
        
        last_body_node = self.visit_branch(while_node, data.body)
        self.visit_branch(while_node, data.orelse)
        self.link_body_to_orelse(while_node, last_body_node)
        
        return while_node
    
    def on_for(self, data, parent_node=None):
        #iter
        iter_f = self.visit(data.iter.ast_type)
        iter_node = iter_f(data.iter,parent_node)
        #target
        target_f = self.visit(data.iter.ast_type)
        target_node = target_f(data.iter,parent_node)
        
        for_node = For_Node(data.lineno, iter_node, target_node)
        
        last_body_node = self.visit_branch(for_node, data.body)
        self.visit_branch(for_node, data.orelse)
        self.link_body_to_orelse(for_node, last_body_node)

        return for_node
    
    def link_body_to_orelse(self, root_node, last_body_node):
        last_body_node.add_children(root_node)
        root_node.add_parent(last_body_node)
